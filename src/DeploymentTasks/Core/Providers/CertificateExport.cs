using Certify.Models;
using Certify.Models.Config;
using Certify.Providers.Deployment.Core.Shared;
using Certify.Shared.Core.Utils.PKI;
using Plugin.DeploymentTasks.Shared;
using SimpleImpersonation;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace Certify.Providers.DeploymentTasks
{
    // For formats see: https://serverfault.com/questions/9708/what-is-a-pem-file-and-how-does-it-differ-from-other-openssl-generated-key-file
    public class CertificateExport : IDeploymentTaskProvider
    {
        public static DeploymentProviderDefinition Definition { get; }
        public DeploymentProviderDefinition GetDefinition(DeploymentProviderDefinition currentDefinition = null) => (currentDefinition ?? Definition);


        static private Dictionary<string, string> ExportTypes = new Dictionary<string, string> {
            {"pemcrt", "PEM - Primary Certificate (e.g. .crt)" },
            {"pemchain", "PEM - Intermediate Certificate Chain + Root CA Cert (e.g. .chain)" },
            {"pemintermediates", "PEM - Intermediate Certificate Chain (e.g. .pem)" },
            {"pemkey", "PEM - Private Key (e.g. .key)" },
            {"pemfullnokey", "PEM - Full Certificate Chain (Excluding Key)" },
            {"pemfull", "PEM - Full Certificate Chain (Including Key)" },
            {"pemcrtpartialchain", "PEM - Primary Certificate + Intermediate Certificate Chain (e.g. .crt)" },
            {"pfxfull", "PFX (PKCX#12), Full certificate including private key" }
        };

        static CertificateExport()
        {
            var optionsList = string.Join(";", ExportTypes.Select(e => e.Key + "=" + e.Value));

            Definition = new DeploymentProviderDefinition
            {
                Id = "Certify.Providers.DeploymentTasks.CertificateExport",
                Title = "Export Certificate",
                IsExperimental = false,
                UsageType = DeploymentProviderUsage.PostRequest,
                SupportedContexts = DeploymentContextType.LocalAsService | DeploymentContextType.LocalAsUser | DeploymentContextType.WindowsNetwork | DeploymentContextType.SSH,
                Description = "Deploy latest certificate to a file (locally or remote)",
                ProviderParameters =

                    new List<ProviderParameter> {
                        new ProviderParameter { Key = "path", Name = "Destination File Path", IsRequired = true, IsCredential = false, Description="output file, e.g. C:\\CertifyCerts\\mycert.ext" },
                        new ProviderParameter { Key = "type", Name = "Export As", IsRequired = true, IsCredential = false, Value = "pfxfull", Type=OptionType.Select, OptionsList = optionsList },
                        }
            };
        }

        public Task<List<ActionResult>> Validate(DeploymentTaskExecutionParams execParams)
        {
            var settings = execParams.Settings;

            var results = new List<ActionResult> { };
            if (settings.ChallengeProvider == StandardAuthTypes.STANDARD_AUTH_LOCAL || settings.ChallengeProvider == StandardAuthTypes.STANDARD_AUTH_LOCAL_AS_USER)
            {
                //
            }
            else if (settings.ChallengeProvider == StandardAuthTypes.STANDARD_AUTH_WINDOWS)
            {
                //if windows network and paths are not UNC, fail validation
                var path = settings.Parameters.FirstOrDefault(c => c.Key == "path")?.Value.Trim();
                if (!path.StartsWith("\\\\"))
                {
                    results.Add(new ActionResult { IsSuccess = false, Message = "UNC Path Expected for Windows Network resource" });
                }
            }

            return Task.FromResult(results);
        }

        public async Task<List<ActionResult>> Execute(
               DeploymentTaskExecutionParams execParams
            )
        {
            var definition = execParams.Definition;

            if (definition == null)
            {
                definition = CertificateExport.Definition;
            }

            var results = await Validate(execParams);

            var managedCert = ManagedCertificate.GetManagedCertificate(execParams.Subject);

            if (string.IsNullOrEmpty(managedCert.CertificatePath) || !File.Exists(managedCert.CertificatePath))
            {
                results.Add(new ActionResult("Source certificate file is not present. Export cannot continue.", false));
            }

            if (results.Any())
            {
                // failed validation
                return results;
            }

            try
            {

                var settings = execParams.Settings;
                var log = execParams.Log;

                // prepare collection of files in the required formats

                // copy files to the required destination (local, UNC or SFTP)

                var pfxData = File.ReadAllBytes(managedCert.CertificatePath);

                // prepare list of files to copy

                var destPath = settings.Parameters.FirstOrDefault(c => c.Key == "path")?.Value.Trim();

                if (string.IsNullOrEmpty(destPath))
                {
                    return new List<ActionResult> { new ActionResult("Empty path provided. Skipping export", false) };
                }

                var exportType = settings.Parameters.FirstOrDefault(c => c.Key == "type")?.Value.Trim();
                var files = new Dictionary<string, byte[]>();

                var certPwd = "";

                if (!string.IsNullOrWhiteSpace(managedCert.CertificatePasswordCredentialId))
                {
                    var cred = await execParams.CredentialsManager.GetUnlockedCredentialsDictionary(managedCert.CertificatePasswordCredentialId);
                    if (cred != null)
                    {
                        certPwd = cred["password"];
                    }
                }


                // TODO: custom pfx pwd for export
                /*
                if (execParams.Credentials != null && execParams.Credentials.Any(c => c.Key == "cert_pwd_key"))
                {
                    var credKey = execParams.Credentials.First(c => c.Key == "cert_pwd_key");
                }
                */

                if (exportType == "pfxfull")
                {
                    files.Add(destPath, pfxData);
                }
                else if (exportType == "pemkey")
                {
                    files.Add(destPath, CertUtils.GetCertComponentsAsPEMBytes(pfxData, certPwd, ExportFlags.PrivateKey));
                }
                else if (exportType == "pemchain")
                {
                    files.Add(destPath, CertUtils.GetCertComponentsAsPEMBytes(pfxData, certPwd, ExportFlags.IntermediateCertificates | ExportFlags.RootCertificate));
                }
                else if (exportType == "pemintermediates")
                {
                    files.Add(destPath, CertUtils.GetCertComponentsAsPEMBytes(pfxData, certPwd, ExportFlags.IntermediateCertificates));
                }
                else if (exportType == "pemcrt")
                {
                    files.Add(destPath, CertUtils.GetCertComponentsAsPEMBytes(pfxData, certPwd, ExportFlags.EndEntityCertificate));
                }
                else if (exportType == "pemcrtpartialchain")
                {
                    files.Add(destPath, CertUtils.GetCertComponentsAsPEMBytes(pfxData, certPwd, ExportFlags.EndEntityCertificate | ExportFlags.IntermediateCertificates));
                }
                else if (exportType == "pemfull")
                {
                    files.Add(destPath, CertUtils.GetCertComponentsAsPEMBytes(pfxData, certPwd, ExportFlags.PrivateKey | ExportFlags.EndEntityCertificate | ExportFlags.IntermediateCertificates | ExportFlags.RootCertificate));
                }
                else if (exportType == "pemfullnokey")
                {
                    files.Add(destPath, CertUtils.GetCertComponentsAsPEMBytes(pfxData, certPwd, ExportFlags.EndEntityCertificate | ExportFlags.IntermediateCertificates | ExportFlags.RootCertificate));
                }

                // copy to destination

                var copiedOk = false;
                var msg = "";
                if (settings.ChallengeProvider == StandardAuthTypes.STANDARD_AUTH_SSH)
                {
                    // sftp file copy
                    var sshConfig = SshClient.GetConnectionConfig(settings, execParams.Credentials);

                    var sftp = new SftpClient(sshConfig);
                    var remotePath = destPath;

                    if (execParams.IsPreviewOnly)
                    {
                        var step = $"{definition.Title}: (Preview) would copy file via sftp to {remotePath} on host {sshConfig.Host}:{sshConfig.Port}";
                        msg += step + "\r\n";
                        log.Information(msg);
                    }
                    else
                    {
                        // copy via sftp
                        copiedOk = sftp.CopyLocalToRemote(files, log);

                        if (copiedOk)
                        {
                            log.Information($"{definition.Title}: copied file via sftp to {remotePath} on host {sshConfig.Host}:{sshConfig.Port}");
                        }
                        else
                        {
                            // file copy failed, abort
                            return new List<ActionResult>{
                            new ActionResult { IsSuccess = false, Message = "Export failed due to connection or file copy failure. Check log for more information."}
                        };
                        }
                    }
                }
                else if (settings.ChallengeProvider == StandardAuthTypes.STANDARD_AUTH_WINDOWS || settings.ChallengeProvider == StandardAuthTypes.STANDARD_AUTH_LOCAL_AS_USER || settings.ChallengeProvider == StandardAuthTypes.STANDARD_AUTH_LOCAL)
                {
                    // windows remote file copy

                    UserCredentials windowsCredentials = null;
                    if (execParams.Credentials != null && execParams.Credentials.Count > 0)
                    {
                        try
                        {
                            windowsCredentials = Helpers.GetWindowsCredentials(execParams.Credentials);
                        }
                        catch
                        {
                            var err = "Task with Windows Credentials requires username and password.";
                            log.Error(err);

                            return new List<ActionResult>{
                            new ActionResult { IsSuccess = false, Message = err
}
                        };
                        }
                    }

                    var _client = new WindowsNetworkFileClient(windowsCredentials);
                    if (execParams.IsPreviewOnly)
                    {
                        var step = $"{definition.Title}: (Preview) Windows file copy to {destPath}";
                        msg += step + " \r\n";
                    }
                    else
                    {
                        var step = $"{definition.Title}: Copying file (Windows file copy) to {destPath}";
                        msg += step + " \r\n";
                        log.Information(step);

                        var copyResults = _client.CopyLocalToRemote(log, files);

                        results.AddRange(copyResults);
                    }
                }
            }
            catch (Exception exp)
            {
                results.Add(new ActionResult($"Export failed with error: {exp}", false));
            }

            return await Task.FromResult(results);
        }
    }
}
