using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Certify.Models;
using Certify.Models.Config;
using Certify.Providers.Deployment.Core.Shared;
using Certify.Shared.Core.Utils.PKI;
using Plugin.DeploymentTasks.Shared;
using SimpleImpersonation;

namespace Certify.Providers.DeploymentTasks
{
    public class CentralizedCertificateStore : IDeploymentTaskProvider
    {
        public static DeploymentProviderDefinition Definition { get; }
        public DeploymentProviderDefinition GetDefinition(DeploymentProviderDefinition currentDefinition = null) => (currentDefinition ?? Definition);

        static CentralizedCertificateStore()
        {
            Definition = new DeploymentProviderDefinition
            {
                Id = "Certify.Providers.DeploymentTasks.CCS",
                Title = "Deploy to Centralized Certificate Store (CCS)",
                DefaultTitle = "Deploy to CCS",
                IsExperimental = false,
                UsageType = DeploymentProviderUsage.PostRequest,
                SupportedContexts = DeploymentContextType.LocalAsService | DeploymentContextType.LocalAsUser | DeploymentContextType.WindowsNetwork,
                SupportsRemoteTarget = true,
                Description = "Deploy latest certificate to Windows Centralized Certificate Store. Note: if a local IIS install is present you should disable Auto deployment to avoid mixing use of local certs bindings and CCS.",
                ProviderParameters = new System.Collections.Generic.List<ProviderParameter>
                {
                    new ProviderParameter{
                        Key ="path",
                        Name ="Destination Path",
                        IsRequired =true,
                        IsCredential =false,
                        Description="UNC Path or Local Share"
                    },
                    ExportPassword.GetParameter()
                }
            };
        }

        public async Task<List<ActionResult>> Execute(DeploymentTaskExecutionParams execParams)
        {

            var validationResults = await Validate(execParams);
            if (validationResults.Any())
            {
                return validationResults;
            }

            var managedCert = ManagedCertificate.GetManagedCertificate(execParams.Subject);

            UserCredentials windowsCredentials = null;

            if (execParams.Credentials != null && execParams.Credentials.Count > 0)
            {
                try
                {
                    windowsCredentials = Helpers.GetWindowsCredentials(execParams.Credentials);
                }
                catch
                {
                    return new List<ActionResult>{
                        new ActionResult { IsSuccess = false, Message = "CCS Export task with Windows Credentials requires username and password." }
                    };
                }
            }

            try
            {

                var windowsFileClient = new WindowsNetworkFileClient(windowsCredentials);

                var pfxData = File.ReadAllBytes(managedCert.CertificatePath);

                // if the task sets a new password, re-encrypt the PFX with it, otherwise copy the PFX as-is
                var newPwd = await ExportPassword.GetNewPassword(execParams);
                if (!newPwd.IsSuccess)
                {
                    return new List<ActionResult> { newPwd };
                }

                if (newPwd.Result != null)
                {
                    var certPwd = await ExportPassword.GetCertificatePassword(execParams, managedCert);
                    if (!certPwd.IsSuccess)
                    {
                        return new List<ActionResult> { certPwd };
                    }

                    pfxData = CertUtils.GetPfxWithNewPassword(pfxData, certPwd.Result, newPwd.Result, execParams.Context?.UseModernPFXAlgs == true);
                }

                var domains = managedCert.GetCertificateDomains();

                var files = new Dictionary<string, byte[]>();

                var destinationPath = execParams.Settings.Parameters?.FirstOrDefault(d => d.Key == "path")?.Value;

                foreach (var domain in domains)
                {

                    // normalise wildcard domains to _.domain.com for file store
                    var targetDomain = domain.Replace('*', '_');

                    // attempt save to store, which may be a network UNC path or otherwise authenticated resource

                    if (!string.IsNullOrWhiteSpace(destinationPath))
                    {
                        var filename = Path.Combine(destinationPath.Trim(), targetDomain + ".pfx");

                        execParams.Log?.Information($"{Definition.Title}: Storing PFX as {filename}");

                        files[filename] = pfxData;
                    }
                }

                if (files.Count == 0)
                {
                    return new List<ActionResult>{
                    new ActionResult { IsSuccess = true, Message = $"{Definition.Title}: Nothing to copy." }
                   };
                }
                else
                {
                    if (!execParams.IsPreviewOnly)
                    {
                        var results = windowsFileClient.CopyLocalToRemote(execParams.Log, files);

                        if (!results.All(s => s.IsSuccess == true))
                        {
                            return results;
                        }
                    }
                }

                return new List<ActionResult>{
                   new ActionResult { IsSuccess = true, Message = "File copying completed" }
                };

            }
            catch (Exception exp)
            {
                return new List<ActionResult>{
                   new ActionResult { IsSuccess = false, Message = $"CCS Export Failed with error: {exp}" }
                };
            }
        }

        public async Task<List<ActionResult>> Validate(DeploymentTaskExecutionParams execParams)
        {
            var results = new List<ActionResult>();

            var destinationPath = execParams.Settings.Parameters?.FirstOrDefault(d => d.Key == "path")?.Value;

            if (string.IsNullOrEmpty(destinationPath))
            {
                results.Add(new ActionResult("A path parameter is required for export.", false));
            }

            return await Task.FromResult(results);
        }
    }
}

