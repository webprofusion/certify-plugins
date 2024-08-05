using Certify.Management;
using Certify.Models;
using Certify.Models.Config;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace Certify.Providers.DeploymentTasks
{
    public class SetCertificateKeyPermissions : IDeploymentTaskProvider
    {
        public static DeploymentProviderDefinition Definition { get; }
        public DeploymentProviderDefinition GetDefinition(DeploymentProviderDefinition currentDefinition = null) => (currentDefinition ?? Definition);

        static SetCertificateKeyPermissions()
        {
            Definition = new DeploymentProviderDefinition
            {
                Id = "Certify.Providers.DeploymentTasks.SetCertificateKeyPermissions",
                Title = "Set Certificate Key Permissions)",
                DefaultTitle = "Set Certificate Key Permissions",
                IsExperimental = true,
                UsageType = DeploymentProviderUsage.PostRequest,
                SupportedContexts = DeploymentContextType.LocalAsService,
                SupportsRemoteTarget = false,
                Description = "Enable read access for the stored certificate private key for a specific account",
                ProviderParameters = new List<ProviderParameter>
                {
                      new ProviderParameter{ Key="account", Name="Account To Allow", IsRequired=true, IsCredential=false, Value="NT AUTHORITY\\LOCAL SERVICE"},
                      new ProviderParameter{ Key="permission", Name="Permission To Grant", IsRequired=false, IsCredential=false, Value="read", OptionsList="read=Read;fullcontrol=Full Control;" },
                }
            };
        }

        private List<ActionResult> PrepareErrorResult(string message)
        {
            return new List<ActionResult> { new ActionResult { IsSuccess = false, Message = message } };
        }

        public async Task<List<ActionResult>> Execute(DeploymentTaskExecutionParams execParams)
        {

            var validation = await Validate(execParams);

            if (validation.Any())
            {
                return validation;
            }

            var certRequest = execParams.Subject as CertificateRequestResult;

            execParams.Log?.Information("Executing command via PowerShell");

            var account = execParams.Settings.Parameters.FirstOrDefault(p => p.Key == "account")?.Value;
            var permission = execParams.Settings.Parameters.FirstOrDefault(p => p.Key == "permission")?.Value ?? "read";

            var managedCert = ManagedCertificate.GetManagedCertificate(execParams.Subject);

            if (string.IsNullOrEmpty(managedCert.CertificatePath) || !File.Exists(managedCert.CertificatePath))
            {
                return new List<ActionResult> { new ActionResult($"Certificate file not found: {managedCert.CertificatePath}", false) };
            }

            try
            {

                var settings = execParams.Settings;
                var log = execParams.Log;

                var pfxData = File.ReadAllBytes(managedCert.CertificatePath);

                var certPwd = "";

                if (!string.IsNullOrWhiteSpace(managedCert.CertificatePasswordCredentialId))
                {
                    var cred = await execParams.CredentialsManager.GetUnlockedCredentialsDictionary(managedCert.CertificatePasswordCredentialId);
                    if (cred != null)
                    {
                        certPwd = cred["password"];
                    }
                    else
                    {
                        return PrepareErrorResult($"The credentials for this task could not be unlocked or were not accessible {managedCert.CertificatePasswordCredentialId}.");
                    }
                }

                // get cert from store first otherwise it will be recreated on load with a new key file

                var cert = CertificateManager.GetCertificateByThumbprint(managedCert.CertificateThumbprintHash);

                if (cert == null)
                {
                    return PrepareErrorResult($"Certificate is not found in the machine certificate store. Private key permissions cannot be modified unless certificate has been stored.");
                }

                var certKeyPath = CertificateManager.GetCertificatePrivateKeyPath(cert);

                if (CertificateManager.GrantUserAccessToCertificatePrivateKey(cert, account, fileSystemRights: permission, execParams.Log))
                {
                    return new List<ActionResult> { new ActionResult($"Certificate private key ({certKeyPath}) permissions updated for account {account}", true) };
                }
                else
                {
                    return PrepareErrorResult($"Failed to update certificate private key permissions updated for account {account}");
                }
            }
            catch (Exception exp)
            {
                return PrepareErrorResult($"Failed to update certificate private key permissions updated for account {account}:: {exp}");
            }
        }

        public async Task<List<ActionResult>> Validate(DeploymentTaskExecutionParams execParams)
        {
            var results = new List<ActionResult>();

            if (string.IsNullOrEmpty(execParams.Settings.Parameters.FirstOrDefault(p => p.Key == "account")?.Value))
            {
                results.Add(new ActionResult("An account is required", false));
            }

            return await Task.FromResult(results);
        }

    }
}
