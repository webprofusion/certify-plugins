using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Certify.Management;
using Certify.Models;
using Certify.Models.Config;

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
                Title = "Set Certificate Key Permissions",
                DefaultTitle = "Set Certificate Key Permissions",
                IsExperimental = true,
                UsageType = DeploymentProviderUsage.PostRequest,
                SupportedContexts = DeploymentContextType.LocalAsService,
                SupportsRemoteTarget = false,
                Description = "Enable read access for the stored certificate private key for a specific account",
                ProviderParameters = new List<ProviderParameter>
                {
                      new() { Key="account", Name="Account To Allow", IsRequired=true, IsCredential=false, Value="NT AUTHORITY\\LOCAL SERVICE"},
                      new() { Key="permission", Name="Permission To Grant", IsRequired=false, IsCredential=false, Value="read", OptionsList="read=Read;fullcontrol=Full Control;" },
                }
            };
        }

        private List<ActionResult> PrepareErrorResult(string message)
        {
            return new List<ActionResult> { new() { IsSuccess = false, Message = message } };
        }

        public async Task<List<ActionResult>> Execute(DeploymentTaskExecutionParams execParams)
        {

            var validation = await Validate(execParams);

            if (validation.Any())
            {
                return validation;
            }

            var account = execParams.Settings.Parameters.FirstOrDefault(p => p.Key == "account")?.Value;
            var permission = execParams.Settings.Parameters.FirstOrDefault(p => p.Key == "permission")?.Value ?? "read";

            var managedCert = ManagedCertificate.GetManagedCertificate(execParams.Subject);

            if (string.IsNullOrEmpty(managedCert?.CertificateThumbprintHash))
            {
                return PrepareErrorResult("There is no current certificate for this managed certificate. Private key permissions can be updated once a certificate has been requested and stored.");
            }

            try
            {
                // get cert from store (try My, then Web Hosting), as the private key permissions apply to the stored key

                var cert = CertificateManager.GetCertificateByThumbprint(managedCert.CertificateThumbprintHash, CertificateManager.DEFAULT_STORE_NAME);

                if (cert == null)
                {
                    cert = CertificateManager.GetCertificateByThumbprint(managedCert.CertificateThumbprintHash, CertificateManager.WEBHOSTING_STORE_NAME);
                }

                if (cert == null)
                {
                    return PrepareErrorResult($"Certificate {managedCert.CertificateThumbprintHash} was not found in the machine certificate store (Personal or Web Hosting). Private key permissions can only be updated for a stored certificate.");
                }

                var certKeyPath = CertificateManager.GetCertificatePrivateKeyPath(cert);

                if (CertificateManager.GrantUserAccessToCertificatePrivateKey(cert, account, fileSystemRights: permission, execParams.Log))
                {
                    return new List<ActionResult> { new($"Certificate private key ({certKeyPath}) permissions updated for account {account}", true) };
                }
                else
                {
                    return PrepareErrorResult($"Failed to update certificate private key ({certKeyPath}) permissions for account {account}.");
                }
            }
            catch (Exception exp)
            {
                return PrepareErrorResult($"Failed to update certificate private key permissions for account {account}: {exp.Message}");
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
