using Certify.Management;
using Certify.Models;
using Certify.Models.Config;
using Plugin.DeploymentTasks.Shared;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Certify.Providers.DeploymentTasks
{
    public class SetCertificateKeyPermissions : IDeploymentTaskProvider
    {
        public static DeploymentProviderDefinition Definition { get; }
        public DeploymentProviderDefinition GetDefinition(DeploymentProviderDefinition currentDefinition = null) => (currentDefinition ?? Definition);

        private const string SCRIPT_NAME = "SetCertificateKeyPermissions.ps1";

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
                Description = "Enable read access for the stored certificate private key for a specific account",
                ProviderParameters = new List<ProviderParameter>
                {
                      new ProviderParameter{ Key="account", Name="Account To Allow", IsRequired=true, IsCredential=false, Value="NT AUTHORITY\\LOCAL SERVICE"},
                }
            };
        }

        public async Task<List<ActionResult>> Execute(DeploymentTaskExecutionParams execParams)
        {

            var validation = await Validate(execParams);

            if (validation.Any())
            {
                return validation;
            }

            var script = Helpers.ReadStringResource(SCRIPT_NAME);

            var certRequest = execParams.Subject as CertificateRequestResult;

            execParams.Log?.Information("Executing command via PowerShell");

            var account = execParams.Settings.Parameters.FirstOrDefault(p => p.Key == "account")?.Value;

            var parameters = new Dictionary<string, object>
            {
                { "account", account }
            };

            var scriptResult = await PowerShellManager.RunScript(execParams.Context.PowershellExecutionPolicy, certRequest, parameters: parameters, scriptContent: script, credentials: execParams.Credentials);

            return new List<ActionResult> { scriptResult };
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
