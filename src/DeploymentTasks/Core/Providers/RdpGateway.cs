using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Certify.Config;
using Certify.Management;
using Certify.Models;
using Certify.Models.Config;
using Certify.Models.Providers;
using Plugin.DeploymentTasks.Shared;

namespace Certify.Providers.DeploymentTasks
{
    public class RdpGateway : IDeploymentTaskProvider
    {
        public static DeploymentProviderDefinition Definition { get; }
        public DeploymentProviderDefinition GetDefinition(DeploymentProviderDefinition currentDefinition = null) => (currentDefinition ?? Definition);

        private const string SCRIPT_NAME = "RDPGatewayServices.ps1";

        static RdpGateway()
        {
            Definition = new DeploymentProviderDefinition
            {
                Id = "Certify.Providers.DeploymentTasks.RDPGateway",
                Title = "Deploy to RDP Gateway Service",
                IsExperimental = true,
                UsageType = DeploymentProviderUsage.PostRequest,
                SupportedContexts = DeploymentContextType.LocalAsService | DeploymentContextType.LocalAsUser,
                Description = "Deploy latest certificate to RDP Gateway Service using Powershell",
                ProviderParameters = new List<ProviderParameter>
                {
                    new ProviderParameter { Key = "restartServices", Name = "Include Service Restart?", Type= OptionType.Boolean, IsCredential = false, Value="false" },
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

            var parameters = new Dictionary<string, object>();

            var scriptResult = await PowerShellManager.RunScript(execParams.Context.PowershellExecutionPolicy, certRequest, parameters: parameters, scriptContent: script, credentials: execParams.Credentials);

            return new List<ActionResult> { scriptResult };

        }

        public async Task<List<ActionResult>> Validate(DeploymentTaskExecutionParams execParams)
        {
            var results = new List<ActionResult>();

            return await Task.FromResult(results);
        }
    }
}
