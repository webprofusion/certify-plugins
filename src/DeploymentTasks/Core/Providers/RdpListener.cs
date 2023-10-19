using Certify.Management;
using Certify.Models;
using Certify.Models.Config;
using Plugin.DeploymentTasks.Shared;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Certify.Providers.DeploymentTasks
{
    public class RdpListener : IDeploymentTaskProvider
    {
        public static DeploymentProviderDefinition Definition { get; }
        public DeploymentProviderDefinition GetDefinition(DeploymentProviderDefinition currentDefinition = null) => (currentDefinition ?? Definition);

        private const string SCRIPT_NAME = "RDPListenerService.ps1";

        static RdpListener()
        {
            Definition = new DeploymentProviderDefinition
            {
                Id = "Certify.Providers.DeploymentTasks.RDPListener",
                Title = "Deploy to RDP Listener Service (Terminal Services)",
                IsExperimental = true,
                UsageType = DeploymentProviderUsage.PostRequest,
                SupportedContexts = DeploymentContextType.LocalAsService | DeploymentContextType.LocalAsUser | DeploymentContextType.WindowsNetwork,
                Description = "Deploy latest certificate to RDP Listener Service using Powershell",
                ProviderParameters = new System.Collections.Generic.List<ProviderParameter>()
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
