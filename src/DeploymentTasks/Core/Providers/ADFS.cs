using System.Collections.Generic;
using System.Threading.Tasks;
using Certify.Config;
using Certify.Models;
using Certify.Models.Providers;
using Certify.Models.Config;
using Plugin.DeploymentTasks.Shared;
using System.Linq;
using System.Threading;
using Certify.Management;

namespace Certify.Providers.DeploymentTasks
{
    public class Adfs : IDeploymentTaskProvider
    {
        public static DeploymentProviderDefinition Definition { get; }
        public DeploymentProviderDefinition GetDefinition(DeploymentProviderDefinition currentDefinition) => (currentDefinition ?? Definition);

        private const string SCRIPT_NAME = "ADFS.ps1";

        public async Task<List<ActionResult>> Execute(ILog log, object subject, DeploymentTaskConfig settings, Dictionary<string, string> credentials, bool isPreviewOnly, DeploymentProviderDefinition definition, CancellationToken cancellationToken)
        {
            var validation = await Validate(subject, settings, credentials, definition);

            if (validation.Any())
            {
                return validation;
            }

            var script = Helpers.ReadStringResource(SCRIPT_NAME);

            definition = GetDefinition(definition);

            var certRequest = subject as CertificateRequestResult;

            log?.Information("Executing command via PowerShell");

            var performRestart = settings.Parameters.FirstOrDefault(p => p.Key == "performServiceRestart")?.Value;

            var parameters = new Dictionary<string, object>
            {
                { "performServiceRestart", performRestart }
            };

            var scriptResult = await PowerShellManager.RunScript(certRequest, parameters: parameters, scriptContent: script, credentials: credentials);

            return new List<ActionResult> { scriptResult };
        }

        public new async Task<List<ActionResult>> Validate(object subject, DeploymentTaskConfig settings, Dictionary<string, string> credentials, DeploymentProviderDefinition definition)
        {
            var results = new List<ActionResult>();

            // validate

            return await Task.FromResult(results);
        }

        static Adfs()
        {
            Definition = new DeploymentProviderDefinition
            {
                Id = "Certify.Providers.DeploymentTasks.ADFS",
                Title = "Deploy Certificate to ADFS",
                UsageType = DeploymentProviderUsage.PostRequest,
                SupportedContexts = DeploymentContextType.LocalAsService | DeploymentContextType.LocalAsUser,
                IsExperimental = true,
                Description = "Apply certificate to local Active Directory Federation Services (ADFS) service",
                ProviderParameters = new List<ProviderParameter>
                {
                     new ProviderParameter { Key = "restartServices", Name = "Include Service Restart?",  Type= OptionType.Boolean, IsCredential = false,Value="false" },
                }
            };
        }
    }
}
