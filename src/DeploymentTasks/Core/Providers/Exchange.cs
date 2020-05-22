using Certify.Config;
using Certify.Management;
using Certify.Models;
using Certify.Models.Config;
using Certify.Models.Providers;
using Plugin.DeploymentTasks.Shared;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace Certify.Providers.DeploymentTasks
{
    public class Exchange : IDeploymentTaskProvider
    {
        public static DeploymentProviderDefinition Definition { get; }
        public DeploymentProviderDefinition GetDefinition(DeploymentProviderDefinition currentDefinition = null) => (currentDefinition ?? Definition);

        private const string SCRIPT_NAME = "Exchange.ps1";

        static Exchange()
        {
            Definition = new DeploymentProviderDefinition
            {
                Id = "Certify.Providers.DeploymentTasks.Exchange",
                Title = "Deploy to Microsoft Exchange (2013 or higher)",
                DefaultTitle = "Deploy to Exchange",
                IsExperimental = false,
                UsageType = DeploymentProviderUsage.PostRequest,
                SupportedContexts = DeploymentContextType.LocalAsService | DeploymentContextType.LocalAsUser,
                Description = "Deploy latest certificate to MS Exchange Services",
                ProviderParameters = new List<ProviderParameter>
                {
                      new ProviderParameter{ Key="services", Name="Services", IsRequired=true, IsCredential=false, Value="POP,IMAP,SMTP,IIS"}
                }
            };
        }

        public async Task<List<ActionResult>> Execute(ILog log, object subject, DeploymentTaskConfig settings, Dictionary<string, string> credentials, bool isPreviewOnly, DeploymentProviderDefinition definition, CancellationToken cancellationToken)
        {

            var validation = await Validate(subject, settings, credentials, definition);

            if (validation.Any())
            {
                return validation;
            }

            var script = Helpers.ReadStringResource(SCRIPT_NAME);

            var certRequest = subject as CertificateRequestResult;

            log?.Information("Executing command via PowerShell");

            var services = settings.Parameters.FirstOrDefault(p => p.Key == "services")?.Value;

            var parameters = new Dictionary<string, object>
            {
                { "services", services }
            };

            var scriptResult = await PowerShellManager.RunScript(certRequest, parameters: parameters, scriptContent: script, credentials: credentials);

            return new List<ActionResult> { scriptResult };
        }

        public async Task<List<ActionResult>> Validate(object subject, DeploymentTaskConfig settings, Dictionary<string, string> credentials, DeploymentProviderDefinition definition)
        {
            var results = new List<ActionResult>();

            if (string.IsNullOrEmpty(settings.Parameters.FirstOrDefault(p => p.Key == "services")?.Value))
            {
                results.Add(new ActionResult("One or more services are required to apply certificate to. E.g. POP,IMAP,SMTP,IIS", false));
            }
            return results;
        }

    }
}
