using Certify.Management;
using Certify.Models;
using Certify.Models.Config;
using Plugin.DeploymentTasks.Shared;
using System.Collections.Generic;
using System.Linq;
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
                SupportedContexts = DeploymentContextType.LocalAsService | DeploymentContextType.LocalAsUser | DeploymentContextType.WindowsNetwork,
                Description = "Deploy latest certificate to MS Exchange Services",
                ProviderParameters = new List<ProviderParameter>
                {
                      new ProviderParameter{ Key="services", Name="Services", IsRequired=true, IsCredential=false, Value="POP,IMAP,SMTP,IIS"},
                      new ProviderParameter{ Key="donotrequiressl", Name="Do Not Require Ssl", IsRequired=false, Type= OptionType.Boolean, IsCredential = false,Value="false" },
                      new ProviderParameter { Key = "logontype", Name = "Impersonation LogonType", IsRequired= false, IsCredential= false, Type= OptionType.Select, Value="interactive", OptionsList=Helpers.LogonTypeOptions },
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

            var services = execParams.Settings.Parameters.FirstOrDefault(p => p.Key == "services")?.Value;
            var doNotRequireSsl = execParams.Settings.Parameters.FirstOrDefault(p => p.Key == "donotrequiressl")?.Value;
            var logonType = execParams.Settings.Parameters.FirstOrDefault(c => c.Key == "logontype")?.Value ?? null;

            var parameters = new Dictionary<string, object>
            {
                { "services", services },
                { "addDoNotRequireSslFlag", doNotRequireSsl }
            };

            var scriptResult = await PowerShellManager.RunScript(execParams.Context.PowershellExecutionPolicy, certRequest, parameters: parameters, scriptContent: script, credentials: execParams.Credentials, logonType: logonType);

            return new List<ActionResult> { scriptResult };
        }

        public async Task<List<ActionResult>> Validate(DeploymentTaskExecutionParams execParams)
        {
            var results = new List<ActionResult>();

            if (string.IsNullOrEmpty(execParams.Settings.Parameters.FirstOrDefault(p => p.Key == "services")?.Value))
            {
                results.Add(new ActionResult("One or more services are required to apply certificate to. E.g. POP,IMAP,SMTP,IIS", false));
            }

            return await Task.FromResult(results);
        }

    }
}
