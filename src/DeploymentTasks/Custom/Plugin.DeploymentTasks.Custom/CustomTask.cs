using Certify.Models.Config;
using Certify.Providers.DeploymentTasks;
using RestSharp;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Plugin.DeploymentTasks.Custom
{

    public class CustomTask : IDeploymentTaskProvider
    {
        public static DeploymentProviderDefinition Definition { get; }
        public DeploymentProviderDefinition GetDefinition(DeploymentProviderDefinition currentDefinition = null) => (currentDefinition ?? Definition);

        static CustomTask()
        {
            Definition = new DeploymentProviderDefinition
            {
                Id = "Certify.Providers.DeploymentTasks.Custom",
                Title = "Example Custom Plugin Task",
                IsExperimental = true,
                UsageType = DeploymentProviderUsage.PostRequest,
                SupportedContexts = DeploymentContextType.LocalAsService,
                Description = "This is a simple custom plugin task",
                ProviderParameters = new List<ProviderParameter>
                {
                    new ProviderParameter{ Key="msg", Name="Message", IsRequired=true, IsCredential=false,  Description="e.g. hello", Type= OptionType.String },
                }
            };
        }

        public async Task<List<ActionResult>> Execute(DeploymentTaskExecutionParams execParams)
        {

            var definition = GetDefinition(execParams.Definition);

            var results = await Validate(execParams);

            if (results.Any())
            {
                return results;
            }
            
            // perform a custom step which will invoke a foreign dependency not used by the main Certify app

            var client = new RestClient("http://worldtimeapi.org/api");
            var request = new RestRequest("/ip", DataFormat.Json);
            var httpResult = await client.GetAsync<string>(request);

            var msg = execParams.Settings.Parameters.FirstOrDefault(c => c.Key == "msg")?.Value ?? "<none>";

            msg += httpResult;

            results.Add(new ActionResult(msg, true));

            return results;
        }

        public async Task<List<ActionResult>> Validate(DeploymentTaskExecutionParams execParams)
        {
            var results = new List<ActionResult> { };

            var msg = execParams.Settings.Parameters.FirstOrDefault(c => c.Key == "msg")?.Value;
            if (string.IsNullOrEmpty(msg))
            {
                results.Add(new ActionResult("Please provide a message", false));
            }

            return await Task.FromResult(results);
        }
    }
}
