using Certify.Models.Config;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Certify.Providers.DeploymentTasks
{
    /// <summary>
    /// nginx specific version of certificate export deployment task
    /// </summary>
    public class Nginx : Apache, IDeploymentTaskProvider
    {
        public static new DeploymentProviderDefinition Definition { get; }
        public new DeploymentProviderDefinition GetDefinition(DeploymentProviderDefinition currentDefinition = null) => (currentDefinition ?? Definition);

        static Nginx()
        {
            Definition = new DeploymentProviderDefinition
            {
                Id = "Certify.Providers.DeploymentTasks.Nginx",
                Title = "Deploy to nginx",
                IsExperimental = false,
                UsageType = DeploymentProviderUsage.PostRequest,
                SupportedContexts = DeploymentContextType.LocalAsService | DeploymentContextType.LocalAsUser | DeploymentContextType.WindowsNetwork | DeploymentContextType.SSH,
                Description = "Deploy latest certificate to a local or remote nginx server",
                ProviderParameters = Apache.Definition.ProviderParameters
            };
        }

        public new async Task<List<ActionResult>> Execute(DeploymentTaskExecutionParams execParams)
        {
            return await base.Execute(execParams);
        }

        public new async Task<List<ActionResult>> Validate(DeploymentTaskExecutionParams execParams)
        {

            return await base.Validate(execParams);
        }
    }
}
