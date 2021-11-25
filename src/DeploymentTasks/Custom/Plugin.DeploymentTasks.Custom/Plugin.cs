using Certify.Models.Config;
using Certify.Models.Plugins;
using Certify.Providers.DeploymentTasks;

namespace Plugin.DeploymentTasks.Custom
{
    public class Plugin : PluginProviderBase<IDeploymentTaskProvider, DeploymentProviderDefinition>, IDeploymentTaskProviderPlugin
    { }

}
