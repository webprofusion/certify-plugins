using Certify.Models.Config;
using Certify.Models.Plugins;
using Certify.Providers.DeploymentTasks;

namespace Plugin.DeploymentTasks.Azure
{
    public class Plugin : PluginProviderBase<IDeploymentTaskProvider, DeploymentProviderDefinition>, IDeploymentTaskProviderPlugin
    { }

}
