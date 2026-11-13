using System.Collections.Generic;
using Certify.Models.Config;
using Certify.Models.Plugins;
using Certify.Plugins;
using Certify.Providers.DeploymentTasks;

namespace Plugin.DeploymentTasks.Core
{

    public class Plugin : PluginProviderBase<IDeploymentTaskProvider, DeploymentProviderDefinition>, IDeploymentTaskProviderPlugin, ICredentialTypeProviderPlugin
    {
        public List<ChallengeProviderDefinition> GetCredentialTypes() => CredentialTypes.GetAll();
    }
}
