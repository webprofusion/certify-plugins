using Certify.Models.Config;
using Certify.Models.Plugins;
using Certify.Models.Providers;
using Certify.Plugins;

namespace Plugin.ServerProviders.Core.Nginx
{

    public class Plugin : PluginProviderBase<ITargetWebServer, ProviderDefinition>, IServerProviderPlugin
    {

    }
}
