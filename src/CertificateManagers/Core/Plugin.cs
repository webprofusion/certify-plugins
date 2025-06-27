using Certify.Models.Config;
using Certify.Models.Plugins;
using Certify.Plugins;
using Certify.Providers.CertificateManagers;

namespace Certify.Plugin.CertificateManagers
{
    public class Plugin : PluginProviderBase<ICertificateManager, ProviderDefinition>, ICertificateManagerProviderPlugin
    {
    }
}
