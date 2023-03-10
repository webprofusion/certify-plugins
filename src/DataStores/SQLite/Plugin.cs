using Certify.Management;
using Certify.Models.Config;
using Certify.Models.Plugins;
using Certify.Plugins;
using Certify.Providers;

namespace Certify.Datastore.SQLite
{
    public class ManagedItemPlugin : PluginProviderBase<IManagedItemStore, ProviderDefinition>, IManagedItemProviderPlugin
    {

    }
    public class CredentialsStorePlugin : PluginProviderBase<ICredentialsManager, ProviderDefinition>, ICredentialStoreProviderPlugin
    {

    }
}
