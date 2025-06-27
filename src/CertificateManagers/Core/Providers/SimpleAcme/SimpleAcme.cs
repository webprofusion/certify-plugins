using Certify.Models.Config;
using Certify.Providers.CertificateManagers;

namespace Certify.Plugin.CertificateManagers.Providers.SimpleAcme
{
    public class SimpleAcme : CertificateManagers.Providers.WinAcme.WinAcme, ICertificateManager
    {
        internal override string AppDataFolder => "simple-acme";
        internal override string ProviderId => Definition.Id;
        internal override string ProviderTitle => Definition.Title;
        internal override string IdPrefix => Definition.Id;
        public static new ProviderDefinition Definition
        {
            get
            {
                return new ProviderDefinition
                {
                    Id = "simple-acme",
                    Title = "simple-acme",
                    Description = "Queries local config for certificates managed by simple-acme",
                    HelpUrl = "https://simple-acme.com"
                };
            }
        }
    }
}
