using System;
using System.Collections.Generic;
using System.Linq;

namespace Certify.Plugin.CertificateManagers.Migration
{
    /// <summary>
    /// A DNS provider known to the migration, keyed by a tool neutral catalogue key
    /// </summary>
    public class DnsProviderEntry
    {
        public string Key { get; init; } = string.Empty;
        public string Title { get; init; } = string.Empty;

        /// <summary>
        /// The challenge provider here, or null if there is no equivalent
        /// </summary>
        public string? ProviderId { get; init; }

        /// <summary>
        /// Values set on every migrated challenge, by parameter key
        /// </summary>
        public Dictionary<string, string> FixedValues { get; init; } = new();

        /// <summary>
        /// Shown as an assumption whenever the provider is mapped
        /// </summary>
        public string? Note { get; init; }
    }

    /// <summary>
    /// How one tool names a DNS provider and its options
    /// </summary>
    public class DnsProviderAlias
    {
        public string SourcePluginId { get; init; } = string.Empty;
        public string Key { get; init; } = string.Empty;

        /// <summary>
        /// Source option name to parameter key here. An option not listed is reported as unmapped
        /// </summary>
        public Dictionary<string, string> Options { get; init; } = new(StringComparer.OrdinalIgnoreCase);

        /// <summary>
        /// Source option values translated for a parameter, by parameter key, then source value (case-insensitive)
        /// </summary>
        public Dictionary<string, Dictionary<string, string>> ValueMaps { get; init; } = new();

        /// <summary>
        /// Options which, when true, mean the source authenticates without a stored secret (e.g. a managed identity),
        /// which cannot migrate as is
        /// </summary>
        public string[] AmbientAuthOptions { get; init; } = [];

        /// <summary>
        /// Options holding the path of a file whose content is the parameter value (e.g. a key file), by parameter key
        /// </summary>
        public Dictionary<string, string> FileOptions { get; init; } = new(StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Mapping tables shared by migration sources. Provider ids and parameter keys are those of the providers here, and
    /// each tool lists its own names for them as aliases
    /// </summary>
    public static class MigrationCatalogue
    {
        public const string PoshAcmePrefix = "DNS01.API.PoshACME.";
        public const string ScriptDnsProviderId = "DNS01.Scripting";
        public const string ManualDnsProviderId = "DNS01.Manual";
        public const string AcmeDnsProviderId = "DNS01.API.AcmeDns";

        public const string TaskCertificateExport = "Certify.Providers.DeploymentTasks.CertificateExport";
        public const string TaskCcs = "Certify.Providers.DeploymentTasks.CCS";
        public const string TaskKeyVault = "Certify.Providers.DeploymentTasks.AzureKeyVault";
        public const string TaskKeyPermissions = "Certify.Providers.DeploymentTasks.SetCertificateKeyPermissions";
        public const string TaskPowerShell = "Certify.Providers.DeploymentTasks.Powershell";

        public const string PasswordCredentialType = "Certify.StandardChallenges.Password";
        public const string AzureClientSecretCredentialType = "ExternalAuth.Azure.ClientSecret";

        public static readonly IReadOnlyList<DnsProviderEntry> DnsProviders =
        [
            new() { Key = "azure", Title = "Azure DNS", ProviderId = "DNS01.API.Azure" },
            new() { Key = "cloudflare", Title = "Cloudflare", ProviderId = "DNS01.API.Cloudflare" },
            new() { Key = "digitalocean", Title = "DigitalOcean", ProviderId = PoshAcmePrefix + "DigitalOcean" },
            new() { Key = "dnsexit", Title = "DNSExit", ProviderId = PoshAcmePrefix + "DNSExit" },
            new() { Key = "dnsmadeeasy", Title = "DNS Made Easy", ProviderId = "DNS01.API.DnsMadeEasy" },
            new() { Key = "domeneshop", Title = "Domeneshop", ProviderId = PoshAcmePrefix + "Domeneshop" },
            new() { Key = "dreamhost", Title = "DreamHost", ProviderId = PoshAcmePrefix + "Dreamhost" },
            new() { Key = "godaddy", Title = "GoDaddy", ProviderId = "DNS01.API.GoDaddy" },
            new() { Key = "googlecloud", Title = "Google Cloud DNS", ProviderId = PoshAcmePrefix + "GCloud", Note = "The service account key file stays where it is and is read from that path at each renewal." },
            new() { Key = "hetzner", Title = "Hetzner DNS", ProviderId = PoshAcmePrefix + "Hetzner" },
            new() { Key = "hetznercloud", Title = "Hetzner Cloud DNS", ProviderId = PoshAcmePrefix + "HetznerCloud" },
            new() { Key = "infomaniak", Title = "Infomaniak", ProviderId = PoshAcmePrefix + "InfomaniakV2" },
            new() { Key = "linode", Title = "Linode", ProviderId = PoshAcmePrefix + "Linode" },
            new() { Key = "luadns", Title = "LuaDNS", ProviderId = PoshAcmePrefix + "LuaDns" },
            new() { Key = "ns1", Title = "NS1", ProviderId = PoshAcmePrefix + "NS1" },
            new() { Key = "rfc2136", Title = "RFC2136 (dynamic DNS update)", ProviderId = PoshAcmePrefix + "RFC2136", Note = "Updates are sent with nsupdate, which must be installed on this machine. Set its path on the item if it is not on the PATH." },
            new() { Key = "route53", Title = "Amazon Route 53", ProviderId = "DNS01.API.Route53" },
            new() { Key = "simply", Title = "Simply.com", ProviderId = PoshAcmePrefix + "Simply" },
            new() { Key = "tencent", Title = "Tencent Cloud DNS", ProviderId = PoshAcmePrefix + "TencentDNS" },
            new() { Key = "transip", Title = "TransIP", ProviderId = "DNS01.API.TransIP" },
            new() { Key = "aliyun", Title = "Alibaba Cloud DNS", ProviderId = "DNS01.API.Aliyun" },
            new() { Key = "bunny", Title = "Bunny DNS", ProviderId = PoshAcmePrefix + "Bunny" },
            new() { Key = "acme-dns", Title = "acme-dns", ProviderId = AcmeDnsProviderId },
            new() { Key = "script", Title = "Script", ProviderId = ScriptDnsProviderId, Note = "The source's script runs through a wrapper script, which passes it the arguments it was configured with. The script must work when run by this instance's service account." },
            new() { Key = "ovh", Title = "OVH", ProviderId = "DNS01.API.Ovh" },
            new() { Key = "ionos", Title = "IONOS", ProviderId = "DNS01.API.IONOS" },
            new() { Key = "dnsimple", Title = "DNSimple", ProviderId = PoshAcmePrefix + "DNSimple" },
            new() { Key = "desec", Title = "deSEC", ProviderId = PoshAcmePrefix + "DeSEC" },
            new() { Key = "porkbun", Title = "Porkbun", ProviderId = PoshAcmePrefix + "Porkbun" },
            new() { Key = "hurricaneelectric", Title = "Hurricane Electric", ProviderId = PoshAcmePrefix + "HurricaneElectric" },
            new() { Key = "dynu", Title = "Dynu", ProviderId = PoshAcmePrefix + "Dynu" },
            new() { Key = "inwx", Title = "INWX", ProviderId = PoshAcmePrefix + "INWX" },
            new() { Key = "gandi", Title = "Gandi", ProviderId = PoshAcmePrefix + "Gandi" },
            new() { Key = "namesilo", Title = "NameSilo", ProviderId = PoshAcmePrefix + "NameSilo" },
            new() { Key = "namecheap", Title = "Namecheap", ProviderId = PoshAcmePrefix + "NameCheap" },
            new() { Key = "namecom", Title = "Name.com", ProviderId = PoshAcmePrefix + "NameCom" },

            // no equivalent here
            new() { Key = "gehirn", Title = "Gehirn DNS" },
            new() { Key = "sakuracloud", Title = "Sakura Cloud DNS" },
            new() { Key = "arsys", Title = "Arsys" },
            new() { Key = "czechia", Title = "Czechia" },
            new() { Key = "dnsmint", Title = "DnsMint" },
            new() { Key = "huaweicloud", Title = "Huawei Cloud DNS" },
            new() { Key = "ipprojects", Title = "IP-Projects" },
            new() { Key = "level27", Title = "Level27" },
            new() { Key = "webnames", Title = "Webnames" }
        ];

        private static readonly Dictionary<string, string> AzureEnvironments = new(StringComparer.OrdinalIgnoreCase)
        {
            ["AzureCloud"] = "global",
            ["AzurePublicCloud"] = "global",
            ["AzureChinaCloud"] = "china",
            ["AzureGermanCloud"] = "germany",
            ["AzureGermany"] = "germany",
            ["AzureUSGovernment"] = "usgov",
            ["AzureUSGovernmentCloud"] = "usgov"
        };

        private static Dictionary<string, string> Map(params (string Source, string Target)[] pairs) =>
            pairs.ToDictionary(p => p.Source, p => p.Target, StringComparer.OrdinalIgnoreCase);

        /// <summary>
        /// win-acme and simple-acme DNS validation plugins, by plugin GUID
        /// </summary>
        public static readonly IReadOnlyList<DnsProviderAlias> WinAcmeDnsAliases =
        [
            new()
            {
                SourcePluginId = "aa57b028-45fb-4aca-9cac-a63d94c76b4a", Key = "azure",
                Options = Map(("AzureEnvironment", "service"), ("ClientId", "clientid"), ("SecretSafe", "secret"), ("SubscriptionId", "subscriptionid"), ("TenantId", "tenantid"), ("ResourceGroupName", "resourcegroupname")),
                ValueMaps = new() { ["service"] = AzureEnvironments },
                AmbientAuthOptions = ["UseMsi"]
            },
            new() { SourcePluginId = "73af2c2e-4cf1-4198-a4c8-1129003cfb75", Key = "cloudflare", Options = Map(("ApiToken", "apitoken")) },
            new() { SourcePluginId = "1a87d670-3fa3-4a2a-bb10-491d48feb5db", Key = "digitalocean", Options = Map(("ApiToken", "DOToken")) },
            new() { SourcePluginId = "c9017182-1000-4257-a8da-0553cd1490ec", Key = "dnsexit", Options = Map(("ApiKey", "DNSExitApiKey")) },
            new() { SourcePluginId = "13993334-2d74-4ff6-801b-833b99bf231d", Key = "dnsmadeeasy", Options = Map(("ApiKey", "apikey"), ("ApiSecret", "apisecret")) },

            // these plugins store their first secret under the name SecretSafe
            new() { SourcePluginId = "0bd9b320-08e0-4bfe-a535-b979886187e4", Key = "domeneshop", Options = Map(("SecretSafe", "DomeneshopToken"), ("ClientSecret", "DomeneshopSecret")) },
            new() { SourcePluginId = "2bfb3ef8-64b8-47f1-8185-ea427b793c1a", Key = "dreamhost", Options = Map(("SecretSafe", "DreamhostApiKey")) },
            new() { SourcePluginId = "966c4c3d-1572-44c7-9134-5e2bc8fa021d", Key = "godaddy", Options = Map(("SecretSafe", "authkey"), ("ApiSecret", "authsecret")) },

            new() { SourcePluginId = "b61505e9-1709-43fd-996f-c74c3686286c", Key = "googlecloud", Options = Map(("ServiceAccountKeyPath", "GCKeyFile"), ("ProjectId", "GCProjectId")) },
            new() { SourcePluginId = "7176cc8f-ba08-4b07-aa39-2f5d012c1d5a", Key = "hetzner", Options = Map(("ApiToken", "HetznerTokenInsecure"), ("ZoneId", "")) },
            new() { SourcePluginId = "d1401d1e-b925-407d-a38b-924d67b2d1b5", Key = "infomaniak", Options = Map(("ApiToken", "InfomaniakToken")) },
            new() { SourcePluginId = "12fdc54c-be30-4458-8066-2c1c565fe2d9", Key = "linode", Options = Map(("ApiToken", "LITokenInsecure")) },
            new() { SourcePluginId = "3b0c3cca-db98-40b7-b678-b34791070d42", Key = "luadns", Options = Map(("Username", "LuaUsername"), ("APIKeySafe", "LuaPassword")) },
            new() { SourcePluginId = "c66cc8be-3046-46c2-a0ba-ec4ec3e7fe96", Key = "ns1", Options = Map(("APIKeySafe", "NS1KeyInsecure")) },
            new()
            {
                SourcePluginId = "ed5dc9d1-739c-4f6a-854f-238bf65b63ee", Key = "rfc2136",
                Options = Map(("ServerHost", "DDNSNameserver"), ("ServerPort", "DDNSPort"), ("TsigKeyName", "DDNSKeyName"), ("TsigKeySecret", "DDNSKeyValueInsecure"), ("TsigKeyAlgorithm", "DDNSKeyType"))
            },
            new() { SourcePluginId = "4e5dc595-45c7-4461-929a-8f96a0c96b3d", Key = "route53", Options = Map(("AccessKeyId", "accesskey"), ("SecretAccessKeySafe", "secretaccesskey"), ("ARNRole", "rolearn"), ("Region", "")), AmbientAuthOptions = ["IAMRole"] },
            new() { SourcePluginId = "3693c40c-7c2f-4b70-aead-27869d8cbdf3", Key = "simply", Options = Map(("Account", "SimplyAccount"), ("ApiKey", "SimplyAPIKeyInsecure")) },
            new() { SourcePluginId = "6ea628c3-0f74-68bb-cf17-4fdd3d53f3af", Key = "tencent", Options = Map(("ApiID", "TencentKeyId"), ("ApiKey", "TencentSecret")) },
            new() { SourcePluginId = "c49a7a9a-f8c9-494a-a6a4-c6b9daae7d9d", Key = "transip", Options = Map(("Login", "login"), ("PrivateKey", "privatekey")) },
            new() { SourcePluginId = "1d4db2ea-ce7c-46ce-b86f-40b356fcf999", Key = "aliyun", Options = Map(("ApiID", "accesskeyid"), ("ApiSecret", "accesskeysecret"), ("ApiServer", "")) },
            new() { SourcePluginId = "86feb060-ac79-49d0-85c3-ef55687c2660", Key = "bunny", Options = Map(("APIKey", "BunnyAccessKey")) },

            new() { SourcePluginId = "2472d0c3-d3de-4bbc-806d-f36786ae94ed", Key = "arsys" },
            new() { SourcePluginId = "837692a9-25bc-4adc-908e-dc3316f11e32", Key = "czechia" },
            new() { SourcePluginId = "87b5008b-62f2-4dd6-9fd7-30b46e4ddfd5", Key = "dnsmint" },
            new() { SourcePluginId = "ec5a5198-7224-447e-aac5-99c2ccda78a1", Key = "huaweicloud" },
            new() { SourcePluginId = "6370923c-7840-4e8c-b003-a3b514312e5a", Key = "ipprojects" },
            new() { SourcePluginId = "55891a42-ca55-4085-b107-b6a0c4f6f30b", Key = "level27" },
            new() { SourcePluginId = "86c8d86b-2069-4048-9bf1-fadb07e84d61", Key = "webnames" }
        ];

        private static readonly Dictionary<string, string> Rfc2136Algorithms = new(StringComparer.OrdinalIgnoreCase)
        {
            ["HMAC-MD5"] = "hmac-md5",
            ["HMAC-SHA1"] = "hmac-sha1",
            ["HMAC-SHA224"] = "hmac-sha224",
            ["HMAC-SHA256"] = "hmac-sha256",
            ["HMAC-SHA384"] = "hmac-sha384",
            ["HMAC-SHA512"] = "hmac-sha512"
        };

        /// <summary>
        /// certbot DNS authenticators, by authenticator name, with the options of their credentials file. certbot's
        /// Route 53 and Google plugins take no credentials file, so their readers handle them
        /// </summary>
        public static readonly IReadOnlyList<DnsProviderAlias> CertbotDnsAliases =
        [
            new() { SourcePluginId = "dns-cloudflare", Key = "cloudflare", Options = Map(("dns_cloudflare_api_token", "apitoken"), ("dns_cloudflare_email", "emailaddress"), ("dns_cloudflare_api_key", "authkey")) },
            new() { SourcePluginId = "dns-digitalocean", Key = "digitalocean", Options = Map(("dns_digitalocean_token", "DOToken")) },
            new() { SourcePluginId = "dns-dnsimple", Key = "dnsimple", Options = Map(("dns_dnsimple_token", "DSTokenInsecure")) },
            new() { SourcePluginId = "dns-dnsmadeeasy", Key = "dnsmadeeasy", Options = Map(("dns_dnsmadeeasy_api_key", "apikey"), ("dns_dnsmadeeasy_secret_key", "apisecret")) },
            new() { SourcePluginId = "dns-linode", Key = "linode", Options = Map(("dns_linode_key", "LITokenInsecure"), ("dns_linode_version", "")) },
            new() { SourcePluginId = "dns-luadns", Key = "luadns", Options = Map(("dns_luadns_email", "LuaUsername"), ("dns_luadns_token", "LuaPassword")) },
            new() { SourcePluginId = "dns-nsone", Key = "ns1", Options = Map(("dns_nsone_api_key", "NS1KeyInsecure")) },
            new()
            {
                SourcePluginId = "dns-ovh", Key = "ovh",
                Options = Map(("dns_ovh_endpoint", "appendpoint"), ("dns_ovh_application_key", "appkey"), ("dns_ovh_application_secret", "appsecret"), ("dns_ovh_consumer_key", "consumerkey"))
            },
            new()
            {
                SourcePluginId = "dns-rfc2136", Key = "rfc2136",
                Options = Map(("dns_rfc2136_server", "DDNSNameserver"), ("dns_rfc2136_port", "DDNSPort"), ("dns_rfc2136_name", "DDNSKeyName"), ("dns_rfc2136_secret", "DDNSKeyValueInsecure"), ("dns_rfc2136_algorithm", "DDNSKeyType"), ("dns_rfc2136_sign_query", "")),
                ValueMaps = new() { ["DDNSKeyType"] = Rfc2136Algorithms }
            },
            new() { SourcePluginId = "dns-route53", Key = "route53" },
            new() { SourcePluginId = "dns-google", Key = "googlecloud" },
            new() { SourcePluginId = "dns-gehirn", Key = "gehirn" },
            new() { SourcePluginId = "dns-sakuracloud", Key = "sakuracloud" }
        ];

        /// <summary>
        /// acme.sh DNS API scripts, by script name, with the variables they save (in account.conf or the domain's conf).
        /// acme-dns, nsupdate and gcloud are handled by the reader
        /// </summary>
        public static readonly IReadOnlyList<DnsProviderAlias> AcmeShDnsAliases =
        [
            new() { SourcePluginId = "dns_cf", Key = "cloudflare", Options = Map(("CF_Token", "apitoken"), ("CF_Key", "authkey"), ("CF_Email", "emailaddress"), ("CF_Zone_ID", "zoneid"), ("CF_Account_ID", "")) },
            new() { SourcePluginId = "dns_aws", Key = "route53", Options = Map(("AWS_ACCESS_KEY_ID", "accesskey"), ("AWS_SECRET_ACCESS_KEY", "secretaccesskey"), ("AWS_DNS_SLOWRATE", "")) },
            new()
            {
                SourcePluginId = "dns_azure", Key = "azure",
                Options = Map(("AZUREDNS_SUBSCRIPTIONID", "subscriptionid"), ("AZUREDNS_TENANTID", "tenantid"), ("AZUREDNS_APPID", "clientid"), ("AZUREDNS_CLIENTSECRET", "secret")),
                AmbientAuthOptions = ["AZUREDNS_MANAGEDIDENTITY"]
            },
            new() { SourcePluginId = "dns_dgon", Key = "digitalocean", Options = Map(("DO_API_KEY", "DOToken")) },
            new() { SourcePluginId = "dns_gd", Key = "godaddy", Options = Map(("GD_Key", "authkey"), ("GD_Secret", "authsecret")) },
            new() { SourcePluginId = "dns_linode_v4", Key = "linode", Options = Map(("LINODE_V4_API_KEY", "LITokenInsecure")) },
            new() { SourcePluginId = "dns_me", Key = "dnsmadeeasy", Options = Map(("ME_Key", "apikey"), ("ME_Secret", "apisecret")) },
            new() { SourcePluginId = "dns_ovh", Key = "ovh", Options = Map(("OVH_AK", "appkey"), ("OVH_AS", "appsecret"), ("OVH_CK", "consumerkey"), ("OVH_END_POINT", "appendpoint")) },
            new() { SourcePluginId = "dns_hetzner", Key = "hetzner", Options = Map(("HETZNER_Token", "HetznerTokenInsecure")) },
            new() { SourcePluginId = "dns_hetznercloud", Key = "hetznercloud", Options = Map(("HETZNER_TOKEN", "HCToken")) },
            new() { SourcePluginId = "dns_lua", Key = "luadns", Options = Map(("LUA_Email", "LuaUsername"), ("LUA_Key", "LuaPassword")) },
            new() { SourcePluginId = "dns_nsone", Key = "ns1", Options = Map(("NS1_Key", "NS1KeyInsecure")) },
            new() { SourcePluginId = "dns_ali", Key = "aliyun", Options = Map(("Ali_Key", "accesskeyid"), ("Ali_Secret", "accesskeysecret")) },
            new() { SourcePluginId = "dns_tencent", Key = "tencent", Options = Map(("Tencent_SecretId", "TencentKeyId"), ("Tencent_SecretKey", "TencentSecret")) },
            new() { SourcePluginId = "dns_bunny", Key = "bunny", Options = Map(("BUNNY_API_KEY", "BunnyAccessKey")) },
            new() { SourcePluginId = "dns_simply", Key = "simply", Options = Map(("SIMPLY_AccountName", "SimplyAccount"), ("SIMPLY_ApiKey", "SimplyAPIKeyInsecure")) },
            new() { SourcePluginId = "dns_domeneshop", Key = "domeneshop", Options = Map(("DOMENESHOP_Token", "DomeneshopToken"), ("DOMENESHOP_Secret", "DomeneshopSecret")) },
            new() { SourcePluginId = "dns_infomaniak", Key = "infomaniak", Options = Map(("INFOMANIAK_API_TOKEN", "InfomaniakToken")) },
            new() { SourcePluginId = "dns_porkbun", Key = "porkbun", Options = Map(("PORKBUN_API_KEY", "PorkbunAPIKey"), ("PORKBUN_SECRET_API_KEY", "PorkbunSecret")) },
            new() { SourcePluginId = "dns_desec", Key = "desec", Options = Map(("DEDYN_TOKEN", "DSTokenInsecure")) },
            new() { SourcePluginId = "dns_he", Key = "hurricaneelectric", Options = Map(("HE_Username", "HEUsername"), ("HE_Password", "HEPassword")) },
            new() { SourcePluginId = "dns_ionos", Key = "ionos", Options = Map(("IONOS_PREFIX", "public"), ("IONOS_SECRET", "secret")) },
            new() { SourcePluginId = "dns_dynu", Key = "dynu", Options = Map(("Dynu_ClientId", "DynuClientID"), ("Dynu_Secret", "DynuSecret")) },
            new() { SourcePluginId = "dns_inwx", Key = "inwx", Options = Map(("INWX_User", "INWXUsername"), ("INWX_Password", "INWXPassword")) },
            new() { SourcePluginId = "dns_gandi_livedns", Key = "gandi", Options = Map(("GANDI_LIVEDNS_TOKEN", "GandiPAT"), ("GANDI_LIVEDNS_KEY", "GandiTokenInsecure")) },
            new() { SourcePluginId = "dns_namesilo", Key = "namesilo", Options = Map(("Namesilo_Key", "NameSiloKey")) },
            new() { SourcePluginId = "dns_namecheap", Key = "namecheap", Options = Map(("NAMECHEAP_USERNAME", "NCUsername"), ("NAMECHEAP_API_KEY", "NCApiKey"), ("NAMECHEAP_SOURCEIP", "")) },
            new() { SourcePluginId = "dns_namecom", Key = "namecom", Options = Map(("Namecom_Username", "NameComUserName"), ("Namecom_Token", "NameComToken")) },
            new() { SourcePluginId = "dns_dnsimple", Key = "dnsimple", Options = Map(("DNSimple_OAUTH_TOKEN", "DSTokenInsecure")) },
            new() { SourcePluginId = "dns_transip", Key = "transip", Options = Map(("TRANSIP_Username", "login")), FileOptions = Map(("TRANSIP_Key_File", "privatekey")) },
            new() { SourcePluginId = "dns_gcloud", Key = "googlecloud" }
        ];

        /// <summary>
        /// Posh-ACME plugins which map to a provider here other than the one running the same plugin, by plugin name.
        /// Other plugins map to the provider here running them, by their own argument names
        /// </summary>
        public static readonly IReadOnlyList<DnsProviderAlias> PoshAcmeDnsAliases =
        [
            new()
            {
                SourcePluginId = "Cloudflare", Key = "cloudflare",
                Options = Map(("CFToken", "apitoken"), ("CFTokenInsecure", "apitoken"), ("CFAuthEmail", "emailaddress"), ("CFAuthKey", "authkey"), ("CFAuthKeySecure", "authkey"),
                    ("CFTokenReadAll", ""), ("CFTokenReadAllInsecure", ""))
            },
            new()
            {
                SourcePluginId = "Route53", Key = "route53",
                Options = Map(("R53AccessKey", "accesskey"), ("R53SecretKey", "secretaccesskey"), ("R53SecretKeyInsecure", "secretaccesskey")),
                AmbientAuthOptions = ["R53UseIAMRole", "R53ProfileName"]
            },
            new()
            {
                SourcePluginId = "Azure", Key = "azure",
                Options = Map(("AZSubscriptionId", "subscriptionid"), ("AZTenantId", "tenantid"), ("AZAppUsername", "clientid"), ("AZAppPasswordInsecure", "secret"),
                    ("AZAppCred.user", "clientid"), ("AZAppCred.pass", "secret")),
                AmbientAuthOptions = ["AZUseIMDS", "AZAccessToken", "AZCertThumbprint", "AZCertPfx"]
            }
        ];

        public static DnsProviderEntry? GetDnsProvider(string? key) =>
            key == null ? null : DnsProviders.FirstOrDefault(p => string.Equals(p.Key, key, StringComparison.OrdinalIgnoreCase));

        public static DnsProviderAlias? GetWinAcmeDnsAlias(string? pluginId) => GetAlias(WinAcmeDnsAliases, pluginId);

        public static DnsProviderAlias? GetAlias(IEnumerable<DnsProviderAlias> aliases, string? pluginId) =>
            pluginId == null ? null : aliases.FirstOrDefault(a => string.Equals(a.SourcePluginId, pluginId, StringComparison.OrdinalIgnoreCase));

        /// <summary>
        /// The key algorithm here for an RSA key size, and whether it is exact
        /// </summary>
        public static (string KeyType, bool IsExact) GetRsaKeyType(int? bits) => bits switch
        {
            null or 3072 => ("RS256_3072", true),
            2048 => ("RS256", true),
            4096 => ("RS256_4096", true),
            < 3072 => ("RS256", false),
            < 4096 => ("RS256_3072", false),
            _ => ("RS256_4096", false)
        };

        /// <summary>
        /// The key algorithm here for an EC curve name, or null if unsupported
        /// </summary>
        public static string? GetEcKeyType(string? curve) => (curve ?? "secp384r1").Trim().ToLowerInvariant() switch
        {
            "secp256r1" or "prime256v1" or "nistp256" or "p-256" => "ECDSA256",
            "secp384r1" or "nistp384" or "p-384" => "ECDSA384",
            "secp521r1" or "nistp521" or "p-521" => "ECDSA521",
            _ => null
        };
    }
}
