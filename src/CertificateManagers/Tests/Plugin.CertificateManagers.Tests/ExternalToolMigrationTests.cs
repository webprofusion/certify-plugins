using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Certify.Models;
using Certify.Models.Config;
using Certify.Models.Config.Migration;
using Certify.Plugin.CertificateManagers.Providers.AcmeSh;
using Certify.Plugin.CertificateManagers.Providers.Certbot;
using Certify.Plugin.CertificateManagers.Providers.PoshAcme;
using Certify.Providers.CertificateManagers;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests.Plugin.CertificateManagers
{
    /// <summary>
    /// Migration of certbot, acme.sh and Posh-ACME certificates: what the preview proposes, what secrets resolve to, the
    /// account and certificate read from each tool, and how the source is disabled, restored and removed
    /// </summary>
    [TestClass]
    public class ExternalToolMigrationTests
    {
        private const string CloudflareProvider = "DNS01.API.Cloudflare";
        private const string PorkbunProvider = "DNS01.API.PoshACME.Porkbun";
        private const string Token = "cf-token-value-123";
        private const string ExportTask = "Certify.Providers.DeploymentTasks.CertificateExport";
        private const string PowerShellTask = "Certify.Providers.DeploymentTasks.Powershell";

        private string _root = string.Empty;

        [TestInitialize]
        public void Setup()
        {
            _root = Path.Combine(Path.GetTempPath(), $"certmanager-tool-migration-test-{Guid.NewGuid():N}");
            Directory.CreateDirectory(_root);
        }

        [TestCleanup]
        public void Cleanup()
        {
            if (Directory.Exists(_root))
            {
                Directory.Delete(_root, true);
            }
        }

        private static ExternalMigrationContext Context() => new()
        {
            Accounts = [new AccountDetails { StorageKey = "acc", CertificateAuthorityId = "letsencrypt.org", IsStagingAccount = false }],
            ChallengeProviders =
            [
                new ChallengeProviderDefinition
                {
                    Id = CloudflareProvider,
                    Title = "Cloudflare DNS API",
                    ProviderParameters =
                    [
                        new ProviderParameter { Key = "apitoken", Name = "API Token", IsCredential = true },
                        new ProviderParameter { Key = "zoneid", Name = "Zone Id", IsCredential = false },
                        new ProviderParameter { Key = "propagationdelay", Name = "Propagation Delay", IsCredential = false }
                    ]
                },
                new ChallengeProviderDefinition
                {
                    Id = PorkbunProvider,
                    Title = "Porkbun DNS API (using Posh-ACME)",
                    Config = "Provider=Certify.Providers.DNS.PoshACME;Script=Porkbun",
                    ProviderParameters =
                    [
                        new ProviderParameter { Key = "PorkbunAPIKey", Name = "API Key", IsCredential = true },
                        new ProviderParameter { Key = "PorkbunSecretInsecure", Name = "API Secret", IsCredential = true },
                        new ProviderParameter { Key = "propagationdelay", Name = "Propagation Delay", IsCredential = false }
                    ]
                }
            ],
            DeploymentProviders =
            [
                new DeploymentProviderDefinition { Id = ExportTask, Title = "Export Certificate" },
                new DeploymentProviderDefinition { Id = PowerShellTask, Title = "Run Powershell Script" }
            ]
        };

        private static async Task<T> GetManager<T>(string root) where T : ICertificateManager, new()
        {
            var manager = new T();
            manager.Init(NullLogger.Instance, new CertificateManagerPreference { ConfigPath = root, LogPath = root });
            await manager.GetManagedCertificates();
            return manager;
        }

        private static async Task<string> ItemId(ICertificateManager manager) => (await manager.GetManagedCertificates()).Single().Id!;

        /// <summary>
        /// A certificate for example.com and www.example.com, its key, and an issuer to stand for the chain
        /// </summary>
        private static (string Cert, string Key, string Chain, string Thumbprint) CreateCertificate(string name = "example.com")
        {
            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var request = new CertificateRequest($"CN={name}", key, HashAlgorithmName.SHA256);
            var san = new SubjectAlternativeNameBuilder();
            san.AddDnsName(name);
            san.AddDnsName($"www.{name}");
            request.CertificateExtensions.Add(san.Build());
            using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(60));

            using var issuerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            using var issuer = new CertificateRequest("CN=Test Intermediate", issuerKey, HashAlgorithmName.SHA256).CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(60));

            return (cert.ExportCertificatePem(), key.ExportPkcs8PrivateKeyPem(), issuer.ExportCertificatePem(), cert.Thumbprint);
        }

        private static string Base64Url(byte[] value) => Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

        private static (string Jwk, byte[] PublicKey) CreateJwk()
        {
            using var rsa = RSA.Create(2048);
            var p = rsa.ExportParameters(true);
            var jwk = JsonSerializer.Serialize(new { kty = "RSA", n = Base64Url(p.Modulus!), e = Base64Url(p.Exponent!), d = Base64Url(p.D!), p = Base64Url(p.P!), q = Base64Url(p.Q!), dp = Base64Url(p.DP!), dq = Base64Url(p.DQ!), qi = Base64Url(p.InverseQ!) });
            return (jwk, rsa.ExportSubjectPublicKeyInfo());
        }

        private static void AssertSameKey(byte[] publicKey, string pem)
        {
            StringAssert.StartsWith(pem, "-----BEGIN PRIVATE KEY-----");
            using var imported = RSA.Create();
            imported.ImportFromPem(pem);
            CollectionAssert.AreEqual(publicKey, imported.ExportSubjectPublicKeyInfo(), "The converted key is the same key");
        }

        private static void AssertImportsWithoutSecrets(ExternalMigrationPlan? plan, params string[] secrets)
        {
            Assert.IsNotNull(plan);
            Assert.IsTrue(plan.CanImport, string.Join("; ", plan.Findings.Where(f => f.IsUnresolved).Select(f => f.Description)));

            var json = JsonSerializer.Serialize(plan);
            foreach (var secret in secrets)
            {
                Assert.IsFalse(json.Contains(secret), "The preview refers to secrets without carrying their values");
            }
        }

        // certbot

        private string WriteCertbotLineage(string renewalParams)
        {
            var (cert, key, chain, _) = CreateCertificate();
            var live = Path.Combine(_root, "live", "example.com");
            var archive = Path.Combine(_root, "archive", "example.com");
            Directory.CreateDirectory(live);
            Directory.CreateDirectory(archive);
            Directory.CreateDirectory(Path.Combine(_root, "renewal"));

            File.WriteAllText(Path.Combine(live, "cert.pem"), cert);
            File.WriteAllText(Path.Combine(live, "privkey.pem"), key);
            File.WriteAllText(Path.Combine(live, "chain.pem"), chain);
            File.WriteAllText(Path.Combine(live, "fullchain.pem"), cert + chain);
            File.WriteAllText(Path.Combine(archive, "cert1.pem"), cert);
            File.WriteAllText(Path.Combine(archive, "privkey1.pem"), key);

            var conf = Path.Combine(_root, "renewal", "example.com.conf");
            File.WriteAllText(conf, $"""
                version = 2.11.0
                archive_dir = {archive}
                cert = {Path.Combine(live, "cert.pem")}
                privkey = {Path.Combine(live, "privkey.pem")}
                chain = {Path.Combine(live, "chain.pem")}
                fullchain = {Path.Combine(live, "fullchain.pem")}

                # Options used in the renewal process
                [renewalparams]
                account = 0123abcd
                server = https://acme-v02.api.letsencrypt.org/directory
                key_type = ecdsa
                {renewalParams}
                """);

            return conf;
        }

        [TestMethod]
        public async Task CertbotDnsHooksAccountAndCertificateMigrate()
        {
            var credentials = Path.Combine(_root, "cloudflare.ini");
            File.WriteAllText(credentials, $"# Cloudflare API token\ndns_cloudflare_api_token = {Token}\n");

            WriteCertbotLineage($"""
                authenticator = dns-cloudflare
                dns_cloudflare_credentials = {credentials}
                dns_cloudflare_propagation_seconds = 30
                deploy_hook = systemctl reload nginx
                """);

            var (jwk, publicKey) = CreateJwk();
            var accountFolder = Path.Combine(_root, "accounts", "acme-v02.api.letsencrypt.org", "directory", "0123abcd");
            Directory.CreateDirectory(accountFolder);
            File.WriteAllText(Path.Combine(accountFolder, "private_key.json"), jwk);
            File.WriteAllText(Path.Combine(accountFolder, "regr.json"), """{ "body": { "contact": [ "mailto:admin@example.com" ] }, "uri": "https://acme-v02.api.letsencrypt.org/acme/acct/9" }""");

            var manager = await GetManager<Certbot>(_root);
            var itemId = await ItemId(manager);
            var plan = await manager.PrepareMigrationPlan(itemId, Context(), null);

            AssertImportsWithoutSecrets(plan, Token);

            var item = plan!.ProposedItem!;
            CollectionAssert.AreEquivalent(new[] { "example.com", "www.example.com" }, item.GetCertificateIdentifiers().Select(i => i.Value).ToArray());
            Assert.AreEqual(StandardKeyTypes.ECDSA256, item.RequestConfig.CSRKeyAlg);

            var challenge = item.RequestConfig.Challenges.Single();
            Assert.AreEqual(CloudflareProvider, challenge.ChallengeProvider);
            Assert.AreEqual("30", challenge.Parameters!.Single(p => p.Key == "propagationdelay").Value);

            var draft = plan.Credentials.Single(c => c.Key == challenge.ChallengeCredentialKey);
            Assert.AreEqual(Token, (await manager.ResolveCredentialValues(itemId, draft))["apitoken"], "The token is read from the credentials file at import");

            Assert.AreEqual(4, item.PostRequestTasks!.Count(t => t.TaskTypeId == ExportTask), "The live files are written as certbot wrote them");
            Assert.AreEqual(1, item.PostRequestTasks!.Count(t => t.TaskTypeId == PowerShellTask), "The deploy hook runs after renewal");

            var account = await manager.GetAccount(itemId);
            Assert.AreEqual("https://acme-v02.api.letsencrypt.org/acme/acct/9", account!.AccountUri);
            Assert.AreEqual("admin@example.com", account.EmailAddress);
            AssertSameKey(publicKey, account.AccountKeyPem);

            var current = await manager.GetCurrentCertificate(itemId);
            Assert.IsNotNull(current, "The current certificate and key are read as a PFX");
        }

        [TestMethod]
        public async Task CertbotWebrootMapsToChallengeFolder()
        {
            WriteCertbotLineage($"""
                authenticator = webroot
                [[webroot_map]]
                example.com = {Path.Combine(_root, "www")}
                www.example.com = {Path.Combine(_root, "www")}
                """);

            var manager = await GetManager<Certbot>(_root);
            var plan = await manager.PrepareMigrationPlan(await ItemId(manager), Context(), null);

            AssertImportsWithoutSecrets(plan);
            var challenge = plan!.ProposedItem!.RequestConfig.Challenges.Single();
            Assert.AreEqual(SupportedChallengeTypes.CHALLENGE_TYPE_HTTP, challenge.ChallengeType);
            Assert.AreEqual(Path.Combine(_root, "www"), plan.ProposedItem.RequestConfig.WebsiteRootPath ?? challenge.ChallengeRootPath);
        }

        [TestMethod]
        public async Task CertbotLineageIsDisabledRestoredAndRemoved()
        {
            var conf = WriteCertbotLineage("authenticator = standalone\nautorenew = True");

            var manager = await GetManager<Certbot>(_root);
            var itemId = await ItemId(manager);

            Assert.IsNotNull((await manager.PlanSourceRemoval(itemId)).BlockedReason, "A lineage certbot still renews is not removed");

            Assert.IsTrue((await manager.DisableSourceItem(itemId)).IsSuccess);
            StringAssert.Contains(File.ReadAllText(conf), "autorenew = False");
            var listed = (await manager.GetManagedCertificates()).Single();
            Assert.IsFalse(listed.IncludeInAutoRenew, "The lineage stays listed, no longer renewed by certbot");
            StringAssert.Contains(listed.Comments, "handed over");

            Assert.IsTrue((await manager.RestoreSourceItem(itemId)).IsSuccess);
            StringAssert.Contains(File.ReadAllText(conf), "autorenew = True", "The previous setting is put back");
            Assert.IsFalse(File.ReadAllText(conf).Contains("certify-migrated"));

            Assert.IsTrue((await manager.DisableSourceItem(itemId)).IsSuccess);
            var manifest = await manager.PlanSourceRemoval(itemId);
            Assert.IsNull(manifest.BlockedReason);
            CollectionAssert.AreEquivalent(new[] { conf, Path.Combine(_root, "archive", "example.com", "cert1.pem"), Path.Combine(_root, "archive", "example.com", "privkey1.pem") }, manifest.FilesToDelete);

            Assert.IsTrue((await manager.RemoveSourceItem(itemId, manifest)).IsSuccess);
            Assert.IsFalse(manifest.FilesToDelete.Any(File.Exists));
            Assert.IsTrue(File.Exists(Path.Combine(_root, "live", "example.com", "cert.pem")), "The live files services read are kept");
        }

        // acme.sh

        private string WriteAcmeShDomain(string folderName, string values)
        {
            var (cert, key, chain, _) = CreateCertificate();
            var folder = Path.Combine(_root, folderName);
            Directory.CreateDirectory(folder);

            File.WriteAllText(Path.Combine(folder, "example.com.cer"), cert);
            File.WriteAllText(Path.Combine(folder, "example.com.key"), key);
            File.WriteAllText(Path.Combine(folder, "ca.cer"), chain);
            File.WriteAllText(Path.Combine(folder, "fullchain.cer"), cert + chain);

            var conf = Path.Combine(folder, "example.com.conf");
            File.WriteAllText(conf, $"""
                Le_Domain='example.com'
                Le_Alt='www.example.com'
                Le_API='https://acme-v02.api.letsencrypt.org/directory'
                {values}
                """);

            return conf;
        }

        [TestMethod]
        public async Task AcmeShDnsInstallAndAccountMigrate()
        {
            var installed = Path.Combine(_root, "installed");
            var reload = "service nginx force-reload";

            WriteAcmeShDomain("example.com_ecc", $"""
                Le_Webroot='dns_cf'
                Le_Keylength='ec-256'
                Le_RealCertPath='{Path.Combine(installed, "cert.pem")}'
                Le_RealKeyPath='{Path.Combine(installed, "key.pem")}'
                Le_RealFullChainPath='{Path.Combine(installed, "fullchain.pem")}'
                Le_ReloadCmd='__ACME_BASE64__START_{Convert.ToBase64String(Encoding.UTF8.GetBytes(reload))}__ACME_BASE64__END_'
                """);

            File.WriteAllText(Path.Combine(_root, "account.conf"), $"ACCOUNT_EMAIL='admin@example.com'\nSAVED_CF_Token='{Token}'\nSAVED_CF_Zone_ID='zone-1'\n");

            using var accountKey = RSA.Create(2048);
            var ca = Path.Combine(_root, "ca", "acme-v02.api.letsencrypt.org", "directory");
            Directory.CreateDirectory(ca);
            File.WriteAllText(Path.Combine(ca, "account.key"), accountKey.ExportRSAPrivateKeyPem());
            File.WriteAllText(Path.Combine(ca, "ca.conf"), "ACCOUNT_URL='https://acme-v02.api.letsencrypt.org/acme/acct/7'\n");

            var manager = await GetManager<AcmeSh>(_root);
            var itemId = await ItemId(manager);
            var plan = await manager.PrepareMigrationPlan(itemId, Context(), null);

            AssertImportsWithoutSecrets(plan, Token, "zone-1");

            var item = plan!.ProposedItem!;
            Assert.AreEqual(StandardKeyTypes.ECDSA256, item.RequestConfig.CSRKeyAlg);

            var challenge = item.RequestConfig.Challenges.Single();
            Assert.AreEqual(CloudflareProvider, challenge.ChallengeProvider);

            var draft = plan.Credentials.Single(c => c.Key == challenge.ChallengeCredentialKey);
            Assert.AreEqual(Token, (await manager.ResolveCredentialValues(itemId, draft))["apitoken"], "The saved token is read from account.conf at import");

            Assert.AreEqual(3, item.PostRequestTasks!.Count(t => t.TaskTypeId == ExportTask), "The installed files are written where acme.sh installed them");
            Assert.AreEqual(1, item.PostRequestTasks!.Count(t => t.TaskTypeId == PowerShellTask), "The reload command runs after renewal");
            StringAssert.Contains(JsonSerializer.Serialize(plan.Findings), reload, "The base64 encoded command is decoded");

            var account = await manager.GetAccount(itemId);
            Assert.AreEqual("https://acme-v02.api.letsencrypt.org/acme/acct/7", account!.AccountUri);
            Assert.AreEqual("admin@example.com", account.EmailAddress);
            AssertSameKey(accountKey.ExportSubjectPublicKeyInfo(), account.AccountKeyPem);

            Assert.IsNotNull(await manager.GetCurrentCertificate(itemId));
        }

        [TestMethod]
        public async Task AcmeShEccAndRsaCertificatesOfOneDomainHaveTheirOwnIds()
        {
            WriteAcmeShDomain("example.com_ecc", "Le_Webroot='no'\nLe_Keylength='ec-256'");

            var manager = await GetManager<AcmeSh>(_root);
            var eccOnly = await ItemId(manager);

            WriteAcmeShDomain("example.com", "Le_Webroot='no'\nLe_Keylength='2048'");
            var ids = (await manager.GetManagedCertificates()).Select(i => i.Id).ToList();

            Assert.AreEqual(2, ids.Distinct().Count());
            Assert.IsTrue(ids.Contains(eccOnly), "The RSA certificate keeps the plain id");

            var ecc = ids.Single(i => i != eccOnly)!;
            var plan = await manager.PrepareMigrationPlan(ecc, Context(), null);
            Assert.AreEqual(StandardKeyTypes.ECDSA256, plan!.ProposedItem!.RequestConfig.CSRKeyAlg, "Each id reads its own certificate");
        }

        [TestMethod]
        public async Task AcmeShDomainIsDisabledRestoredAndRemoved()
        {
            var conf = WriteAcmeShDomain("example.com", "Le_Webroot='no'");
            File.WriteAllText(Path.Combine(_root, "account.conf"), "ACCOUNT_EMAIL='admin@example.com'\n");

            var manager = await GetManager<AcmeSh>(_root);
            var itemId = await ItemId(manager);

            Assert.IsNotNull((await manager.PlanSourceRemoval(itemId)).BlockedReason);

            Assert.IsTrue((await manager.DisableSourceItem(itemId)).IsSuccess);
            Assert.IsTrue(File.Exists(conf + ".removed"));
            Assert.IsFalse((await manager.GetManagedCertificates()).Any(), "A removed domain is no longer monitored");

            Assert.IsTrue((await manager.RestoreSourceItem(itemId)).IsSuccess);
            Assert.IsTrue(File.Exists(conf));
            Assert.IsTrue((await manager.DisableSourceItem(itemId)).IsSuccess);

            var manifest = await manager.PlanSourceRemoval(itemId);
            Assert.IsNull(manifest.BlockedReason);
            Assert.AreEqual(5, manifest.FilesToDelete.Count);

            Assert.IsTrue((await manager.RemoveSourceItem(itemId, manifest)).IsSuccess);
            Assert.IsFalse(Directory.Exists(Path.GetDirectoryName(conf)));
            Assert.IsTrue(File.Exists(Path.Combine(_root, "account.conf")), "The account and saved settings are kept");
        }

        // Posh-ACME

        /// <summary>
        /// A value as ConvertFrom-SecureString -Key exports it
        /// </summary>
        private static string ExportSecureString(string value, byte[] key)
        {
            using var aes = Aes.Create();
            aes.Key = key;
            var iv = RandomNumberGenerator.GetBytes(16);
            var data = aes.EncryptCbc(Encoding.Unicode.GetBytes(value), iv);
            var package = $"2|{Convert.ToBase64String(iv)}|{Convert.ToHexString(data).ToLowerInvariant()}";
            return "76492d1116743f0423413b16050a5345" + Convert.ToBase64String(Encoding.Unicode.GetBytes(package));
        }

        private string WritePoshAcmeOrder(string plugin, string pluginArgs, string? sskey, string jwk, string extra = "")
        {
            var server = Path.Combine(_root, "acme-v02.api.letsencrypt.org");
            var account = Path.Combine(server, "123456");
            var order = Path.Combine(account, "example.com");
            Directory.CreateDirectory(order);

            File.WriteAllText(Path.Combine(server, "dir.json"), """{ "location": "https://acme-v02.api.letsencrypt.org/directory" }""");
            File.WriteAllText(Path.Combine(account, "acct.json"), JsonSerializer.Serialize(new
            {
                id = "123456",
                status = "valid",
                contact = new[] { "mailto:admin@example.com" },
                location = "https://acme-v02.api.letsencrypt.org/acme/acct/123456",
                key = JsonDocument.Parse(jwk).RootElement,
                sskey
            }));

            var (cert, key, chain, _) = CreateCertificate();
            File.WriteAllText(Path.Combine(order, "cert.cer"), cert);
            File.WriteAllText(Path.Combine(order, "cert.key"), key);
            File.WriteAllText(Path.Combine(order, "chain.cer"), chain);
            File.WriteAllText(Path.Combine(order, "pluginargs.json"), pluginArgs);

            var orderFile = Path.Combine(order, "order.json");
            File.WriteAllText(orderFile, $$"""
                {
                  "MainDomain": "example.com",
                  "SANs": [ "www.example.com" ],
                  "FriendlyName": "example.com",
                  "status": "valid",
                  "location": "https://acme-v02.api.letsencrypt.org/acme/order/123456/1",
                  "KeyLength": "ec-256",
                  "Plugin": [ "{{plugin}}" ],
                  "DnsSleep": 60{{extra}}
                }
                """);

            return orderFile;
        }

        [TestMethod]
        public async Task PoshAcmePluginWithEncryptedArgsMigrates()
        {
            var key = RandomNumberGenerator.GetBytes(32);
            var secret = "porkbun-secret-456";
            var (jwk, publicKey) = CreateJwk();

            WritePoshAcmeOrder("Porkbun", JsonSerializer.Serialize(new Dictionary<string, object>
            {
                ["PorkbunAPIKey"] = "pk1_key",
                ["PorkbunSecret"] = new { origType = "securestring", value = ExportSecureString(secret, key) }
            }), Base64Url(key), jwk);

            var manager = await GetManager<PoshAcme>(_root);
            var itemId = await ItemId(manager);
            var plan = await manager.PrepareMigrationPlan(itemId, Context(), null);

            AssertImportsWithoutSecrets(plan, secret, "pk1_key");

            var challenge = plan!.ProposedItem!.RequestConfig.Challenges.Single();
            Assert.AreEqual(PorkbunProvider, challenge.ChallengeProvider, "The same Posh-ACME plugin runs here");
            Assert.AreEqual("60", challenge.Parameters!.Single(p => p.Key == "propagationdelay").Value);

            var draft = plan.Credentials.Single(c => c.Key == challenge.ChallengeCredentialKey);
            var values = await manager.ResolveCredentialValues(itemId, draft);
            Assert.AreEqual("pk1_key", values["PorkbunAPIKey"]);
            Assert.AreEqual(secret, values["PorkbunSecretInsecure"], "The secure value is decrypted with the account's key at import");

            Assert.IsTrue(plan.Findings.Any(f => f.Level == ExternalMigrationFindingLevel.Assumption && f.Description.Contains("Submit-Renewal")),
                "What Posh-ACME's renewal script does afterwards is called out");

            var account = await manager.GetAccount(itemId);
            Assert.AreEqual("https://acme-v02.api.letsencrypt.org/acme/acct/123456", account!.AccountUri);
            Assert.AreEqual("admin@example.com", account.EmailAddress);
            AssertSameKey(publicKey, account.AccountKeyPem);

            Assert.IsNotNull(await manager.GetCurrentCertificate(itemId));
        }

        [TestMethod]
        public async Task PoshAcmeCloudflareAliasAndDnsAliasBlocker()
        {
            var key = RandomNumberGenerator.GetBytes(32);
            var (jwk, _) = CreateJwk();

            WritePoshAcmeOrder("Cloudflare", JsonSerializer.Serialize(new Dictionary<string, object>
            {
                ["CFToken"] = new { origType = "securestring", value = ExportSecureString(Token, key) }
            }), Base64Url(key), jwk);

            var manager = await GetManager<PoshAcme>(_root);
            var itemId = await ItemId(manager);
            var plan = await manager.PrepareMigrationPlan(itemId, Context(), null);

            AssertImportsWithoutSecrets(plan, Token);
            var challenge = plan!.ProposedItem!.RequestConfig.Challenges.Single();
            Assert.AreEqual(CloudflareProvider, challenge.ChallengeProvider);
            Assert.AreEqual(Token, (await manager.ResolveCredentialValues(itemId, plan.Credentials.Single(c => c.Key == challenge.ChallengeCredentialKey)))["apitoken"]);

            WritePoshAcmeOrder("Cloudflare", "{}", Base64Url(key), jwk, ",\n  \"DnsAlias\": [ \"example.net\" ]");
            var aliased = await manager.PrepareMigrationPlan(itemId, Context(), null);
            Assert.IsTrue(aliased!.HasBlockers, "DNS alias validation is not migrated");
        }

        [TestMethod]
        public async Task PoshAcmeOrderIsDisabledRestoredAndRemoved()
        {
            var (jwk, _) = CreateJwk();
            var orderFile = WritePoshAcmeOrder("WebRoot", JsonSerializer.Serialize(new { WRPath = Path.Combine(_root, "www") }), null, jwk);

            var manager = await GetManager<PoshAcme>(_root);
            var itemId = await ItemId(manager);

            var plan = await manager.PrepareMigrationPlan(itemId, Context(), null);
            AssertImportsWithoutSecrets(plan);
            Assert.AreEqual(SupportedChallengeTypes.CHALLENGE_TYPE_HTTP, plan!.ProposedItem!.RequestConfig.Challenges.Single().ChallengeType);

            Assert.IsNotNull((await manager.PlanSourceRemoval(itemId)).BlockedReason);

            Assert.IsTrue((await manager.DisableSourceItem(itemId)).IsSuccess);
            Assert.IsTrue(File.Exists(orderFile + ".certify-migrated"));
            Assert.IsFalse((await manager.GetManagedCertificates()).Any(), "A set aside order is no longer monitored");

            Assert.IsTrue((await manager.RestoreSourceItem(itemId)).IsSuccess);
            Assert.IsTrue(File.Exists(orderFile));
            Assert.IsTrue((await manager.DisableSourceItem(itemId)).IsSuccess);

            var manifest = await manager.PlanSourceRemoval(itemId);
            Assert.IsNull(manifest.BlockedReason);
            Assert.AreEqual(5, manifest.FilesToDelete.Count);

            Assert.IsTrue((await manager.RemoveSourceItem(itemId, manifest)).IsSuccess);
            Assert.IsFalse(Directory.Exists(Path.GetDirectoryName(orderFile)));
            Assert.IsTrue(File.Exists(Path.Combine(_root, "acme-v02.api.letsencrypt.org", "123456", "acct.json")), "The account is kept");
        }
    }
}
