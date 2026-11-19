#nullable enable

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Certify.Models;
using Certify.Models.Config;
using Certify.Models.Config.Migration;
using Certify.Plugin.CertificateManagers.Providers.PoshAcme;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests.Plugin.CertificateManagers
{
    /// <summary>
    /// Migration of Posh-ACME orders: what the preview proposes for each plugin and order setting, how saved plugin
    /// arguments are decrypted, the account and certificate, and how the order is set aside, put back and removed
    /// </summary>
    [TestClass]
    public class PoshAcmeMigrationTests : ExternalToolMigrationTestBase
    {
        private const string OrderLocation = "https://acme-v02.api.letsencrypt.org/acme/order/123456/1";

        private string Server => Path.Combine(_root, "acme-v02.api.letsencrypt.org");
        private string AccountFolder => Path.Combine(Server, "123456");
        private string OrderFolder => Path.Combine(AccountFolder, "example.com");
        private string OrderFile => Path.Combine(OrderFolder, "order.json");

        private readonly byte[] _key = RandomNumberGenerator.GetBytes(32);
        private string SsKey => Base64Url(_key);

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

        private object Secure(string value) => new { origType = "securestring", value = ExportSecureString(value, _key) };

        /// <param name="plugins">the order's Plugin value</param>
        /// <param name="pluginArgs">pluginargs.json, serialized unless already a string</param>
        /// <param name="change">changes to order.json, where a null value removes the setting</param>
        /// <param name="accountKey">acct.json's key, a JWK object by default</param>
        private string WritePoshAcmeOrder(object plugins, object pluginArgs, string? sskey, string? jwk = null, Action<Dictionary<string, object?>>? change = null,
            bool argsInAccountFolder = false, object? accountKey = null, string? accountLocation = "https://acme-v02.api.letsencrypt.org/acme/acct/123456")
        {
            Directory.CreateDirectory(OrderFolder);

            File.WriteAllText(Path.Combine(Server, "dir.json"), """{ "location": "https://acme-v02.api.letsencrypt.org/directory" }""");
            File.WriteAllText(Path.Combine(AccountFolder, "acct.json"), JsonSerializer.Serialize(new
            {
                id = "123456",
                status = "valid",
                contact = new[] { "mailto:admin@example.com" },
                location = accountLocation,
                key = accountKey ?? JsonDocument.Parse(jwk ?? CreateJwk().Jwk).RootElement,
                sskey
            }));

            var (cert, key, chain, _) = CreateCertificate();
            File.WriteAllText(Path.Combine(OrderFolder, "cert.cer"), cert);
            File.WriteAllText(Path.Combine(OrderFolder, "cert.key"), key);
            File.WriteAllText(Path.Combine(OrderFolder, "chain.cer"), chain);
            File.WriteAllText(Path.Combine(argsInAccountFolder ? AccountFolder : OrderFolder, "pluginargs.json"), pluginArgs as string ?? JsonSerializer.Serialize(pluginArgs));

            var order = new Dictionary<string, object?>
            {
                ["MainDomain"] = "example.com",
                ["SANs"] = new[] { "www.example.com" },
                ["FriendlyName"] = "example.com",
                ["status"] = "valid",
                ["location"] = OrderLocation,
                ["KeyLength"] = "ec-256",
                ["Plugin"] = plugins,
                ["DnsSleep"] = 60
            };

            change?.Invoke(order);
            File.WriteAllText(OrderFile, JsonSerializer.Serialize(order.Where(o => o.Value != null).ToDictionary()));

            return OrderFile;
        }

        private async Task<(PoshAcme Manager, ExternalMigrationPlan Plan)> PreviewOrder(object plugins, object pluginArgs, Action<Dictionary<string, object?>>? change = null,
            ExternalMigrationContext? context = null, IDictionary<string, string>? inputs = null, bool argsInAccountFolder = false, string? sskey = "")
        {
            WritePoshAcmeOrder(plugins, pluginArgs, sskey == "" ? SsKey : sskey, change: change, argsInAccountFolder: argsInAccountFolder);
            var manager = await GetManager<PoshAcme>(_root);
            return (manager, await Preview(manager, context, inputs));
        }

        // validation

        [TestMethod]
        public async Task PoshAcmePluginWithEncryptedArgsMigrates()
        {
            var secret = "porkbun-secret-456";
            var (jwk, publicKey) = CreateJwk();

            WritePoshAcmeOrder(new[] { "Porkbun" }, new Dictionary<string, object>
            {
                ["PorkbunAPIKey"] = "pk1_key",
                ["PorkbunSecret"] = Secure(secret)
            }, SsKey, jwk);

            var manager = await GetManager<PoshAcme>(_root);
            var itemId = await ItemId(manager);
            var plan = await manager.PrepareMigrationPlan(itemId, Context(), null);

            AssertImportsWithoutSecrets(plan, secret, "pk1_key");

            var challenge = plan!.ProposedItem!.RequestConfig.Challenges.Single();
            Assert.AreEqual(PorkbunProvider, challenge.ChallengeProvider, "The same Posh-ACME plugin runs here");
            Assert.AreEqual("60", Parameter(challenge, "propagationdelay"));

            var draft = plan.Credentials.Single(c => c.Key == challenge.ChallengeCredentialKey);
            var values = await manager.ResolveCredentialValues(itemId, draft);
            Assert.AreEqual("pk1_key", values["PorkbunAPIKey"]);
            Assert.AreEqual(secret, values["PorkbunSecretInsecure"], "The secure value is decrypted with the account's key at import");
            StringAssert.Contains(draft.Title, "renewal example.com", "Arguments saved for the order alone are named after it");

            AssertAssumption(plan, "Submit-Renewal");

            var account = await manager.GetAccount(itemId);
            Assert.AreEqual("https://acme-v02.api.letsencrypt.org/acme/acct/123456", account!.AccountUri);
            Assert.AreEqual("admin@example.com", account.EmailAddress);
            AssertSameKey(publicKey, account.AccountKeyPem);

            Assert.IsNotNull(await manager.GetCurrentCertificate(itemId));
            Assert.AreEqual(DeploymentOption.NoDeployment, plan.ProposedItem.RequestConfig.DeploymentSiteOption, "The order was not installed");
        }

        [TestMethod]
        [DataRow("key", DisplayName = "Encrypted with the account's key")]
        [DataRow("hex", DisplayName = "Exported outside Windows, only hex encoded")]
        [DataRow("dpapi", DisplayName = "Encrypted with Windows DPAPI for this user")]
        public async Task PoshAcmeSecureValueFormsAreDecrypted(string form)
        {
            var secret = "porkbun-secret-456";
            string exported;

            switch (form)
            {
                case "key":
                    exported = ExportSecureString(secret, _key);
                    break;

                case "hex":
                    exported = Convert.ToHexString(Encoding.Unicode.GetBytes(secret)).ToLowerInvariant();
                    break;

                default:
                    if (!OperatingSystem.IsWindows())
                    {
                        Assert.Inconclusive("DPAPI is only on Windows");
                    }

                    exported = Convert.ToHexString(ProtectedData.Protect(Encoding.Unicode.GetBytes(secret), null, DataProtectionScope.CurrentUser)).ToLowerInvariant();
                    break;
            }

            var (manager, plan) = await PreviewOrder(new[] { "Porkbun" }, new Dictionary<string, object>
            {
                ["PorkbunAPIKey"] = "pk1_key",
                ["PorkbunSecret"] = new { origType = "securestring", value = exported }
            }, sskey: form == "key" ? SsKey : null);

            AssertImportsWithoutSecrets(plan, secret);
            Assert.AreEqual(secret, (await ResolveChallengeCredential(manager, plan, plan.ProposedItem!.RequestConfig.Challenges.Single()))["PorkbunSecretInsecure"]);
        }

        [TestMethod]
        [DataRow("VAULT", "secret", "SecretManagement vault", DisplayName = "Key in a SecretManagement vault")]
        [DataRow(null, "secret", "key the account no longer has", DisplayName = "Account without its key")]
        [DataRow("key", "zz-not-a-value", "not in a recognised form", DisplayName = "Value not in a recognised form")]
        [DataRow("short-key", "secret", "could not be decrypted", DisplayName = "A key AES cannot use")]
        public async Task PoshAcmeUnreadableSecureValueAsksForACredential(string? sskey, string value, string reason)
        {
            var exported = value == "secret" ? ExportSecureString("porkbun-secret-456", _key) : value;
            var accountKey = sskey switch { "key" => SsKey, "short-key" => Base64Url(RandomNumberGenerator.GetBytes(20)), var other => other };

            var (manager, plan) = await PreviewOrder(new[] { "Porkbun" }, new Dictionary<string, object>
            {
                ["PorkbunAPIKey"] = "pk1_key",
                ["PorkbunSecret"] = new { origType = "securestring", value = exported }
            }, sskey: accountKey);

            AssertBlocker(plan, "validation-0-credential", reason);

            var stored = new StoredCredential { StorageKey = "porkbun", ProviderType = PorkbunProvider };
            var resolved = await Preview(manager, Context(true, stored), new Dictionary<string, string> { ["validation-0-credential"] = "porkbun" });
            Assert.IsTrue(resolved.CanImport, "A stored credential is used instead");
        }

        [TestMethod]
        public async Task PoshAcmeArgumentsSavedForTheAccountAreShared()
        {
            var (manager, plan) = await PreviewOrder(new[] { "Porkbun" }, new Dictionary<string, object>
            {
                ["PorkbunAPIKey"] = "pk1_key",
                ["PorkbunSecret"] = Secure("porkbun-secret-456")
            }, argsInAccountFolder: true);

            AssertImportsWithoutSecrets(plan, "porkbun-secret-456");
            var challenge = plan.ProposedItem!.RequestConfig.Challenges.Single();
            StringAssert.Contains(plan.Credentials.Single(c => c.Key == challenge.ChallengeCredentialKey).Title, Path.Combine(AccountFolder, "pluginargs.json"),
                "Posh-ACME 3 saved the arguments for every order of the account");
            Assert.AreEqual("porkbun-secret-456", (await ResolveChallengeCredential(manager, plan, challenge))["PorkbunSecretInsecure"]);
        }

        [TestMethod]
        public async Task PoshAcmeArgumentChangedAfterPreviewIsReadAgainAtImport()
        {
            var (manager, plan) = await PreviewOrder(new[] { "Porkbun" }, new Dictionary<string, object> { ["PorkbunAPIKey"] = "pk1_key", ["PorkbunSecret"] = Secure("first") });
            var challenge = plan.ProposedItem!.RequestConfig.Challenges.Single();

            File.WriteAllText(Path.Combine(OrderFolder, "pluginargs.json"), JsonSerializer.Serialize(new Dictionary<string, object> { ["PorkbunAPIKey"] = "pk1_key", ["PorkbunSecret"] = Secure("second") }));
            Assert.AreEqual("second", (await ResolveChallengeCredential(manager, plan, challenge))["PorkbunSecretInsecure"]);

            File.WriteAllText(Path.Combine(OrderFolder, "pluginargs.json"), JsonSerializer.Serialize(new Dictionary<string, object> { ["PorkbunAPIKey"] = "pk1_key" }));
            await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => ResolveChallengeCredential(manager, plan, challenge));
        }

        [TestMethod]
        public async Task PoshAcmeCloudflareAliasAndDnsAliasBlocker()
        {
            var (manager, plan) = await PreviewOrder(new[] { "Cloudflare" }, new Dictionary<string, object> { ["CFToken"] = Secure(Token) });

            AssertImportsWithoutSecrets(plan, Token);
            var challenge = plan.ProposedItem!.RequestConfig.Challenges.Single();
            Assert.AreEqual(CloudflareProvider, challenge.ChallengeProvider);
            Assert.AreEqual(Token, (await ResolveChallengeCredential(manager, plan, challenge))["apitoken"]);

            WritePoshAcmeOrder(new[] { "Cloudflare" }, "{}", SsKey, change: o => o["DnsAlias"] = new[] { "example.net" });
            var aliased = await Preview(manager);
            Assert.IsTrue(aliased.HasBlockers, "DNS alias validation is not migrated");
            Assert.IsTrue(aliased.Findings.Any(f => f.Description.Contains("example.net")));
        }

        [TestMethod]
        public async Task PoshAcmeCredentialArgumentIsSplitIntoUserAndPassword()
        {
            var (manager, plan) = await PreviewOrder(new[] { "Azure" }, new Dictionary<string, object>
            {
                ["AZSubscriptionId"] = "sub",
                ["AZTenantId"] = "tenant",
                ["AZAppCred"] = new { origType = "pscredential", user = "app-id", pass = ExportSecureString("azure-secret", _key) }
            });

            AssertImportsWithoutSecrets(plan, "azure-secret");
            var challenge = plan.ProposedItem!.RequestConfig.Challenges.Single();
            Assert.AreEqual(AzureProvider, challenge.ChallengeProvider);

            var values = await ResolveChallengeCredential(manager, plan, challenge);
            Assert.AreEqual("app-id", values["clientid"]);
            Assert.AreEqual("azure-secret", values["secret"]);
            Assert.AreEqual("tenant", values["tenantid"]);
            Assert.AreEqual("sub", values["subscriptionid"]);
        }

        [TestMethod]
        [DataRow("Azure", "AZUseIMDS", true, "the machine's managed identity", DisplayName = "Azure managed identity")]
        [DataRow("Azure", "AZAccessToken", "token", "an access token or certificate", DisplayName = "Azure access token")]
        [DataRow("Route53", "R53ProfileName", "prod", "the AWS profile prod", DisplayName = "Route 53 profile")]
        [DataRow("Route53", "R53UseIAMRole", true, "the machine's IAM role", DisplayName = "Route 53 IAM role")]
        public async Task PoshAcmeAmbientAuthenticationIsNotMigrated(string plugin, string argument, object value, string expected)
        {
            var (_, plan) = await PreviewOrder(new[] { plugin }, new Dictionary<string, object> { [argument] = value });

            AssertBlocker(plan, "validation-0-credential", expected);
        }

        [TestMethod]
        public async Task PoshAcmePluginNotOnThisInstanceIsBlocked()
        {
            var (_, plan) = await PreviewOrder(new[] { "Akamai" }, new Dictionary<string, object> { ["AKHost"] = "host", ["AKAccessToken"] = Secure("akamai-secret-token") });

            AssertBlocker(plan, "validation-0", "There is no DNS provider for Akamai");
            AssertNoSecrets(plan, "akamai-secret-token");
        }

        [TestMethod]
        public async Task PoshAcmeArgumentsThePluginHereDoesNotTakeAreReported()
        {
            var (_, plan) = await PreviewOrder(new[] { "Porkbun" }, new Dictionary<string, object>
            {
                ["PorkbunAPIKey"] = "pk1_key",
                ["PorkbunSecret"] = Secure("porkbun-secret-456"),
                ["PorkbunUnused"] = false,
                ["PorkbunEndpoint"] = "https://api.example.net"
            });

            Assert.IsTrue(plan.CanImport);
            StringAssert.Contains(Finding(plan, "validation-0-options").Description, "PorkbunEndpoint");
            Assert.IsFalse(Finding(plan, "validation-0-options").Description.Contains("PorkbunUnused"), "An argument set to false is not set");
        }

        [TestMethod]
        public async Task PoshAcmeArgumentTheProviderHereNamesDifferentlyMapsByItsAltParamKey()
        {
            var context = Context();
            context.ChallengeProviders.Add(new ChallengeProviderDefinition
            {
                Id = "DNS01.API.PoshACME.Dynu",
                Title = "Dynu (using Posh-ACME)",
                Config = "Provider=Certify.Providers.DNS.PoshACME;Script=Dynu",
                ProviderParameters =
                [
                    new ProviderParameter { Key = "DynuClientIdentifier", Name = "Client ID", IsCredential = true, ExtendedConfig = """{"IsSecureString": false, "AltParamKey":"DynuClientID"}""" },
                    new ProviderParameter { Key = "DynuSecretInsecure", Name = "Secret", IsCredential = true }
                ]
            });

            var (manager, plan) = await PreviewOrder("Dynu", new Dictionary<string, object> { ["DynuClientID"] = "client", ["DynuSecret"] = Secure("dynu-secret") }, context: context);

            AssertImportsWithoutSecrets(plan, "dynu-secret");
            var values = await ResolveChallengeCredential(manager, plan, plan.ProposedItem!.RequestConfig.Challenges.Single());
            Assert.AreEqual("client", values["DynuClientIdentifier"]);
            Assert.AreEqual("dynu-secret", values["DynuSecretInsecure"]);
        }

        [TestMethod]
        public async Task PoshAcmePluginPerIdentifierValidatesEachItsOwnWay()
        {
            var www = Path.Combine(_root, "www");
            var (_, plan) = await PreviewOrder(new[] { "WebRoot", "Cloudflare" }, new Dictionary<string, object> { ["WRPath"] = www, ["CFToken"] = Secure(Token) });

            AssertImportsWithoutSecrets(plan, Token);
            var challenges = plan.ProposedItem!.RequestConfig.Challenges;
            Assert.AreEqual(2, challenges.Count);
            Assert.AreEqual(www, challenges.Single(c => c.DomainMatch == "example.com").ChallengeRootPath);
            Assert.AreEqual(CloudflareProvider, challenges.Single(c => c.DomainMatch == "www.example.com").ChallengeProvider);
        }

        [TestMethod]
        [DataRow("DnsPlugin", "Cloudflare", CloudflareProvider, DisplayName = "Posh-ACME 3's DnsPlugin")]
        [DataRow(null, null, ManualProvider, DisplayName = "No plugin, Posh-ACME's manual default")]
        public async Task PoshAcmeOlderAndDefaultPluginSettingsMigrate(string? setting, string? plugin, string provider)
        {
            var (_, plan) = await PreviewOrder(new[] { "Unused" }, new Dictionary<string, object> { ["CFToken"] = Secure(Token) }, o =>
            {
                o["Plugin"] = null;
                if (setting != null)
                {
                    o[setting] = new[] { plugin };
                }
            });

            Assert.AreEqual(provider, plan.ProposedItem!.RequestConfig.Challenges.Single().ChallengeProvider);
        }

        [TestMethod]
        public async Task PoshAcmeWebRootExactPathMapsToTheSiteRoot()
        {
            var www = Path.Combine(_root, "www");
            var (_, plan) = await PreviewOrder("WebRoot", new { WRPath = Path.Combine(www, ".well-known", "acme-challenge"), WRExactPath = true });

            AssertImportsWithoutSecrets(plan);
            Assert.AreEqual(www, plan.ProposedItem!.RequestConfig.Challenges.Single().ChallengeRootPath, "Challenge files go under .well-known/acme-challenge of the root here");
        }

        [TestMethod]
        [DataRow(true, "straight into", DisplayName = "Exact path which is not a challenge folder")]
        [DataRow(false, "and only", DisplayName = "More than one web root")]
        public async Task PoshAcmeWebRootWhichCannotBeKeptAsItIsIsCalledOut(bool exact, string expected)
        {
            var first = Path.Combine(_root, "first");
            object args = exact ? new { WRPath = first, WRExactPath = true } : new { WRPath = new[] { first, Path.Combine(_root, "second") } };

            var (_, plan) = await PreviewOrder("WebRoot", args);

            Assert.AreEqual(first, plan.ProposedItem!.RequestConfig.Challenges.Single().ChallengeRootPath);
            AssertAssumption(plan, expected);
        }

        [TestMethod]
        public async Task PoshAcmeWebRootWithoutAPathIsBlocked()
        {
            var (_, plan) = await PreviewOrder("WebRoot", "{}");

            AssertBlocker(plan, "validation-0", "Webroot with no path");
        }

        [TestMethod]
        public async Task PoshAcmeWebSelfHostIsAnsweredByTheChallengeServer()
        {
            var (_, plan) = await PreviewOrder("WebSelfHost", new { WSHPort = 8080 });

            AssertImportsWithoutSecrets(plan);
            Assert.AreEqual(SupportedChallengeTypes.CHALLENGE_TYPE_HTTP, plan.ProposedItem!.RequestConfig.Challenges.Single().ChallengeType);
            AssertAssumption(plan, "listens on port 8080");
        }

        [TestMethod]
        public async Task PoshAcmeManualPluginNeedsSomeoneToCreateTheRecord()
        {
            var (_, plan) = await PreviewOrder("Manual", "{}");

            Assert.AreEqual(ManualProvider, plan.ProposedItem!.RequestConfig.Challenges.Single().ChallengeProvider);
            AssertAssumption(plan, "cannot renew unattended");
        }

        [TestMethod]
        public async Task PoshAcmeAcmeDnsRegistrationOfEachNameMigrates()
        {
            var (manager, plan) = await PreviewOrder("AcmeDns", new
            {
                ACMEServer = "auth.acme-dns.io",
                ACMERegistration = new Dictionary<string, string[]>
                {
                    ["_acme-challenge.example.com"] = ["sub-1", "user-1", "pass-1", "sub-1.auth.acme-dns.io"],
                    ["_acme-challenge.www.example.com"] = ["sub-2", "user-2", "pass-2", "sub-2.auth.acme-dns.io"]
                }
            });

            AssertImportsWithoutSecrets(plan, "pass-1", "pass-2");
            var challenges = plan.ProposedItem!.RequestConfig.Challenges;
            Assert.AreEqual(2, challenges.Count);
            Assert.IsTrue(challenges.All(c => c.ChallengeProvider == AcmeDnsProvider && Parameter(c, "api") == "https://auth.acme-dns.io"));

            using var www = JsonDocument.Parse(await ResolveInlineParameter(manager, plan, challenges.Single(c => c.DomainMatch == "www.example.com"), "credentials_json"));
            Assert.AreEqual("sub-2", www.RootElement.GetProperty("subdomain").GetString());
            Assert.AreEqual("user-2", www.RootElement.GetProperty("username").GetString());
            Assert.AreEqual("pass-2", www.RootElement.GetProperty("password").GetString());
            Assert.AreEqual("sub-2.auth.acme-dns.io", www.RootElement.GetProperty("fulldomain").GetString());
        }

        [TestMethod]
        public async Task PoshAcmeAcmeDnsNameWithoutARegistrationIsBlocked()
        {
            var (_, plan) = await PreviewOrder("AcmeDns", new
            {
                ACMEServer = "https://auth.acme-dns.io",
                ACMERegistration = new Dictionary<string, string[]> { ["_acme-challenge.example.com"] = ["sub-1", "user-1", "pass-1", "sub-1.auth.acme-dns.io"] }
            });

            AssertBlocker(plan, "validation-1-secret", "no acme-dns registration for _acme-challenge.www.example.com");
            Assert.AreEqual("https://auth.acme-dns.io", Parameter(plan.ProposedItem!.RequestConfig.Challenges.First(), "api"), "A server given with its scheme is kept as it is");
        }

        // order settings

        [TestMethod]
        [DataRow("4096", StandardKeyTypes.RSA256_4096, DisplayName = "RSA 4096")]
        [DataRow("ec-384", StandardKeyTypes.ECDSA384, DisplayName = "EC P-384")]
        [DataRow(null, StandardKeyTypes.RSA256, DisplayName = "Posh-ACME's RSA default")]
        public async Task PoshAcmeKeyLengthMigrates(string? keyLength, string expected)
        {
            var (_, plan) = await PreviewOrder("Manual", "{}", o => o["KeyLength"] = keyLength);

            Assert.AreEqual(expected, plan.ProposedItem!.RequestConfig.CSRKeyAlg);
        }

        [TestMethod]
        public async Task PoshAcmeOrderSettingsMigrate()
        {
            var (_, plan) = await PreviewOrder("Manual", "{}", o =>
            {
                o["AlwaysNewKey"] = true;
                o["OCSPMustStaple"] = true;
                o["PreferredChain"] = "ISRG Root X1";
                o["Profile"] = "shortlived";
                o["LifetimeDays"] = 7;
                o["Subject"] = "CN=Custom Subject";
                o["Install"] = true;
                o["status"] = "invalid";
            });

            var config = plan.ProposedItem!.RequestConfig;
            Assert.IsFalse(config.ReusePrivateKey);
            Assert.IsTrue(config.RequireOcspMustStaple);
            Assert.AreEqual("ISRG Root X1", config.PreferredChain);
            Assert.AreEqual("shortlived", config.AcmeProfile);
            Assert.AreEqual(7, config.PreferredExpiryDays);
            AssertAssumption(plan, "CN=Custom Subject is not migrated");

            Assert.AreEqual(DeploymentOption.DeploymentStoreOnly, config.DeploymentSiteOption, "Install put the certificate in the machine store");
            Assert.AreEqual(ExternalMigrationFindingLevel.Mapped, Finding(plan, "store-0").Level);

            Assert.AreEqual(ExternalMigrationFindingLevel.Assumption, Finding(plan, "last-run").Level, "An invalid last order is called out");
        }

        [TestMethod]
        public async Task PoshAcmeKeepsTheKeyByDefault()
        {
            var (_, plan) = await PreviewOrder("Manual", "{}");

            Assert.IsTrue(plan.ProposedItem!.RequestConfig.ReusePrivateKey, "Posh-ACME reuses the key unless AlwaysNewKey is set");
            Assert.IsFalse(plan.Findings.Any(f => f.Key == "last-run"));
        }

        // account and certificate

        [TestMethod]
        public async Task PoshAcmeAccountKeyAsAnEcJwkStringIsRead()
        {
            var (jwk, publicKey) = CreateEcJwk();
            WritePoshAcmeOrder("Manual", "{}", null, accountKey: jwk);

            var manager = await GetManager<PoshAcme>(_root);
            var plan = await Preview(manager, Context(withAccount: false));

            Assert.IsTrue(plan.CanImport, string.Join("; ", plan.Findings.Where(f => f.IsUnresolved).Select(f => f.Description)));
            AssertSameEcKey(publicKey, (await manager.GetAccount(await ItemId(manager)))!.AccountKeyPem);
        }

        /// <summary>
        /// An EC JWK with each value as short as Posh-ACME encodes it, which drops leading zero bytes
        /// </summary>
        private static (string Jwk, byte[] PublicKey) CreateMinimalEcJwk(ECCurve curve, string name, bool needsLeadingZero)
        {
            static string Minimal(byte[] value) => Base64Url(value.SkipWhile(b => b == 0).ToArray());

            // about one key in a hundred has a value starting with a zero byte
            for (var attempt = 0; ; attempt++)
            {
                using var ec = ECDsa.Create(curve);
                var p = ec.ExportParameters(true);

                if (needsLeadingZero && !new[] { p.D!, p.Q.X!, p.Q.Y! }.Any(v => v[0] == 0))
                {
                    Assert.IsTrue(attempt < 10000, "A key with a leading zero byte is found");
                    continue;
                }

                return (JsonSerializer.Serialize(new { kty = "EC", crv = name, x = Minimal(p.Q.X!), y = Minimal(p.Q.Y!), d = Minimal(p.D!) }), ec.ExportSubjectPublicKeyInfo());
            }
        }

        [TestMethod]
        [DataRow("P-256", true, DisplayName = "P-256 with a value shortened by a leading zero byte")]
        [DataRow("P-384", false, DisplayName = "P-384")]
        [DataRow("P-521", false, DisplayName = "P-521")]
        public async Task PoshAcmeEcAccountKeysAreRead(string name, bool needsLeadingZero)
        {
            var curve = name switch { "P-256" => ECCurve.NamedCurves.nistP256, "P-384" => ECCurve.NamedCurves.nistP384, _ => ECCurve.NamedCurves.nistP521 };
            var (jwk, publicKey) = CreateMinimalEcJwk(curve, name, needsLeadingZero);
            WritePoshAcmeOrder("Manual", "{}", null, jwk);

            var manager = await GetManager<PoshAcme>(_root);

            AssertSameEcKey(publicKey, (await manager.GetAccount(await ItemId(manager)))!.AccountKeyPem);
        }

        [TestMethod]
        [DataRow("location", "does not include the account URL", DisplayName = "No account URL")]
        [DataRow("oct", "is not supported", DisplayName = "A key type ACME accounts do not use")]
        [DataRow("file", "could not be read", DisplayName = "No account file")]
        [DataRow("key", "could not be read", DisplayName = "An account key that is not a JWK")]
        public async Task PoshAcmeAccountWhichCannotBeReadNeedsAnAccountHere(string problem, string expected)
        {
            object? accountKey = problem switch
            {
                "key" => "not a key",
                "oct" => JsonDocument.Parse("""{ "kty": "oct", "k": "c2VjcmV0" }""").RootElement,
                _ => null
            };

            WritePoshAcmeOrder("Manual", "{}", null, accountLocation: problem == "location" ? null : "https://acme-v02.api.letsencrypt.org/acme/acct/123456", accountKey: accountKey);

            if (problem == "file")
            {
                File.Delete(Path.Combine(AccountFolder, "acct.json"));
            }

            var manager = await GetManager<PoshAcme>(_root);
            var plan = await Preview(manager, Context(withAccount: false));

            AssertBlocker(plan, "account", expected);
            Assert.IsNull(await manager.GetAccount(await ItemId(manager)));
        }

        // disable, restore and remove

        [TestMethod]
        public async Task PoshAcmeOrderIsDisabledRestoredAndRemoved()
        {
            var orderFile = WritePoshAcmeOrder("WebRoot", new { WRPath = Path.Combine(_root, "www") }, null);

            var manager = await GetManager<PoshAcme>(_root);
            var itemId = await ItemId(manager);

            var plan = await manager.PrepareMigrationPlan(itemId, Context(), null);
            AssertImportsWithoutSecrets(plan);
            Assert.AreEqual(SupportedChallengeTypes.CHALLENGE_TYPE_HTTP, plan!.ProposedItem!.RequestConfig.Challenges.Single().ChallengeType);

            Assert.IsNotNull((await manager.PlanSourceRemoval(itemId)).BlockedReason);

            Assert.IsTrue((await manager.DisableSourceItem(itemId)).IsSuccess);
            Assert.IsTrue(File.Exists(orderFile + ".certify-migrated"));
            Assert.IsFalse((await manager.GetManagedCertificates()).Any(), "A set aside order is no longer monitored");
            Assert.IsNull(await manager.PrepareMigrationPlan(itemId, Context(), null), "A set aside order is not offered for migration again");
            Assert.IsNotNull(await manager.GetCurrentCertificate(itemId), "The certificate can still be adopted after cut over");
            Assert.IsNotNull(await manager.GetAccount(itemId));
            StringAssert.Contains((await manager.DisableSourceItem(itemId)).Message, "already set aside");

            Assert.IsTrue((await manager.RestoreSourceItem(itemId)).IsSuccess);
            Assert.IsTrue(File.Exists(orderFile));
            StringAssert.Contains((await manager.RestoreSourceItem(itemId)).Message, "already renewed");
            Assert.IsTrue((await manager.DisableSourceItem(itemId)).IsSuccess);

            var manifest = await manager.PlanSourceRemoval(itemId);
            Assert.IsNull(manifest.BlockedReason);
            Assert.AreEqual(5, manifest.FilesToDelete.Count);

            Assert.IsTrue((await manager.RemoveSourceItem(itemId, manifest)).IsSuccess);
            Assert.IsFalse(Directory.Exists(Path.GetDirectoryName(orderFile)));
            Assert.IsTrue(File.Exists(Path.Combine(AccountFolder, "acct.json")), "The account is kept");
        }

        [TestMethod]
        public async Task PoshAcmeOrderCreatedAgainAfterCutOverIsLeftAsItIs()
        {
            var orderFile = WritePoshAcmeOrder("Manual", "{}", null);

            var manager = await GetManager<PoshAcme>(_root);
            var itemId = await ItemId(manager);
            Assert.IsTrue((await manager.DisableSourceItem(itemId)).IsSuccess);

            // New-PACertificate run again for the same names, which is a new order
            File.WriteAllText(orderFile, File.ReadAllText(orderFile + ".certify-migrated").Replace("/order/123456/1", "/order/123456/2"));
            var listed = (await manager.GetManagedCertificates()).Single();
            Assert.AreNotEqual(itemId, listed.Id, "The new order is a new item");

            var restore = await manager.RestoreSourceItem(itemId);
            Assert.IsFalse(restore.IsSuccess);
            StringAssert.Contains(restore.Message, "already exists");
            Assert.IsTrue(File.Exists(orderFile + ".certify-migrated"));
        }

        [TestMethod]
        public async Task PoshAcmeRemovalChangedSincePreviewIsRefused()
        {
            var orderFile = WritePoshAcmeOrder("Manual", "{}", null);

            var manager = await GetManager<PoshAcme>(_root);
            var itemId = await ItemId(manager);
            Assert.IsTrue((await manager.DisableSourceItem(itemId)).IsSuccess);
            var manifest = await manager.PlanSourceRemoval(itemId);

            File.WriteAllText(Path.Combine(OrderFolder, "fullchain.cer"), "new");

            var result = await manager.RemoveSourceItem(itemId, manifest);
            Assert.IsFalse(result.IsSuccess);
            StringAssert.Contains(result.Message, "changed since");
            Assert.IsTrue(File.Exists(orderFile + ".certify-migrated"));
        }
    }
}
