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
using Certify.Plugin.CertificateManagers.Providers.WinAcme;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests.Plugin.CertificateManagers
{
    /// <summary>
    /// Migration of win-acme renewals: what the preview proposes, what secrets resolve to, and how the source is
    /// disabled, restored and removed
    /// </summary>
    [TestClass]
    public class MigrationTests
    {
        private const string CloudflareProvider = "DNS01.API.Cloudflare";

        private string _root = string.Empty;
        private string _server = string.Empty;

        [TestInitialize]
        public void Setup()
        {
            _root = Path.Combine(Path.GetTempPath(), $"certmanager-migration-test-{Guid.NewGuid():N}");
            _server = Path.Combine(_root, "acme-v02.api.letsencrypt.org");
            Directory.CreateDirectory(_server);
        }

        [TestCleanup]
        public void Cleanup()
        {
            if (Directory.Exists(_root))
            {
                Directory.Delete(_root, true);
            }
        }

        private static string Protect(string value) => Convert.ToBase64String(Encoding.UTF8.GetBytes(value));

        private void WriteRenewal(string id, string validation, string stores = "[]", string installations = "[]")
        {
            File.WriteAllText(Path.Combine(_server, $"{id}.renewal.json"), $$"""
            {
              "Id": "{{id}}",
              "LastFriendlyName": "[Manual] {{id}}.example.com",
              "TargetPluginOptions": { "CommonName": "{{id}}.example.com", "AlternativeNames": [ "{{id}}.example.com", "www.{{id}}.example.com" ], "Plugin": "e239db3b-b42f-48aa-b64f-46d4f3e9941b" },
              "ValidationPluginOptions": {{validation}},
              "CsrPluginOptions": { "Plugin": "b9060d4b-c2d3-49ac-b37f-962e7c3cbe9d" },
              "StorePluginOptions": {{stores}},
              "InstallationPluginOptions": {{installations}},
              "History": [ { "Date": "2025-06-01T00:00:00Z", "Success": true, "OrderResults": [ { "Name": "main", "Success": true, "ExpireDate": "2025-08-30T00:00:00Z", "Thumbprint": "AAAA" } ] } ]
            }
            """);
        }

        private async Task<WinAcme> GetManager()
        {
            var manager = new WinAcme();
            manager.Init(NullLogger.Instance, new CertificateManagerPreference { ConfigPath = _root, LogPath = _root });
            await manager.GetManagedCertificates();
            return manager;
        }

        private static ExternalMigrationContext Context(params StoredCredential[] credentials) => new()
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
                        new ProviderParameter { Key = "zoneid", Name = "Zone Id", IsCredential = false }
                    ]
                }
            ],
            Credentials = credentials.ToList()
        };

        private const string ItemId = "ext-win-acme-cf";

        // the suffix win-acme renewal files are given when disabled for migration
        private const string DisabledSuffix = ".certify-migrated";

        [TestMethod]
        [DataRow(false, DisplayName = "Token protected as base64")]
        [DataRow(true, DisplayName = "Token in clear text")]
        public async Task DnsValidationMapsToCredentialDraftWithoutSecretValues(bool clear)
        {
            var token = "cf-token-value-123";
            WriteRenewal("cf", $$"""{ "ApiToken": "{{(clear ? "clear-" + token : Protect(token))}}", "Plugin": "73af2c2e-4cf1-4198-a4c8-1129003cfb75" }""");

            var manager = await GetManager();
            var plan = await manager.PrepareMigrationPlan(ItemId, Context(), null);

            Assert.IsNotNull(plan);
            Assert.IsTrue(plan.CanImport, string.Join("; ", plan.Findings.Where(f => f.IsUnresolved).Select(f => f.Description)));

            var challenge = plan.ProposedItem!.RequestConfig.Challenges.Single();
            Assert.AreEqual(SupportedChallengeTypes.CHALLENGE_TYPE_DNS, challenge.ChallengeType);
            Assert.AreEqual(CloudflareProvider, challenge.ChallengeProvider);
            Assert.IsTrue(ExternalMigrationCredentialDraft.IsDraftKey(challenge.ChallengeCredentialKey), "The credential is created at import");

            CollectionAssert.AreEquivalent(new[] { "cf.example.com", "www.cf.example.com" }, plan.ProposedItem.GetCertificateIdentifiers().Select(i => i.Value).ToArray());
            Assert.AreEqual(DeploymentOption.NoDeployment, plan.ProposedItem.RequestConfig.DeploymentSiteOption, "Nothing is stored or installed by the renewal");
            Assert.IsFalse(plan.ProposedItem.IncludeInAutoRenew, "Auto renewal stays off until cut over");

            var draft = plan.Credentials.Single(c => c.Key == challenge.ChallengeCredentialKey);
            Assert.AreEqual(CloudflareProvider, draft.ProviderType);

            Assert.IsFalse(JsonSerializer.Serialize(plan).Contains(token), "The preview refers to the secret without carrying its value");

            var values = await manager.ResolveCredentialValues(ItemId, draft);
            Assert.AreEqual(token, values["apitoken"], "The value is read from the renewal at import");
        }

        [TestMethod]
        public async Task SharedVaultSecretIsResolvedFromSecretsJson()
        {
            File.WriteAllText(Path.Combine(_server, "secrets.json"), $$"""[ { "Key": "cf", "Secret": "{{Protect("vault-token")}}" } ]""");
            WriteRenewal("cf", """{ "ApiToken": "vault://json/cf", "Plugin": "73af2c2e-4cf1-4198-a4c8-1129003cfb75" }""");

            var manager = await GetManager();
            var plan = await manager.PrepareMigrationPlan(ItemId, Context(), null);

            Assert.IsTrue(plan!.CanImport);
            var draft = plan.Credentials.Single(c => !c.IsInlineValue);
            Assert.AreEqual("vault-token", (await manager.ResolveCredentialValues(ItemId, draft))["apitoken"]);
        }

        [TestMethod]
        public async Task UnreadableSecretNeedsAReplacementCredential()
        {
            WriteRenewal("cf", """{ "ApiToken": "vault://json/missing", "Plugin": "73af2c2e-4cf1-4198-a4c8-1129003cfb75" }""");

            var manager = await GetManager();
            var plan = await manager.PrepareMigrationPlan(ItemId, Context(), null);

            Assert.IsFalse(plan!.CanImport);
            var finding = plan.Findings.Single(f => f.Key == "validation-0-credential");
            Assert.IsTrue(finding.IsUnresolved);
            Assert.AreEqual(ExternalMigrationInputTypes.Credential, finding.InputType);
            Assert.AreEqual(CloudflareProvider, finding.CredentialType);

            // a stored credential of the right type resolves it, one of another type does not
            var stored = new StoredCredential { StorageKey = "cf-stored", ProviderType = CloudflareProvider, Title = "Cloudflare" };
            var other = new StoredCredential { StorageKey = "other", ProviderType = "DNS01.API.Route53", Title = "Route 53" };

            var wrong = await manager.PrepareMigrationPlan(ItemId, Context(stored, other), new Dictionary<string, string> { ["validation-0-credential"] = "other" });
            Assert.IsFalse(wrong!.CanImport);

            var resolved = await manager.PrepareMigrationPlan(ItemId, Context(stored, other), new Dictionary<string, string> { ["validation-0-credential"] = "cf-stored" });
            Assert.IsTrue(resolved!.CanImport);
            Assert.AreEqual("cf-stored", resolved.ProposedItem!.RequestConfig.Challenges.Single().ChallengeCredentialKey);
        }

        [TestMethod]
        public async Task MappedSettingsOfferTheSourceValueOrTheDefault()
        {
            File.WriteAllText(Path.Combine(_server, "settings.json"), """{ "ScheduledTask": { "RenewalDays": 60 }, "Security": { "RSAKeyBits": 4096 } }""");
            WriteRenewal("cf", $$"""{ "ApiToken": "{{Protect("t")}}", "Plugin": "73af2c2e-4cf1-4198-a4c8-1129003cfb75" }""");

            var manager = await GetManager();
            var plan = await manager.PrepareMigrationPlan(ItemId, Context(), null);

            var renewal = plan!.Findings.Single(f => f.Key == "renewal-days");
            Assert.AreEqual(ExternalMigrationFindingLevel.Mapped, renewal.Level);
            Assert.AreEqual(ExternalMigrationInputTypes.Choice, renewal.InputType);
            Assert.AreEqual(ExternalMigrationChoices.Default, renewal.AppliedInput, "The renewal interval is this instance's by default");
            Assert.IsNull(plan.ProposedItem!.CustomRenewalTarget);

            var key = plan.Findings.Single(f => f.Key == "key");
            Assert.AreEqual(ExternalMigrationChoices.Source, key.AppliedInput, "Other settings keep the source's value by default");
            Assert.AreEqual(StandardKeyTypes.RSA256_4096, plan.ProposedItem.RequestConfig.CSRKeyAlg);

            var chosen = await manager.PrepareMigrationPlan(ItemId, Context(), new Dictionary<string, string>
            {
                ["renewal-days"] = ExternalMigrationChoices.Source,
                ["key"] = ExternalMigrationChoices.Default
            });

            Assert.AreEqual(60f, chosen!.ProposedItem!.CustomRenewalTarget);
            Assert.AreEqual(ExternalMigrationChoices.Source, chosen.Findings.Single(f => f.Key == "renewal-days").AppliedInput);
            Assert.IsNull(chosen.ProposedItem.RequestConfig.CSRKeyAlg, "The default key type follows this instance's setting");
            Assert.IsTrue(chosen.CanImport);
        }

        [TestMethod]
        public async Task MissingDnsProviderBlocksImport()
        {
            WriteRenewal("cf", $$"""{ "ApiToken": "{{Protect("t")}}", "Plugin": "73af2c2e-4cf1-4198-a4c8-1129003cfb75" }""");

            var context = Context();
            context.ChallengeProviders.Clear();

            var plan = await (await GetManager()).PrepareMigrationPlan(ItemId, context, null);

            Assert.IsTrue(plan!.HasBlockers);
            Assert.IsFalse(plan.CanImport);
        }

        [TestMethod]
        [DataRow("ES256", DisplayName = "EC account key")]
        [DataRow("RS256", DisplayName = "RSA account key")]
        public async Task AccountKeyIsReadAsPkcs8(string keyType)
        {
            WriteRenewal("cf", """{ "Plugin": "e45d62b9-f9a8-441e-b95f-c5ee0dcd8040" }""");

            byte[] publicKey;
            string export;

            if (keyType == "ES256")
            {
                using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
                var p = ec.ExportParameters(true);
                publicKey = ec.ExportSubjectPublicKeyInfo();
                export = JsonSerializer.Serialize(new { HashSize = 256, D = p.D, X = p.Q.X, Y = p.Q.Y });
            }
            else
            {
                using var rsa = RSA.Create(2048);
                publicKey = rsa.ExportSubjectPublicKeyInfo();
                export = rsa.ToXmlString(true);
            }

            var signer = JsonSerializer.Serialize(new { KeyType = keyType, KeyExport = export });
            File.WriteAllText(Path.Combine(_server, "Signer_v2"), Protect(signer));
            File.WriteAllText(Path.Combine(_server, "Registration_v2"), """{ "Payload": { "Contact": [ "mailto:admin@example.com" ] }, "Kid": "https://acme-v02.api.letsencrypt.org/acme/acct/1" }""");

            var account = await (await GetManager()).GetAccount(ItemId);

            Assert.IsNotNull(account);
            Assert.AreEqual("https://acme-v02.api.letsencrypt.org/acme/acct/1", account.AccountUri);
            Assert.AreEqual("admin@example.com", account.EmailAddress);
            StringAssert.StartsWith(account.AccountKeyPem, "-----BEGIN PRIVATE KEY-----");

            using AsymmetricAlgorithm imported = keyType == "ES256" ? ECDsa.Create() : RSA.Create();
            imported.ImportFromPem(account.AccountKeyPem);
            CollectionAssert.AreEqual(publicKey, imported.ExportSubjectPublicKeyInfo(), "The converted key is the same key");
        }

        [TestMethod]
        public async Task SourceIsDisabledRestoredAndRemoved()
        {
            WriteRenewal("cf", """{ "Plugin": "e45d62b9-f9a8-441e-b95f-c5ee0dcd8040" }""");
            WriteRenewal("other", """{ "Plugin": "e45d62b9-f9a8-441e-b95f-c5ee0dcd8040" }""");

            var cache = Path.Combine(_server, "Certificates");
            Directory.CreateDirectory(cache);
            File.WriteAllText(Path.Combine(cache, "cf-main-abc.pfx"), "x");
            File.WriteAllText(Path.Combine(cache, "other-main-abc.pfx"), "x");

            var manager = await GetManager();
            var renewalFile = Path.Combine(_server, "cf.renewal.json");

            var blocked = await manager.PlanSourceRemoval(ItemId);
            Assert.IsNotNull(blocked.BlockedReason, "An active renewal is not removed");

            Assert.IsTrue((await manager.DisableSourceItem(ItemId)).IsSuccess);
            Assert.IsFalse(File.Exists(renewalFile));
            Assert.IsTrue(File.Exists(renewalFile + DisabledSuffix));
            Assert.IsFalse((await manager.GetManagedCertificates()).Any(i => i.Id == ItemId), "A disabled renewal is no longer monitored");
            Assert.IsTrue((await manager.DisableSourceItem(ItemId)).IsSuccess, "Disabling again changes nothing");

            Assert.IsTrue((await manager.RestoreSourceItem(ItemId)).IsSuccess);
            Assert.IsTrue(File.Exists(renewalFile));
            Assert.IsTrue((await manager.DisableSourceItem(ItemId)).IsSuccess);

            var manifest = await manager.PlanSourceRemoval(ItemId);
            Assert.IsNull(manifest.BlockedReason);
            CollectionAssert.AreEquivalent(new[] { renewalFile + DisabledSuffix, Path.Combine(cache, "cf-main-abc.pfx") }, manifest.FilesToDelete,
                "Only this renewal's own files are deleted");

            var changed = new SourceRemovalManifest { SourceItemId = ItemId, FilesToDelete = manifest.FilesToDelete.Take(1).ToList() };
            Assert.IsFalse((await manager.RemoveSourceItem(ItemId, changed)).IsSuccess, "Only the previewed set of files is deleted");

            Assert.IsTrue((await manager.RemoveSourceItem(ItemId, manifest)).IsSuccess);
            Assert.IsFalse(manifest.FilesToDelete.Any(File.Exists));
            Assert.IsTrue(File.Exists(Path.Combine(_server, "other.renewal.json")) && File.Exists(Path.Combine(cache, "other-main-abc.pfx")), "Other renewals are untouched");
        }
    }
}
