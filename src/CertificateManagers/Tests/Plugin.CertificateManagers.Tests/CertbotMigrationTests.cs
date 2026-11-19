#nullable enable

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Certify.Models;
using Certify.Models.Config;
using Certify.Models.Config.Migration;
using Certify.Plugin.CertificateManagers.Providers.Certbot;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests.Plugin.CertificateManagers
{
    /// <summary>
    /// Migration of certbot lineages: what the preview proposes for each authenticator, installer and setting, what
    /// secrets resolve to, the account and certificate, and how autorenew is turned off, put back and the lineage removed
    /// </summary>
    [TestClass]
    public class CertbotMigrationTests : ExternalToolMigrationTestBase
    {
        private string Live => Path.Combine(_root, "live", "example.com");
        private string Archive => Path.Combine(_root, "archive", "example.com");
        private string Conf => Path.Combine(_root, "renewal", "example.com.conf");

        /// <param name="renewalParams">settings of [renewalparams], after account and server</param>
        /// <param name="top">settings above [renewalparams], after the file paths</param>
        private string WriteCertbotLineage(string renewalParams, string top = "", bool writeLiveFiles = true)
        {
            var (cert, key, chain, _) = CreateCertificate();
            Directory.CreateDirectory(Live);
            Directory.CreateDirectory(Archive);
            Directory.CreateDirectory(Path.Combine(_root, "renewal"));

            if (writeLiveFiles)
            {
                File.WriteAllText(Path.Combine(Live, "cert.pem"), cert);
                File.WriteAllText(Path.Combine(Live, "privkey.pem"), key);
                File.WriteAllText(Path.Combine(Live, "chain.pem"), chain);
                File.WriteAllText(Path.Combine(Live, "fullchain.pem"), cert + chain);
            }

            File.WriteAllText(Path.Combine(Archive, "cert1.pem"), cert);
            File.WriteAllText(Path.Combine(Archive, "privkey1.pem"), key);

            File.WriteAllText(Conf, $"""
                version = 2.11.0
                archive_dir = {Archive}
                cert = {Path.Combine(Live, "cert.pem")}
                privkey = {Path.Combine(Live, "privkey.pem")}
                chain = {Path.Combine(Live, "chain.pem")}
                fullchain = {Path.Combine(Live, "fullchain.pem")}
                {top}

                # Options used in the renewal process
                [renewalparams]
                account = 0123abcd
                server = https://acme-v02.api.letsencrypt.org/directory
                {renewalParams}
                """);

            return Conf;
        }

        private byte[] WriteAccount()
        {
            var (jwk, publicKey) = CreateJwk();
            var accountFolder = Path.Combine(_root, "accounts", "acme-v02.api.letsencrypt.org", "directory", "0123abcd");
            Directory.CreateDirectory(accountFolder);
            File.WriteAllText(Path.Combine(accountFolder, "private_key.json"), jwk);
            File.WriteAllText(Path.Combine(accountFolder, "regr.json"), """{ "body": { "contact": [ "mailto:admin@example.com" ] }, "uri": "https://acme-v02.api.letsencrypt.org/acme/acct/9" }""");
            return publicKey;
        }

        private async Task<(Certbot Manager, ExternalMigrationPlan Plan)> PreviewLineage(string renewalParams, string top = "", ExternalMigrationContext? context = null, IDictionary<string, string>? inputs = null)
        {
            WriteCertbotLineage(renewalParams, top);
            var manager = await GetManager<Certbot>(_root);
            return (manager, await Preview(manager, context, inputs));
        }

        // validation

        [TestMethod]
        public async Task CertbotDnsHooksAccountAndCertificateMigrate()
        {
            var credentials = Path.Combine(_root, "cloudflare.ini");
            File.WriteAllText(credentials, $"# Cloudflare API token\ndns_cloudflare_api_token = {Token}\n");

            WriteCertbotLineage($"""
                key_type = ecdsa
                authenticator = dns-cloudflare
                dns_cloudflare_credentials = {credentials}
                dns_cloudflare_propagation_seconds = 30
                deploy_hook = systemctl reload nginx
                """);

            var publicKey = WriteAccount();

            var manager = await GetManager<Certbot>(_root);
            var itemId = await ItemId(manager);
            var plan = await manager.PrepareMigrationPlan(itemId, Context(), null);

            AssertImportsWithoutSecrets(plan, Token);

            var item = plan!.ProposedItem!;
            CollectionAssert.AreEquivalent(new[] { "example.com", "www.example.com" }, item.GetCertificateIdentifiers().Select(i => i.Value).ToArray());
            Assert.AreEqual(StandardKeyTypes.ECDSA256, item.RequestConfig.CSRKeyAlg);

            var challenge = item.RequestConfig.Challenges.Single();
            Assert.AreEqual(CloudflareProvider, challenge.ChallengeProvider);
            Assert.AreEqual("30", Parameter(challenge, "propagationdelay"));

            var draft = plan.Credentials.Single(c => c.Key == challenge.ChallengeCredentialKey);
            Assert.AreEqual(Token, (await manager.ResolveCredentialValues(itemId, draft))["apitoken"], "The token is read from the credentials file at import");
            StringAssert.Contains(draft.Title, credentials, "A credentials file other lineages may share is named as the credential's origin");

            Assert.AreEqual(4, item.PostRequestTasks!.Count(t => t.TaskTypeId == ExportTask), "The live files are written as certbot wrote them");
            Assert.AreEqual(1, item.PostRequestTasks!.Count(t => t.TaskTypeId == PowerShellTask), "The deploy hook runs after renewal");
            Assert.AreEqual(DeploymentOption.NoDeployment, item.RequestConfig.DeploymentSiteOption, "certbot never touched IIS bindings");

            var account = await manager.GetAccount(itemId);
            Assert.AreEqual("https://acme-v02.api.letsencrypt.org/acme/acct/9", account!.AccountUri);
            Assert.AreEqual("admin@example.com", account.EmailAddress);
            AssertSameKey(publicKey, account.AccountKeyPem);

            var current = await manager.GetCurrentCertificate(itemId);
            Assert.IsNotNull(current?.PfxData, "The current certificate and key are read as a PFX");
            Assert.IsTrue(plan.CanAdoptCurrentCertificate);
        }

        [TestMethod]
        public async Task CertbotCredentialChangedAfterPreviewIsReadAgainAtImport()
        {
            var credentials = Path.Combine(_root, "cloudflare.ini");
            File.WriteAllText(credentials, $"dns_cloudflare_api_token = {Token}\n");

            var (manager, plan) = await PreviewLineage($"authenticator = dns-cloudflare\ndns_cloudflare_credentials = {credentials}");
            var challenge = plan.ProposedItem!.RequestConfig.Challenges.Single();

            File.WriteAllText(credentials, "dns_cloudflare_api_token = rotated-token\n");
            Assert.AreEqual("rotated-token", (await ResolveChallengeCredential(manager, plan, challenge))["apitoken"]);

            File.WriteAllText(credentials, "# emptied\n");
            var error = await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => ResolveChallengeCredential(manager, plan, challenge));
            StringAssert.Contains(error.Message, "no longer has", "The credential refers to a setting the file no longer holds");
        }

        [TestMethod]
        public async Task CertbotUnreadableCredentialsFileAsksForAStoredCredential()
        {
            var missing = Path.Combine(_root, "missing.ini");
            var (_, plan) = await PreviewLineage($"authenticator = dns-cloudflare\ndns_cloudflare_credentials = {missing}");

            AssertBlocker(plan, "validation-0-credential", "could not be read");
            Assert.IsTrue(plan.Secrets.Any(s => !s.IsReadable), "The preview shows which secret could not be read");

            var stored = new StoredCredential { StorageKey = "cf-stored", ProviderType = CloudflareProvider, Title = "Cloudflare" };
            var withCredential = await Preview(await GetManager<Certbot>(_root), Context(true, stored), new Dictionary<string, string> { ["validation-0-credential"] = "cf-stored" });

            Assert.IsTrue(withCredential.CanImport, "Choosing a stored credential resolves it");
            Assert.AreEqual("cf-stored", withCredential.ProposedItem!.RequestConfig.Challenges.Single().ChallengeCredentialKey);
        }

        [TestMethod]
        public async Task CertbotDnsAuthenticatorWithoutCredentialsFileIsBlocked()
        {
            var (_, plan) = await PreviewLineage("authenticator = dns-cloudflare");

            Assert.IsTrue(plan.HasBlockers);
            Assert.IsTrue(plan.Findings.Any(f => f.Level == ExternalMigrationFindingLevel.Blocker && f.Description.Contains("credentials file is not set")));
        }

        [TestMethod]
        public async Task CertbotRoute53UsesAmbientCredentialsSoAStoredCredentialIsChosen()
        {
            var (manager, plan) = await PreviewLineage("authenticator = dns-route53\ndns_route53_propagation_seconds = 20");

            AssertBlocker(plan, "validation-0-credential", "AWS credentials");
            Assert.AreEqual(Route53Provider, plan.ProposedItem!.RequestConfig.Challenges.Single().ChallengeProvider);

            var stored = new StoredCredential { StorageKey = "aws", ProviderType = Route53Provider, Title = "AWS" };
            var resolved = await Preview(manager, Context(true, stored), new Dictionary<string, string> { ["validation-0-credential"] = "aws" });

            Assert.IsTrue(resolved.CanImport);
            var challenge = resolved.ProposedItem!.RequestConfig.Challenges.Single();
            Assert.AreEqual("aws", challenge.ChallengeCredentialKey);
            Assert.AreEqual("20", Parameter(challenge, "propagationdelay"));

            var wrongType = await Preview(manager, Context(true, new StoredCredential { StorageKey = "aws", ProviderType = CloudflareProvider }), new Dictionary<string, string> { ["validation-0-credential"] = "aws" });
            Assert.IsFalse(wrongType.CanImport, "A credential for another provider is not accepted");
        }

        [TestMethod]
        public async Task CertbotGoogleKeyFileAndProjectAreUsedInPlace()
        {
            var keyFile = Path.Combine(_root, "google.json");
            File.WriteAllText(keyFile, """{ "type": "service_account", "project_id": "my-project", "private_key": "not-read" }""");

            var (_, plan) = await PreviewLineage($"authenticator = dns-google\ndns_google_credentials = {keyFile}");

            AssertImportsWithoutSecrets(plan, "not-read");
            var challenge = plan.ProposedItem!.RequestConfig.Challenges.Single();
            Assert.AreEqual(GoogleCloudProvider, challenge.ChallengeProvider);
            Assert.AreEqual(keyFile, Parameter(challenge, "GCKeyFile"));
            Assert.AreEqual("my-project", Parameter(challenge, "GCProjectId"));
            AssertAssumption(plan, "key file stays where it is");
        }

        [TestMethod]
        [DataRow("dns-gehirn", "There is no DNS provider for Gehirn DNS", DisplayName = "A certbot DNS plugin with no provider here")]
        [DataRow("dns-unheardof", "There is no DNS provider for dns-unheardof", DisplayName = "A DNS plugin not in the catalogue")]
        [DataRow("thirdparty:custom", "custom is not recognised", DisplayName = "A third party authenticator")]
        public async Task CertbotAuthenticatorsWithoutAnEquivalentAreBlocked(string authenticator, string expected)
        {
            var (_, plan) = await PreviewLineage($"authenticator = {authenticator}\n{authenticator.Replace('-', '_')}_credentials = {Path.Combine(_root, "x.ini")}");

            AssertBlocker(plan, "validation-0", expected);
            Assert.IsFalse(plan.ProposedItem!.RequestConfig.Challenges.Any());
        }

        [TestMethod]
        public async Task CertbotWebrootMapsToChallengeFolder()
        {
            var (_, plan) = await PreviewLineage($"""
                authenticator = webroot
                [[webroot_map]]
                example.com = {Path.Combine(_root, "www")}
                www.example.com = {Path.Combine(_root, "www")}
                """);

            AssertImportsWithoutSecrets(plan);
            var challenge = plan.ProposedItem!.RequestConfig.Challenges.Single();
            Assert.AreEqual(SupportedChallengeTypes.CHALLENGE_TYPE_HTTP, challenge.ChallengeType);
            Assert.AreEqual(Path.Combine(_root, "www"), challenge.ChallengeRootPath);
            Assert.IsNull(challenge.DomainMatch, "One folder serves every name");
        }

        [TestMethod]
        public async Task CertbotWebrootWithAFolderPerNameValidatesEachFromItsFolder()
        {
            var (_, plan) = await PreviewLineage($"""
                authenticator = webroot
                [[webroot_map]]
                example.com = {Path.Combine(_root, "site")}
                www.example.com = {Path.Combine(_root, "www")}
                """);

            AssertImportsWithoutSecrets(plan);
            var challenges = plan.ProposedItem!.RequestConfig.Challenges;
            Assert.AreEqual(2, challenges.Count);
            Assert.AreEqual(Path.Combine(_root, "site"), challenges.Single(c => c.DomainMatch == "example.com").ChallengeRootPath);
            Assert.AreEqual(Path.Combine(_root, "www"), challenges.Single(c => c.DomainMatch == "www.example.com").ChallengeRootPath);
        }

        [TestMethod]
        public async Task CertbotWebrootPathIsUsedForNamesNotInTheMap()
        {
            var (_, plan) = await PreviewLineage($"authenticator = webroot\nwebroot_path = {Path.Combine(_root, "www")},");

            AssertImportsWithoutSecrets(plan);
            Assert.AreEqual(Path.Combine(_root, "www"), plan.ProposedItem!.RequestConfig.Challenges.Single().ChallengeRootPath);
        }

        [TestMethod]
        public async Task CertbotStandaloneOnAnotherPortIsAnsweredByTheChallengeServer()
        {
            var (_, plan) = await PreviewLineage("authenticator = standalone\nhttp01_port = 8080", context: null);

            AssertImportsWithoutSecrets(plan);
            Assert.AreEqual(SupportedChallengeTypes.CHALLENGE_TYPE_HTTP, plan.ProposedItem!.RequestConfig.Challenges.Single().ChallengeType);
            AssertAssumption(plan, "listens on port 8080");
            AssertAssumption(plan, "http challenge server is off");
        }

        [TestMethod]
        public async Task CertbotNginxAuthenticatorAndInstallerMigrate()
        {
            var (_, plan) = await PreviewLineage("authenticator = nginx\ninstaller = nginx");

            AssertImportsWithoutSecrets(plan);
            Assert.AreEqual(SupportedChallengeTypes.CHALLENGE_TYPE_HTTP, plan.ProposedItem!.RequestConfig.Challenges.Single().ChallengeType);
            AssertAssumption(plan, "/.well-known/acme-challenge/");

            Assert.AreEqual(1, plan.ProposedItem.PostRequestTasks!.Count(t => t.TaskTypeId == PowerShellTask), "nginx is reloaded after renewal");
            Assert.AreEqual("nginx", Finding(plan, "install-0").Title);
            StringAssert.Contains(Finding(plan, "install-0").Description, "nginx -s reload");
        }

        [TestMethod]
        public async Task CertbotUnknownInstallerIsBlocked()
        {
            var (_, plan) = await PreviewLineage("authenticator = standalone\ninstaller = haproxy");

            AssertBlocker(plan, "install-0", "haproxy");
        }

        [TestMethod]
        public async Task CertbotManualDnsHooksRunThroughTheScriptProvider()
        {
            var (_, plan) = await PreviewLineage("""
                authenticator = manual
                pref_challs = dns-01,
                manual_auth_hook = /etc/letsencrypt/auth.sh
                manual_cleanup_hook = /etc/letsencrypt/cleanup.sh
                """);

            AssertImportsWithoutSecrets(plan);
            var challenge = plan.ProposedItem!.RequestConfig.Challenges.Single();
            Assert.AreEqual(ScriptProvider, challenge.ChallengeProvider);

            // the hook wrappers are written at import, so the preview refers to them without writing anything
            foreach (var parameter in new[] { "createscriptpath", "deletescriptpath" })
            {
                var draft = plan.Credentials.Single(c => c.Key == Parameter(challenge, parameter));
                Assert.IsTrue(draft.IsInlineValue);
            }

            Assert.IsFalse(plan.Secrets.Any(), "Generated wrappers are not secrets the preview asks about");
            AssertAssumption(plan, "CERTBOT_DOMAIN");
        }

        [TestMethod]
        public async Task CertbotManualDnsWithoutHooksNeedsSomeoneToCreateTheRecord()
        {
            var (_, plan) = await PreviewLineage("authenticator = manual\npref_challs = dns-01");

            Assert.AreEqual(ManualProvider, plan.ProposedItem!.RequestConfig.Challenges.Single().ChallengeProvider);
            AssertAssumption(plan, "cannot renew unattended");
        }

        [TestMethod]
        public async Task CertbotManualHttpHookIsBlocked()
        {
            var (_, plan) = await PreviewLineage("authenticator = manual\nmanual_auth_hook = /etc/letsencrypt/upload.sh");

            AssertBlocker(plan, "validation-0", "not supported here");
        }

        // request settings

        [TestMethod]
        [DataRow("key_type = rsa\nrsa_key_size = 4096", StandardKeyTypes.RSA256_4096, false, DisplayName = "RSA 4096")]
        [DataRow("rsa_key_size = 3072", StandardKeyTypes.RSA256_3072, false, DisplayName = "RSA before certbot 2.0, which did not record the key type")]
        [DataRow("key_type = ecdsa\nelliptic_curve = secp384r1", StandardKeyTypes.ECDSA384, false, DisplayName = "EC P-384")]
        [DataRow("", StandardKeyTypes.ECDSA256, false, DisplayName = "No key settings, so from the certificate")]
        [DataRow("key_type = rsa\nrsa_key_size = 8192", StandardKeyTypes.RSA256_4096, true, DisplayName = "An RSA size not supported here")]
        public async Task CertbotKeyTypeMigrates(string settings, string expected, bool isChanged)
        {
            var (_, plan) = await PreviewLineage($"authenticator = standalone\n{settings}");

            Assert.AreEqual(expected, plan.ProposedItem!.RequestConfig.CSRKeyAlg);
            Assert.AreEqual(isChanged ? ExternalMigrationFindingLevel.Assumption : ExternalMigrationFindingLevel.Mapped, Finding(plan, "key").Level);
        }

        [TestMethod]
        public async Task CertbotRequestSettingsMigrate()
        {
            var (_, plan) = await PreviewLineage("""
                authenticator = standalone
                reuse_key = True
                must_staple = True
                preferred_chain = ISRG Root X1
                required_profile = shortlived
                allow_subset_of_names = True
                """);

            var config = plan.ProposedItem!.RequestConfig;
            Assert.IsTrue(config.ReusePrivateKey);
            Assert.IsTrue(config.RequireOcspMustStaple);
            Assert.AreEqual("ISRG Root X1", config.PreferredChain);
            Assert.AreEqual("shortlived", config.AcmeProfile);
            AssertAssumption(plan, "allow_subset_of_names");

            var defaults = await Preview(await GetManager<Certbot>(_root), inputs: new Dictionary<string, string>
            {
                ["reuse-key"] = ExternalMigrationChoices.Default,
                ["chain"] = ExternalMigrationChoices.Default,
                ["profile"] = ExternalMigrationChoices.Default
            });

            Assert.IsFalse(defaults.ProposedItem!.RequestConfig.ReusePrivateKey);
            Assert.IsNull(defaults.ProposedItem.RequestConfig.PreferredChain);
            Assert.IsNull(defaults.ProposedItem.RequestConfig.AcmeProfile);
        }

        [TestMethod]
        public async Task CertbotSettingsOffAreNotMigrated()
        {
            var (_, plan) = await PreviewLineage("authenticator = standalone\nreuse_key = False\nmust_staple = False\npreferred_chain = None");

            var config = plan.ProposedItem!.RequestConfig;
            Assert.IsFalse(config.ReusePrivateKey);
            Assert.IsFalse(config.RequireOcspMustStaple);
            Assert.IsNull(config.PreferredChain, "None is certbot's empty value");
        }

        [TestMethod]
        [DataRow("30 days", 30, DisplayName = "Days")]
        [DataRow("2 weeks", 14, DisplayName = "Weeks")]
        public async Task CertbotRenewBeforeExpiryIsOfferedAsTheRenewalInterval(string setting, int days)
        {
            var (manager, plan) = await PreviewLineage("authenticator = standalone", $"renew_before_expiry = {setting}");

            Assert.AreEqual(ExternalMigrationChoices.Default, Finding(plan, "renewal-days").AppliedInput, "This instance's interval is used unless chosen");
            Assert.IsNull(plan.ProposedItem!.CustomRenewalTarget);

            var kept = await Preview(manager, inputs: new Dictionary<string, string> { ["renewal-days"] = ExternalMigrationChoices.Source });
            Assert.AreEqual((float?)days, kept.ProposedItem!.CustomRenewalTarget);
            Assert.AreEqual("DaysBeforeExpiry", kept.ProposedItem.CustomRenewalIntervalMode);
        }

        [TestMethod]
        public async Task CertbotRenewBeforeExpiryNotInDaysIsReported()
        {
            var (_, plan) = await PreviewLineage("authenticator = standalone", "renew_before_expiry = 1 month");

            AssertAssumption(plan, "renew_before_expiry = 1 month is not in days");
            Assert.AreEqual(ExternalMigrationFindingLevel.Mapped, Finding(plan, "renewal-days").Level);
            Assert.IsNull(Finding(plan, "renewal-days").InputType, "There is no source interval to choose");
        }

        // hooks and settings

        [TestMethod]
        public async Task CertbotHooksAndRenewalHookFoldersMigrate()
        {
            foreach (var stage in new[] { "deploy", "post", "pre" })
            {
                Directory.CreateDirectory(Path.Combine(_root, "renewal-hooks", stage));
            }

            File.WriteAllText(Path.Combine(_root, "renewal-hooks", "deploy", "01-reload.sh"), "#!/bin/sh\n");
            File.WriteAllText(Path.Combine(_root, "renewal-hooks", "deploy", "README"), "certbot's own readme\n");
            File.WriteAllText(Path.Combine(_root, "renewal-hooks", "deploy", ".hidden"), "");
            File.WriteAllText(Path.Combine(_root, "renewal-hooks", "pre", "stop.sh"), "#!/bin/sh\n");

            var (_, plan) = await PreviewLineage("""
                authenticator = standalone
                renew_hook = /usr/local/bin/renewed.sh
                pre_hook = systemctl stop nginx
                post_hook = systemctl start nginx
                """);

            AssertImportsWithoutSecrets(plan);
            Assert.AreEqual(3, plan.ProposedItem!.PostRequestTasks!.Count(t => t.TaskTypeId == PowerShellTask), "The renew hook, post hook and deploy folder script run after renewal");
            StringAssert.Contains(Finding(plan, "install-0").Description, "RENEWED_LINEAGE", "The deploy and renew hooks are given the variables certbot gives them");
            Assert.IsFalse(Finding(plan, "install-1").Description.Contains("RENEWED_LINEAGE"), "The post hook is not");
            StringAssert.Contains(Finding(plan, "install-2").Description, "01-reload.sh");

            AssertAssumption(plan, "The pre hook \"systemctl stop nginx\"");
            AssertAssumption(plan, "stop.sh runs before");
            Assert.IsFalse(plan.Findings.Any(f => f.Description.Contains("README")));
        }

        [TestMethod]
        public async Task CertbotCliIniSettingsAreCalledOut()
        {
            File.WriteAllText(Path.Combine(_root, "cli.ini"), "# defaults\nemail = admin@example.com\nkey-type = rsa\n");

            var (_, plan) = await PreviewLineage("authenticator = standalone");

            var settings = Finding(plan, "settings");
            Assert.AreEqual(ExternalMigrationFindingLevel.Assumption, settings.Level);
            StringAssert.Contains(settings.Description, "email, key-type");
        }

        // account and certificate

        [TestMethod]
        public async Task CertbotAccountWhichCannotBeReadNeedsAnAccountHere()
        {
            var (manager, withoutAccount) = await PreviewLineage("authenticator = standalone", context: Context(withAccount: false));

            AssertBlocker(withoutAccount, "account");
            Assert.IsNull(await manager.GetAccount(await ItemId(manager)));

            var withAccount = await Preview(manager);
            Assert.IsTrue(withAccount.CanImport, "The account here is used instead");
            StringAssert.Contains(Finding(withAccount, "account").Title, "Existing ACME account");

            WriteAccount();
            var imported = await Preview(manager, Context(withAccount: false));
            Assert.IsTrue(imported.CanImport);
            StringAssert.Contains(Finding(imported, "account").Description, "acme/acct/9");
        }

        [TestMethod]
        public async Task CertbotLineageWithoutLiveFilesTakesItsNamesFromTheWebrootMap()
        {
            WriteCertbotLineage($"""
                authenticator = webroot
                [[webroot_map]]
                example.com = {Path.Combine(_root, "www")}
                www.example.com = {Path.Combine(_root, "www")}
                """, writeLiveFiles: false);

            var manager = await GetManager<Certbot>(_root);
            var itemId = await ItemId(manager);
            var plan = await Preview(manager);

            CollectionAssert.AreEquivalent(new[] { "example.com", "www.example.com" }, plan.ProposedItem!.GetCertificateIdentifiers().Select(i => i.Value).ToArray());
            Assert.IsFalse(plan.CanAdoptCurrentCertificate);
            AssertAssumption(plan, "was not found");
            Assert.IsNull(await manager.GetCurrentCertificate(itemId));
        }

        [TestMethod]
        public async Task CertbotLiveCertificateWithAnotherKeyIsNotAdopted()
        {
            WriteCertbotLineage("authenticator = standalone");

            using var other = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            File.WriteAllText(Path.Combine(Live, "privkey.pem"), other.ExportPkcs8PrivateKeyPem());

            var manager = await GetManager<Certbot>(_root);
            var plan = await Preview(manager);

            Assert.IsFalse(plan.CanAdoptCurrentCertificate);
            AssertAssumption(plan, "could not be read");
        }

        // disable, restore and remove

        [TestMethod]
        public async Task CertbotLineageIsDisabledRestoredAndRemoved()
        {
            var conf = WriteCertbotLineage("authenticator = standalone\nautorenew = True");

            var manager = await GetManager<Certbot>(_root);
            var itemId = await ItemId(manager);

            Assert.IsNotNull((await manager.PlanSourceRemoval(itemId)).BlockedReason, "A lineage certbot still renews is not removed");
            Assert.IsFalse((await manager.RemoveSourceItem(itemId, new SourceRemovalManifest { SourceItemId = itemId })).IsSuccess);

            Assert.IsTrue((await manager.DisableSourceItem(itemId)).IsSuccess);
            StringAssert.Contains(File.ReadAllText(conf), "autorenew = False");
            var listed = (await manager.GetManagedCertificates()).Single();
            Assert.IsFalse(listed.IncludeInAutoRenew, "The lineage stays listed, no longer renewed by certbot");
            StringAssert.Contains(listed.Comments, "handed over");

            var again = await manager.DisableSourceItem(itemId);
            Assert.IsTrue(again.IsSuccess);
            StringAssert.Contains(again.Message, "already off");

            Assert.IsTrue((await manager.RestoreSourceItem(itemId)).IsSuccess);
            StringAssert.Contains(File.ReadAllText(conf), "autorenew = True", "The previous setting is put back");
            Assert.IsFalse(File.ReadAllText(conf).Contains("certify-migrated"));

            Assert.IsTrue((await manager.DisableSourceItem(itemId)).IsSuccess);
            var manifest = await manager.PlanSourceRemoval(itemId);
            Assert.IsNull(manifest.BlockedReason);
            CollectionAssert.AreEquivalent(new[] { conf, Path.Combine(Archive, "cert1.pem"), Path.Combine(Archive, "privkey1.pem") }, manifest.FilesToDelete);

            Assert.IsTrue((await manager.RemoveSourceItem(itemId, manifest)).IsSuccess);
            Assert.IsFalse(manifest.FilesToDelete.Any(File.Exists));
            Assert.IsTrue(File.Exists(Path.Combine(Live, "cert.pem")), "The live files services read are kept");

            Assert.IsFalse((await manager.DisableSourceItem(itemId)).IsSuccess, "A removed lineage is no longer found");
        }

        [TestMethod]
        [DataRow("\n", "autorenew = True", DisplayName = "autorenew set")]
        [DataRow("\n", "", DisplayName = "autorenew not set")]
        [DataRow("\r\n", "autorenew = yes", DisplayName = "Windows line endings")]
        public async Task CertbotAutoRenewIsPutBackAsItWas(string newline, string setting)
        {
            WriteCertbotLineage($"authenticator = standalone\n{setting}");
            File.WriteAllText(Conf, File.ReadAllText(Conf).Replace("\r\n", "\n").Replace("\n", newline));
            var original = File.ReadAllText(Conf);

            var manager = await GetManager<Certbot>(_root);
            var itemId = await ItemId(manager);

            Assert.IsTrue((await manager.DisableSourceItem(itemId)).IsSuccess);
            var disabled = File.ReadAllText(Conf);
            Assert.IsFalse((await manager.GetManagedCertificates()).Single().IncludeInAutoRenew);
            Assert.AreEqual(newline == "\r\n", disabled.Contains("\r\n"), "The file keeps its line endings");

            Assert.IsTrue((await manager.RestoreSourceItem(itemId)).IsSuccess);
            Assert.AreEqual(original, File.ReadAllText(Conf));
            Assert.IsTrue((await manager.GetManagedCertificates()).Single().IncludeInAutoRenew);
        }

        [TestMethod]
        public async Task CertbotLineageWithoutRenewalParamsIsDisabledAndRestored()
        {
            WriteCertbotLineage("authenticator = standalone");
            File.WriteAllText(Conf, $"version = 2.11.0\narchive_dir = {Archive}\ncert = {Path.Combine(Live, "cert.pem")}\nprivkey = {Path.Combine(Live, "privkey.pem")}\n");

            var manager = await GetManager<Certbot>(_root);
            var itemId = await ItemId(manager);

            Assert.IsTrue((await manager.DisableSourceItem(itemId)).IsSuccess);
            Assert.IsFalse((await manager.GetManagedCertificates()).Single().IncludeInAutoRenew);
            StringAssert.Contains(File.ReadAllText(Conf), "[renewalparams]");

            Assert.IsTrue((await manager.RestoreSourceItem(itemId)).IsSuccess);
            Assert.IsTrue((await manager.GetManagedCertificates()).Single().IncludeInAutoRenew);
            Assert.IsFalse(File.ReadAllText(Conf).Contains("autorenew"), "autorenew is unset again");
        }

        [TestMethod]
        public async Task CertbotRenewalTurnedOffBeforeMigrationIsLeftOff()
        {
            var conf = WriteCertbotLineage("authenticator = standalone\nautorenew = False");
            var original = File.ReadAllText(conf);

            var manager = await GetManager<Certbot>(_root);
            var itemId = await ItemId(manager);

            var disable = await manager.DisableSourceItem(itemId);
            Assert.IsTrue(disable.IsSuccess);
            StringAssert.Contains(disable.Message, "already off");

            var restore = await manager.RestoreSourceItem(itemId);
            Assert.IsTrue(restore.IsSuccess);
            StringAssert.Contains(restore.Message, "before the migration");
            Assert.AreEqual(original, File.ReadAllText(conf), "The lineage is not changed");
        }

        [TestMethod]
        public async Task CertbotRemovalKeepsTheArchiveFilesTheLiveLinksPointTo()
        {
            var (cert, key, chain, _) = CreateCertificate();
            WriteCertbotLineage("authenticator = standalone\nautorenew = True", writeLiveFiles: false);

            foreach (var (name, content) in new[] { ("cert", cert), ("privkey", key), ("chain", chain), ("fullchain", cert + chain) })
            {
                File.WriteAllText(Path.Combine(Archive, $"{name}2.pem"), content);
                CreateSymbolicLink(Path.Combine(Live, $"{name}.pem"), Path.Combine("..", "..", "archive", "example.com", $"{name}2.pem"));
            }

            var manager = await GetManager<Certbot>(_root);
            var itemId = await ItemId(manager);

            var plan = await Preview(manager);
            AssertAssumption(plan, "archive folder, and are written through those links");
            Assert.IsTrue(plan.CanAdoptCurrentCertificate, "The certificate is read through the links");

            Assert.IsTrue((await manager.DisableSourceItem(itemId)).IsSuccess);
            var manifest = await manager.PlanSourceRemoval(itemId);

            CollectionAssert.AreEquivalent(new[] { Conf, Path.Combine(Archive, "cert1.pem"), Path.Combine(Archive, "privkey1.pem") }, manifest.FilesToDelete,
                "Superseded archive files are removed, and the ones the live links point to are kept");

            Assert.IsTrue((await manager.RemoveSourceItem(itemId, manifest)).IsSuccess);
            Assert.IsTrue(File.Exists(Path.Combine(Live, "cert.pem")) && File.ReadAllText(Path.Combine(Live, "cert.pem")) == cert, "The live links still resolve");
        }

        [TestMethod]
        public async Task CertbotRemovalChangedSincePreviewIsRefused()
        {
            WriteCertbotLineage("authenticator = standalone");

            var manager = await GetManager<Certbot>(_root);
            var itemId = await ItemId(manager);

            Assert.IsTrue((await manager.DisableSourceItem(itemId)).IsSuccess);
            var manifest = await manager.PlanSourceRemoval(itemId);

            File.WriteAllText(Path.Combine(Archive, "cert2.pem"), "issued since");

            var result = await manager.RemoveSourceItem(itemId, manifest);
            Assert.IsFalse(result.IsSuccess);
            StringAssert.Contains(result.Message, "changed since");
            Assert.IsTrue(File.Exists(Conf), "Nothing is deleted");
        }
    }
}
