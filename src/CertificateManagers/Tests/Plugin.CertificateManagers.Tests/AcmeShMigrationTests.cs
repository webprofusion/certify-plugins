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
using Certify.Plugin.CertificateManagers.Providers.AcmeSh;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests.Plugin.CertificateManagers
{
    /// <summary>
    /// Migration of acme.sh certificates: what the preview proposes for each validation method, saved DNS API setting,
    /// installation and hook, the account and certificate, and how the domain is removed from acme.sh, put back and deleted
    /// </summary>
    [TestClass]
    public class AcmeShMigrationTests : ExternalToolMigrationTestBase
    {
        private const string LetsEncrypt = "https://acme-v02.api.letsencrypt.org/directory";

        private string AccountConf => Path.Combine(_root, "account.conf");

        /// <param name="values">conf variables after Le_Domain, Le_Alt and Le_API</param>
        /// <param name="api">Le_API, or null to leave it out</param>
        private string WriteAcmeShDomain(string folderName, string values, string? api = LetsEncrypt)
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
                {(api == null ? "" : $"Le_API='{api}'")}
                {values}
                """);

            return conf;
        }

        private async Task<(AcmeSh Manager, ExternalMigrationPlan Plan)> PreviewDomain(string values, ExternalMigrationContext? context = null, IDictionary<string, string>? inputs = null)
        {
            WriteAcmeShDomain("example.com", values);
            var manager = await GetManager<AcmeSh>(_root);
            return (manager, await Preview(manager, context, inputs));
        }

        private string WriteCaAccount(string host, string path, string keyPem, string caConf)
        {
            var folder = Path.Combine(_root, "ca", host, path);
            Directory.CreateDirectory(folder);
            File.WriteAllText(Path.Combine(folder, "account.key"), keyPem);
            File.WriteAllText(Path.Combine(folder, "ca.conf"), caConf);
            return folder;
        }

        // validation

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

            File.WriteAllText(AccountConf, $"ACCOUNT_EMAIL='admin@example.com'\nSAVED_CF_Token='{Token}'\nSAVED_CF_Zone_ID='zone-1'\n");

            using var accountKey = RSA.Create(2048);
            WriteCaAccount("acme-v02.api.letsencrypt.org", "directory", accountKey.ExportRSAPrivateKeyPem(), "ACCOUNT_URL='https://acme-v02.api.letsencrypt.org/acme/acct/7'\n");

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
            StringAssert.Contains(draft.Title, AccountConf, "A setting saved in account.conf, which other certificates use, is named as the credential's origin");
            Assert.AreEqual("zone-1", await ResolveInlineParameter(manager, plan, challenge, "zoneid"), "The saved zone is read at import too");

            Assert.AreEqual(3, item.PostRequestTasks!.Count(t => t.TaskTypeId == ExportTask), "The installed files are written where acme.sh installed them");
            Assert.AreEqual(1, item.PostRequestTasks!.Count(t => t.TaskTypeId == PowerShellTask), "The reload command runs after renewal");
            StringAssert.Contains(JsonSerializer.Serialize(plan.Findings), reload, "The base64 encoded command is decoded");
            AssertAssumption(plan, "Paths acme.sh did not install the certificate to");

            var account = await manager.GetAccount(itemId);
            Assert.AreEqual("https://acme-v02.api.letsencrypt.org/acme/acct/7", account!.AccountUri);
            Assert.AreEqual("admin@example.com", account.EmailAddress);
            AssertSameKey(accountKey.ExportSubjectPublicKeyInfo(), account.AccountKeyPem);

            Assert.IsNotNull(await manager.GetCurrentCertificate(itemId));
        }

        [TestMethod]
        public async Task AcmeShSettingSavedForTheDomainIsUsedBeforeAccountConf()
        {
            File.WriteAllText(AccountConf, $"SAVED_CF_Token='{Token}'\n");

            var (manager, plan) = await PreviewDomain("Le_Webroot='dns_cf'\nSAVED_CF_Token='domain-token'");

            AssertImportsWithoutSecrets(plan, Token, "domain-token");
            var challenge = plan.ProposedItem!.RequestConfig.Challenges.Single();
            Assert.AreEqual("domain-token", (await ResolveChallengeCredential(manager, plan, challenge))["apitoken"]);
            StringAssert.Contains(plan.Credentials.Single(c => c.Key == challenge.ChallengeCredentialKey).Title, "renewal example.com", "A setting of this certificate alone is named after it");
        }

        [TestMethod]
        public async Task AcmeShExportedAndDoubleQuotedSettingsAreRead()
        {
            File.WriteAllText(AccountConf, $"# saved by acme.sh\nexport CF_Token=\"{Token}\"\n\n");

            var (manager, plan) = await PreviewDomain("Le_Webroot='dns_cf'");

            AssertImportsWithoutSecrets(plan, Token);
            Assert.AreEqual(Token, (await ResolveChallengeCredential(manager, plan, plan.ProposedItem!.RequestConfig.Challenges.Single()))["apitoken"]);
        }

        [TestMethod]
        public async Task AcmeShMethodPerIdentifierValidatesEachItsOwnWay()
        {
            File.WriteAllText(AccountConf, $"SAVED_CF_Token='{Token}'\n");
            var www = Path.Combine(_root, "www");

            var (_, plan) = await PreviewDomain($"Le_Webroot='{www},dns_cf'");

            AssertImportsWithoutSecrets(plan, Token);
            var challenges = plan.ProposedItem!.RequestConfig.Challenges;
            Assert.AreEqual(2, challenges.Count);

            var http = challenges.Single(c => c.DomainMatch == "example.com");
            Assert.AreEqual(SupportedChallengeTypes.CHALLENGE_TYPE_HTTP, http.ChallengeType);
            Assert.AreEqual(www, http.ChallengeRootPath);

            Assert.AreEqual(CloudflareProvider, challenges.Single(c => c.DomainMatch == "www.example.com").ChallengeProvider);
        }

        [TestMethod]
        [DataRow("Le_ChallengeAlias='alias.example.net,'", true, DisplayName = "Challenge alias")]
        [DataRow("Le_DomainAlias='no,alias.example.net'", true, DisplayName = "Domain alias for the second name")]
        [DataRow("Le_ChallengeAlias='no,no'", false, DisplayName = "No alias")]
        public async Task AcmeShDnsAliasModeIsBlocked(string alias, bool isBlocked)
        {
            File.WriteAllText(AccountConf, $"SAVED_CF_Token='{Token}'\n");

            var (_, plan) = await PreviewDomain($"Le_Webroot='dns_cf'\n{alias}");

            Assert.AreEqual(isBlocked, plan.HasBlockers);
            Assert.AreEqual(isBlocked, plan.Findings.Any(f => f.Description.Contains("DNS alias mode")));
        }

        [TestMethod]
        public async Task AcmeShNsupdateTsigKeyMigratesToRfc2136()
        {
            var keyFile = Path.Combine(_root, "acme.key");
            File.WriteAllText(keyFile, """
                key "acme-key." {
                    algorithm HMAC-SHA256;
                    secret "c2VjcmV0LXZhbHVl";
                };
                """);

            File.WriteAllText(AccountConf, $"SAVED_NSUPDATE_SERVER='ns1.example.com'\nSAVED_NSUPDATE_SERVER_PORT='5353'\nSAVED_NSUPDATE_ZONE='example.com'\nSAVED_NSUPDATE_KEY='{keyFile}'\n");

            var (manager, plan) = await PreviewDomain("Le_Webroot='dns_nsupdate'");

            AssertImportsWithoutSecrets(plan, "c2VjcmV0LXZhbHVl");
            var challenge = plan.ProposedItem!.RequestConfig.Challenges.Single();
            Assert.AreEqual(Rfc2136Provider, challenge.ChallengeProvider);
            Assert.AreEqual("ns1.example.com", Parameter(challenge, "DDNSNameserver"));
            Assert.AreEqual("5353", Parameter(challenge, "DDNSPort"));
            Assert.AreEqual("example.com", Parameter(challenge, "DDNSZone"));
            Assert.AreEqual("acme-key.", Parameter(challenge, "DDNSKeyName"));
            Assert.AreEqual("hmac-sha256", Parameter(challenge, "DDNSKeyType"));
            Assert.AreEqual("c2VjcmV0LXZhbHVl", (await ResolveChallengeCredential(manager, plan, challenge))["DDNSKeyValueInsecure"], "The secret is read from the key file at import");
            AssertAssumption(plan, "nsupdate");
        }

        [TestMethod]
        public async Task AcmeShNsupdateKeyFileWhichIsNotATsigKeyAsksForACredential()
        {
            var keyFile = Path.Combine(_root, "acme.key");
            File.WriteAllText(keyFile, "not a key file");
            File.WriteAllText(AccountConf, $"SAVED_NSUPDATE_SERVER='ns1.example.com'\nSAVED_NSUPDATE_KEY='{keyFile}'\n");

            var (_, plan) = await PreviewDomain("Le_Webroot='dns_nsupdate'");

            AssertBlocker(plan, "validation-0-credential", "not a TSIG key file");
        }

        [TestMethod]
        public async Task AcmeShAcmeDnsRegistrationOfEachDomainMigrates()
        {
            File.WriteAllText(AccountConf, "SAVED_ACMEDNS_BASE_URL='https://auth.acme-dns.io'\nSAVED_ACMEDNS_USERNAME='user-1 user-2'\nSAVED_ACMEDNS_PASSWORD='pass-1 pass-2'\nSAVED_ACMEDNS_SUBDOMAIN='sub-1 sub-2'\n");

            var (manager, plan) = await PreviewDomain("Le_Webroot='dns_acmedns'");

            AssertImportsWithoutSecrets(plan, "pass-1", "pass-2");
            var challenges = plan.ProposedItem!.RequestConfig.Challenges;
            Assert.AreEqual(2, challenges.Count);
            Assert.IsTrue(challenges.All(c => c.ChallengeProvider == AcmeDnsProvider && Parameter(c, "api") == "https://auth.acme-dns.io"));

            using var www = JsonDocument.Parse(await ResolveInlineParameter(manager, plan, challenges.Single(c => c.DomainMatch == "www.example.com"), "credentials_json"));
            Assert.AreEqual("user-2", www.RootElement.GetProperty("username").GetString(), "Each domain's registration is at its position in the saved lists");
            Assert.AreEqual("pass-2", www.RootElement.GetProperty("password").GetString());
            Assert.AreEqual("sub-2.auth.acme-dns.io", www.RootElement.GetProperty("fulldomain").GetString());
        }

        [TestMethod]
        public async Task AcmeShAcmeDnsWithoutASavedRegistrationIsBlocked()
        {
            File.WriteAllText(AccountConf, "SAVED_ACMEDNS_BASE_URL='https://auth.acme-dns.io'\n");

            var (_, plan) = await PreviewDomain("Le_Webroot='dns_acmedns'");

            Assert.IsTrue(plan.HasBlockers);
            AssertBlocker(plan, "validation-0-secret", "registration is not saved");
        }

        [TestMethod]
        public async Task AcmeShRoute53WithoutSavedKeysUsesTheMachineRole()
        {
            var (manager, plan) = await PreviewDomain("Le_Webroot='dns_aws'");

            AssertBlocker(plan, "validation-0-credential", "IAM role");

            File.WriteAllText(AccountConf, "SAVED_AWS_ACCESS_KEY_ID='AKIA123'\nSAVED_AWS_SECRET_ACCESS_KEY='aws-secret'\n");
            var withKeys = await Preview(manager);

            AssertImportsWithoutSecrets(withKeys, "AKIA123", "aws-secret");
            var values = await ResolveChallengeCredential(manager, withKeys, withKeys.ProposedItem!.RequestConfig.Challenges.Single());
            Assert.AreEqual("AKIA123", values["accesskey"]);
            Assert.AreEqual("aws-secret", values["secretaccesskey"]);
        }

        [TestMethod]
        public async Task AcmeShTransIpKeyFileIsReadAtImport()
        {
            var keyFile = Path.Combine(_root, "transip.key");
            File.WriteAllText(keyFile, "-----BEGIN PRIVATE KEY-----\ntransip-key\n-----END PRIVATE KEY-----\n");
            File.WriteAllText(AccountConf, $"SAVED_TRANSIP_Username='transip-user'\nSAVED_TRANSIP_Key_File='{keyFile}'\n");

            var (manager, plan) = await PreviewDomain("Le_Webroot='dns_transip'");

            AssertImportsWithoutSecrets(plan, "transip-key");
            var values = await ResolveChallengeCredential(manager, plan, plan.ProposedItem!.RequestConfig.Challenges.Single());
            Assert.AreEqual("transip-user", values["login"]);
            Assert.AreEqual(File.ReadAllText(keyFile), values["privatekey"], "The key is the content of the file");
        }

        [TestMethod]
        public async Task AcmeShAzureClientSecretMigratesAndManagedIdentityDoesNot()
        {
            File.WriteAllText(AccountConf, "SAVED_AZUREDNS_SUBSCRIPTIONID='sub'\nSAVED_AZUREDNS_TENANTID='tenant'\nSAVED_AZUREDNS_APPID='app'\nSAVED_AZUREDNS_CLIENTSECRET='azure-secret'\n");

            var (manager, plan) = await PreviewDomain("Le_Webroot='dns_azure'");

            AssertImportsWithoutSecrets(plan, "azure-secret");
            var values = await ResolveChallengeCredential(manager, plan, plan.ProposedItem!.RequestConfig.Challenges.Single());
            Assert.AreEqual("azure-secret", values["secret"]);
            Assert.AreEqual("app", values["clientid"]);
            AssertAssumption(plan, "resource group");

            File.AppendAllText(AccountConf, "SAVED_AZUREDNS_MANAGEDIDENTITY='true'\n");
            AssertBlocker(await Preview(manager), "validation-0-credential", "managed identity");
        }

        [TestMethod]
        [DataRow("no", SupportedChallengeTypes.CHALLENGE_TYPE_HTTP, null, DisplayName = "Standalone")]
        [DataRow("apache", SupportedChallengeTypes.CHALLENGE_TYPE_HTTP, "/.well-known/acme-challenge/", DisplayName = "Apache")]
        [DataRow("dns", SupportedChallengeTypes.CHALLENGE_TYPE_DNS, "cannot renew unattended", DisplayName = "Manual DNS")]
        public async Task AcmeShValidationMethodsMigrate(string method, string challengeType, string? assumption)
        {
            var (_, plan) = await PreviewDomain($"Le_Webroot='{method}'");

            Assert.IsFalse(plan.HasBlockers, string.Join("; ", plan.Findings.Where(f => f.IsUnresolved).Select(f => f.Description)));
            Assert.AreEqual(challengeType, plan.ProposedItem!.RequestConfig.Challenges.Single().ChallengeType);

            if (assumption != null)
            {
                AssertAssumption(plan, assumption);
            }
        }

        [TestMethod]
        public async Task AcmeShStandalonePortIsCalledOut()
        {
            var (_, plan) = await PreviewDomain("Le_Webroot='no'\nLe_HTTPPort='8080'");

            AssertAssumption(plan, "listens on port 8080");
        }

        [TestMethod]
        [DataRow("alpn", "tls-alpn-01", DisplayName = "tls-alpn-01")]
        [DataRow("stateless", "Stateless mode", DisplayName = "Stateless")]
        [DataRow("dns_someprovider", "There is no DNS provider for dns_someprovider", DisplayName = "A DNS API not in the catalogue")]
        [DataRow("", "none is not recognised", DisplayName = "No method")]
        public async Task AcmeShValidationMethodsWithoutAnEquivalentAreBlocked(string method, string expected)
        {
            var (_, plan) = await PreviewDomain(method.Length == 0 ? "" : $"Le_Webroot='{method}'");

            AssertBlocker(plan, "validation-0", expected);
        }

        // request settings

        [TestMethod]
        [DataRow("example.com", "Le_Keylength='4096'", StandardKeyTypes.RSA256_4096, DisplayName = "RSA 4096")]
        [DataRow("example.com", "Le_Keylength='ec-384'", StandardKeyTypes.ECDSA384, DisplayName = "EC P-384")]
        [DataRow("example.com", "", StandardKeyTypes.RSA256, DisplayName = "acme.sh's RSA default")]
        [DataRow("example.com_ecc", "", StandardKeyTypes.ECDSA256, DisplayName = "An ECC folder's default")]
        public async Task AcmeShKeyTypeMigrates(string folder, string keyLength, string expected)
        {
            WriteAcmeShDomain(folder, $"Le_Webroot='no'\n{keyLength}");
            var plan = await Preview(await GetManager<AcmeSh>(_root));

            Assert.AreEqual(expected, plan.ProposedItem!.RequestConfig.CSRKeyAlg);
        }

        [TestMethod]
        public async Task AcmeShRequestSettingsMigrate()
        {
            var (manager, plan) = await PreviewDomain("""
                Le_Webroot='no'
                Le_OCSP_Staple='1'
                Le_Preferred_Chain='ISRG Root X1'
                Le_Certificate_Profile='shortlived'
                Le_Valid_To='+6d'
                Le_RenewalDays='30'
                """);

            var config = plan.ProposedItem!.RequestConfig;
            Assert.IsTrue(config.ReusePrivateKey, "acme.sh keeps the domain key by default");
            Assert.IsTrue(config.RequireOcspMustStaple);
            Assert.AreEqual("ISRG Root X1", config.PreferredChain);
            Assert.AreEqual("shortlived", config.AcmeProfile);
            Assert.AreEqual(6, config.PreferredExpiryDays);
            Assert.IsNull(plan.ProposedItem.CustomRenewalTarget, "This instance's renewal interval is used unless chosen");

            var kept = await Preview(manager, inputs: new Dictionary<string, string> { ["renewal-days"] = ExternalMigrationChoices.Source });
            Assert.AreEqual(30f, kept.ProposedItem!.CustomRenewalTarget);
            Assert.AreEqual("DaysAfterLastRenewal", kept.ProposedItem.CustomRenewalIntervalMode);
        }

        [TestMethod]
        public async Task AcmeShNewKeyEachRenewalAndValidityEndDateMigrate()
        {
            var (_, plan) = await PreviewDomain("Le_Webroot='no'\nLe_ForceNewDomainKey='1'\nLe_Valid_To='2027-01-01T00:00:00Z'");

            Assert.IsFalse(plan.ProposedItem!.RequestConfig.ReusePrivateKey);
            Assert.IsNull(plan.ProposedItem.RequestConfig.PreferredExpiryDays);
            AssertAssumption(plan, "The requested validity end 2027-01-01T00:00:00Z is not migrated");
        }

        // installation and hooks

        [TestMethod]
        public async Task AcmeShHooksMigrateAndDeployHooksAreCalledOut()
        {
            var (_, plan) = await PreviewDomain("""
                Le_Webroot='no'
                Le_RenewHook='/root/renewed.sh'
                Le_PostHook='systemctl start nginx'
                Le_PreHook='systemctl stop nginx'
                Le_DeployHook='haproxy,docker'
                """);

            AssertImportsWithoutSecrets(plan);
            Assert.AreEqual(2, plan.ProposedItem!.PostRequestTasks!.Count(t => t.TaskTypeId == PowerShellTask), "The renew and post hooks run after renewal");
            Assert.AreEqual(0, plan.ProposedItem.PostRequestTasks!.Count(t => t.TaskTypeId == ExportTask), "Nothing was installed");

            AssertAssumption(plan, "The pre hook \"systemctl stop nginx\"");
            AssertAssumption(plan, "deploy hook haproxy");
            AssertAssumption(plan, "deploy hook docker");
            AssertAssumption(plan, "not installed anywhere");
            AssertAssumption(plan, "own copies, which are no longer updated");
        }

        [TestMethod]
        public async Task AcmeShEveryInstalledFileIsWritten()
        {
            var installed = Path.Combine(_root, "installed");
            var (_, plan) = await PreviewDomain($"""
                Le_Webroot='no'
                Le_RealCertPath='{Path.Combine(installed, "cert.pem")}'
                Le_RealCACertPath='{Path.Combine(installed, "ca.pem")}'
                Le_RealKeyPath='{Path.Combine(installed, "key.pem")}'
                Le_RealFullChainPath='{Path.Combine(installed, "fullchain.pem")}'
                Le_ReloadCmd='systemctl reload nginx'
                """);

            var exports = plan.ProposedItem!.PostRequestTasks!.Where(t => t.TaskTypeId == ExportTask).ToList();
            CollectionAssert.AreEquivalent(new[] { "pemcrt", "pemintermediates", "pemkey", "pemcrtpartialchain" },
                exports.Select(t => t.Parameters.Single(p => p.Key == "type").Value).ToArray());
            Assert.AreEqual(Path.Combine(installed, "ca.pem"), exports.Single(t => t.Parameters.Any(p => p.Key == "type" && p.Value == "pemintermediates")).Parameters.Single(p => p.Key == "path").Value);
            Assert.IsFalse(plan.Findings.Any(f => f.Description.Contains("own copies")), "Every path the reload command is given is still written");
        }

        // account and certificate

        [TestMethod]
        public async Task AcmeShEcAccountKeyAndCaEmailAreRead()
        {
            File.WriteAllText(AccountConf, "ACCOUNT_EMAIL='account@example.com'\n");

            using var accountKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

            // acme.sh before 3.0 kept the account in ca/{host}
            var folder = Path.Combine(_root, "ca", "acme-v02.api.letsencrypt.org");
            Directory.CreateDirectory(folder);
            File.WriteAllText(Path.Combine(folder, "account.key"), accountKey.ExportECPrivateKeyPem());
            File.WriteAllText(Path.Combine(folder, "ca.conf"), "ACCOUNT_URL='https://acme-v02.api.letsencrypt.org/acme/acct/8'\nCA_EMAIL='ca@example.com'\n");

            var (manager, plan) = await PreviewDomain("Le_Webroot='no'", Context(withAccount: false));

            Assert.IsTrue(plan.CanImport);
            var account = await manager.GetAccount(await ItemId(manager));
            Assert.AreEqual("https://acme-v02.api.letsencrypt.org/acme/acct/8", account!.AccountUri);
            Assert.AreEqual("ca@example.com", account.EmailAddress, "The CA's own email is preferred");
            AssertSameEcKey(accountKey.ExportSubjectPublicKeyInfo(), account.AccountKeyPem);
        }

        [TestMethod]
        [DataRow("rsa-pkcs1", DisplayName = "RSA, PKCS#1 as acme.sh writes it")]
        [DataRow("rsa-pkcs8", DisplayName = "RSA, PKCS#8")]
        [DataRow("ec-sec1", DisplayName = "EC, SEC 1 as acme.sh writes it")]
        [DataRow("ec-pkcs8", DisplayName = "EC, PKCS#8")]
        public async Task AcmeShAccountKeyFormsAreReadAsPkcs8(string form)
        {
            using var rsa = RSA.Create(2048);
            using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP384);

            var pem = form switch
            {
                "rsa-pkcs1" => rsa.ExportRSAPrivateKeyPem(),
                "rsa-pkcs8" => rsa.ExportPkcs8PrivateKeyPem(),
                "ec-sec1" => ec.ExportECPrivateKeyPem(),
                _ => ec.ExportPkcs8PrivateKeyPem()
            };

            WriteCaAccount("acme-v02.api.letsencrypt.org", "directory", pem, "ACCOUNT_URL='https://acme-v02.api.letsencrypt.org/acme/acct/7'\n");
            WriteAcmeShDomain("example.com", "Le_Webroot='no'");

            var manager = await GetManager<AcmeSh>(_root);
            var account = await manager.GetAccount(await ItemId(manager));

            if (form.StartsWith("rsa"))
            {
                AssertSameKey(rsa.ExportSubjectPublicKeyInfo(), account!.AccountKeyPem);
            }
            else
            {
                AssertSameEcKey(ec.ExportSubjectPublicKeyInfo(), account!.AccountKeyPem);
            }
        }

        [TestMethod]
        public async Task AcmeShAccountWithoutItsUrlNeedsAnAccountHere()
        {
            using var accountKey = RSA.Create(2048);
            WriteCaAccount("acme-v02.api.letsencrypt.org", "directory", accountKey.ExportRSAPrivateKeyPem(), "CA_EMAIL='ca@example.com'\n");

            var (manager, plan) = await PreviewDomain("Le_Webroot='no'", Context(withAccount: false));

            AssertBlocker(plan, "account", "does not include the account URL");
            Assert.IsNull(await manager.GetAccount(await ItemId(manager)));
        }

        [TestMethod]
        public async Task AcmeShDefaultServerIsUsedWhenTheDomainDoesNotNameOne()
        {
            File.WriteAllText(AccountConf, "DEFAULT_ACME_SERVER='https://acme-staging-v02.api.letsencrypt.org/directory'\n");

            using var accountKey = RSA.Create(2048);
            WriteCaAccount("acme-staging-v02.api.letsencrypt.org", "directory", accountKey.ExportRSAPrivateKeyPem(), "ACCOUNT_URL='https://acme-staging-v02.api.letsencrypt.org/acme/acct/5'\n");
            WriteAcmeShDomain("example.com", "Le_Webroot='no'", api: null);

            var manager = await GetManager<AcmeSh>(_root);
            var plan = await Preview(manager);

            Assert.IsTrue(plan.CanImport, string.Join("; ", plan.Findings.Where(f => f.IsUnresolved).Select(f => f.Description)));
            Assert.AreEqual("letsencrypt.org", plan.ProposedItem!.CertificateAuthorityId);
            Assert.IsTrue(plan.ProposedItem.UseStagingMode);
            Assert.AreEqual("https://acme-staging-v02.api.letsencrypt.org/acme/acct/5", (await manager.GetAccount(await ItemId(manager)))!.AccountUri);
        }

        [TestMethod]
        public async Task AcmeShUnknownServerNeedsACertificateAuthorityHere()
        {
            WriteAcmeShDomain("example.com", "Le_Webroot='no'", api: "https://acme.example.net/directory");

            var plan = await Preview(await GetManager<AcmeSh>(_root));

            AssertBlocker(plan, "ca", "acme.example.net");
        }

        [TestMethod]
        public async Task AcmeShCertificateWithAnotherKeyIsNotAdopted()
        {
            var conf = WriteAcmeShDomain("example.com", "Le_Webroot='no'");
            using var other = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            File.WriteAllText(Path.Combine(Path.GetDirectoryName(conf)!, "example.com.key"), other.ExportPkcs8PrivateKeyPem());

            var plan = await Preview(await GetManager<AcmeSh>(_root));

            Assert.IsFalse(plan.CanAdoptCurrentCertificate);
            Assert.AreEqual(ExternalMigrationFindingLevel.Assumption, Finding(plan, "current-certificate").Level);
        }

        // disable, restore and remove

        [TestMethod]
        public async Task AcmeShDomainIsDisabledRestoredAndRemoved()
        {
            var conf = WriteAcmeShDomain("example.com", "Le_Webroot='no'");
            File.WriteAllText(AccountConf, "ACCOUNT_EMAIL='admin@example.com'\n");

            var manager = await GetManager<AcmeSh>(_root);
            var itemId = await ItemId(manager);

            Assert.IsNotNull((await manager.PlanSourceRemoval(itemId)).BlockedReason);

            Assert.IsTrue((await manager.DisableSourceItem(itemId)).IsSuccess);
            Assert.IsTrue(File.Exists(conf + ".removed"));
            Assert.IsFalse((await manager.GetManagedCertificates()).Any(), "A removed domain is no longer monitored");
            Assert.IsNull(await manager.PrepareMigrationPlan(itemId, Context(), null), "A removed domain is not offered for migration again");
            Assert.IsNotNull(await manager.GetCurrentCertificate(itemId), "The certificate can still be adopted after cut over");

            var again = await manager.DisableSourceItem(itemId);
            Assert.IsTrue(again.IsSuccess);
            StringAssert.Contains(again.Message, "already removed");

            Assert.IsTrue((await manager.RestoreSourceItem(itemId)).IsSuccess);
            Assert.IsTrue(File.Exists(conf));
            StringAssert.Contains((await manager.RestoreSourceItem(itemId)).Message, "already renewed");
            Assert.IsTrue((await manager.DisableSourceItem(itemId)).IsSuccess);

            var manifest = await manager.PlanSourceRemoval(itemId);
            Assert.IsNull(manifest.BlockedReason);
            Assert.AreEqual(5, manifest.FilesToDelete.Count);

            Assert.IsTrue((await manager.RemoveSourceItem(itemId, manifest)).IsSuccess);
            Assert.IsFalse(Directory.Exists(Path.GetDirectoryName(conf)));
            Assert.IsTrue(File.Exists(AccountConf), "The account and saved settings are kept");
        }

        [TestMethod]
        public async Task AcmeShDomainIssuedAgainAfterCutOverIsLeftAsItIs()
        {
            var conf = WriteAcmeShDomain("example.com", "Le_Webroot='no'");

            var manager = await GetManager<AcmeSh>(_root);
            var itemId = await ItemId(manager);
            Assert.IsTrue((await manager.DisableSourceItem(itemId)).IsSuccess);

            // acme.sh --issue run again for the domain after cut over
            var reissued = "Le_Domain='example.com'\nLe_Webroot='no'\n";
            File.WriteAllText(conf, reissued);

            var restore = await manager.RestoreSourceItem(itemId);
            Assert.IsTrue(restore.IsSuccess);
            StringAssert.Contains(restore.Message, "already renewed", "The conf acme.sh renews is the one found");

            var disable = await manager.DisableSourceItem(itemId);
            Assert.IsFalse(disable.IsSuccess, "The removed conf is not overwritten");
            StringAssert.Contains(disable.Message, "already exists");

            Assert.IsNotNull((await manager.PlanSourceRemoval(itemId)).BlockedReason);
            Assert.AreEqual(reissued, File.ReadAllText(conf));
            Assert.IsTrue(File.Exists(conf + ".removed"));
        }

        [TestMethod]
        public async Task AcmeShRemovalKeepsFilesInstalledIntoTheDomainFolder()
        {
            var folder = Path.Combine(_root, "example.com");
            var installed = Path.Combine(folder, "installed-cert.pem");
            WriteAcmeShDomain("example.com", $"Le_Webroot='no'\nLe_RealCertPath='{installed}'");
            File.WriteAllText(installed, "installed");

            var manager = await GetManager<AcmeSh>(_root);
            var itemId = await ItemId(manager);
            Assert.IsTrue((await manager.DisableSourceItem(itemId)).IsSuccess);

            var manifest = await manager.PlanSourceRemoval(itemId);
            Assert.IsFalse(manifest.FilesToDelete.Contains(installed));
            Assert.IsTrue(manifest.Kept.Any(k => k.Contains(installed)));

            Assert.IsTrue((await manager.RemoveSourceItem(itemId, manifest)).IsSuccess);
            Assert.IsTrue(File.Exists(installed), "The file the migrated item now writes is kept, and so its folder");
        }

        [TestMethod]
        public async Task AcmeShRemovalChangedSincePreviewIsRefused()
        {
            var conf = WriteAcmeShDomain("example.com", "Le_Webroot='no'");

            var manager = await GetManager<AcmeSh>(_root);
            var itemId = await ItemId(manager);
            Assert.IsTrue((await manager.DisableSourceItem(itemId)).IsSuccess);
            var manifest = await manager.PlanSourceRemoval(itemId);

            File.WriteAllText(Path.Combine(Path.GetDirectoryName(conf)!, "example.com.csr"), "new");

            var result = await manager.RemoveSourceItem(itemId, manifest);
            Assert.IsFalse(result.IsSuccess);
            StringAssert.Contains(result.Message, "changed since");
            Assert.IsTrue(File.Exists(conf + ".removed"));
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

            Assert.IsTrue((await manager.DisableSourceItem(eccOnly)).IsSuccess);
            Assert.AreEqual(ecc, (await manager.GetManagedCertificates()).Single().Id, "The ECC certificate keeps its id while the RSA one is removed from acme.sh");
        }
    }
}
