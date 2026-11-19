#nullable enable

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Threading.Tasks;
using Certify.Models;
using Certify.Models.Config;
using Certify.Models.Config.Migration;
using Certify.Providers.CertificateManagers;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests.Plugin.CertificateManagers
{
    /// <summary>
    /// What the certbot, acme.sh and Posh-ACME migration tests share: a scratch folder for the tool's files, the
    /// providers of an instance to migrate to, and certificates and keys as the tools write them
    /// </summary>
    public abstract class ExternalToolMigrationTestBase
    {
        protected const string CloudflareProvider = "DNS01.API.Cloudflare";
        protected const string PorkbunProvider = "DNS01.API.PoshACME.Porkbun";
        protected const string Rfc2136Provider = "DNS01.API.PoshACME.RFC2136";
        protected const string GoogleCloudProvider = "DNS01.API.PoshACME.GCloud";
        protected const string Route53Provider = "DNS01.API.Route53";
        protected const string AzureProvider = "DNS01.API.Azure";
        protected const string TransIpProvider = "DNS01.API.TransIP";
        protected const string AcmeDnsProvider = "DNS01.API.AcmeDns";
        protected const string ScriptProvider = "DNS01.Scripting";
        protected const string ManualProvider = "DNS01.Manual";
        protected const string Token = "cf-token-value-123";
        protected const string ExportTask = "Certify.Providers.DeploymentTasks.CertificateExport";
        protected const string PowerShellTask = "Certify.Providers.DeploymentTasks.Powershell";

        protected string _root = string.Empty;

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

        private static ProviderParameter Credential(string key) => new() { Key = key, Name = key, IsCredential = true };
        private static ProviderParameter Setting(string key) => new() { Key = key, Name = key, IsCredential = false };
        private static ProviderParameter PropagationDelay => Setting("propagationdelay");

        /// <param name="withAccount">false if the instance has no account for Let's Encrypt yet</param>
        protected static ExternalMigrationContext Context(bool withAccount = true, params StoredCredential[] credentials) => new()
        {
            Accounts = withAccount ? [new AccountDetails { StorageKey = "acc", CertificateAuthorityId = "letsencrypt.org", IsStagingAccount = false }] : [],
            ChallengeProviders =
            [
                new ChallengeProviderDefinition { Id = CloudflareProvider, Title = "Cloudflare DNS API", ProviderParameters = [Credential("apitoken"), Setting("zoneid"), PropagationDelay] },
                new ChallengeProviderDefinition
                {
                    Id = PorkbunProvider,
                    Title = "Porkbun DNS API (using Posh-ACME)",
                    Config = "Provider=Certify.Providers.DNS.PoshACME;Script=Porkbun",
                    ProviderParameters = [Credential("PorkbunAPIKey"), Credential("PorkbunSecretInsecure"), PropagationDelay]
                },
                new ChallengeProviderDefinition
                {
                    Id = Rfc2136Provider,
                    Title = "RFC2136 (using Posh-ACME)",
                    Config = "Provider=Certify.Providers.DNS.PoshACME;Script=RFC2136",
                    ProviderParameters = [Setting("DDNSNameserver"), Setting("DDNSPort"), Setting("DDNSKeyName"), Setting("DDNSKeyType"), Credential("DDNSKeyValueInsecure"), Setting("DDNSZone"), PropagationDelay]
                },
                new ChallengeProviderDefinition
                {
                    Id = GoogleCloudProvider,
                    Title = "Google Cloud DNS (using Posh-ACME)",
                    Config = "Provider=Certify.Providers.DNS.PoshACME;Script=GCloud",
                    ProviderParameters = [Setting("GCKeyFile"), Setting("GCProjectId"), PropagationDelay]
                },
                new ChallengeProviderDefinition { Id = Route53Provider, Title = "Amazon Route 53 DNS API", ProviderParameters = [Credential("accesskey"), Credential("secretaccesskey"), Setting("zoneid"), PropagationDelay] },
                new ChallengeProviderDefinition
                {
                    Id = AzureProvider,
                    Title = "Azure DNS API",
                    ProviderParameters = [Credential("tenantid"), Credential("clientid"), Credential("secret"), Credential("subscriptionid"), Setting("resourcegroupname"), PropagationDelay]
                },
                new ChallengeProviderDefinition { Id = TransIpProvider, Title = "TransIP DNS API", ProviderParameters = [Credential("login"), Credential("privatekey"), PropagationDelay] },
                new ChallengeProviderDefinition { Id = AcmeDnsProvider, Title = "acme-dns DNS API", ProviderParameters = [Setting("api"), Setting("credentials_json")] },
                new ChallengeProviderDefinition { Id = ScriptProvider, Title = "(Use Custom Script)", ProviderParameters = [Setting("createscriptpath"), Setting("deletescriptpath"), PropagationDelay, Setting("zoneid")] }
            ],
            DeploymentProviders =
            [
                new DeploymentProviderDefinition { Id = ExportTask, Title = "Export Certificate" },
                new DeploymentProviderDefinition { Id = PowerShellTask, Title = "Run Powershell Script" }
            ],
            Credentials = credentials.ToList()
        };

        protected static async Task<T> GetManager<T>(string root) where T : ICertificateManager, new()
        {
            var manager = new T();
            manager.Init(NullLogger.Instance, new CertificateManagerPreference { ConfigPath = root, LogPath = root });
            await manager.GetManagedCertificates();
            return manager;
        }

        protected static async Task<string> ItemId(ICertificateManager manager) => (await manager.GetManagedCertificates()).Single().Id!;

        /// <summary>
        /// The preview of the tool's only item
        /// </summary>
        protected static async Task<ExternalMigrationPlan> Preview(ICertificateManagerMigrationSource manager, ExternalMigrationContext? context = null, IDictionary<string, string>? inputs = null)
        {
            var plan = await manager.PrepareMigrationPlan(await ItemId((ICertificateManager)manager), context ?? Context(), inputs);
            Assert.IsNotNull(plan);
            return plan;
        }

        /// <summary>
        /// The values a challenge's credential resolves to at import
        /// </summary>
        protected static async Task<Dictionary<string, string>> ResolveChallengeCredential(ICertificateManagerMigrationSource manager, ExternalMigrationPlan plan, CertRequestChallengeConfig challenge) =>
            await manager.ResolveCredentialValues(await ItemId((ICertificateManager)manager), plan.Credentials.Single(c => c.Key == challenge.ChallengeCredentialKey));

        /// <summary>
        /// The value of a challenge parameter which is read from the source at import
        /// </summary>
        protected static async Task<string> ResolveInlineParameter(ICertificateManagerMigrationSource manager, ExternalMigrationPlan plan, CertRequestChallengeConfig challenge, string parameterKey)
        {
            var draftKey = challenge.Parameters!.Single(p => p.Key == parameterKey).Value;
            var draft = plan.Credentials.Single(c => c.Key == draftKey);
            Assert.IsTrue(draft.IsInlineValue);
            return (await manager.ResolveCredentialValues(await ItemId((ICertificateManager)manager), draft))[ExternalMigrationCredentialDraft.InlineValueKey];
        }

        protected static string? Parameter(CertRequestChallengeConfig challenge, string key) => challenge.Parameters?.SingleOrDefault(p => p.Key == key)?.Value;

        protected static ExternalMigrationFinding Finding(ExternalMigrationPlan plan, string key) =>
            plan.Findings.SingleOrDefault(f => f.Key == key) ?? throw new AssertFailedException($"No finding {key}. Findings: {string.Join(", ", plan.Findings.Select(f => f.Key))}");

        protected static void AssertBlocker(ExternalMigrationPlan plan, string key, string? containing = null)
        {
            var finding = Finding(plan, key);
            Assert.AreEqual(ExternalMigrationFindingLevel.Blocker, finding.Level, finding.Description);
            Assert.IsTrue(finding.IsUnresolved);
            Assert.IsFalse(plan.CanImport);

            if (containing != null)
            {
                StringAssert.Contains(finding.Description, containing);
            }
        }

        protected static void AssertAssumption(ExternalMigrationPlan plan, string containing) =>
            Assert.IsTrue(plan.Findings.Any(f => f.Level == ExternalMigrationFindingLevel.Assumption && f.Description.Contains(containing, StringComparison.Ordinal)),
                $"An assumption mentions \"{containing}\". Findings: {string.Join(" | ", plan.Findings.Select(f => $"{f.Level} {f.Key}: {f.Description}"))}");

        /// <summary>
        /// A certificate for name and www.name, its key, and an issuer to stand for the chain
        /// </summary>
        protected static (string Cert, string Key, string Chain, string Thumbprint) CreateCertificate(string name = "example.com", bool rsa = false)
        {
            using var ecKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            using var rsaKey = RSA.Create(2048);

            var request = rsa ? new CertificateRequest($"CN={name}", rsaKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1) : new CertificateRequest($"CN={name}", ecKey, HashAlgorithmName.SHA256);
            var san = new SubjectAlternativeNameBuilder();
            san.AddDnsName(name);
            san.AddDnsName($"www.{name}");
            request.CertificateExtensions.Add(san.Build());
            using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(60));

            using var issuerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            using var issuer = new CertificateRequest("CN=Test Intermediate", issuerKey, HashAlgorithmName.SHA256).CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(60));

            return (cert.ExportCertificatePem(), rsa ? rsaKey.ExportPkcs8PrivateKeyPem() : ecKey.ExportPkcs8PrivateKeyPem(), issuer.ExportCertificatePem(), cert.Thumbprint);
        }

        protected static string Base64Url(byte[] value) => Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

        protected static (string Jwk, byte[] PublicKey) CreateJwk()
        {
            using var rsa = RSA.Create(2048);
            var p = rsa.ExportParameters(true);
            var jwk = JsonSerializer.Serialize(new { kty = "RSA", n = Base64Url(p.Modulus!), e = Base64Url(p.Exponent!), d = Base64Url(p.D!), p = Base64Url(p.P!), q = Base64Url(p.Q!), dp = Base64Url(p.DP!), dq = Base64Url(p.DQ!), qi = Base64Url(p.InverseQ!) });
            return (jwk, rsa.ExportSubjectPublicKeyInfo());
        }

        protected static (string Jwk, byte[] PublicKey) CreateEcJwk()
        {
            using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var p = ec.ExportParameters(true);
            var jwk = JsonSerializer.Serialize(new { kty = "EC", crv = "P-256", x = Base64Url(p.Q.X!), y = Base64Url(p.Q.Y!), d = Base64Url(p.D!) });
            return (jwk, ec.ExportSubjectPublicKeyInfo());
        }

        protected static void AssertSameKey(byte[] publicKey, string pem)
        {
            StringAssert.StartsWith(pem, "-----BEGIN PRIVATE KEY-----");
            using var imported = RSA.Create();
            imported.ImportFromPem(pem);
            CollectionAssert.AreEqual(publicKey, imported.ExportSubjectPublicKeyInfo(), "The converted key is the same key");
        }

        protected static void AssertSameEcKey(byte[] publicKey, string pem)
        {
            StringAssert.StartsWith(pem, "-----BEGIN PRIVATE KEY-----");
            using var imported = ECDsa.Create();
            imported.ImportFromPem(pem);
            CollectionAssert.AreEqual(publicKey, imported.ExportSubjectPublicKeyInfo(), "The converted key is the same key");
        }

        protected static void AssertImportsWithoutSecrets(ExternalMigrationPlan? plan, params string[] secrets)
        {
            Assert.IsNotNull(plan);
            Assert.IsTrue(plan.CanImport, string.Join("; ", plan.Findings.Where(f => f.IsUnresolved).Select(f => f.Description)));
            AssertNoSecrets(plan, secrets);
        }

        protected static void AssertNoSecrets(ExternalMigrationPlan plan, params string[] secrets)
        {
            var json = JsonSerializer.Serialize(plan);
            foreach (var secret in secrets)
            {
                Assert.IsFalse(json.Contains(secret), "The preview refers to secrets without carrying their values");
            }
        }

        /// <summary>
        /// Creates a symbolic link, or skips the test where the account running it may not create one
        /// </summary>
        protected static void CreateSymbolicLink(string path, string target)
        {
            try
            {
                File.CreateSymbolicLink(path, target);
            }
            catch (Exception exp) when (exp is IOException or UnauthorizedAccessException)
            {
                Assert.Inconclusive($"Symbolic links cannot be created here: {exp.Message}");
            }
        }
    }
}
