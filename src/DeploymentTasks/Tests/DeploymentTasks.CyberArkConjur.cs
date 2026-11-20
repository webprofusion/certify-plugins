using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Certify.Config;
using Certify.Models;
using Certify.Models.Config;
using Certify.Providers.DeploymentTasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Certify.Tests.DeploymentTaskTests
{
    /// <summary>
    /// Runs the CyberArk Conjur task against a local stand-in for the Conjur REST API
    /// </summary>
    [TestClass]
    public class DeploymentTasksCyberArkConjur : IntegrationTestBase
    {
        private const string VariablePath = "certs/www-example-com";

        private FakeConjur _conjur;
        private string _pfxPath;
        private ManagedCertificate _managedCert;

        [TestInitialize]
        public override void Setup()
        {
            base.Setup();

            _conjur = new FakeConjur();
            _conjur.Declare(VariablePath, "certificate", "private_key", "chain", "fullchain", "pfx");
            (_pfxPath, _) = TestCertificates.CreatePfxWithChain(1);
            _managedCert = GetMockManagedCertificate("CyberArkConjurTest", "1", "www.example.com", PrimaryIISRoot);
            _managedCert.CertificatePath = _pfxPath;
        }

        [TestCleanup]
        public void Cleanup()
        {
            _conjur?.Dispose();
            if (_pfxPath != null && File.Exists(_pfxPath))
            {
                File.Delete(_pfxPath);
            }
        }

        [TestMethod, TestCategory("CyberArkConjur")]
        public async Task DeploymentWritesVariablesWithCertificateLast()
        {
            var results = await Execute();

            Assert.IsTrue(results.All(r => r.IsSuccess && !r.IsWarning), Messages(results));
            StringAssert.Contains(results.Single().Message, $"wrote the certificate to the variables under {VariablePath}");

            using (var cert = X509Certificate2.CreateFromPem(Value("certificate"), Value("private_key")))
            {
                Assert.AreEqual(LeafSerial(), cert.SerialNumber);
            }

            StringAssert.StartsWith(Value("private_key"), "-----BEGIN PRIVATE KEY-----");
            Assert.AreEqual(1, Regex.Matches(Value("chain"), "BEGIN CERTIFICATE").Count);
            Assert.AreEqual(2, Regex.Matches(Value("fullchain"), "BEGIN CERTIFICATE").Count);
            Assert.IsNull(Value("pfx"), "no PFX unless asked for");

            var writes = _conjur.Requests.Where(r => r.Method == "POST" && r.Path.StartsWith("/secrets/")).Select(r => r.Path).ToList();
            Assert.AreEqual(4, writes.Count);
            Assert.AreEqual($"/secrets/myorg/variable/{VariablePath}/certificate", writes.Last());
            Assert.AreEqual(1, _conjur.SignIns, "signs in once");
        }

        [TestMethod, TestCategory("CyberArkConjur")]
        public async Task IncludePfxWritesBase64Pfx()
        {
            var results = await Execute(includePfx: true);

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
            var pfx = X509CertificateLoader.LoadPkcs12Collection(Convert.FromBase64String(Value("pfx")), "");
            Assert.AreEqual(LeafSerial(), pfx.Single(c => c.HasPrivateKey).SerialNumber);
        }

        [TestMethod, TestCategory("CyberArkConjur")]
        public async Task UpToDateVariablesAreNotWritten()
        {
            await Execute();
            _conjur.Requests.Clear();

            var results = await Execute();

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
            StringAssert.Contains(results.Single().Message, "are already up to date");
            Assert.IsFalse(_conjur.Requests.Any(r => r.Method == "POST" && r.Path.StartsWith("/secrets/")));
        }

        [TestMethod, TestCategory("CyberArkConjur")]
        public async Task ChangedCertificateVariableIsWrittenAgain()
        {
            await Execute();
            _conjur.Values[$"{VariablePath}/certificate"] = "changed";
            _conjur.Requests.Clear();

            var results = await Execute();

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
            Assert.AreEqual(4, _conjur.Requests.Count(r => r.Method == "POST" && r.Path.StartsWith("/secrets/")));
        }

        [TestMethod, TestCategory("CyberArkConjur")]
        public async Task UndeclaredVariableFailsBeforeCertificateIsWritten()
        {
            _conjur.Undeclare($"{VariablePath}/fullchain");

            var results = await Execute();

            var failure = results.Single(r => !r.IsSuccess).Message;
            StringAssert.Contains(failure, $"could not write variable {VariablePath}/fullchain: host/certify can't update it, or it isn't declared in policy");
            Assert.IsNull(Value("certificate"), "the certificate is written last, so the next deployment tries again");
        }

        [TestMethod, TestCategory("CyberArkConjur")]
        public async Task WrongApiKeyIsReported()
        {
            var results = await Execute(apiKey: "wrong");

            StringAssert.Contains(results.Single(r => !r.IsSuccess).Message, "Conjur didn't accept the API key of host/certify (401 Unauthorized)");
            Assert.AreEqual(0, _conjur.Values.Count);
        }

        [TestMethod, TestCategory("CyberArkConjur")]
        public async Task PreviewMakesNoChangesAndChecksVariables()
        {
            _conjur.Undeclare($"{VariablePath}/chain");

            var results = await Execute(isPreviewOnly: true);

            StringAssert.Contains(results[0].Message, $"Connected to Conjur at {_conjur.Address} as host/certify. Would write the certificate to the variables {VariablePath}/private_key, {VariablePath}/chain, {VariablePath}/fullchain, {VariablePath}/certificate.");
            StringAssert.Contains(results.Single(r => !r.IsSuccess).Message, $"host/certify can't update variable {VariablePath}/chain, or it isn't declared in policy");
            Assert.AreEqual(0, _conjur.Values.Count);
        }

        [TestMethod, TestCategory("CyberArkConjur")]
        public async Task PreviewReportsUpToDate()
        {
            await Execute();

            var results = await Execute(isPreviewOnly: true);

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
            StringAssert.Contains(results.Single().Message, $"Variable {VariablePath}/certificate already holds this certificate, so deploying would change nothing.");
        }

        [TestMethod, TestCategory("CyberArkConjur")]
        public async Task UrlWithPathIsKept()
        {
            _conjur.BasePath = "/api";

            var results = await Execute(url: _conjur.Address + "/api/");

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
            Assert.IsTrue(_conjur.Requests.All(r => r.Path.StartsWith("/api/")));
        }

        [TestMethod, TestCategory("CyberArkConjur")]
        public async Task InvalidSettingsAreReported()
        {
            var badPath = await Execute(variablePath: "/certs/www");
            var noCredential = await Execute(apiKey: "");

            StringAssert.Contains(badPath.Single(r => !r.IsSuccess).Message, "can't start or end with '/'");
            StringAssert.Contains(noCredential.Single(r => !r.IsSuccess).Message, "A CyberArk Conjur API Key credential is required");
            Assert.AreEqual(0, _conjur.Requests.Count);
        }

        [TestMethod, TestCategory("CyberArkConjur")]
        public async Task TlsServerIsTrustedOnlyWithItsCa()
        {
            using var ca = CreateCa();
            _conjur.Dispose();
            _conjur = new FakeConjur(ServerCertificate(ca));
            _conjur.Declare(VariablePath, "certificate", "private_key", "chain", "fullchain");

            var untrusted = await Execute();
            var trusted = await Execute(caData: ca.ExportCertificatePem());

            StringAssert.Contains(untrusted.Single(r => !r.IsSuccess).Message, "as its TLS certificate isn't trusted. Set the CA Certificate of the credential");
            Assert.IsTrue(trusted.All(r => r.IsSuccess), Messages(trusted));
        }

        private string Value(string name) => _conjur.Values.GetValueOrDefault($"{VariablePath}/{name}");

        private string LeafSerial()
        {
            var collection = X509CertificateLoader.LoadPkcs12CollectionFromFile(_pfxPath, "");
            return collection.Single(c => c.HasPrivateKey).SerialNumber;
        }

        private static X509Certificate2 CreateCa()
        {
            using var key = RSA.Create(2048);
            var request = new CertificateRequest("CN=Conjur Test CA", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        }

        private static X509Certificate2 ServerCertificate(X509Certificate2 ca)
        {
            using var key = RSA.Create(2048);
            var request = new CertificateRequest("CN=conjur", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var san = new SubjectAlternativeNameBuilder();
            san.AddIpAddress(IPAddress.Loopback);
            request.CertificateExtensions.Add(san.Build());
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, false));
            using var issued = request.Create(ca, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(10), new byte[] { 4, 3, 2, 1 });
            using var withKey = issued.CopyWithPrivateKey(key);

            // reload from PKCS#12, as SChannel can't use an ephemeral key
            return X509CertificateLoader.LoadPkcs12(withKey.Export(X509ContentType.Pkcs12), null);
        }

        private static string Messages(List<ActionResult> results) => string.Join("; ", results.Select(r => r.Message));

        private async Task<List<ActionResult>> Execute(bool isPreviewOnly = false, string variablePath = VariablePath, bool includePfx = false, string url = null, string apiKey = null, string caData = null)
        {
            var config = new DeploymentTaskConfig
            {
                TaskTypeId = CyberArkConjur.Definition.Id,
                ChallengeProvider = CredentialTypes.ConjurApiKey,
                Parameters = new List<ProviderParameterSetting>
                {
                    new ProviderParameterSetting("variable_path", variablePath),
                    new ProviderParameterSetting("include_pfx", includePfx.ToString())
                }
            };

            var credentials = new Dictionary<string, string>
            {
                ["url"] = url ?? _conjur.Address,
                ["account"] = "myorg",
                ["login"] = "host/certify",
                ["api_key"] = apiKey ?? FakeConjur.ApiKey,
                ["ca_data"] = caData
            };

            var execParams = new DeploymentTaskExecutionParams(_log, null, _managedCert, config, credentials, isPreviewOnly, CyberArkConjur.Definition, new DeploymentContext(), CancellationToken.None);
            return await new CyberArkConjur().Execute(execParams);
        }

        /// <summary>
        /// Stand-in for the Conjur REST API: API key sign in for host/certify in account myorg, and reading, writing and checking the update
        /// privilege of declared variables. Undeclared variables are not found, as for a host that can't see them.
        /// </summary>
        private sealed class FakeConjur : IDisposable
        {
            public const string ApiKey = "test-api-key";
            private const string Token = "{\"protected\":\"test\",\"payload\":\"token\"}";

            private readonly FakeHttpServer _server;
            private readonly HashSet<string> _declared = new HashSet<string>();

            public Dictionary<string, string> Values { get; } = new Dictionary<string, string>();
            public List<FakeHttpRequest> Requests => _server.Requests;
            public string Address => _server.Address;
            public string BasePath { get; set; } = "";
            public int SignIns { get; private set; }

            public FakeConjur(X509Certificate2 serverCertificate = null)
            {
                _server = new FakeHttpServer(Handle, serverCertificate);
            }

            public void Declare(string path, params string[] names)
            {
                foreach (var name in names)
                {
                    _declared.Add($"{path}/{name}");
                }
            }

            public void Undeclare(string variable) => _declared.Remove(variable);

            private FakeHttpResponse Handle(FakeHttpRequest request)
            {
                if (!request.Path.StartsWith(BasePath + "/"))
                {
                    return NotFound("no such route");
                }

                var path = request.Path[BasePath.Length..];

                if (request.Method == "POST" && path == "/authn/myorg/host/certify/authenticate")
                {
                    if (request.Body != ApiKey)
                    {
                        return new FakeHttpResponse(401, "text/plain", "");
                    }

                    SignIns++;
                    return new FakeHttpResponse(200, "application/json", Token);
                }

                var expected = $"Token token=\"{Convert.ToBase64String(Encoding.UTF8.GetBytes(Token))}\"";
                if (request.Header("Authorization") != expected)
                {
                    return new FakeHttpResponse(401, "text/plain", "");
                }

                const string secrets = "/secrets/myorg/variable/";
                const string resources = "/resources/myorg/variable/";

                if (path.StartsWith(secrets))
                {
                    var variable = path[secrets.Length..];
                    if (!_declared.Contains(variable))
                    {
                        return NotFound($"Variable '{variable}' not found in account 'myorg'");
                    }

                    if (request.Method == "POST")
                    {
                        Values[variable] = request.Body;
                        return new FakeHttpResponse(201, "text/plain", "");
                    }

                    return Values.TryGetValue(variable, out var value)
                        ? new FakeHttpResponse(200, "application/octet-stream", value)
                        : NotFound($"CONJ00076E Variable myorg:variable:{variable} is empty or not found.");
                }

                if (path.StartsWith(resources) && request.Method == "GET" && request.Query.GetValueOrDefault("check") == "true" && request.Query.GetValueOrDefault("privilege") == "update")
                {
                    return _declared.Contains(path[resources.Length..]) ? new FakeHttpResponse(204, "text/plain", "") : new FakeHttpResponse(404, "text/plain", "");
                }

                return NotFound("no such route");
            }

            private static FakeHttpResponse NotFound(string message) => new FakeHttpResponse(404, "application/json", $"{{\"error\":{{\"code\":\"not_found\",\"message\":\"{message}\"}}}}");

            public void Dispose() => _server.Dispose();
        }
    }
}
