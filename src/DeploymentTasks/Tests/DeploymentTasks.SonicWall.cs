using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;
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
    /// Runs the SonicWall task against a local stand-in for the SonicOS API, which signs in with HTTP Digest (SHA-256) or Basic, checks a digest
    /// on every later request (session security), stages changes until they are committed, and refuses to delete a certificate in use
    /// </summary>
    [TestClass]
    public class DeploymentTasksSonicWall : IntegrationTestBase
    {
        private const string Previous = "www_example_com_250101000000";

        private FakeSonicOs _fw;
        private string _pfxPath;

        [TestInitialize]
        public override void Setup()
        {
            base.Setup();

            _fw = new FakeSonicOs("certify", "secret");
            (_pfxPath, _) = TestCertificates.CreatePfxWithChain(1);
        }

        [TestCleanup]
        public void Cleanup()
        {
            _fw?.Dispose();
            if (_pfxPath != null && File.Exists(_pfxPath))
            {
                File.Delete(_pfxPath);
            }
        }

        [TestMethod, TestCategory("SonicWall")]
        public async Task ImportsAndSwitchesManagementAndSslVpn()
        {
            _fw.Running.Certs[Previous] = "old";
            _fw.Running.Certs["other"] = "other";
            _fw.Running.ManagementCert = Previous;
            _fw.Running.SslVpnCert = Previous;

            var results = await Execute("www_example_com");

            Assert.IsTrue(results.All(r => r.IsSuccess && !r.IsWarning), Messages(results));
            StringAssert.Contains(results.Last().Message, "switched the SSL VPN certificate and the HTTPS management certificate to it");

            var newName = _fw.Running.Certs.Keys.Single(c => Regex.IsMatch(c, @"^www_example_com_\d{12}$"));
            Assert.IsFalse(_fw.Running.Certs.ContainsKey(Previous), "previous certificate is deleted");
            Assert.IsTrue(_fw.Running.Certs.ContainsKey("other"));
            Assert.AreEqual(newName, _fw.Running.ManagementCert);
            Assert.AreEqual(newName, _fw.Running.SslVpnCert);
            Assert.IsNull(_fw.Pending, "everything is committed");
            Assert.IsFalse(_fw.SignedIn, "signed out");

            // with digest authentication each request is answered with a challenge, then sent again with the digest
            var authorized = _fw.Requests.Where(r => r.Header("Authorization") != null).ToList();

            var import = authorized.Single(r => r.Path.StartsWith("/api/sonicos/import/"));
            Assert.AreEqual($"/api/sonicos/import/certificates/cert-key-pair/name/{newName}", import.Path);
            CollectionAssert.AreEqual(new[] { "certPasswd", "certificate.exp" }, _fw.LastImportFields.ToArray(), "the password comes before the file");
            Assert.AreEqual(2, _fw.LastImportChainCount, "certificate is imported with its chain");

            var puts = authorized.Where(r => r.Method == "PUT" && !r.Path.Contains("/import/")).Select(r => r.Path).ToList();
            CollectionAssert.AreEqual(new[] { "/api/sonicos/ssl-vpn/server/base", "/api/sonicos/administration/global" }, puts, "HTTPS management changes last");

            Assert.IsTrue(_fw.Requests.Where(r => r.Header("Authorization") != null && r.Path != "/api/sonicos/auth").All(r => r.Header("Authorization").StartsWith("Digest ")));
            Assert.IsTrue(_fw.ManagementRequestsWithValidDigest > 0, "session security digests are sent");
        }

        [TestMethod, TestCategory("SonicWall")]
        public async Task FirstDeploymentHasNothingToSwitch()
        {
            var results = await Execute("www_example_com");

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
            Assert.AreEqual(1, _fw.Running.Certs.Count);
            Assert.IsNull(_fw.Running.ManagementCert, "still the self-signed certificate");
            StringAssert.Contains(results.Last().Message, "select it where it should be used");
            Assert.IsFalse(_fw.Requests.Any(r => r.Method == "DELETE" && r.Path != "/api/sonicos/auth"));
        }

        [TestMethod, TestCategory("SonicWall")]
        public async Task OnlyReplacesThisTasksCertificates()
        {
            _fw.Running.Certs["www_example_com2"] = "a";
            _fw.Running.Certs["www_example_com_old"] = "b";
            _fw.Running.Certs["www_example_com_25010100000"] = "c";

            var results = await Execute("www_example_com");

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
            Assert.AreEqual(4, _fw.Running.Certs.Count);
        }

        [TestMethod, TestCategory("SonicWall")]
        public async Task ReplacesCertificateImportedByHand()
        {
            _fw.Running.Certs["www_example_com"] = "old";
            _fw.Running.SslVpnCert = "www_example_com";

            var results = await Execute("www_example_com");

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
            Assert.IsFalse(_fw.Running.Certs.ContainsKey("www_example_com"));
            StringAssert.StartsWith(_fw.Running.SslVpnCert, "www_example_com_");
        }

        [TestMethod, TestCategory("SonicWall")]
        public async Task CertificateUsedElsewhereIsKept()
        {
            _fw.Running.Certs[Previous] = "old";
            _fw.Running.ManagementCert = Previous;
            _fw.UsedElsewhere.Add(Previous);

            var results = await Execute("www_example_com");

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
            Assert.IsTrue(results.Any(r => r.IsWarning && r.Message.Contains($"could not delete previous certificate '{Previous}'") && r.Message.Contains("in use")));
            Assert.IsTrue(_fw.Running.Certs.ContainsKey(Previous));
            StringAssert.StartsWith(_fw.Running.ManagementCert, "www_example_com_");
        }

        [TestMethod, TestCategory("SonicWall")]
        public async Task KeepsPreviousCertificatesWhenDeleteIsOff()
        {
            _fw.Running.Certs[Previous] = "old";
            _fw.Running.ManagementCert = Previous;

            var results = await Execute("www_example_com", extra: new() { ["delete_previous"] = "false" });

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
            Assert.IsTrue(_fw.Running.Certs.ContainsKey(Previous));
            StringAssert.StartsWith(_fw.Running.ManagementCert, "www_example_com_");
            Assert.IsFalse(_fw.Requests.Any(r => r.Path.StartsWith("/api/sonicos/certificates/name/")));
        }

        [TestMethod, TestCategory("SonicWall")]
        public async Task PreviewMakesNoChanges()
        {
            _fw.Running.Certs[Previous] = "old";
            _fw.Running.ManagementCert = Previous;
            _fw.Running.SslVpnCert = Previous;

            var results = await Execute("www_example_com", isPreviewOnly: true, extra: new() { ["override_admin"] = "true" });

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
            var message = results.Single().Message;
            StringAssert.Contains(message, "Connected to SonicWall");
            StringAssert.Contains(message, "Would import it as certificate 'www_example_com_");
            StringAssert.Contains(message, "switch the HTTPS management certificate and the SSL VPN certificate to it");
            StringAssert.Contains(message, $"then delete '{Previous}'");

            Assert.IsTrue(_fw.Requests.Where(r => r.Path != "/api/sonicos/auth").All(r => r.Method == "GET"));
            Assert.AreEqual(false, _fw.LastAuthOverride, "a preview never takes over from another administrator");
            Assert.IsFalse(_fw.SignedIn);
        }

        [TestMethod, TestCategory("SonicWall")]
        public async Task PreviewBeforeCertificateIssuedChecksConnection()
        {
            var results = await Execute("www_example_com", isPreviewOnly: true, certificatePath: "");

            StringAssert.Contains(results.Single().Message, "Connected to SonicWall");
            StringAssert.Contains(results.Single().Message, "No certificate has been issued yet");
        }

        [TestMethod, TestCategory("SonicWall")]
        public async Task ImportFailureChangesNothing()
        {
            _fw.Running.Certs[Previous] = "old";
            _fw.Running.ManagementCert = Previous;
            _fw.ImportError = "Invalid certificate or password";

            var results = await Execute("www_example_com");

            var failure = results.Single(r => !r.IsSuccess);
            StringAssert.Contains(failure.Message, "nothing was changed");
            StringAssert.Contains(failure.Message, "Invalid certificate");
            Assert.AreEqual(Previous, _fw.Running.ManagementCert);
            Assert.IsFalse(_fw.Requests.Any(r => r.Method == "PUT" && !r.Path.Contains("/import/")));
            Assert.IsFalse(_fw.SignedIn);
        }

        [TestMethod, TestCategory("SonicWall")]
        public async Task UsesImportBeforeSonicOs73()
        {
            _fw.LegacyImport = true;

            var results = await Execute("www_example_com");

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
            var import = _fw.Requests.Where(r => r.Path.StartsWith("/api/sonicos/import/")).Last();
            StringAssert.Matches(import.Path, new Regex(@"^/api/sonicos/import/certificates/cert-key-pair/name/www_example_com_\d{12}/password/[0-9A-F]{32}$"));
            CollectionAssert.AreEqual(new[] { "file" }, _fw.LastImportFields.ToArray());
            Assert.AreEqual(1, _fw.Running.Certs.Count);
        }

        [TestMethod, TestCategory("SonicWall")]
        public async Task CommitFailureKeepsPreviousCertificate()
        {
            _fw.Running.Certs[Previous] = "old";
            _fw.Running.ManagementCert = Previous;
            _fw.CommitError = "Configuration is locked";

            var results = await Execute("www_example_com");

            var failure = results.Single(r => !r.IsSuccess);
            StringAssert.Contains(failure.Message, "could not save the changes, so the SonicWall still uses the previous certificate");
            StringAssert.Contains(failure.Message, "locked");
            Assert.AreEqual(Previous, _fw.Running.ManagementCert);
            Assert.AreEqual(1, _fw.Running.Certs.Count);
            Assert.IsNull(_fw.Pending, "signing out discards the changes");
        }

        [TestMethod, TestCategory("SonicWall")]
        public async Task ReferenceFailureKeepsPreviousCertificate()
        {
            _fw.Running.Certs[Previous] = "old";
            _fw.Running.ManagementCert = Previous;
            _fw.Running.SslVpnCert = Previous;
            _fw.PutError = ("ssl-vpn/server/base", "SSL VPN is not licensed");

            var results = await Execute("www_example_com");

            var failure = results.Single(r => !r.IsSuccess);
            StringAssert.Contains(failure.Message, "the SSL VPN certificate could not be switched to it");
            StringAssert.Contains(failure.Message, $"still uses '{Previous}'");
            Assert.IsTrue(_fw.Running.Certs.ContainsKey(Previous), "previous certificate is kept while it is still used");
            StringAssert.StartsWith(_fw.Running.ManagementCert, "www_example_com_", "the other setting is still switched");
        }

        [TestMethod, TestCategory("SonicWall")]
        public async Task ConnectionClosedWhileSwitchingManagementKeepsPrevious()
        {
            _fw.Running.Certs[Previous] = "old";
            _fw.Running.ManagementCert = Previous;
            _fw.DropOnManagementCommit = true;

            var results = await Execute("www_example_com");

            var failure = results.Single(r => !r.IsSuccess);
            StringAssert.Contains(failure.Message, "the connection closed while saving the switch of the HTTPS management certificate");
            Assert.IsTrue(_fw.Running.Certs.ContainsKey(Previous));
            Assert.IsFalse(_fw.Requests.Any(r => r.Path.StartsWith("/api/sonicos/certificates/name/")));
        }

        [TestMethod, TestCategory("SonicWall")]
        public async Task OtherAdministratorStartsManagementSession()
        {
            _fw.RequireStartManagement = true;

            var results = await Execute("www_example_com");

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
            Assert.IsTrue(_fw.Requests.Any(r => r.Path == "/api/sonicos/start-management"));
        }

        [TestMethod, TestCategory("SonicWall")]
        public async Task AnotherAdministratorManagingNeedsTakeOver()
        {
            _fw.OtherAdminConfiguring = true;

            var results = await Execute("www_example_com");

            var failure = results.Single(r => !r.IsSuccess);
            StringAssert.Contains(failure.Message, "Another administrator");
            StringAssert.Contains(failure.Message, "Take Over Management");
            Assert.AreEqual(0, _fw.Running.Certs.Count);

            results = await Execute("www_example_com", extra: new() { ["override_admin"] = "true" });

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
            Assert.AreEqual(true, _fw.LastAuthOverride);
            Assert.AreEqual(1, _fw.Running.Certs.Count);
        }

        [TestMethod, TestCategory("SonicWall")]
        public async Task SignsInWithBasicAuthentication()
        {
            _fw.BasicAuth = true;
            _fw.SessionSecurity = false;
            _fw.Running.Certs[Previous] = "old";
            _fw.Running.SslVpnCert = Previous;

            var results = await Execute("www_example_com");

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
            StringAssert.StartsWith(_fw.Running.SslVpnCert, "www_example_com_");
            StringAssert.StartsWith(_fw.Requests.Last(r => r.Path == "/api/sonicos/auth" && r.Method == "POST").Header("Authorization"), "Basic ");
        }

        [TestMethod, TestCategory("SonicWall")]
        public async Task ReportsAccessDenied()
        {
            var results = await Execute("www_example_com", password: "wrong");

            var failure = results.Single(r => !r.IsSuccess);
            StringAssert.Contains(failure.Message, "access denied");
            StringAssert.Contains(failure.Message, "SonicOS API is enabled");
        }

        [TestMethod, TestCategory("SonicWall")]
        public async Task ReportsNonSonicOsResponse()
        {
            _fw.ReturnHtml = true;

            var results = await Execute("www_example_com");

            StringAssert.Contains(results.Single(r => !r.IsSuccess).Message, "unexpected response");
        }

        [TestMethod, TestCategory("SonicWall")]
        public async Task ValidatesSettings()
        {
            var provider = new SonicWall();

            async Task<List<ActionResult>> validate(string address, string certName, string password = "secret")
                => await provider.Validate(CreateParams(address, certName, password, false, null));

            Assert.AreEqual(0, (await validate("https://192.168.168.168", "www_example_com")).Count);
            Assert.AreEqual(0, (await validate("https://fw.example.com:4433/", "wildcard.example-com")).Count);
            Assert.IsTrue((await validate("", "www_example_com")).Any(r => !r.IsSuccess));
            Assert.IsTrue((await validate("192.168.168.168", "www_example_com")).Any(r => !r.IsSuccess));
            Assert.IsTrue((await validate("https://192.168.168.168", "")).Any(r => !r.IsSuccess));
            Assert.IsTrue((await validate("https://192.168.168.168", "*.example.com")).Any(r => !r.IsSuccess));
            Assert.IsTrue((await validate("https://192.168.168.168", "www/example")).Any(r => !r.IsSuccess));
            Assert.IsTrue((await validate("https://192.168.168.168", new string('a', 31))).Any(r => !r.IsSuccess));
            Assert.IsTrue((await validate("https://192.168.168.168", "www_example_com", password: "")).Any(r => !r.IsSuccess));
        }

        private static string Messages(List<ActionResult> results) => string.Join("; ", results.Select(r => r.Message));

        private async Task<List<ActionResult>> Execute(string certName, bool isPreviewOnly = false, string password = "secret", string certificatePath = null, Dictionary<string, string> extra = null)
        {
            var execParams = CreateParams(_fw.Address, certName, password, isPreviewOnly, extra);
            if (certificatePath != null)
            {
                ((ManagedCertificate)execParams.Subject).CertificatePath = certificatePath;
            }

            return await new SonicWall().Execute(execParams);
        }

        private DeploymentTaskExecutionParams CreateParams(string address, string certName, string password, bool isPreviewOnly, Dictionary<string, string> extra)
        {
            var config = new DeploymentTaskConfig
            {
                TaskTypeId = SonicWall.Definition.Id,
                TaskName = "SonicWall test",
                ChallengeProvider = StandardAuthTypes.STANDARD_AUTH_GENERIC,
                Parameters = new List<ProviderParameterSetting>
                {
                    new ProviderParameterSetting("sonicwall_address", address),
                    new ProviderParameterSetting("cert_name", certName)
                }
            };

            foreach (var (key, value) in extra ?? new())
            {
                config.Parameters.Add(new ProviderParameterSetting(key, value));
            }

            var managedCert = GetMockManagedCertificate("SonicWallTest", "1", "www.example.com", PrimaryIISRoot);
            managedCert.CertificatePath = _pfxPath;

            var credentials = new Dictionary<string, string> { { "username", "certify" }, { "password", password } };
            return new DeploymentTaskExecutionParams(_log, null, managedCert, config, credentials, isPreviewOnly, SonicWall.Definition, new DeploymentContext(), CancellationToken.None);
        }

        /// <summary>
        /// Stand-in for the SonicOS API: auth (Digest SHA-256 or Basic, then session security), config mode, certificate list, import (7.3 and
        /// earlier endpoints) and delete, the HTTPS management and SSL VPN settings, and pending configuration
        /// </summary>
        private sealed class FakeSonicOs : IDisposable
        {
            public sealed class State
            {
                // certificate name to leaf thumbprint
                public Dictionary<string, string> Certs { get; init; } = new();
                public string ManagementCert { get; set; }
                public string SslVpnCert { get; set; }

                public State Clone() => new State { Certs = new Dictionary<string, string>(Certs), ManagementCert = ManagementCert, SslVpnCert = SslVpnCert };
            }

            private const string Realm = "admin-users@127.0.0.1";

            private readonly FakeHttpServer _server;
            private readonly string _username;
            private readonly string _password;
            private readonly string _nonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
            private bool _configMode;
            private bool _managementStarted;
            private bool _mayConfigure;

            public string Address => _server.Address;
            public List<FakeHttpRequest> Requests => _server.Requests;

            public State Running { get; private set; } = new State();
            public State Pending { get; private set; }
            private State Current => Pending ?? Running;

            public bool SignedIn { get; private set; }
            public bool? LastAuthOverride { get; private set; }
            public List<string> LastImportFields { get; private set; }
            public int LastImportChainCount { get; private set; }
            public int ManagementRequestsWithValidDigest { get; private set; }

            public bool BasicAuth { get; set; }
            public bool SessionSecurity { get; set; } = true;
            public bool LegacyImport { get; set; }
            public bool RequireStartManagement { get; set; }
            public bool OtherAdminConfiguring { get; set; }
            public HashSet<string> UsedElsewhere { get; } = new();
            public string ImportError { get; set; }
            public string CommitError { get; set; }
            public (string Path, string Error)? PutError { get; set; }
            public bool DropOnManagementCommit { get; set; }
            public bool ReturnHtml { get; set; }

            public FakeSonicOs(string username, string password)
            {
                _username = username;
                _password = password;
                _server = new FakeHttpServer(Handle);
            }

            private State Edit() => Pending ??= Running.Clone();

            private FakeHttpResponse Handle(FakeHttpRequest r)
            {
                if (ReturnHtml)
                {
                    return new FakeHttpResponse(200, "text/html", "<!DOCTYPE html><html><body>Login</body></html>");
                }

                Assert.IsTrue(r.Path.StartsWith("/api/sonicos/"), r.Path);
                var path = r.Path["/api/sonicos/".Length..];

                if (path == "auth" && r.Method == "POST")
                {
                    if (!(BasicAuth ? ValidBasic(r) : ValidDigest(r)))
                    {
                        return Challenge();
                    }

                    LastAuthOverride = JsonNode.Parse(r.Body)?["override"]?.GetValue<bool>();
                    SignedIn = true;
                    _configMode = false;
                    _managementStarted = false;
                    _mayConfigure = !OtherAdminConfiguring || LastAuthOverride == true;
                    return Status(true, "E_OK", "Success.");
                }

                if (!SignedIn)
                {
                    return new FakeHttpResponse(401, "application/json", StatusJson(false, "E_UNAUTHORIZED", "Not logged in."));
                }

                if (SessionSecurity)
                {
                    if (!ValidDigest(r))
                    {
                        return Challenge();
                    }

                    ManagementRequestsWithValidDigest++;
                }

                switch (r.Method, path)
                {
                    case ("DELETE", "auth"):
                        SignedIn = false;
                        Pending = null;
                        return Status(true, "E_OK", "Success.");

                    case ("POST", "start-management"):
                        _managementStarted = true;
                        return Status(true, "E_OK", "Success.");

                    case ("POST", "config-mode"):
                        if (!_mayConfigure)
                        {
                            return Status(false, "E_BUSY", "Another administrator is currently configuring the firewall.");
                        }

                        if (RequireStartManagement && !_managementStarted)
                        {
                            return Status(false, "E_UNAUTHORIZED", "Not in a management session.");
                        }

                        _configMode = true;
                        return Status(true, "E_OK", "Success.");

                    case ("GET", "reporting/certificates"):
                        var list = Current.Certs.Keys.Select(c => (JsonNode)new JsonObject { ["certificate"] = c, ["type"] = "Local Certificate", ["validated"] = "Yes", ["expires_on"] = "Dec 30 2026" })
                            .Append(new JsonObject { ["certificate"] = "Default SonicWALL DPI-SSL CA", ["type"] = "CA Certificate", ["validated"] = "Yes", ["expires_on"] = "Dec 30 2030" });
                        return Json(new JsonArray(list.ToArray()));

                    case ("GET", "administration/global"):
                        return Json(new JsonObject { ["administration"] = new JsonObject { ["web_management"] = new JsonObject { ["allow_http"] = false, ["certificate"] = CertificateSetting(Current.ManagementCert) } } });

                    case ("GET", "ssl-vpn/server/base"):
                        return Json(new JsonObject { ["ssl_vpn"] = new JsonObject { ["server"] = new JsonObject { ["port"] = 4433, ["certificate"] = CertificateSetting(Current.SslVpnCert) } } });

                    case ("GET", "config/pending"):
                        return Json(Pending == null ? new JsonObject() : new JsonObject { ["certificates"] = new JsonObject() });
                }

                if (!_configMode)
                {
                    return Status(false, "E_NOT_CONFIG_MODE", "Not in config mode.");
                }

                switch (r.Method, path)
                {
                    case ("PUT", "administration/global"):
                    case ("PUT", "ssl-vpn/server/base"):
                        if (PutError is { } error && error.Path == path)
                        {
                            return Status(false, "E_INVALID", error.Error);
                        }

                        var body = JsonNode.Parse(r.Body);
                        var name = (path == "administration/global" ? body["administration"]["web_management"] : body["ssl_vpn"]["server"])["certificate"]["name"].ToString();
                        if (!Current.Certs.ContainsKey(name))
                        {
                            return Status(false, "E_NOT_FOUND", $"Certificate {name} not found.");
                        }

                        if (path == "administration/global")
                        {
                            Edit().ManagementCert = name;
                        }
                        else
                        {
                            Edit().SslVpnCert = name;
                        }

                        return Status(true, "E_OK", "Success.");

                    case ("PUT", var p) when p.StartsWith("import/certificates/cert-key-pair/name/"):
                        return Import(r, p["import/certificates/cert-key-pair/name/".Length..].Split('/'));

                    case ("DELETE", var p) when p.StartsWith("certificates/name/"):
                        var deleting = p["certificates/name/".Length..];
                        if (deleting == Current.ManagementCert || deleting == Current.SslVpnCert || UsedElsewhere.Contains(deleting))
                        {
                            return Status(false, "E_BUSY", "Certificate is in use.");
                        }

                        return Edit().Certs.Remove(deleting) ? Status(true, "E_OK", "Success.") : Status(false, "E_NOT_FOUND", "Certificate not found.");

                    case ("POST", "config/pending"):
                        if (CommitError != null)
                        {
                            return Status(false, "E_ERROR", CommitError);
                        }

                        var managementChanged = Pending?.ManagementCert != Running.ManagementCert;
                        Running = Pending ?? Running;
                        Pending = null;

                        // the management web server restarts with its new certificate before answering
                        return DropOnManagementCommit && managementChanged ? null : Status(true, "E_OK", "Success.");

                    default:
                        return new FakeHttpResponse(404, "application/json", StatusJson(false, "E_HTTP_404", "Invalid API call."));
                }
            }

            /// <summary>
            /// Import a PKCS#12: SonicOS 7.3 takes name/{NAME} with certPasswd and certificate.exp parts, earlier versions name/{NAME}/password/{PASSWD} with a file part
            /// </summary>
            private FakeHttpResponse Import(FakeHttpRequest r, string[] segments)
            {
                var legacyPath = segments.Length == 3 && segments[1] == "password";
                if (LegacyImport != legacyPath || !(segments.Length == 1 || legacyPath))
                {
                    return new FakeHttpResponse(404, "application/json", StatusJson(false, "E_HTTP_404", "Invalid API call."));
                }

                var boundary = Regex.Match(r.Header("Content-Type"), "boundary=(.+)$").Groups[1].Value;
                var fields = new List<(string Name, byte[] Value)>();
                var body = Encoding.Latin1.GetString(r.BodyBytes);
                foreach (var part in body.Split("--" + boundary).Skip(1).Where(p => !p.StartsWith("--")))
                {
                    var split = part.IndexOf("\r\n\r\n", StringComparison.Ordinal);
                    fields.Add((Regex.Match(part[..split], "name=\"([^\"]+)\"").Groups[1].Value, Encoding.Latin1.GetBytes(part[(split + 4)..^2])));
                }

                LastImportFields = fields.Select(f => f.Name).ToList();

                if (ImportError != null)
                {
                    return Status(false, "E_ERROR", ImportError);
                }

                var name = segments[0];
                var password = legacyPath ? segments[2] : Encoding.ASCII.GetString(fields.Single(f => f.Name == "certPasswd").Value);
                var pfx = fields.Single(f => f.Name == (legacyPath ? "file" : "certificate.exp")).Value;

                var collection = X509CertificateLoader.LoadPkcs12Collection(pfx, password);
                var leaf = collection.Single(c => c.HasPrivateKey);
                LastImportChainCount = collection.Count;

                if (Current.Certs.ContainsKey(name))
                {
                    return Status(false, "E_EXISTS", "Certificate name already exists.");
                }

                Edit().Certs[name] = leaf.Thumbprint;
                return Status(true, "E_OK", "Success.");
            }

            private static JsonNode CertificateSetting(string name) => name == null ? new JsonObject { ["use_self_signed"] = true } : new JsonObject { ["name"] = name };

            private bool ValidBasic(FakeHttpRequest r)
                => r.Header("Authorization") == "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes($"{_username}:{_password}"));

            /// <summary>
            /// RFC 7616 digest with SHA-256 and qop=auth
            /// </summary>
            private bool ValidDigest(FakeHttpRequest r)
            {
                var header = r.Header("Authorization");
                if (header == null || !header.StartsWith("Digest "))
                {
                    return false;
                }

                var p = Regex.Matches(header[7..], "(\\w+)=(?:\"([^\"]*)\"|([^,\\s]*))")
                    .ToDictionary(m => m.Groups[1].Value, m => m.Groups[2].Success ? m.Groups[2].Value : m.Groups[3].Value);

                static string h(string value) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();

                var ha1 = h($"{_username}:{Realm}:{_password}");
                var ha2 = h($"{r.Method}:{p.GetValueOrDefault("uri")}");
                var expected = h($"{ha1}:{p.GetValueOrDefault("nonce")}:{p.GetValueOrDefault("nc")}:{p.GetValueOrDefault("cnonce")}:{p.GetValueOrDefault("qop")}:{ha2}");

                return p.GetValueOrDefault("username") == _username && p.GetValueOrDefault("nonce") == _nonce && p.GetValueOrDefault("response") == expected;
            }

            private FakeHttpResponse Challenge()
            {
                var header = BasicAuth && !SignedIn
                    ? $"Basic realm=\"{Realm}\""
                    : $"Digest realm=\"{Realm}\", qop=\"auth\", algorithm=SHA-256, nonce=\"{_nonce}\", opaque=\"abc123\"";

                return new FakeHttpResponse(401, "application/json", StatusJson(false, "E_UNAUTHORIZED", "Unauthorized."), new Dictionary<string, string> { ["WWW-Authenticate"] = header });
            }

            private static FakeHttpResponse Json(JsonNode body) => new FakeHttpResponse(200, "application/json", body.ToJsonString());

            private static FakeHttpResponse Status(bool success, string code, string message) => new FakeHttpResponse(success ? 200 : 400, "application/json", StatusJson(success, code, message));

            private static string StatusJson(bool success, string code, string message)
                => new JsonObject { ["status"] = new JsonObject { ["success"] = success, ["info"] = new JsonArray(new JsonObject { ["level"] = success ? "info" : "error", ["code"] = code, ["message"] = message }) } }.ToJsonString();

            public void Dispose() => _server.Dispose();
        }
    }
}
