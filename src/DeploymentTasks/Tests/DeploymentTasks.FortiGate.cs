using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
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
    /// Runs the FortiGate task against a local stand-in for the FortiOS REST API, which answers with the same JSON format, reports
    /// certificate usage from its configuration objects, and refuses to delete a certificate that is still used
    /// </summary>
    [TestClass]
    public class DeploymentTasksFortiGate : IntegrationTestBase
    {
        private const string Previous = "www_example_com_250101000000";

        private FakeFortiGate _fgt;
        private string _pfxPath;

        [TestInitialize]
        public override void Setup()
        {
            base.Setup();

            _fgt = new FakeFortiGate("token123");
            UseChain(1);
        }

        [TestCleanup]
        public void Cleanup()
        {
            _fgt?.Dispose();
            DeletePfx();
        }

        [TestMethod, TestCategory("FortiGate")]
        public async Task ImportsAndMovesEveryReference()
        {
            _fgt.LocalCerts.Add(Previous);
            _fgt.LocalCerts.Add("other-ecdsa");
            _fgt.SetObject("system/global", null, new JsonObject { ["admin-server-cert"] = Previous, ["hostname"] = "fw1" });
            _fgt.SetObject("vpn.ssl/settings", null, new JsonObject { ["servercert"] = Previous });
            _fgt.SetObject("firewall/vip", "web-vip", new JsonObject { ["name"] = "web-vip", ["ssl-certificate"] = List(Previous, "other-ecdsa") });
            _fgt.SetObject("firewall/ssl-ssh-profile", "inbound", new JsonObject { ["name"] = "inbound", ["server-cert"] = List(Previous) });

            var results = await Execute("www_example_com");

            Assert.IsTrue(results.All(r => r.IsSuccess && !r.IsWarning), Messages(results));
            StringAssert.Contains(results.Last().Message, "moved 4 reference(s)");

            var newName = _fgt.LocalCerts.Single(c => Regex.IsMatch(c, @"^www_example_com_\d{12}$"));
            Assert.IsFalse(_fgt.LocalCerts.Contains(Previous), "previous certificate is deleted");
            Assert.IsTrue(_fgt.LocalCerts.Contains("other-ecdsa"));

            Assert.AreEqual(newName, _fgt.GetObject("system/global", null)["admin-server-cert"].ToString());
            Assert.AreEqual("fw1", _fgt.GetObject("system/global", null)["hostname"].ToString(), "other settings are unchanged");
            Assert.AreEqual(newName, _fgt.GetObject("vpn.ssl/settings", null)["servercert"].ToString());
            CollectionAssert.AreEqual(new[] { newName, "other-ecdsa" }, Names(_fgt.GetObject("firewall/vip", "web-vip")["ssl-certificate"]), "other certificates in a list are kept");
            CollectionAssert.AreEqual(new[] { newName }, Names(_fgt.GetObject("firewall/ssl-ssh-profile", "inbound")["server-cert"]));

            var puts = _fgt.Requests.Where(r => r.Method == "PUT").ToList();
            Assert.AreEqual("/api/v2/cmdb/system/global", puts.Last().Path, "the admin interface changes last");

            var import = JsonNode.Parse(_fgt.Requests.Single(r => r.Path.EndsWith("/vpn-certificate/local/import")).Body);
            Assert.AreEqual("regular", import["type"].ToString());
            Assert.AreEqual("vdom", import["scope"].ToString());
            Assert.AreEqual(2, CountOf(Decode(import["file_content"]), "-----BEGIN CERTIFICATE-----"), "certificate is imported with its chain");
            StringAssert.Contains(Decode(import["key_file_content"]), "PRIVATE KEY-----");
            Assert.AreEqual(1, _fgt.CaCerts.Count, "intermediate is imported as a CA certificate");

            var import1 = _fgt.Requests.IndexOf(_fgt.Requests.Single(r => r.Path.EndsWith("/vpn-certificate/local/import")));
            Assert.IsTrue(_fgt.Requests.Select((r, i) => (r, i)).Where(x => x.r.Method == "PUT").All(x => x.i > import1), "references move only after the import");

            Assert.IsTrue(_fgt.Requests.All(r => r.Header("Authorization") == "Bearer token123" && r.Query.GetValueOrDefault("vdom") == "root"));
        }

        [TestMethod, TestCategory("FortiGate")]
        public async Task ReplacesCertificateImportedByHand()
        {
            _fgt.LocalCerts.Add("www_example_com");
            _fgt.SetObject("system/global", null, new JsonObject { ["admin-server-cert"] = "www_example_com" });

            var results = await Execute("www_example_com");

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
            Assert.IsFalse(_fgt.LocalCerts.Contains("www_example_com"));
            StringAssert.StartsWith(_fgt.GetObject("system/global", null)["admin-server-cert"].ToString(), "www_example_com_");
            StringAssert.Contains(results.Last().Message, "the admin interface");
        }

        [TestMethod, TestCategory("FortiGate")]
        public async Task FirstDeploymentHasNothingToMove()
        {
            _fgt.SetObject("system/global", null, new JsonObject { ["admin-server-cert"] = "Fortinet_GUI_Server" });

            var results = await Execute("www_example_com");

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
            Assert.AreEqual(1, _fgt.LocalCerts.Count(c => c.StartsWith("www_example_com_")));
            Assert.AreEqual("Fortinet_GUI_Server", _fgt.GetObject("system/global", null)["admin-server-cert"].ToString());
            Assert.IsFalse(_fgt.Requests.Any(r => r.Method == "PUT" || r.Method == "DELETE"));
            StringAssert.Contains(results.Last().Message, "select it where it should be used");
        }

        [TestMethod, TestCategory("FortiGate")]
        public async Task OnlyReplacesThisTasksCertificates()
        {
            _fgt.LocalCerts.Add("www_example_com2");
            _fgt.LocalCerts.Add("www_example_com_old");
            _fgt.LocalCerts.Add("www_example_com_25010100000");
            _fgt.FactoryCerts.Add("www_example_com");

            var results = await Execute("www_example_com");

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
            Assert.IsFalse(_fgt.Requests.Any(r => r.Method == "DELETE"));
            Assert.AreEqual(4, _fgt.LocalCerts.Count);
        }

        [TestMethod, TestCategory("FortiGate")]
        public async Task PreviewMakesNoChanges()
        {
            _fgt.LocalCerts.Add(Previous);
            _fgt.SetObject("firewall/vip", "web-vip", new JsonObject { ["name"] = "web-vip", ["ssl-certificate"] = List(Previous) });
            _fgt.SetObject("system/global", null, new JsonObject { ["admin-server-cert"] = Previous });

            var results = await Execute("www_example_com", isPreviewOnly: true);

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
            var message = results.Single().Message;
            StringAssert.Contains(message, "Would import it as local certificate 'www_example_com_");
            StringAssert.Contains(message, "move 2 reference(s) to it (firewall.vip 'web-vip' ssl-certificate, the admin interface)");
            StringAssert.Contains(message, $"then delete '{Previous}'");
            Assert.IsTrue(_fgt.Requests.All(r => r.Method == "GET"));
        }

        [TestMethod, TestCategory("FortiGate")]
        public async Task PreviewBeforeCertificateIssuedChecksConnection()
        {
            var results = await Execute("www_example_com", isPreviewOnly: true, certificatePath: "");

            StringAssert.Contains(results.Single().Message, "Connected to FortiGate");
            StringAssert.Contains(results.Single().Message, "No certificate has been issued yet");
            Assert.IsTrue(_fgt.Requests.All(r => r.Method == "GET"));
        }

        [TestMethod, TestCategory("FortiGate")]
        public async Task ImportFailureChangesNothing()
        {
            _fgt.LocalCerts.Add(Previous);
            _fgt.SetObject("system/global", null, new JsonObject { ["admin-server-cert"] = Previous });
            _fgt.ImportError = "Certificate and private key do not match";

            var results = await Execute("www_example_com");

            var failure = results.Single(r => !r.IsSuccess);
            StringAssert.Contains(failure.Message, "nothing was changed");
            StringAssert.Contains(failure.Message, "do not match");
            Assert.IsTrue(_fgt.LocalCerts.Contains(Previous));
            Assert.IsFalse(_fgt.Requests.Any(r => r.Method == "PUT" || r.Method == "DELETE"));
        }

        [TestMethod, TestCategory("FortiGate")]
        public async Task ReferenceFailureKeepsPreviousCertificate()
        {
            _fgt.LocalCerts.Add(Previous);
            _fgt.SetObject("system/global", null, new JsonObject { ["admin-server-cert"] = Previous });
            _fgt.SetObject("firewall/vip", "web-vip", new JsonObject { ["name"] = "web-vip", ["ssl-certificate"] = List(Previous) });
            _fgt.PutError = ("firewall/vip/web-vip", "Permission denied for firewall settings");

            var results = await Execute("www_example_com");

            var failure = results.Single(r => !r.IsSuccess);
            StringAssert.Contains(failure.Message, "firewall.vip 'web-vip' ssl-certificate could not be changed");
            StringAssert.Contains(failure.Message, $"still uses '{Previous}'");
            StringAssert.Contains(failure.Message, "Permission denied");
            Assert.IsTrue(_fgt.LocalCerts.Contains(Previous), "previous certificate is kept while it is still used");
            StringAssert.StartsWith(_fgt.GetObject("system/global", null)["admin-server-cert"].ToString(), "www_example_com_", "other references still move");
        }

        [TestMethod, TestCategory("FortiGate")]
        public async Task ExistingIntermediateIsNotAWarning()
        {
            _fgt.CaAlreadyExists = true;

            var results = await Execute("www_example_com");

            Assert.IsTrue(results.All(r => r.IsSuccess && !r.IsWarning), Messages(results));
        }

        [TestMethod, TestCategory("FortiGate")]
        public async Task IntermediateFailureIsWarningOnly()
        {
            _fgt.CaError = "Permission denied";

            var results = await Execute("www_example_com");

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
            Assert.IsTrue(results.Any(r => r.IsWarning && r.Message.Contains("intermediate") && r.Message.Contains("Permission denied")));
            Assert.AreEqual(1, _fgt.LocalCerts.Count);
        }

        [TestMethod, TestCategory("FortiGate")]
        public async Task UsesConfiguredVdom()
        {
            var results = await Execute("www_example_com", vdom: "customers");

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
            Assert.IsTrue(_fgt.Requests.All(r => r.Query.GetValueOrDefault("vdom") == "customers"));
        }

        [TestMethod, TestCategory("FortiGate")]
        public async Task ReportsAccessDenied()
        {
            var results = await Execute("www_example_com", token: "wrong");

            var failure = results.Single(r => !r.IsSuccess);
            StringAssert.Contains(failure.Message, "access denied");
            StringAssert.Contains(failure.Message, "trusted hosts");
            Assert.AreEqual(1, _fgt.Requests.Count);
        }

        [TestMethod, TestCategory("FortiGate")]
        public async Task ReportsNonFortiOsResponse()
        {
            _fgt.ReturnHtml = true;

            var results = await Execute("www_example_com");

            StringAssert.Contains(results.Single(r => !r.IsSuccess).Message, "unexpected response");
        }

        [TestMethod, TestCategory("FortiGate")]
        public async Task ValidatesSettings()
        {
            var provider = new FortiGate();

            async Task<List<ActionResult>> validate(string address, string certName, string token = "abc", string vdom = null)
                => await provider.Validate(CreateParams(address, certName, token, false, vdom));

            Assert.AreEqual(0, (await validate("https://192.168.1.99", "www_example_com")).Count);
            Assert.AreEqual(0, (await validate("https://fw.example.com:10443/", "wildcard.example.com", vdom: "customers")).Count);
            Assert.IsTrue((await validate("", "www_example_com")).Any(r => !r.IsSuccess));
            Assert.IsTrue((await validate("192.168.1.99", "www_example_com")).Any(r => !r.IsSuccess));
            Assert.IsTrue((await validate("https://192.168.1.99", "")).Any(r => !r.IsSuccess));
            Assert.IsTrue((await validate("https://192.168.1.99", "*.example.com")).Any(r => !r.IsSuccess));
            Assert.IsTrue((await validate("https://192.168.1.99", "a_name_longer_than_22ch")).Any(r => !r.IsSuccess));
            Assert.IsTrue((await validate("https://192.168.1.99", "www_example_com", vdom: "root&x=1")).Any(r => !r.IsSuccess));
            Assert.IsTrue((await validate("https://192.168.1.99", "www_example_com", token: " ")).Any(r => !r.IsSuccess));
        }

        private void UseChain(int intermediates)
        {
            DeletePfx();
            (_pfxPath, _) = TestCertificates.CreatePfxWithChain(intermediates);
        }

        private void DeletePfx()
        {
            if (_pfxPath != null && File.Exists(_pfxPath))
            {
                File.Delete(_pfxPath);
            }
        }

        private static JsonArray List(params string[] names) => new JsonArray(names.Select(n => (JsonNode)new JsonObject { ["name"] = n, ["q_origin_key"] = n }).ToArray());

        private static string[] Names(JsonNode list) => list.AsArray().Select(i => i["name"].ToString()).ToArray();

        private static string Decode(JsonNode base64) => Encoding.ASCII.GetString(Convert.FromBase64String(base64.ToString()));

        private static string Messages(List<ActionResult> results) => string.Join("; ", results.Select(r => r.Message));

        private static int CountOf(string text, string value) => (text.Length - text.Replace(value, "").Length) / value.Length;

        private async Task<List<ActionResult>> Execute(string certName, bool isPreviewOnly = false, string token = "token123", string certificatePath = null, string vdom = null)
        {
            var execParams = CreateParams(_fgt.Address, certName, token, isPreviewOnly, vdom);
            if (certificatePath != null)
            {
                ((ManagedCertificate)execParams.Subject).CertificatePath = certificatePath;
            }

            return await new FortiGate().Execute(execParams);
        }

        private DeploymentTaskExecutionParams CreateParams(string address, string certName, string token, bool isPreviewOnly, string vdom)
        {
            var config = new DeploymentTaskConfig
            {
                TaskTypeId = FortiGate.Definition.Id,
                TaskName = "FortiGate test",
                ChallengeProvider = StandardAuthTypes.STANDARD_AUTH_API_TOKEN,
                Parameters = new List<ProviderParameterSetting>
                {
                    new ProviderParameterSetting("fgt_address", address),
                    new ProviderParameterSetting("cert_name", certName)
                }
            };

            if (vdom != null)
            {
                config.Parameters.Add(new ProviderParameterSetting("vdom", vdom));
            }

            var managedCert = GetMockManagedCertificate("FortiGateTest", "1", "www.example.com", PrimaryIISRoot);
            managedCert.CertificatePath = _pfxPath;

            var credentials = new Dictionary<string, string> { { "api_token", token } };
            return new DeploymentTaskExecutionParams(_log, null, managedCert, config, credentials, isPreviewOnly, FortiGate.Definition, new DeploymentContext(), CancellationToken.None);
        }

        /// <summary>
        /// Stand-in for the FortiOS REST API: available certificates, object usage, certificate and CA import, certificate delete, and
        /// CMDB read and update of the configuration objects which use certificates
        /// </summary>
        private sealed class FakeFortiGate : IDisposable
        {
            private const int CertificateQType = 155;

            private readonly FakeHttpServer _server;
            private readonly string _token;

            // configuration objects by path ("firewall/vip") and key (null for a single object such as system/global)
            private readonly Dictionary<(string Path, string MKey), JsonObject> _objects = new Dictionary<(string, string), JsonObject>();

            public string Address => _server.Address;
            public List<FakeHttpRequest> Requests => _server.Requests;

            public HashSet<string> LocalCerts { get; } = new HashSet<string>();
            public HashSet<string> FactoryCerts { get; } = new HashSet<string>();
            public List<string> CaCerts { get; } = new List<string>();

            public string ImportError { get; set; }
            public string CaError { get; set; }
            public bool CaAlreadyExists { get; set; }
            public (string Object, string Error)? PutError { get; set; }
            public bool ReturnHtml { get; set; }

            public FakeFortiGate(string token)
            {
                _token = token;
                _server = new FakeHttpServer(Handle);
            }

            public void SetObject(string path, string mkey, JsonObject value) => _objects[(path, mkey)] = value;

            public JsonObject GetObject(string path, string mkey) => _objects[(path, mkey)];

            private FakeHttpResponse Handle(FakeHttpRequest r)
            {
                if (ReturnHtml)
                {
                    return new FakeHttpResponse(200, "text/html", "<!DOCTYPE html><html><body>Login</body></html>");
                }

                if (r.Header("Authorization") != "Bearer " + _token)
                {
                    return new FakeHttpResponse(401, "text/html", "<html><body>401 Unauthorized</body></html>");
                }

                Assert.IsFalse(string.IsNullOrEmpty(r.Query.GetValueOrDefault("vdom")), "every request names the VDOM");
                var body = string.IsNullOrEmpty(r.Body) ? null : JsonNode.Parse(r.Body);
                var path = r.Path["/api/v2/".Length..];

                switch (r.Method, path)
                {
                    case ("GET", "monitor/system/available-certificates"):
                        var certs = LocalCerts.Select(c => (c, "user")).Concat(FactoryCerts.Select(c => (c, "factory")))
                            .Select(c => (JsonNode)new JsonObject { ["name"] = c.Item1, ["source"] = c.Item2, ["q_type"] = CertificateQType, ["type"] = "local-cer" });
                        return Success(new JsonArray(certs.ToArray()));

                    case ("GET", "monitor/system/object/usage"):
                        Assert.AreEqual($"[{CertificateQType}]", r.Query["qtypes"]);
                        var usedBy = UsesOf(r.Query["mkey"])
                            .Where(u => !(u.Path == "system/global" && u.Attribute == "admin-server-cert")) // not reported by FortiOS
                            .Select(u =>
                            {
                                var parts = u.Path.Split('/');
                                var item = new JsonObject { ["path"] = parts[0], ["name"] = parts[1], ["attribute"] = u.Attribute };
                                if (u.MKey != null)
                                {
                                    item["mkey"] = u.MKey;
                                }

                                return (JsonNode)item;
                            });
                        return Success(new JsonObject { ["currently_using"] = new JsonArray(usedBy.ToArray()) });

                    case ("POST", "monitor/vpn-certificate/local/import"):
                        Assert.IsTrue(Encoding.ASCII.GetString(Convert.FromBase64String(body["file_content"].ToString())).Contains("-----BEGIN CERTIFICATE-----"));
                        var name = body["certname"].ToString();
                        if (ImportError != null)
                        {
                            return Error(500, -1, ImportError);
                        }

                        if (!LocalCerts.Add(name))
                        {
                            return Error(500, -5, "A duplicate entry already exists.");
                        }

                        return Success(new JsonObject { ["mkey"] = name });

                    case ("POST", "monitor/vpn-certificate/ca/import"):
                        if (CaError != null)
                        {
                            return Error(500, -1, CaError);
                        }

                        var content = body["file_content"].ToString();
                        if (CaAlreadyExists || CaCerts.Contains(content))
                        {
                            return Error(500, -328, "");
                        }

                        CaCerts.Add(content);
                        return Success(new JsonObject { ["mkey"] = $"CA_Cert_{CaCerts.Count}" });

                    case ("DELETE", var p) when p.StartsWith("cmdb/vpn.certificate/local/"):
                        var deleting = p["cmdb/vpn.certificate/local/".Length..];
                        if (UsesOf(deleting).Any())
                        {
                            return Error(500, -23, "The entry is used by other entries.");
                        }

                        return LocalCerts.Remove(deleting) ? Success(new JsonObject()) : Error(404, -3, "Entry not found.");

                    case (_, var p) when p.StartsWith("cmdb/"):
                        var segments = p["cmdb/".Length..].Split('/');
                        var key = (segments[0] + "/" + segments[1], segments.Length > 2 ? segments[2] : null);
                        if (!_objects.TryGetValue(key, out var obj))
                        {
                            return Error(404, -3, "Entry not found.");
                        }

                        if (r.Method == "GET")
                        {
                            // a table entry is read as an array of results, a single object as an object
                            return Success(key.Item2 != null ? new JsonArray(obj.DeepClone()) : obj.DeepClone());
                        }

                        if (r.Method == "PUT")
                        {
                            if (PutError is { } error && error.Object == $"{key.Item1}{(key.Item2 != null ? "/" + key.Item2 : "")}")
                            {
                                return Error(500, -37, error.Error);
                            }

                            foreach (var property in body.AsObject().ToList())
                            {
                                var value = property.Value?.DeepClone();
                                if (value is JsonArray list)
                                {
                                    // FortiOS adds q_origin_key to table entries
                                    foreach (var entry in list.OfType<JsonObject>())
                                    {
                                        entry["q_origin_key"] = entry["name"]?.ToString();
                                    }
                                }

                                obj[property.Key] = value;
                            }

                            return Success(new JsonObject { ["mkey"] = key.Item2 });
                        }

                        return Error(405, -1, "Method not allowed");

                    default:
                        return Error(404, -3, $"Unknown path {path}");
                }
            }

            /// <summary>
            /// Every configuration attribute which uses a certificate, as a string or in a list of { name }
            /// </summary>
            private List<(string Path, string MKey, string Attribute)> UsesOf(string certificate)
            {
                var uses = new List<(string, string, string)>();
                foreach (var ((path, mkey), obj) in _objects)
                {
                    foreach (var (attribute, value) in obj)
                    {
                        var used = value switch
                        {
                            JsonValue v => v.ToString() == certificate,
                            JsonArray a => a.Any(i => i?["name"]?.ToString() == certificate),
                            _ => false
                        };

                        if (used && attribute != "name")
                        {
                            uses.Add((path, mkey, attribute));
                        }
                    }
                }

                return uses;
            }

            private static FakeHttpResponse Success(JsonNode results)
                => new FakeHttpResponse(200, "application/json", new JsonObject { ["http_method"] = "GET", ["status"] = "success", ["http_status"] = 200, ["vdom"] = "root", ["results"] = results }.ToJsonString());

            private static FakeHttpResponse Error(int status, int error, string cliError)
                => new FakeHttpResponse(status, "application/json", new JsonObject { ["status"] = "error", ["http_status"] = status, ["error"] = error, ["cli_error"] = cliError }.ToJsonString());

            public void Dispose() => _server.Dispose();
        }
    }
}
