using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json.Nodes;
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
    /// Runs the NetScaler task against a local stand-in for the NITRO configuration API, which answers with the same JSON format and errors
    /// </summary>
    [TestClass]
    public class DeploymentTasksNetScaler : IntegrationTestBase
    {
        private const string OldCertFile = "www_example_com-20250101-000000000.crt";
        private const string OldKeyFile = "www_example_com-20250101-000000000.key";

        private FakeNetScaler _ns;
        private string _pfxPath;
        private List<string> _intermediates;

        [TestInitialize]
        public override void Setup()
        {
            base.Setup();

            _ns = new FakeNetScaler("nsroot", "secret");
            UseChain(1);
        }

        [TestCleanup]
        public void Cleanup()
        {
            _ns?.Dispose();
            DeletePfx();
        }

        [TestMethod, TestCategory("NetScaler")]
        public async Task UpdatesExistingPairAndLinksIntermediate()
        {
            AddExistingPair("www_example_com", OldCertFile, OldKeyFile);

            var results = await Execute("www_example_com");

            Assert.IsTrue(results.All(r => r.IsSuccess && !r.IsWarning), Messages(results));
            StringAssert.Contains(results.Last().Message, "updated and configuration saved");

            var pair = _ns.CertKeys["www_example_com"];
            Assert.AreNotEqual(OldCertFile, pair.Cert);
            StringAssert.StartsWith(pair.Cert, "www_example_com-");
            StringAssert.Contains(_ns.Files[pair.Cert], "-----BEGIN CERTIFICATE-----");
            StringAssert.Contains(_ns.Files[pair.Key], "PRIVATE KEY-----");
            Assert.AreEqual(1, CountOf(_ns.Files[pair.Cert], "-----BEGIN CERTIFICATE-----"), "only the leaf certificate is in the certificate file");

            var update = _ns.Requests.Single(r => r.Path.EndsWith("/sslcertkey") && r.Query.GetValueOrDefault("action") == "update");
            Assert.AreEqual(true, Payload(update)["nodomaincheck"]?.GetValue<bool>());

            var intermediateName = IntermediateName(0);
            Assert.IsTrue(_ns.CertKeys.ContainsKey(intermediateName));
            Assert.IsNull(_ns.CertKeys[intermediateName].Key);
            Assert.AreEqual(intermediateName, pair.Link);
            Assert.AreEqual(1, _ns.Saves);

            var addIntermediate = _ns.Requests.Single(r => r.Method == "POST" && r.Path.EndsWith("/sslcertkey") && !r.Query.ContainsKey("action"));
            Assert.IsTrue(_ns.Requests.IndexOf(addIntermediate) < _ns.Requests.IndexOf(update), "intermediate is added before the certificate changes");

            Assert.IsFalse(_ns.Files.ContainsKey(OldCertFile) || _ns.Files.ContainsKey(OldKeyFile), "previous files are removed");
            Assert.IsTrue(_ns.Requests.All(r => r.Header("X-NITRO-USER") == "nsroot" && r.Header("X-NITRO-PASS") == "secret"));

            // a second deployment does not add or relink the intermediate, and removes the first deployment's files
            var firstFiles = (pair.Cert, pair.Key);
            _ns.Requests.Clear();
            await Task.Delay(5);

            results = await Execute("www_example_com");

            Assert.IsTrue(results.All(r => r.IsSuccess && !r.IsWarning), Messages(results));
            Assert.IsFalse(_ns.Requests.Any(r => r.Path.EndsWith("/sslcertkey") && r.Method == "POST" && r.Query.GetValueOrDefault("action") != "update"));
            Assert.IsFalse(_ns.Files.ContainsKey(firstFiles.Cert) || _ns.Files.ContainsKey(firstFiles.Key));
            Assert.AreEqual(2, _ns.Saves);
        }

        [TestMethod, TestCategory("NetScaler")]
        public async Task AddsNewPair()
        {
            var results = await Execute("new_example_com");

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
            Assert.IsTrue(_ns.CertKeys.ContainsKey("new_example_com"));
            Assert.IsFalse(_ns.Requests.Any(r => r.Query.GetValueOrDefault("action") == "update"));
            Assert.AreEqual(IntermediateName(0), _ns.CertKeys["new_example_com"].Link);
            StringAssert.Contains(results.Last().Message, "Bind it to the required virtual servers");
        }

        [TestMethod, TestCategory("NetScaler")]
        public async Task LinksEachIntermediateToItsIssuer()
        {
            UseChain(2);

            var results = await Execute("www_example_com");

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
            Assert.AreEqual(IntermediateName(0), _ns.CertKeys["www_example_com"].Link);
            Assert.AreEqual(IntermediateName(1), _ns.CertKeys[IntermediateName(0)].Link);
            Assert.IsNull(_ns.CertKeys[IntermediateName(1)].Link);
        }

        [TestMethod, TestCategory("NetScaler")]
        public async Task RelinksWhenIssuerChanges()
        {
            _ns.CertKeys["old-ca"] = new FakeCertKey { Cert = "old-ca.crt" };
            AddExistingPair("www_example_com", OldCertFile, OldKeyFile, link: "old-ca");

            var results = await Execute("www_example_com");

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
            Assert.AreEqual(IntermediateName(0), _ns.CertKeys["www_example_com"].Link);
            Assert.IsTrue(_ns.Requests.Any(r => r.Query.GetValueOrDefault("action") == "unlink"));
        }

        [TestMethod, TestCategory("NetScaler")]
        public async Task PreviewMakesNoChanges()
        {
            AddExistingPair("www_example_com", OldCertFile, OldKeyFile);

            var results = await Execute("www_example_com", isPreviewOnly: true);

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
            StringAssert.Contains(results.Single().Message, "Would update certificate-key pair 'www_example_com'");
            StringAssert.Contains(results.Single().Message, "add 1 intermediate certificate");
            StringAssert.Contains(results.Single().Message, "save the configuration");
            Assert.IsTrue(_ns.Requests.All(r => r.Method == "GET"));
        }

        [TestMethod, TestCategory("NetScaler")]
        public async Task PreviewBeforeCertificateIssuedChecksSignIn()
        {
            var results = await Execute("www_example_com", isPreviewOnly: true, certificatePath: "");

            StringAssert.Contains(results.Single().Message, "Signed in to NetScaler");
            StringAssert.Contains(results.Single().Message, "No certificate has been issued yet");
            Assert.IsTrue(_ns.Requests.All(r => r.Method == "GET"));
        }

        [TestMethod, TestCategory("NetScaler")]
        public async Task UpdateFailureRemovesUploadedFiles()
        {
            AddExistingPair("www_example_com", OldCertFile, OldKeyFile);
            _ns.UpdateError = "Certificate and key do not match";

            var results = await Execute("www_example_com");

            StringAssert.Contains(results.Single(r => !r.IsSuccess).Message, "Certificate and key do not match");
            Assert.AreEqual(OldCertFile, _ns.CertKeys["www_example_com"].Cert);
            Assert.IsFalse(_ns.Files.Keys.Any(f => f.StartsWith("www_example_com-") && f != OldCertFile && f != OldKeyFile), "uploaded files are removed");
            Assert.IsTrue(_ns.Files.ContainsKey(OldCertFile) && _ns.Files.ContainsKey(OldKeyFile), "files in use are kept");
            Assert.AreEqual(0, _ns.Saves);
        }

        [TestMethod, TestCategory("NetScaler")]
        public async Task KeepsPreviousFilesNotUploadedByTask()
        {
            AddExistingPair("www_example_com", "www.example.com.pem", "www.example.com.key");

            var results = await Execute("www_example_com");

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
            Assert.IsTrue(_ns.Files.ContainsKey("www.example.com.pem") && _ns.Files.ContainsKey("www.example.com.key"));
            Assert.IsFalse(_ns.Requests.Any(r => r.Method == "DELETE"));
        }

        [TestMethod, TestCategory("NetScaler")]
        public async Task SaveConfigCanBeDisabled()
        {
            var results = await Execute("www_example_com", saveConfig: "false");

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
            Assert.AreEqual(0, _ns.Saves);
            Assert.IsFalse(results.Last().Message.Contains("configuration saved"));
        }

        [TestMethod, TestCategory("NetScaler")]
        public async Task SaveFailureIsError()
        {
            _ns.SaveError = "Operation not permitted";

            var results = await Execute("www_example_com");

            var failure = results.Single(r => !r.IsSuccess);
            StringAssert.Contains(failure.Message, "saving the configuration failed");
            StringAssert.Contains(failure.Message, "Operation not permitted");
        }

        [TestMethod, TestCategory("NetScaler")]
        public async Task IntermediateFailureIsWarningOnly()
        {
            _ns.AddIntermediateError = "Certificate already exists";

            var results = await Execute("www_example_com");

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
            Assert.IsTrue(results.Any(r => r.IsWarning && r.Message.Contains("Certificate already exists")));
            Assert.IsTrue(_ns.CertKeys.ContainsKey("www_example_com"));
            Assert.IsFalse(_ns.Requests.Any(r => r.Query.GetValueOrDefault("action") == "link"));
        }

        [TestMethod, TestCategory("NetScaler")]
        public async Task LinkFailureIsError()
        {
            _ns.LinkError = "Invalid certificate link";

            var results = await Execute("www_example_com");

            var failure = results.Single(r => !r.IsSuccess);
            StringAssert.Contains(failure.Message, "could not be linked");
            StringAssert.Contains(failure.Message, "Invalid certificate link");
            Assert.AreEqual(1, _ns.Saves, "the configuration is still saved, as the certificate itself changed");
        }

        [TestMethod, TestCategory("NetScaler")]
        public async Task ReportsAccessDenied()
        {
            var results = await Execute("www_example_com", password: "wrong");

            var failure = results.Single(r => !r.IsSuccess);
            StringAssert.Contains(failure.Message, "access denied");
            StringAssert.Contains(failure.Message, "Invalid username or password");
            Assert.IsTrue(_ns.Requests.All(r => r.Method == "GET"));
        }

        [TestMethod, TestCategory("NetScaler")]
        public async Task ReportsNonNitroResponse()
        {
            _ns.ReturnHtml = true;

            var results = await Execute("www_example_com");

            StringAssert.Contains(results.Single(r => !r.IsSuccess).Message, "unexpected response");
        }

        [TestMethod, TestCategory("NetScaler")]
        public async Task ValidatesSettings()
        {
            var provider = new NetScaler();

            async Task<List<ActionResult>> validate(string address, string certKeyName, Dictionary<string, string> credentials = null) => await provider.Validate(CreateParams(address, certKeyName, credentials ?? Credentials("secret"), false, null));

            Assert.AreEqual(0, (await validate("https://192.168.1.10", "www_example_com")).Count);
            Assert.AreEqual(0, (await validate("https://ns.example.com:8443/", "www.example.com 2026")).Count);
            Assert.AreEqual(0, (await validate("https://192.168.1.10", "_wildcard-example.com")).Count);
            Assert.IsTrue((await validate("", "www_example_com")).Any(r => !r.IsSuccess));
            Assert.IsTrue((await validate("192.168.1.10", "www_example_com")).Any(r => !r.IsSuccess));
            Assert.IsTrue((await validate("https://192.168.1.10", "")).Any(r => !r.IsSuccess));
            Assert.IsTrue((await validate("https://192.168.1.10", "*.example.com")).Any(r => !r.IsSuccess));
            Assert.IsTrue((await validate("https://192.168.1.10", "-www")).Any(r => !r.IsSuccess));
            Assert.IsTrue((await validate("https://192.168.1.10", new string('a', 64))).Any(r => !r.IsSuccess));
            Assert.IsTrue((await validate("https://192.168.1.10", "www_example_com", new Dictionary<string, string> { { "username", "nsroot" } })).Any(r => !r.IsSuccess));
        }

        private void UseChain(int intermediates)
        {
            DeletePfx();
            (_pfxPath, _intermediates) = TestCertificates.CreatePfxWithChain(intermediates);
        }

        private void DeletePfx()
        {
            if (_pfxPath != null && File.Exists(_pfxPath))
            {
                File.Delete(_pfxPath);
            }
        }

        private string IntermediateName(int index) => $"certify-ca-{_intermediates[index][..16]}";

        private void AddExistingPair(string name, string certFile, string keyFile, string link = null)
        {
            _ns.Files[certFile] = "-----BEGIN CERTIFICATE-----\nold\n-----END CERTIFICATE-----\n";
            _ns.Files[keyFile] = "-----BEGIN RSA PRIVATE KEY-----\nold\n-----END RSA PRIVATE KEY-----\n";
            _ns.CertKeys[name] = new FakeCertKey { Cert = certFile, Key = keyFile, Link = link };
        }

        private static Dictionary<string, string> Credentials(string password) => new Dictionary<string, string> { { "username", "nsroot" }, { "password", password } };

        private static string Messages(List<ActionResult> results) => string.Join("; ", results.Select(r => r.Message));

        private static JsonNode Payload(FakeHttpRequest request) => JsonNode.Parse(request.Body)["sslcertkey"];

        private static int CountOf(string text, string value) => (text.Length - text.Replace(value, "").Length) / value.Length;

        private async Task<List<ActionResult>> Execute(string certKeyName, bool isPreviewOnly = false, string password = "secret", string certificatePath = null, string saveConfig = null)
        {
            var execParams = CreateParams(_ns.Address, certKeyName, Credentials(password), isPreviewOnly, saveConfig);
            if (certificatePath != null)
            {
                ((ManagedCertificate)execParams.Subject).CertificatePath = certificatePath;
            }

            return await new NetScaler().Execute(execParams);
        }

        private DeploymentTaskExecutionParams CreateParams(string address, string certKeyName, Dictionary<string, string> credentials, bool isPreviewOnly, string saveConfig)
        {
            var config = new DeploymentTaskConfig
            {
                TaskTypeId = NetScaler.Definition.Id,
                TaskName = "NetScaler test",
                ChallengeProvider = StandardAuthTypes.STANDARD_AUTH_GENERIC,
                Parameters = new List<ProviderParameterSetting>
                {
                    new ProviderParameterSetting("ns_address", address),
                    new ProviderParameterSetting("certkey_name", certKeyName)
                }
            };

            if (saveConfig != null)
            {
                config.Parameters.Add(new ProviderParameterSetting("save_config", saveConfig));
            }

            var managedCert = GetMockManagedCertificate("NetScalerTest", "1", "www.example.com", PrimaryIISRoot);
            managedCert.CertificatePath = _pfxPath;

            return new DeploymentTaskExecutionParams(_log, null, managedCert, config, credentials, isPreviewOnly, NetScaler.Definition, new DeploymentContext(), CancellationToken.None);
        }

        private sealed class FakeCertKey
        {
            public string Cert { get; set; }
            public string Key { get; set; }
            public string Link { get; set; }
        }

        /// <summary>
        /// Stand-in for the NITRO configuration API: sslcertkey (list, add, update, link, unlink), systemfile (add, delete) and nsconfig save,
        /// authenticated with the X-NITRO-USER and X-NITRO-PASS headers
        /// </summary>
        private sealed class FakeNetScaler : IDisposable
        {
            private const string ApiPath = "/nitro/v1/config/";
            private const string SslFolder = "/nsconfig/ssl";

            private readonly FakeHttpServer _server;
            private readonly string _username;
            private readonly string _password;

            public string Address => _server.Address;
            public List<FakeHttpRequest> Requests => _server.Requests;

            /// <summary>
            /// Files in /nsconfig/ssl, by name
            /// </summary>
            public Dictionary<string, string> Files { get; } = new Dictionary<string, string>();
            public Dictionary<string, FakeCertKey> CertKeys { get; } = new Dictionary<string, FakeCertKey>();
            public int Saves { get; private set; }

            public string UpdateError { get; set; }
            public string AddIntermediateError { get; set; }
            public string LinkError { get; set; }
            public string SaveError { get; set; }
            public bool ReturnHtml { get; set; }

            public FakeNetScaler(string username, string password)
            {
                _username = username;
                _password = password;
                _server = new FakeHttpServer(Handle);
            }

            private FakeHttpResponse Handle(FakeHttpRequest r)
            {
                if (ReturnHtml)
                {
                    return new FakeHttpResponse(200, "text/html", "<!DOCTYPE html><html><body>Login</body></html>");
                }

                if (r.Header("X-NITRO-USER") != _username || r.Header("X-NITRO-PASS") != _password)
                {
                    return Error(401, 354, "Invalid username or password");
                }

                if (!r.Path.StartsWith(ApiPath))
                {
                    return Error(404, 258, "No such resource");
                }

                var resource = r.Path[ApiPath.Length..];
                var action = r.Query.GetValueOrDefault("action");
                var body = string.IsNullOrEmpty(r.Body) ? null : JsonNode.Parse(r.Body);

                switch (r.Method, resource, action)
                {
                    case ("GET", "sslcertkey", null):
                        var list = new JsonArray(CertKeys.Select(c => (JsonNode)new JsonObject
                        {
                            ["certkey"] = c.Key,
                            ["cert"] = $"{SslFolder}/{c.Value.Cert}",
                            ["key"] = c.Value.Key == null ? null : $"{SslFolder}/{c.Value.Key}",
                            ["linkcertkeyname"] = c.Value.Link,
                            ["inform"] = "PEM"
                        }).ToArray());
                        var listResult = Done();
                        if (list.Count > 0)
                        {
                            listResult["sslcertkey"] = list;
                        }

                        return new FakeHttpResponse(200, "application/json", listResult.ToJsonString());

                    case ("POST", "systemfile", null):
                        var file = body["systemfile"];
                        Assert.AreEqual(SslFolder, file["filelocation"].GetValue<string>());
                        Assert.AreEqual("BASE64", file["fileencoding"].GetValue<string>());
                        var fileName = file["filename"].GetValue<string>();
                        if (Files.ContainsKey(fileName))
                        {
                            return Error(409, 1642, "File already exists");
                        }

                        Files[fileName] = Encoding.ASCII.GetString(Convert.FromBase64String(file["filecontent"].GetValue<string>()));
                        return Ok(201);

                    case ("DELETE", var path, null) when path.StartsWith("systemfile/"):
                        Assert.AreEqual($"filelocation:{SslFolder}", r.Query.GetValueOrDefault("args"));
                        return Files.Remove(path["systemfile/".Length..]) ? Ok() : Error(404, 3441, "No such file or directory");

                    case ("POST", "sslcertkey", null):
                        var add = body["sslcertkey"];
                        var name = add["certkey"].GetValue<string>();
                        var key = add["key"]?.GetValue<string>();
                        if (key == null && AddIntermediateError != null)
                        {
                            return Error(599, 1540, AddIntermediateError);
                        }

                        if (CertKeys.ContainsKey(name))
                        {
                            return Error(409, 273, "Resource already exists");
                        }

                        var missing = MissingFile(add["cert"].GetValue<string>(), key);
                        if (missing != null)
                        {
                            return missing;
                        }

                        CertKeys[name] = new FakeCertKey { Cert = add["cert"].GetValue<string>(), Key = key };
                        return Ok(201);

                    case ("POST", "sslcertkey", "update"):
                        var update = body["sslcertkey"];
                        if (!CertKeys.TryGetValue(update["certkey"].GetValue<string>(), out var existing))
                        {
                            return Error(404, 258, "No such resource");
                        }

                        if (UpdateError != null)
                        {
                            return Error(599, 1660, UpdateError);
                        }

                        var missingUpdate = MissingFile(update["cert"].GetValue<string>(), update["key"]?.GetValue<string>());
                        if (missingUpdate != null)
                        {
                            return missingUpdate;
                        }

                        existing.Cert = update["cert"].GetValue<string>();
                        existing.Key = update["key"]?.GetValue<string>();
                        return Ok();

                    case ("POST", "sslcertkey", "link"):
                        var link = body["sslcertkey"];
                        var from = CertKeys.GetValueOrDefault(link["certkey"].GetValue<string>());
                        var to = link["linkcertkeyname"].GetValue<string>();
                        if (LinkError != null)
                        {
                            return Error(599, 1541, LinkError);
                        }

                        if (from == null || !CertKeys.ContainsKey(to))
                        {
                            return Error(404, 258, "No such resource");
                        }

                        if (from.Link != null)
                        {
                            return Error(599, 1542, "Certificate already linked");
                        }

                        from.Link = to;
                        return Ok();

                    case ("POST", "sslcertkey", "unlink"):
                        var unlink = CertKeys.GetValueOrDefault(body["sslcertkey"]["certkey"].GetValue<string>());
                        if (unlink == null)
                        {
                            return Error(404, 258, "No such resource");
                        }

                        unlink.Link = null;
                        return Ok();

                    case ("POST", "nsconfig", "save"):
                        if (SaveError != null)
                        {
                            return Error(599, 1, SaveError);
                        }

                        Saves++;
                        return Ok();

                    default:
                        return Error(405, 1, "Not implemented by fake");
                }
            }

            private FakeHttpResponse MissingFile(string cert, string key)
            {
                foreach (var file in new[] { cert, key }.Where(f => f != null))
                {
                    if (!Files.ContainsKey(file))
                    {
                        return Error(599, 1561, $"Invalid file: {file}");
                    }
                }

                return null;
            }

            private static JsonObject Done() => new JsonObject { ["errorcode"] = 0, ["message"] = "Done", ["severity"] = "NONE" };

            private static FakeHttpResponse Ok(int status = 200) => new FakeHttpResponse(status, "application/json", Done().ToJsonString());

            private static FakeHttpResponse Error(int status, int errorCode, string message)
                => new FakeHttpResponse(status, "application/json", new JsonObject { ["errorcode"] = errorCode, ["message"] = message, ["severity"] = "ERROR" }.ToJsonString());

            public void Dispose() => _server.Dispose();
        }
    }
}
