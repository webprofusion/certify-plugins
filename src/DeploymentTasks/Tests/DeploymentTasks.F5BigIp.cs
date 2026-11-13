using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
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
    /// Runs the F5 BIG-IP task against a local stand-in for the iControl REST API, which answers with the same JSON format and
    /// applies changes queued in a transaction only when it is committed
    /// </summary>
    [TestClass]
    public class DeploymentTasksF5BigIp : IntegrationTestBase
    {
        private const string Old = "-----BEGIN CERTIFICATE-----\nold\n-----END CERTIFICATE-----\n";

        private FakeBigIp _bigip;
        private string _pfxPath;

        [TestInitialize]
        public override void Setup()
        {
            base.Setup();

            _bigip = new FakeBigIp("admin", "secret");
            UseChain(1);
        }

        [TestCleanup]
        public void Cleanup()
        {
            _bigip?.Dispose();
            DeletePfx();
        }

        [TestMethod, TestCategory("F5BigIp")]
        public async Task UpdatesExistingObjectsInOneTransaction()
        {
            AddExisting("www.example.com", chain: true);

            var results = await Execute("www.example.com");

            Assert.IsTrue(results.All(r => r.IsSuccess && !r.IsWarning), Messages(results));
            StringAssert.Contains(results.Last().Message, "updated, with chain 'www.example.com_chain', configuration saved.");

            StringAssert.Contains(_bigip.Objects[("ssl-key", "www.example.com")], "PRIVATE KEY-----");
            Assert.AreEqual(1, CountOf(_bigip.Objects[("ssl-cert", "www.example.com")], "-----BEGIN CERTIFICATE-----"));
            Assert.IsFalse(_bigip.Objects[("ssl-cert", "www.example.com")].Contains("PRIVATE KEY"));
            Assert.AreEqual(1, CountOf(_bigip.Objects[("ssl-cert", "www.example.com_chain")], "-----BEGIN CERTIFICATE-----"));
            Assert.AreNotEqual(_bigip.Objects[("ssl-cert", "www.example.com")], _bigip.Objects[("ssl-cert", "www.example.com_chain")]);

            var writes = _bigip.Requests.Where(r => r.Path.StartsWith("/mgmt/tm/sys/file/") && r.Method != "GET").ToList();
            Assert.AreEqual(3, writes.Count);
            Assert.IsTrue(writes.All(r => r.Method == "PATCH" && r.Header("X-F5-REST-Coordination-Id") != null), "existing objects are updated in the transaction");
            Assert.AreEqual(1, _bigip.Commits);

            Assert.AreEqual(0, _bigip.Uploads.Count, "uploaded files are removed");
            Assert.AreEqual(3, _bigip.Requests.Count(r => r.Path == "/mgmt/tm/util/unix-rm"));
            Assert.AreEqual(1, _bigip.Saves);
            Assert.IsTrue(_bigip.SignedOut);
            Assert.IsTrue(_bigip.Requests.Where(r => !r.Path.EndsWith("/authn/login")).All(r => r.Header("X-F5-Auth-Token") == FakeBigIp.Token));
        }

        [TestMethod, TestCategory("F5BigIp")]
        public async Task AddsNewObjects()
        {
            var results = await Execute("www.example.com");

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
            Assert.IsTrue(_bigip.Objects.ContainsKey(("ssl-key", "www.example.com")));
            Assert.IsTrue(_bigip.Objects.ContainsKey(("ssl-cert", "www.example.com")));
            Assert.IsTrue(_bigip.Objects.ContainsKey(("ssl-cert", "www.example.com_chain")));

            var creates = _bigip.Requests.Where(r => r.Path.StartsWith("/mgmt/tm/sys/file/") && r.Method != "GET").ToList();
            Assert.IsTrue(creates.All(r => r.Method == "POST" && JsonNode.Parse(r.Body)["partition"].GetValue<string>() == "Common"));
            StringAssert.Contains(results.Last().Message, "Select it and chain 'www.example.com_chain' in the client SSL profiles");
        }

        [TestMethod, TestCategory("F5BigIp")]
        public async Task ChainHasAllIntermediates()
        {
            UseChain(2);

            var results = await Execute("www.example.com");

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
            Assert.AreEqual(2, CountOf(_bigip.Objects[("ssl-cert", "www.example.com_chain")], "-----BEGIN CERTIFICATE-----"));
        }

        [TestMethod, TestCategory("F5BigIp")]
        public async Task PreviewMakesNoChanges()
        {
            AddExisting("www.example.com", chain: false);

            var results = await Execute("www.example.com", isPreviewOnly: true);

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
            StringAssert.Contains(results.Single().Message, "Would update certificate and key 'www.example.com', add chain 'www.example.com_chain'");
            Assert.IsTrue(_bigip.Requests.All(r => r.Method == "GET" || r.Path.EndsWith("/authn/login") || r.Path.Contains("/authz/tokens/")));
            Assert.IsTrue(_bigip.SignedOut);
        }

        [TestMethod, TestCategory("F5BigIp")]
        public async Task PreviewBeforeCertificateIssuedChecksSignIn()
        {
            var results = await Execute("www.example.com", isPreviewOnly: true, certificatePath: "");

            StringAssert.Contains(results.Single().Message, "Signed in to BIG-IP");
            StringAssert.Contains(results.Single().Message, "No certificate has been issued yet");
        }

        [TestMethod, TestCategory("F5BigIp")]
        public async Task CommitFailureChangesNothing()
        {
            AddExisting("www.example.com", chain: true);
            _bigip.CommitError = "01070313:3: Error reading key PEM file";

            var results = await Execute("www.example.com");

            var failure = results.Single(r => !r.IsSuccess);
            StringAssert.Contains(failure.Message, "nothing was changed");
            StringAssert.Contains(failure.Message, "Error reading key PEM file");
            Assert.AreEqual(Old, _bigip.Objects[("ssl-cert", "www.example.com")]);
            Assert.AreEqual(0, _bigip.Uploads.Count, "uploaded files are still removed");
            Assert.AreEqual(0, _bigip.Saves);
            Assert.IsTrue(_bigip.SignedOut);
        }

        [TestMethod, TestCategory("F5BigIp")]
        public async Task UploadRemovalFailureIsWarning()
        {
            _bigip.RemoveError = "Authorization failed: user=certify resource=/mgmt/tm/util/unix-rm";

            var results = await Execute("www.example.com");

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
            Assert.IsTrue(results.Any(r => r.IsWarning && r.Message.Contains("which contains the private key") && r.Message.Contains("unix-rm")));
        }

        [TestMethod, TestCategory("F5BigIp")]
        public async Task SyncsToDeviceGroup()
        {
            var results = await Execute("www.example.com", extra: new() { ["sync_group"] = "failover-group" });

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
            CollectionAssert.AreEqual(new[] { "config-sync to-group failover-group" }, _bigip.Syncs);
            StringAssert.Contains(results.Last().Message, "synced to 'failover-group'");
        }

        [TestMethod, TestCategory("F5BigIp")]
        public async Task SaveConfigCanBeDisabled()
        {
            var results = await Execute("www.example.com", extra: new() { ["save_config"] = "false" });

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
            Assert.AreEqual(0, _bigip.Saves);
            Assert.AreEqual(0, _bigip.Syncs.Count);
        }

        [TestMethod, TestCategory("F5BigIp")]
        public async Task SaveFailureIsError()
        {
            _bigip.SaveError = "Unable to save configuration";

            var results = await Execute("www.example.com", extra: new() { ["sync_group"] = "failover-group" });

            var failure = results.Single(r => !r.IsSuccess);
            StringAssert.Contains(failure.Message, "saving the configuration failed");
            Assert.AreEqual(0, _bigip.Syncs.Count);
        }

        [TestMethod, TestCategory("F5BigIp")]
        public async Task ReportsAccessDenied()
        {
            var results = await Execute("www.example.com", password: "wrong");

            var failure = results.Single(r => !r.IsSuccess);
            StringAssert.Contains(failure.Message, "access denied");
            StringAssert.Contains(failure.Message, "Authentication failed");
            Assert.AreEqual(1, _bigip.Requests.Count);
        }

        [TestMethod, TestCategory("F5BigIp")]
        public async Task ReportsNonBigIpResponse()
        {
            _bigip.ReturnHtml = true;

            var results = await Execute("www.example.com");

            StringAssert.Contains(results.Single(r => !r.IsSuccess).Message, "unexpected response");
        }

        [TestMethod, TestCategory("F5BigIp")]
        public async Task ValidatesSettings()
        {
            var provider = new F5BigIp();

            async Task<List<ActionResult>> validate(string address, string certName, Dictionary<string, string> credentials = null, Dictionary<string, string> extra = null)
                => await provider.Validate(CreateParams(address, certName, credentials ?? Credentials("secret"), false, extra));

            Assert.AreEqual(0, (await validate("https://192.168.1.245", "www.example.com")).Count);
            Assert.AreEqual(0, (await validate("https://bigip.example.com:8443/", "_wildcard.example.com", extra: new() { ["sync_group"] = "failover-group" })).Count);
            Assert.IsTrue((await validate("", "www.example.com")).Any(r => !r.IsSuccess));
            Assert.IsTrue((await validate("192.168.1.245", "www.example.com")).Any(r => !r.IsSuccess));
            Assert.IsTrue((await validate("https://192.168.1.245", "")).Any(r => !r.IsSuccess));
            Assert.IsTrue((await validate("https://192.168.1.245", "*.example.com")).Any(r => !r.IsSuccess));
            Assert.IsTrue((await validate("https://192.168.1.245", "1www.example.com")).Any(r => !r.IsSuccess));
            Assert.IsTrue((await validate("https://192.168.1.245", "/Common/www.example.com")).Any(r => !r.IsSuccess));
            Assert.IsTrue((await validate("https://192.168.1.245", "www.example.com", extra: new() { ["sync_group"] = "group; rm" })).Any(r => !r.IsSuccess));
            Assert.IsTrue((await validate("https://192.168.1.245", "www.example.com", new Dictionary<string, string> { { "username", "admin" } })).Any(r => !r.IsSuccess));
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

        private void AddExisting(string name, bool chain)
        {
            _bigip.Objects[("ssl-key", name)] = "-----BEGIN RSA PRIVATE KEY-----\nold\n-----END RSA PRIVATE KEY-----\n";
            _bigip.Objects[("ssl-cert", name)] = Old;
            if (chain)
            {
                _bigip.Objects[("ssl-cert", name + "_chain")] = Old;
            }
        }

        private static Dictionary<string, string> Credentials(string password) => new Dictionary<string, string> { { "username", "admin" }, { "password", password } };

        private static string Messages(List<ActionResult> results) => string.Join("; ", results.Select(r => r.Message));

        private static int CountOf(string text, string value) => (text.Length - text.Replace(value, "").Length) / value.Length;

        private async Task<List<ActionResult>> Execute(string certName, bool isPreviewOnly = false, string password = "secret", string certificatePath = null, Dictionary<string, string> extra = null)
        {
            var execParams = CreateParams(_bigip.Address, certName, Credentials(password), isPreviewOnly, extra);
            if (certificatePath != null)
            {
                ((ManagedCertificate)execParams.Subject).CertificatePath = certificatePath;
            }

            return await new F5BigIp().Execute(execParams);
        }

        private DeploymentTaskExecutionParams CreateParams(string address, string certName, Dictionary<string, string> credentials, bool isPreviewOnly, Dictionary<string, string> extra)
        {
            var config = new DeploymentTaskConfig
            {
                TaskTypeId = F5BigIp.Definition.Id,
                TaskName = "F5 BIG-IP test",
                ChallengeProvider = StandardAuthTypes.STANDARD_AUTH_GENERIC,
                Parameters = new List<ProviderParameterSetting>
                {
                    new ProviderParameterSetting("bigip_address", address),
                    new ProviderParameterSetting("cert_name", certName)
                }
            };

            foreach (var (key, value) in extra ?? new())
            {
                config.Parameters.Add(new ProviderParameterSetting(key, value));
            }

            var managedCert = GetMockManagedCertificate("F5BigIpTest", "1", "www.example.com", PrimaryIISRoot);
            managedCert.CertificatePath = _pfxPath;

            return new DeploymentTaskExecutionParams(_log, null, managedCert, config, credentials, isPreviewOnly, F5BigIp.Definition, new DeploymentContext(), CancellationToken.None);
        }

        /// <summary>
        /// Stand-in for iControl REST: token sign in and sign out, file uploads, sys/file ssl-key and ssl-cert objects (changed only through
        /// a transaction), util/unix-rm, sys/config save and cm config-sync
        /// </summary>
        private sealed class FakeBigIp : IDisposable
        {
            public const string Token = "TOKEN123";
            private const string UploadFolder = "/var/config/rest/downloads/";

            private readonly FakeHttpServer _server;
            private readonly string _username;
            private readonly string _password;
            private readonly Dictionary<string, List<Action>> _transactions = new Dictionary<string, List<Action>>();
            private int _nextTransaction = 1000;

            public string Address => _server.Address;
            public List<FakeHttpRequest> Requests => _server.Requests;

            public Dictionary<string, string> Uploads { get; } = new Dictionary<string, string>();
            public Dictionary<(string Type, string Name), string> Objects { get; } = new Dictionary<(string, string), string>();
            public List<string> Syncs { get; } = new List<string>();
            public int Saves { get; private set; }
            public int Commits { get; private set; }
            public bool SignedOut { get; private set; }

            public string CommitError { get; set; }
            public string RemoveError { get; set; }
            public string SaveError { get; set; }
            public bool ReturnHtml { get; set; }

            public FakeBigIp(string username, string password)
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

                var body = string.IsNullOrEmpty(r.Body) || r.Header("Content-Type")?.StartsWith("application/json") != true ? null : JsonNode.Parse(r.Body);

                if (r.Method == "POST" && r.Path == "/mgmt/shared/authn/login")
                {
                    Assert.AreEqual("tmos", body["loginProviderName"].GetValue<string>());
                    return body["username"].GetValue<string>() == _username && body["password"].GetValue<string>() == _password
                        ? Json(200, new JsonObject { ["username"] = _username, ["token"] = new JsonObject { ["token"] = Token, ["timeout"] = 1200 } })
                        : Error(401, "Authentication failed.");
                }

                if (r.Header("X-F5-Auth-Token") != Token)
                {
                    return Error(401, "Authorization failed: no user authentication header or token detected.");
                }

                if (r.Method == "DELETE" && r.Path == $"/mgmt/shared/authz/tokens/{Token}")
                {
                    SignedOut = true;
                    return Json(200, new JsonObject());
                }

                if (r.Method == "POST" && r.Path.StartsWith("/mgmt/shared/file-transfer/uploads/"))
                {
                    Assert.AreEqual($"0-{r.Body.Length - 1}/{r.Body.Length}", r.Header("Content-Range"));
                    Assert.AreEqual("application/octet-stream", r.Header("Content-Type"));
                    var file = r.Path["/mgmt/shared/file-transfer/uploads/".Length..];
                    Uploads[file] = r.Body;
                    return Json(200, new JsonObject { ["remoteSize"] = r.Body.Length, ["localFilePath"] = UploadFolder + file });
                }

                var transaction = r.Header("X-F5-REST-Coordination-Id");
                var fileObject = System.Text.RegularExpressions.Regex.Match(r.Path, "^/mgmt/tm/sys/file/(ssl-key|ssl-cert)(?:/~Common~(.+))?$");

                if (fileObject.Success)
                {
                    var type = fileObject.Groups[1].Value;
                    var name = fileObject.Groups[2].Success ? fileObject.Groups[2].Value : body?["name"]?.GetValue<string>();

                    if (r.Method == "GET")
                    {
                        return Objects.ContainsKey((type, name)) ? Json(200, new JsonObject { ["name"] = name, ["partition"] = "Common" }) : Error(404, $"01020036:3: The requested {type} (/Common/{name}) was not found.");
                    }

                    // object changes are only made in a transaction by the task, so the fake only supports them there
                    Assert.IsNotNull(transaction, "sys/file changes are made in a transaction");
                    var sourcePath = body["sourcePath"].GetValue<string>();
                    Assert.IsTrue(sourcePath.StartsWith("file://" + UploadFolder), sourcePath);
                    var upload = sourcePath[("file://" + UploadFolder).Length..];

                    if (r.Method == "POST")
                    {
                        Assert.AreEqual("Common", body["partition"].GetValue<string>());
                    }

                    _transactions[transaction].Add(() =>
                    {
                        if (r.Method == "PATCH" && !Objects.ContainsKey((type, name)))
                        {
                            throw new InvalidOperationException($"01020036:3: The requested {type} (/Common/{name}) was not found.");
                        }

                        if (r.Method == "POST" && Objects.ContainsKey((type, name)))
                        {
                            throw new InvalidOperationException($"01020066:3: The requested {type} (/Common/{name}) already exists.");
                        }

                        Objects[(type, name)] = Uploads.TryGetValue(upload, out var content) ? content : throw new InvalidOperationException($"File not found: {sourcePath}");
                    });

                    return Json(200, body.AsObject().DeepClone());
                }

                switch (r.Method, r.Path)
                {
                    case ("POST", "/mgmt/tm/transaction"):
                        var id = (_nextTransaction++).ToString();
                        _transactions[id] = new List<Action>();
                        return Json(200, new JsonObject { ["transId"] = long.Parse(id), ["state"] = "STARTED" });

                    case ("PATCH", var path) when path.StartsWith("/mgmt/tm/transaction/"):
                        var commitId = path["/mgmt/tm/transaction/".Length..];
                        Assert.AreEqual("VALIDATING", body["state"].GetValue<string>());
                        var actions = _transactions[commitId];
                        _transactions.Remove(commitId);

                        if (CommitError != null)
                        {
                            return Error(400, $"transaction failed:{CommitError}");
                        }

                        // all or nothing
                        var before = Objects.ToDictionary(o => o.Key, o => o.Value);
                        try
                        {
                            actions.ForEach(a => a());
                        }
                        catch (InvalidOperationException exp)
                        {
                            Objects.Clear();
                            foreach (var o in before)
                            {
                                Objects[o.Key] = o.Value;
                            }

                            return Error(400, $"transaction failed:{exp.Message}");
                        }

                        Commits++;
                        return Json(200, new JsonObject { ["transId"] = long.Parse(commitId), ["state"] = "COMPLETED" });

                    case ("DELETE", var path) when path.StartsWith("/mgmt/tm/transaction/"):
                        _transactions.Remove(path["/mgmt/tm/transaction/".Length..]);
                        return Json(200, new JsonObject());

                    case ("POST", "/mgmt/tm/util/unix-rm"):
                        Assert.AreEqual("run", body["command"].GetValue<string>());
                        if (RemoveError != null)
                        {
                            return Error(400, RemoveError);
                        }

                        var removePath = body["utilCmdArgs"].GetValue<string>();
                        Assert.IsTrue(removePath.StartsWith(UploadFolder));
                        Uploads.Remove(removePath[UploadFolder.Length..]);
                        return Json(200, new JsonObject { ["kind"] = "tm:util:unix-rm:runstate", ["command"] = "run", ["utilCmdArgs"] = removePath });

                    case ("POST", "/mgmt/tm/sys/config"):
                        Assert.AreEqual("save", body["command"].GetValue<string>());
                        if (SaveError != null)
                        {
                            return Error(400, SaveError);
                        }

                        Saves++;
                        return Json(200, new JsonObject { ["kind"] = "tm:sys:config:savestate", ["command"] = "save" });

                    case ("POST", "/mgmt/tm/cm"):
                        Assert.AreEqual("run", body["command"].GetValue<string>());
                        Syncs.Add(body["utilCmdArgs"].GetValue<string>());
                        return Json(200, new JsonObject { ["kind"] = "tm:cm:runstate", ["command"] = "run" });

                    default:
                        return Error(404, $"URI path {r.Path} not registered.");
                }
            }

            private static FakeHttpResponse Json(int status, JsonNode body) => new FakeHttpResponse(status, "application/json", body.ToJsonString());

            private static FakeHttpResponse Error(int status, string message)
                => Json(status, new JsonObject { ["code"] = status, ["message"] = message, ["errorStack"] = new JsonArray(), ["apiError"] = 3 });

            public void Dispose() => _server.Dispose();
        }
    }
}
