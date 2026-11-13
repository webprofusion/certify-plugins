using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
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
    /// Runs the Kemp LoadMaster task against a local stand-in for the LoadMaster RESTful API (/access), which answers with the same XML response format
    /// </summary>
    [TestClass]
    public class DeploymentTasksKempLoadMaster : IntegrationTestBase
    {
        private FakeLoadMaster _lm;
        private string _pfxPath;
        private string _intermediateName;

        [TestInitialize]
        public override void Setup()
        {
            base.Setup();

            _lm = new FakeLoadMaster("admin", "secret", "key+/=");
            var (pfxPath, intermediates) = TestCertificates.CreatePfxWithChain();
            _pfxPath = pfxPath;
            _intermediateName = $"certify-ca-{intermediates[0]}";
        }

        [TestCleanup]
        public void Cleanup()
        {
            _lm?.Dispose();
            if (_pfxPath != null && File.Exists(_pfxPath))
            {
                File.Delete(_pfxPath);
            }
        }

        [TestMethod, TestCategory("KempLoadMaster")]
        public async Task ReplacesExistingCertificateAndAddsMissingIntermediate()
        {
            _lm.Certs.Add("www.example.com");

            var results = await Execute("www.example.com");

            Assert.IsTrue(results.All(r => r.IsSuccess), string.Join("; ", results.Select(r => r.Message)));

            var addCert = _lm.Requests.Single(r => r.Path == "/access/addcert");
            Assert.AreEqual("www.example.com", addCert.Query["cert"]);
            Assert.AreEqual("1", addCert.Query["replace"]);
            StringAssert.Contains(addCert.Body, "PRIVATE KEY-----");
            Assert.AreEqual(1, CountOf(addCert.Body, "-----BEGIN CERTIFICATE-----"), "only the leaf certificate is sent with the key");

            var addIntermediate = _lm.Requests.Single(r => r.Path == "/access/addintermediate");
            Assert.AreEqual(_intermediateName, addIntermediate.Query["cert"]);
            Assert.AreEqual(1, CountOf(addIntermediate.Body, "-----BEGIN CERTIFICATE-----"));
            Assert.IsFalse(addIntermediate.Body.Contains("PRIVATE KEY"));

            Assert.IsTrue(_lm.Requests.IndexOf(addIntermediate) < _lm.Requests.IndexOf(addCert), "intermediate is added before the certificate changes");
            Assert.IsTrue(_lm.Requests.All(r => r.Header("Authorization") == "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes("admin:secret"))));

            // a second deployment does not add the intermediate again
            _lm.Requests.Clear();
            results = await Execute("www.example.com");

            Assert.IsTrue(results.All(r => r.IsSuccess));
            Assert.IsFalse(_lm.Requests.Any(r => r.Path == "/access/addintermediate"));
            Assert.AreEqual("1", _lm.Requests.Single(r => r.Path == "/access/addcert").Query["replace"]);
        }

        [TestMethod, TestCategory("KempLoadMaster")]
        public async Task AddsNewCertificateWithoutReplace()
        {
            var results = await Execute("new.example.com");

            Assert.IsTrue(results.All(r => r.IsSuccess));
            Assert.AreEqual("0", _lm.Requests.Single(r => r.Path == "/access/addcert").Query["replace"]);
            StringAssert.Contains(results.Last().Message, "Virtual Services");
        }

        [TestMethod, TestCategory("KempLoadMaster")]
        public async Task PreviewMakesNoChanges()
        {
            _lm.Certs.Add("www.example.com");

            var results = await Execute("www.example.com", isPreviewOnly: true);

            Assert.IsTrue(results.All(r => r.IsSuccess));
            StringAssert.Contains(results.Single().Message, "Would replace certificate 'www.example.com'");
            StringAssert.Contains(results.Single().Message, "1 intermediate certificate");
            Assert.IsFalse(_lm.Requests.Any(r => r.Method == "POST"));
        }

        [TestMethod, TestCategory("KempLoadMaster")]
        public async Task ReportsLoadMasterError()
        {
            _lm.AddCertError = "Invalid certificate";

            var results = await Execute("www.example.com");

            var failure = results.Single(r => !r.IsSuccess);
            StringAssert.Contains(failure.Message, "Invalid certificate");
        }

        [TestMethod, TestCategory("KempLoadMaster")]
        public async Task IntermediateFailureIsWarningOnly()
        {
            _lm.AddIntermediateError = "Filename already exists";

            var results = await Execute("www.example.com");

            Assert.IsTrue(results.All(r => r.IsSuccess));
            Assert.IsTrue(results.Any(r => r.IsWarning && r.Message.Contains("Filename already exists")));
            Assert.IsTrue(_lm.Requests.Any(r => r.Path == "/access/addcert"));
        }

        [TestMethod, TestCategory("KempLoadMaster")]
        public async Task ReportsAccessDenied()
        {
            var results = await Execute("www.example.com", credentials: UserCredentials("wrong"));

            var failure = results.Single(r => !r.IsSuccess);
            StringAssert.Contains(failure.Message, "access denied");
            StringAssert.Contains(failure.Message, "username and password");
            Assert.IsFalse(_lm.Requests.Any(r => r.Method == "POST"));
        }

        [TestMethod, TestCategory("KempLoadMaster")]
        public async Task SignsInWithApiKey()
        {
            _lm.Certs.Add("www.example.com");

            var results = await Execute("www.example.com", credentials: ApiKeyCredentials("key+/="));

            Assert.IsTrue(results.All(r => r.IsSuccess), string.Join("; ", results.Select(r => r.Message)));
            Assert.IsTrue(_lm.Requests.Count >= 3);
            Assert.IsTrue(_lm.Requests.All(r => r.Query.GetValueOrDefault("apikey") == "key+/=" && r.Header("Authorization") == null), "every request sends the API key, and no basic authentication");

            var addCert = _lm.Requests.Single(r => r.Path == "/access/addcert");
            Assert.AreEqual("www.example.com", addCert.Query["cert"]);
            Assert.AreEqual("1", addCert.Query["replace"]);
        }

        [TestMethod, TestCategory("KempLoadMaster")]
        public async Task ApiKeyIsUsedWhenUsernameAlsoSet()
        {
            var credentials = UserCredentials("secret");
            credentials["api_key"] = "key+/=";

            var results = await Execute("www.example.com", credentials: credentials);

            Assert.IsTrue(results.All(r => r.IsSuccess));
            Assert.IsTrue(_lm.Requests.All(r => r.Header("Authorization") == null));
        }

        [TestMethod, TestCategory("KempLoadMaster")]
        public async Task ReportsWrongApiKey()
        {
            var results = await Execute("www.example.com", credentials: ApiKeyCredentials("wrong"));

            var failure = results.Single(r => !r.IsSuccess);
            StringAssert.Contains(failure.Message, "access denied");
            StringAssert.Contains(failure.Message, "API key");
            Assert.IsFalse(_lm.Requests.Any(r => r.Method == "POST"));
        }

        [TestMethod, TestCategory("KempLoadMaster")]
        public async Task RequiresCredentials()
        {
            var results = await Execute("www.example.com", credentials: new Dictionary<string, string> { { "username", "admin" } });

            StringAssert.Contains(results.Single(r => !r.IsSuccess).Message, "API key, or a username and password");
            Assert.AreEqual(0, _lm.Requests.Count);
        }

        [TestMethod, TestCategory("KempLoadMaster")]
        public async Task PreviewBeforeCertificateIssuedChecksSignIn()
        {
            var results = await Execute("www.example.com", isPreviewOnly: true, credentials: ApiKeyCredentials("key+/="), certificatePath: "");

            StringAssert.Contains(results.Single().Message, "Signed in to LoadMaster");
            StringAssert.Contains(results.Single().Message, "No certificate has been issued yet");
            Assert.IsFalse(_lm.Requests.Any(r => r.Method == "POST"));
        }

        [TestMethod, TestCategory("KempLoadMaster")]
        public async Task ReportsNonLoadMasterResponse()
        {
            _lm.ReturnHtml = true;

            var results = await Execute("www.example.com");

            StringAssert.Contains(results.Single(r => !r.IsSuccess).Message, "unexpected response");
        }

        [TestMethod, TestCategory("KempLoadMaster")]
        public async Task ValidatesSettings()
        {
            var provider = new KempLoadMaster();

            async Task<List<ActionResult>> validate(string address, string certName, Dictionary<string, string> credentials = null) => await provider.Validate(CreateParams(address, certName, credentials ?? UserCredentials("secret"), false));

            Assert.AreEqual(0, (await validate("https://192.168.1.10", "www.example.com")).Count);
            Assert.AreEqual(0, (await validate("https://192.168.1.10", "www.example.com", ApiKeyCredentials("abc"))).Count);
            Assert.IsTrue((await validate("https://192.168.1.10", "www.example.com", new Dictionary<string, string>())).Any(r => !r.IsSuccess));
            Assert.IsTrue((await validate("https://192.168.1.10", "www.example.com", new Dictionary<string, string> { { "api_key", " " }, { "username", "admin" } })).Any(r => !r.IsSuccess));
            Assert.AreEqual(0, (await validate("https://lm.example.com:8443/", "wildcard_example.com")).Count);
            Assert.IsTrue((await validate("", "www.example.com")).Any(r => !r.IsSuccess));
            Assert.IsTrue((await validate("192.168.1.10", "www.example.com")).Any(r => !r.IsSuccess));
            Assert.IsTrue((await validate("ftp://192.168.1.10", "www.example.com")).Any(r => !r.IsSuccess));
            Assert.IsTrue((await validate("https://192.168.1.10", "")).Any(r => !r.IsSuccess));
            Assert.IsTrue((await validate("https://192.168.1.10", "*.example.com")).Any(r => !r.IsSuccess));
            Assert.IsTrue((await validate("https://192.168.1.10", "my cert")).Any(r => !r.IsSuccess));
            Assert.IsTrue((await validate("https://192.168.1.10", "replacement.example.com")).Any(r => !r.IsSuccess));
        }

        private static Dictionary<string, string> UserCredentials(string password) => new Dictionary<string, string> { { "username", "admin" }, { "password", password } };

        private static Dictionary<string, string> ApiKeyCredentials(string apiKey) => new Dictionary<string, string> { { "api_key", apiKey }, { "username", "" }, { "password", "" } };

        private async Task<List<ActionResult>> Execute(string certName, bool isPreviewOnly = false, Dictionary<string, string> credentials = null, string certificatePath = null)
        {
            var execParams = CreateParams(_lm.Address, certName, credentials ?? UserCredentials("secret"), isPreviewOnly);
            if (certificatePath != null)
            {
                ((ManagedCertificate)execParams.Subject).CertificatePath = certificatePath;
            }

            return await new KempLoadMaster().Execute(execParams);
        }

        private DeploymentTaskExecutionParams CreateParams(string address, string certName, Dictionary<string, string> credentials, bool isPreviewOnly)
        {
            var config = new DeploymentTaskConfig
            {
                TaskTypeId = KempLoadMaster.Definition.Id,
                TaskName = "Kemp LoadMaster test",
                ChallengeProvider = CredentialTypes.KempLoadMaster,
                Parameters = new List<ProviderParameterSetting>
                {
                    new ProviderParameterSetting("lm_address", address),
                    new ProviderParameterSetting("cert_name", certName)
                }
            };

            var managedCert = GetMockManagedCertificate("KempTest", "1", "www.example.com", PrimaryIISRoot);
            managedCert.CertificatePath = _pfxPath;

            return new DeploymentTaskExecutionParams(_log, null, managedCert, config, credentials, isPreviewOnly, KempLoadMaster.Definition, new DeploymentContext(), CancellationToken.None);
        }

        private static int CountOf(string text, string value) => (text.Length - text.Replace(value, "").Length) / value.Length;

        /// <summary>
        /// Stand-in for the LoadMaster RESTful API: listcert, listintermediate, addcert and addintermediate with basic authentication or an API key
        /// </summary>
        private sealed class FakeLoadMaster : IDisposable
        {
            private readonly FakeHttpServer _server;
            private readonly string _expectedAuth;
            private readonly string _expectedApiKey;

            public string Address => _server.Address;
            public List<FakeHttpRequest> Requests => _server.Requests;
            public HashSet<string> Certs { get; } = new HashSet<string>();
            public HashSet<string> Intermediates { get; } = new HashSet<string>();
            public string AddCertError { get; set; }
            public string AddIntermediateError { get; set; }
            public bool ReturnHtml { get; set; }

            public FakeLoadMaster(string username, string password, string apiKey)
            {
                _expectedAuth = "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes($"{username}:{password}"));
                _expectedApiKey = apiKey;
                _server = new FakeHttpServer(Handle);
            }

            private FakeHttpResponse Handle(FakeHttpRequest r)
            {
                if (r.Header("Authorization") != _expectedAuth && r.Query.GetValueOrDefault("apikey") != _expectedApiKey)
                {
                    return new FakeHttpResponse(401, "text/html", "<html>Unauthorized</html>");
                }

                if (ReturnHtml)
                {
                    return new FakeHttpResponse(200, "text/html", "<!DOCTYPE html><html><body>Login</body></html>");
                }

                switch (r.Path)
                {
                    case "/access/listcert":
                        return Ok(List(Certs));
                    case "/access/listintermediate":
                        return Ok(List(Intermediates));
                    case "/access/addcert":
                        if (AddCertError != null)
                        {
                            return Fail(AddCertError);
                        }

                        if (Certs.Contains(r.Query["cert"]) && r.Query.GetValueOrDefault("replace") != "1")
                        {
                            return Fail("Filename already exists");
                        }

                        Certs.Add(r.Query["cert"]);
                        return Ok("Certificate Successfully Installed");
                    case "/access/addintermediate":
                        if (AddIntermediateError != null)
                        {
                            return Fail(AddIntermediateError);
                        }

                        Intermediates.Add(r.Query["cert"]);
                        return Ok("Intermediate Certificate Successfully Installed");
                    default:
                        return Fail("Unknown command");
                }
            }

            private static string List(IEnumerable<string> names) => "<Data>" + string.Concat(names.Select(n => $"<cert><name>{n}</name><type>RSA</type></cert>")) + "</Data>";

            private static FakeHttpResponse Ok(string success) => new FakeHttpResponse(200, "text/xml", $"<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n<Response stat=\"200\" code=\"ok\">\n<Success>{success}</Success>\n</Response>");

            private static FakeHttpResponse Fail(string error) => new FakeHttpResponse(422, "text/xml", $"<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n<Response stat=\"422\" code=\"fail\">\n<Error>{error}</Error>\n</Response>");

            public void Dispose() => _server.Dispose();
        }
    }
}
