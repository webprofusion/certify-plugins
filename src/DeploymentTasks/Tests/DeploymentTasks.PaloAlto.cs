using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
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
    /// Runs the Palo Alto task against a local stand-in for the PAN-OS XML API, which answers with the same XML format, keeps imports in a
    /// candidate configuration and only applies them to the running configuration when a commit job finishes
    /// </summary>
    [TestClass]
    public class DeploymentTasksPaloAlto : IntegrationTestBase
    {
        private const string CertName = "www.example.com";

        private FakePanOs _fw;
        private string _pfxPath;

        [TestInitialize]
        public override void Setup()
        {
            base.Setup();

            _fw = new FakePanOs("certify", "secret");
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

        [TestMethod, TestCategory("PaloAlto")]
        public async Task ReplacesCertificateAndCommits()
        {
            _fw.Running[(null, CertName)] = (OtherCertPem(), true);

            var results = await Execute(CertName);

            Assert.IsTrue(results.All(r => r.IsSuccess && !r.IsWarning), Messages(results));
            StringAssert.Contains(results.Last().Message, "replaced certificate 'www.example.com' in Shared and committed the change");
            Assert.AreEqual(Thumbprint(LeafPem()), Thumbprint(_fw.Running[(null, CertName)].CertPem), "running configuration has the new certificate");

            var import = _fw.Requests.Single(r => r.Query.GetValueOrDefault("type") == "import");
            Assert.AreEqual("keypair", import.Query["category"]);
            Assert.AreEqual("pem", import.Query["format"]);
            Assert.AreEqual(CertName, import.Query["certificate-name"]);
            Assert.IsFalse(import.Query.ContainsKey("vsys"));

            var file = _fw.LastImportFields["file"];
            StringAssert.StartsWith(file, "-----BEGIN RSA PRIVATE KEY-----", "the key is first in the file");
            Assert.AreEqual(2, Regex.Matches(file, "-----BEGIN CERTIFICATE-----").Count, "certificate is imported with its chain");
            Assert.IsFalse(string.IsNullOrEmpty(_fw.LastImportFields["passphrase"]));

            var commit = _fw.FormOf(_fw.Requests.Single(r => _fw.FormOf(r).GetValueOrDefault("type") == "commit"));
            Assert.AreEqual("partial", commit["action"]);
            Assert.AreEqual("<commit><partial><admin><member>certify</member></admin></partial></commit>", commit["cmd"], "only this administrator's changes are committed");

            Assert.IsTrue(_fw.Requests.All(r => r.Method == "POST" && r.Path == "/api/"));
            Assert.IsTrue(_fw.Requests.All(r => !r.Query.ContainsKey("key") && !r.Query.ContainsKey("password")), "secrets are never in the URL");
        }

        [TestMethod, TestCategory("PaloAlto")]
        public async Task FirstDeploymentAddsCertificate()
        {
            var results = await Execute(CertName);

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
            StringAssert.Contains(results.Last().Message, "added certificate 'www.example.com' to Shared");
            StringAssert.Contains(results.Last().Message, "Select it where it should be used");
            Assert.IsTrue(_fw.Running.ContainsKey((null, CertName)));
        }

        [TestMethod, TestCategory("PaloAlto")]
        public async Task CurrentCertificateIsNotImportedAgain()
        {
            _fw.Running[(null, CertName)] = (LeafPem(), true);

            var results = await Execute(CertName);

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
            StringAssert.Contains(results.Single().Message, "already up to date");
            Assert.IsFalse(_fw.Requests.Any(r => r.Query.GetValueOrDefault("type") == "import" || _fw.FormOf(r).GetValueOrDefault("type") == "commit"));
        }

        [TestMethod, TestCategory("PaloAlto")]
        public async Task CurrentCertificateWithoutKeyIsImported()
        {
            _fw.Running[(null, CertName)] = (LeafPem(), false);

            var results = await Execute(CertName);

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
            Assert.IsTrue(_fw.Running[(null, CertName)].HasKey);
        }

        [TestMethod, TestCategory("PaloAlto")]
        public async Task PreviewMakesNoChanges()
        {
            _fw.Running[(null, CertName)] = (OtherCertPem(), true);

            var results = await Execute(CertName, isPreviewOnly: true);

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
            StringAssert.Contains(results.Single().Message, "Would replace certificate 'www.example.com' in Shared, then commit the changes made by 'certify'.");
            CollectionAssert.AreEqual(new[] { "keygen", "config" }, _fw.Requests.Select(r => _fw.FormOf(r)["type"]).ToArray());
        }

        [TestMethod, TestCategory("PaloAlto")]
        public async Task PreviewBeforeCertificateIssuedChecksConnection()
        {
            var results = await Execute(CertName, isPreviewOnly: true, certificatePath: "");

            StringAssert.Contains(results.Single().Message, "Connected to firewall");
            StringAssert.Contains(results.Single().Message, "No certificate has been issued yet. Deploying would add certificate 'www.example.com' to Shared");
            Assert.IsFalse(_fw.Requests.Any(r => r.Query.GetValueOrDefault("type") == "import"));
        }

        [TestMethod, TestCategory("PaloAlto")]
        public async Task ImportFailureChangesNothing()
        {
            _fw.Running[(null, CertName)] = (OtherCertPem(), true);
            _fw.ImportError = "Import of www.example.com failed. Private key and certificate do not match";

            var results = await Execute(CertName);

            var failure = results.Single(r => !r.IsSuccess);
            StringAssert.Contains(failure.Message, "nothing was changed");
            StringAssert.Contains(failure.Message, "do not match");
            Assert.IsFalse(_fw.Requests.Any(r => _fw.FormOf(r).GetValueOrDefault("type") == "commit"));
        }

        [TestMethod, TestCategory("PaloAlto")]
        public async Task CommitFailureIsReported()
        {
            var previous = OtherCertPem();
            _fw.Running[(null, CertName)] = (previous, true);
            _fw.CommitError = "Commit lock is currently held by admin";

            var results = await Execute(CertName);

            var failure = results.Single(r => !r.IsSuccess);
            StringAssert.Contains(failure.Message, "was imported, but committing it failed, so the firewall isn't using it yet");
            StringAssert.Contains(failure.Message, "Commit lock");
            Assert.AreEqual(previous, _fw.Running[(null, CertName)].CertPem);
        }

        [TestMethod, TestCategory("PaloAlto")]
        public async Task CommitJobFailureIsReported()
        {
            _fw.CommitJobFailure = "Validation Error: ssl-tls-service-profile -> mgmt is invalid";

            var results = await Execute(CertName);

            var failure = results.Single(r => !r.IsSuccess);
            StringAssert.Contains(failure.Message, "commit job 1 failed: Validation Error");
            Assert.IsFalse(_fw.Running.ContainsKey((null, CertName)));
        }

        [TestMethod, TestCategory("PaloAlto")]
        public async Task WaitsForCommitJob()
        {
            _fw.CommitJobActivePolls = 2;

            var results = await Execute(CertName);

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
            Assert.AreEqual(3, _fw.Requests.Count(r => _fw.FormOf(r).GetValueOrDefault("type") == "op"));
            Assert.IsTrue(_fw.Running.ContainsKey((null, CertName)));
        }

        [TestMethod, TestCategory("PaloAlto")]
        public async Task UsesVirtualSystem()
        {
            _fw.Running[("vsys2", CertName)] = (OtherCertPem(), true);

            var results = await Execute(CertName, vsys: "vsys2");

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
            StringAssert.Contains(results.Last().Message, "replaced certificate 'www.example.com' in virtual system vsys2");
            Assert.AreEqual("vsys2", _fw.Requests.Single(r => r.Query.GetValueOrDefault("type") == "import").Query["vsys"]);
            Assert.AreEqual(Thumbprint(LeafPem()), Thumbprint(_fw.Running[("vsys2", CertName)].CertPem));
        }

        [TestMethod, TestCategory("PaloAlto")]
        public async Task ReportsAccessDenied()
        {
            var results = await Execute(CertName, password: "wrong");

            var failure = results.Single(r => !r.IsSuccess);
            StringAssert.Contains(failure.Message, "access denied (Invalid Credential)");
            StringAssert.Contains(failure.Message, "XML API");
            Assert.AreEqual(1, _fw.Requests.Count);
        }

        [TestMethod, TestCategory("PaloAlto")]
        public async Task ReportsNonPanOsResponse()
        {
            _fw.ReturnHtml = true;

            var results = await Execute(CertName);

            StringAssert.Contains(results.Single(r => !r.IsSuccess).Message, "unexpected response");
        }

        [TestMethod, TestCategory("PaloAlto")]
        public async Task ValidatesSettings()
        {
            var provider = new PaloAlto();

            async Task<List<ActionResult>> validate(string address, string certName, string vsys = null, string password = "secret")
                => await provider.Validate(CreateParams(address, certName, password, false, vsys));

            Assert.AreEqual(0, (await validate("https://192.168.1.1", "www.example.com")).Count);
            Assert.AreEqual(0, (await validate("https://fw.example.com:8443/", "wildcard_example-com", vsys: "vsys12")).Count);
            Assert.IsTrue((await validate("", "www.example.com")).Any(r => !r.IsSuccess));
            Assert.IsTrue((await validate("192.168.1.1", "www.example.com")).Any(r => !r.IsSuccess));
            Assert.IsTrue((await validate("https://192.168.1.1", "")).Any(r => !r.IsSuccess));
            Assert.IsTrue((await validate("https://192.168.1.1", "*.example.com")).Any(r => !r.IsSuccess));
            Assert.IsTrue((await validate("https://192.168.1.1", "www.example.com']/x")).Any(r => !r.IsSuccess));
            Assert.IsTrue((await validate("https://192.168.1.1", new string('a', 64))).Any(r => !r.IsSuccess));
            Assert.IsTrue((await validate("https://192.168.1.1", "www.example.com", vsys: "Shared")).Any(r => !r.IsSuccess));
            Assert.IsTrue((await validate("https://192.168.1.1", "www.example.com", password: "")).Any(r => !r.IsSuccess));
        }

        private string LeafPem()
        {
            var collection = X509CertificateLoader.LoadPkcs12CollectionFromFile(_pfxPath, "");
            return collection.Single(c => c.HasPrivateKey).ExportCertificatePem();
        }

        private static string OtherCertPem()
        {
            using var key = RSA.Create(2048);
            using var cert = new CertificateRequest("CN=www.example.com", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1).CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-90), DateTimeOffset.UtcNow.AddDays(1));
            return cert.ExportCertificatePem();
        }

        private static string Thumbprint(string pem)
        {
            using var cert = X509Certificate2.CreateFromPem(Regex.Match(pem, "-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----").Value);
            return cert.Thumbprint;
        }

        private static string Messages(List<ActionResult> results) => string.Join("; ", results.Select(r => r.Message));

        private async Task<List<ActionResult>> Execute(string certName, bool isPreviewOnly = false, string password = "secret", string certificatePath = null, string vsys = null)
        {
            var execParams = CreateParams(_fw.Address, certName, password, isPreviewOnly, vsys);
            if (certificatePath != null)
            {
                ((ManagedCertificate)execParams.Subject).CertificatePath = certificatePath;
            }

            return await new PaloAlto().Execute(execParams);
        }

        private DeploymentTaskExecutionParams CreateParams(string address, string certName, string password, bool isPreviewOnly, string vsys)
        {
            var config = new DeploymentTaskConfig
            {
                TaskTypeId = PaloAlto.Definition.Id,
                TaskName = "Palo Alto test",
                ChallengeProvider = StandardAuthTypes.STANDARD_AUTH_GENERIC,
                Parameters = new List<ProviderParameterSetting>
                {
                    new ProviderParameterSetting("panos_address", address),
                    new ProviderParameterSetting("cert_name", certName)
                }
            };

            if (vsys != null)
            {
                config.Parameters.Add(new ProviderParameterSetting("vsys", vsys));
            }

            var managedCert = GetMockManagedCertificate("PaloAltoTest", "1", "www.example.com", PrimaryIISRoot);
            managedCert.CertificatePath = _pfxPath;

            var credentials = new Dictionary<string, string> { { "username", "certify" }, { "password", password } };
            return new DeploymentTaskExecutionParams(_log, null, managedCert, config, credentials, isPreviewOnly, PaloAlto.Definition, new DeploymentContext(), CancellationToken.None);
        }

        /// <summary>
        /// Stand-in for the PAN-OS XML API: keygen, config show of certificates, keypair import (multipart), partial commit and job status
        /// </summary>
        private sealed class FakePanOs : IDisposable
        {
            private const string ApiKey = "LUFRPT1key==";

            private readonly FakeHttpServer _server;
            private readonly string _username;
            private readonly string _password;

            // certificates by virtual system (null for Shared) and name
            private readonly Dictionary<(string Vsys, string Name), (string CertPem, bool HasKey)> _candidate = new();
            private int _jobId;
            private int _jobPolls;

            public string Address => _server.Address;
            public List<FakeHttpRequest> Requests => _server.Requests;

            public Dictionary<(string Vsys, string Name), (string CertPem, bool HasKey)> Running { get; } = new();
            public Dictionary<string, string> LastImportFields { get; private set; }

            public string ImportError { get; set; }
            public string CommitError { get; set; }
            public string CommitJobFailure { get; set; }
            public int CommitJobActivePolls { get; set; }
            public bool ReturnHtml { get; set; }

            public FakePanOs(string username, string password)
            {
                _username = username;
                _password = password;
                _server = new FakeHttpServer(Handle);
            }

            public Dictionary<string, string> FormOf(FakeHttpRequest r)
            {
                if (r.Header("Content-Type")?.StartsWith("application/x-www-form-urlencoded") != true)
                {
                    return new Dictionary<string, string>();
                }

                var form = System.Web.HttpUtility.ParseQueryString(r.Body);
                return form.AllKeys.ToDictionary(k => k, k => form[k]);
            }

            private FakeHttpResponse Handle(FakeHttpRequest r)
            {
                if (ReturnHtml)
                {
                    return new FakeHttpResponse(200, "text/html", "<!DOCTYPE html><html><body>Login</body></html>");
                }

                Assert.AreEqual("POST", r.Method);
                Assert.AreEqual("/api/", r.Path);

                if (r.Query.GetValueOrDefault("type") == "import")
                {
                    return Import(r);
                }

                var form = FormOf(r);
                if (form.GetValueOrDefault("type") == "keygen")
                {
                    return form["user"] == _username && form["password"] == _password
                        ? Response("<result><key>" + ApiKey + "</key></result>")
                        : new FakeHttpResponse(403, "application/xml", "<response status = 'error' code = '403'><result><msg>Invalid Credential</msg></result></response>");
                }

                if (form.GetValueOrDefault("key") != ApiKey)
                {
                    return new FakeHttpResponse(403, "application/xml", "<response status=\"error\" code=\"403\"><result><msg>Invalid key</msg></result></response>");
                }

                switch (form["type"])
                {
                    case "config":
                        Assert.AreEqual("show", form["action"], "the running configuration is read");
                        var match = Regex.Match(form["xpath"], @"^(/config/shared|/config/devices/entry\[@name='localhost\.localdomain'\]/vsys/entry\[@name='(?<vsys>[^']+)'\])/certificate/entry\[@name='(?<name>[^']+)'\]$");
                        Assert.IsTrue(match.Success, form["xpath"]);

                        var key = (match.Groups["vsys"].Success ? match.Groups["vsys"].Value : null, match.Groups["name"].Value);
                        if (!Running.TryGetValue(key, out var cert))
                        {
                            return Response("<msg>No such node</msg>", "error", "7");
                        }

                        return Response($"<result total-count=\"1\" count=\"1\"><entry name=\"{key.Item2}\" admin=\"admin\" dirtyId=\"2\"><common-name>www.example.com</common-name><algorithm>RSA</algorithm>"
                            + $"<public-key>{SecurityElement.Escape(cert.CertPem)}</public-key>{(cert.HasKey ? "<private-key>-AQ==encrypted</private-key>" : "")}</entry></result>");

                    case "commit":
                        Assert.AreEqual($"<commit><partial><admin><member>{_username}</member></admin></partial></commit>", form["cmd"]);
                        if (CommitError != null)
                        {
                            return Response($"<msg><line>{CommitError}</line></msg>", "error", "13");
                        }

                        if (!_candidate.Any())
                        {
                            return Response("<msg>There are no changes to commit.</msg>", code: "19");
                        }

                        _jobId++;
                        _jobPolls = 0;
                        return Response($"<result><msg><line>Commit job enqueued with jobid {_jobId}</line></msg><job>{_jobId}</job></result>", code: "19");

                    case "op":
                        Assert.AreEqual($"<show><jobs><id>{_jobId}</id></jobs></show>", form["cmd"]);
                        if (_jobPolls++ < CommitJobActivePolls)
                        {
                            return Job("ACT", "PEND", "");
                        }

                        if (CommitJobFailure != null)
                        {
                            return Job("FIN", "FAIL", $"<line>{CommitJobFailure}</line><line>Commit failed</line>");
                        }

                        foreach (var (k, v) in _candidate)
                        {
                            Running[k] = v;
                        }

                        _candidate.Clear();
                        return Job("FIN", "OK", "<line>Configuration committed successfully</line>");

                    default:
                        return Response($"<msg>Unknown request type {form["type"]}</msg>", "error", "1");
                }
            }

            private FakeHttpResponse Import(FakeHttpRequest r)
            {
                var contentType = r.Header("Content-Type");
                var boundary = Regex.Match(contentType, "boundary=(.+)$").Groups[1].Value;
                Assert.IsFalse(boundary.Contains('"'), "PAN-OS does not accept a quoted boundary");

                var fields = new Dictionary<string, string>();
                foreach (var part in r.Body.Split("--" + boundary).Skip(1).Where(p => !p.StartsWith("--")))
                {
                    var split = part.IndexOf("\r\n\r\n", StringComparison.Ordinal);
                    var field = Regex.Match(part[..split], "name=\"([^\"]+)\"").Groups[1].Value;
                    fields[field] = part[(split + 4)..^2];
                }

                LastImportFields = fields;

                if (fields.GetValueOrDefault("key") != ApiKey)
                {
                    return new FakeHttpResponse(403, "application/xml", "<response status=\"error\" code=\"403\"><result><msg>Invalid key</msg></result></response>");
                }

                Assert.AreEqual("keypair", r.Query["category"]);
                Assert.IsFalse(string.IsNullOrEmpty(fields.GetValueOrDefault("passphrase")), "PAN-OS requires a passphrase");

                if (ImportError != null)
                {
                    return Response($"<msg><line>{ImportError}</line></msg>", "error");
                }

                var file = fields["file"];
                Assert.IsTrue(file.Contains("PRIVATE KEY-----") && file.Contains("-----BEGIN CERTIFICATE-----"));

                var name = r.Query["certificate-name"];
                _candidate[(r.Query.GetValueOrDefault("vsys"), name)] = (Regex.Match(file, "-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----").Value, true);
                return Response($"<msg><line>Successfully imported {name} into candidate configuration</line></msg>");
            }

            private static FakeHttpResponse Job(string status, string result, string details)
                => Response($"<result><job><tenq>2026/11/19 10:00:00</tenq><id>1</id><type>Commit</type><status>{status}</status><result>{result}</result><progress>{(status == "FIN" ? 100 : 40)}</progress><details>{details}</details></job></result>");

            private static FakeHttpResponse Response(string inner, string status = "success", string code = null)
                => new FakeHttpResponse(200, "application/xml", $"<response status=\"{status}\"{(code != null ? $" code=\"{code}\"" : "")}>{inner}</response>");

            public void Dispose() => _server.Dispose();
        }
    }
}
