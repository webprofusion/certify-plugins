using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
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
    /// Runs the Cisco FMC task against a local stand-in for the FMC REST API, which keeps certificate enrollment objects, device records and the
    /// enrollments installed on devices, and runs device certificate installs as background tasks
    /// </summary>
    [TestClass]
    public class DeploymentTasksCiscoFmc : IntegrationTestBase
    {
        private const string EnrollmentName = "vpn.example.com";

        private FakeFmc _fmc;
        private string _pfxPath;

        [TestInitialize]
        public override void Setup()
        {
            base.Setup();

            _fmc = new FakeFmc("certify", "secret");
            _fmc.AddDevice(FakeFmc.GlobalDomain, "dev-1", "ftd1");
            _fmc.AddDevice(FakeFmc.GlobalDomain, "dev-2", "ftd2");
            (_pfxPath, _) = TestCertificates.CreatePfxWithChain(1);
        }

        [TestCleanup]
        public void Cleanup()
        {
            _fmc?.Dispose();
            if (_pfxPath != null && File.Exists(_pfxPath))
            {
                File.Delete(_pfxPath);
            }
        }

        [TestMethod, TestCategory("CiscoFmc")]
        public async Task ReplacesEnrollmentAndInstallsAgain()
        {
            var id = _fmc.AddEnrollment(FakeFmc.GlobalDomain, EnrollmentName, "PKCS12", OtherPkcs12());
            _fmc.Enrollments[id]["revocation"] = new JsonObject { ["enableCertRevocationList"] = true };
            _fmc.Installed.Add(("dev-1", id));

            var results = await Execute();

            Assert.IsTrue(results.All(r => r.IsSuccess && !r.IsWarning), Messages(results));
            Assert.AreEqual("Cisco FMC: replaced the certificate of enrollment 'vpn.example.com', and installed it again on device 'ftd1'.", results.Last().Message);

            var put = _fmc.Requests.Single(r => r.Method == "PUT");
            Assert.AreEqual($"/api/fmc_config/v1/domain/{FakeFmc.GlobalDomain}/object/certenrollments/{id}", put.Path);
            var body = JsonNode.Parse(put.Body).AsObject();
            Assert.AreEqual(id, body["id"].ToString());
            Assert.AreEqual("PKCS12", body["enrollmentType"].ToString());
            Assert.IsNotNull(body["revocation"], "the enrollment's other settings are kept");
            Assert.IsNull(body["links"]);
            Assert.IsNull(body["metadata"]);

            AssertPkcs12HasCertificate(body["pkcs12Content"]);

            var install = _fmc.ManageRequests.Single();
            Assert.AreEqual("RE_ENROLL", install["action"].ToString());
            Assert.AreEqual("dev-1", install["deviceCertificates"][0]["deviceId"].ToString());
            Assert.AreEqual(id, install["deviceCertificates"][0]["certificates"][0]["certificate"]["id"].ToString());

            Assert.IsTrue(_fmc.Requests.Any(r => r.Path == "/api/fmc_platform/v1/auth/revokeaccess"), "signs out");
            Assert.IsTrue(_fmc.Requests.All(r => !r.Path.Contains("secret") && !r.Query.Values.Any(v => v.Contains("secret"))), "the password is never in the URL");
        }

        [TestMethod, TestCategory("CiscoFmc")]
        public async Task FirstDeploymentAddsEnrollment()
        {
            var results = await Execute();

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
            StringAssert.StartsWith(results.Last().Message, "Cisco FMC: added certificate enrollment 'vpn.example.com'. It isn't installed on any device");

            var post = _fmc.Requests.Single(r => r.Method == "POST" && r.Path.EndsWith("/object/certenrollments"));
            var body = JsonNode.Parse(post.Body).AsObject();
            Assert.AreEqual(EnrollmentName, body["name"].ToString());
            Assert.AreEqual("CertEnrollment", body["type"].ToString());
            Assert.AreEqual("PKCS12", body["enrollmentType"].ToString());
            AssertPkcs12HasCertificate(body["pkcs12Content"]);

            Assert.AreEqual(0, _fmc.ManageRequests.Count, "not installed on any device");
        }

        [TestMethod, TestCategory("CiscoFmc")]
        public async Task InstallsOnNamedDevices()
        {
            var id = _fmc.AddEnrollment(FakeFmc.GlobalDomain, EnrollmentName, "PKCS12", OtherPkcs12());
            _fmc.Installed.Add(("dev-1", id));

            var results = await Execute(devices: "FTD2, ftd1");

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
            StringAssert.Contains(results.Last().Message, "installed it again on device 'ftd1' and installed it on device 'ftd2'");

            CollectionAssert.AreEqual(new[] { "RE_ENROLL dev-1", "ENROLL dev-2" }, _fmc.ManageRequests.Select(m => $"{m["action"]} {m["deviceCertificates"][0]["deviceId"]}").ToArray());
            Assert.IsTrue(_fmc.Installed.Contains(("dev-2", id)));
        }

        [TestMethod, TestCategory("CiscoFmc")]
        public async Task NewEnrollmentIsInstalledOnNamedDevices()
        {
            var results = await Execute(devices: "ftd2");

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
            Assert.AreEqual("Cisco FMC: added certificate enrollment 'vpn.example.com', and installed it on device 'ftd2'.", results.Last().Message);

            var install = _fmc.ManageRequests.Single();
            Assert.AreEqual("ENROLL", install["action"].ToString());
            Assert.AreEqual(_fmc.Enrollments.Keys.Single(), install["deviceCertificates"][0]["certificates"][0]["certificate"]["id"].ToString(), "installs the new enrollment");
        }

        [TestMethod, TestCategory("CiscoFmc")]
        public async Task CurrentCertificateIsNotReplacedAgain()
        {
            Assert.IsTrue((await Execute(devices: "ftd1")).All(r => r.IsSuccess));
            _fmc.Requests.Clear();
            _fmc.ManageRequests.Clear();

            var results = await Execute();

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
            Assert.AreEqual("Cisco FMC: certificate enrollment 'vpn.example.com' already had this certificate, and installed it again on device 'ftd1'.", results.Last().Message);
            Assert.IsFalse(_fmc.Requests.Any(r => r.Method == "PUT" || r.Path.EndsWith("/object/certenrollments") && r.Method == "POST"), "the enrollment is not changed");
            Assert.AreEqual("RE_ENROLL", _fmc.ManageRequests.Single()["action"].ToString(), "devices still get it, in case installing it failed before");
        }

        [TestMethod, TestCategory("CiscoFmc")]
        public async Task PreviewMakesNoChanges()
        {
            var id = _fmc.AddEnrollment(FakeFmc.GlobalDomain, EnrollmentName, "PKCS12", OtherPkcs12());
            _fmc.Installed.Add(("dev-1", id));

            var results = await Execute(isPreviewOnly: true, devices: "ftd2");

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
            StringAssert.Contains(results.Last().Message, "Connected to management center");
            StringAssert.Contains(results.Last().Message, "Would replace the certificate of enrollment 'vpn.example.com', then install it again on device 'ftd1' and install it on device 'ftd2'.");
            Assert.IsTrue(_fmc.Requests.All(r => r.Method == "GET" || r.Path.StartsWith("/api/fmc_platform/v1/auth/")), "only reads");
        }

        [TestMethod, TestCategory("CiscoFmc")]
        public async Task PreviewBeforeCertificateIssuedChecksConnection()
        {
            var results = await Execute(isPreviewOnly: true, certificatePath: "");

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
            StringAssert.Contains(results.Last().Message, "No certificate has been issued yet. Deploying would add certificate enrollment 'vpn.example.com', then not install it on any device");
        }

        [TestMethod, TestCategory("CiscoFmc")]
        public async Task UnknownDeviceFailsBeforeChanges()
        {
            var results = await Execute(devices: "ftd1, ftd9");

            Assert.IsFalse(results.Last().IsSuccess);
            StringAssert.Contains(results.Last().Message, "no device named 'ftd9' was found");
            Assert.IsTrue(_fmc.Requests.All(r => r.Method == "GET" || r.Path.StartsWith("/api/fmc_platform/v1/auth/")), "nothing is changed");
        }

        [TestMethod, TestCategory("CiscoFmc")]
        public async Task OtherEnrollmentTypeIsRefused()
        {
            _fmc.AddEnrollment(FakeFmc.GlobalDomain, EnrollmentName, "SCEP", null);

            var results = await Execute();

            Assert.IsFalse(results.Last().IsSuccess);
            StringAssert.Contains(results.Last().Message, "is a SCEP enrollment");
            Assert.IsFalse(_fmc.Requests.Any(r => r.Method == "PUT"));
        }

        [TestMethod, TestCategory("CiscoFmc")]
        public async Task SaveFailureChangesNothing()
        {
            var id = _fmc.AddEnrollment(FakeFmc.GlobalDomain, EnrollmentName, "PKCS12", OtherPkcs12());
            _fmc.Installed.Add(("dev-1", id));
            _fmc.SaveError = "Invalid PKCS12 file or passphrase.";

            var results = await Execute();

            Assert.IsFalse(results.Last().IsSuccess);
            Assert.AreEqual("Cisco FMC: could not update certificate enrollment 'vpn.example.com', nothing was changed: Invalid PKCS12 file or passphrase.", results.Last().Message);
            Assert.AreEqual(0, _fmc.ManageRequests.Count);
        }

        [TestMethod, TestCategory("CiscoFmc")]
        public async Task InstallTaskFailureIsReported()
        {
            var id = _fmc.AddEnrollment(FakeFmc.GlobalDomain, EnrollmentName, "PKCS12", OtherPkcs12());
            _fmc.Installed.Add(("dev-1", id));
            _fmc.Installed.Add(("dev-2", id));
            _fmc.TaskFailures["dev-2"] = "Failed to import PKCS12 on device.";

            var results = await Execute();

            Assert.IsFalse(results.Last().IsSuccess);
            Assert.AreEqual("Cisco FMC: the certificate of enrollment 'vpn.example.com' was replaced, but installing it failed for device 'ftd2': task 2 failed: Failed to import PKCS12 on device. It was installed on 'ftd1'.", results.Last().Message);
        }

        [TestMethod, TestCategory("CiscoFmc")]
        public async Task WaitsForInstallTask()
        {
            var id = _fmc.AddEnrollment(FakeFmc.GlobalDomain, EnrollmentName, "PKCS12", OtherPkcs12());
            _fmc.Installed.Add(("dev-1", id));
            _fmc.TaskRunningPolls = 2;

            var results = await Execute();

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
            Assert.AreEqual(3, _fmc.Requests.Count(r => r.Path.Contains("/job/taskstatuses/")));
        }

        [TestMethod, TestCategory("CiscoFmc")]
        public async Task OlderManagementCenterIsRefused()
        {
            _fmc.ServerVersion = "7.6.1 (build 291)";

            var results = await Execute();

            Assert.IsFalse(results.Last().IsSuccess);
            StringAssert.Contains(results.Last().Message, "is version 7.6. Installing certificates on devices through its REST API needs version 7.7 or later");
            Assert.IsFalse(_fmc.Requests.Any(r => r.Method == "PUT" || r.Path.Contains("/object/")));
        }

        [TestMethod, TestCategory("CiscoFmc")]
        public async Task UsesDomain()
        {
            _fmc.AddDevice(FakeFmc.BranchDomain, "dev-b", "ftd-branch");

            var results = await Execute(devices: "ftd-branch", domain: "global/branch");

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
            Assert.IsTrue(_fmc.Requests.Where(r => r.Path.StartsWith("/api/fmc_config/")).All(r => r.Path.StartsWith($"/api/fmc_config/v1/domain/{FakeFmc.BranchDomain}/")));
            Assert.AreEqual(FakeFmc.BranchDomain, _fmc.Enrollments.Values.Single()["domain"].ToString());

            var unknown = await Execute(domain: "Global/Other");
            Assert.IsFalse(unknown.Last().IsSuccess);
            StringAssert.Contains(unknown.Last().Message, "domain 'Global/Other' was not found. The user can access: 'Global', 'Global/Branch'.");
        }

        [TestMethod, TestCategory("CiscoFmc")]
        public async Task SignsInAgainWhenTokenExpires()
        {
            var id = _fmc.AddEnrollment(FakeFmc.GlobalDomain, EnrollmentName, "PKCS12", OtherPkcs12());
            _fmc.Installed.Add(("dev-1", id));
            _fmc.ExpireTokenAfterRequests = 6;

            var results = await Execute();

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
            Assert.AreEqual(2, _fmc.Requests.Count(r => r.Path == "/api/fmc_platform/v1/auth/generatetoken"));
        }

        [TestMethod, TestCategory("CiscoFmc")]
        public async Task ReportsSignInFailure()
        {
            var results = await Execute(password: "wrong");

            Assert.IsFalse(results.Last().IsSuccess);
            StringAssert.Contains(results.Last().Message, "could not sign in (Invalid credentials.). Check the username and password");
        }

        [TestMethod, TestCategory("CiscoFmc")]
        public async Task ReportsAccessDenied()
        {
            _fmc.ForbidChanges = true;
            var results = await Execute();

            Assert.IsFalse(results.Last().IsSuccess);
            StringAssert.Contains(results.Last().Message, "access denied (User does not have permission.)");
        }

        [TestMethod, TestCategory("CiscoFmc")]
        public async Task ValidatesSettings()
        {
            async Task<List<ActionResult>> validate(string address, string enrollment, string password = "secret")
                => await new CiscoFmc().Validate(CreateParams(address, enrollment, password, false, null, null));

            Assert.IsTrue((await validate("https://fmc.example.com", EnrollmentName)).All(r => r.IsSuccess));
            Assert.IsTrue((await validate("", EnrollmentName)).Any(r => !r.IsSuccess));
            Assert.IsTrue((await validate("fmc.example.com", EnrollmentName)).Any(r => !r.IsSuccess));
            Assert.IsTrue((await validate("https://fmc.example.com", "")).Any(r => !r.IsSuccess));
            Assert.IsTrue((await validate("https://fmc.example.com", "has space")).Any(r => !r.IsSuccess));
            Assert.IsTrue((await validate("https://fmc.example.com", EnrollmentName, password: "")).Any(r => !r.IsSuccess));
        }

        /// <summary>
        /// The PKCS12 file opens with its passphrase, and has the key, the certificate and its chain
        /// </summary>
        private void AssertPkcs12HasCertificate(JsonNode content)
        {
            var data = Convert.FromBase64String(content["base64Certificate"].ToString());
            var passphrase = content["passPhrase"].ToString();
            Assert.IsTrue(passphrase.Length >= 16);

            var collection = X509CertificateLoader.LoadPkcs12Collection(data, passphrase);
            var leaf = collection.Single(c => c.HasPrivateKey);
            Assert.AreEqual(LeafThumbprint(), leaf.Thumbprint);
            Assert.AreEqual(2, collection.Count, "certificate and intermediate, without the root");

            var info = Pkcs12Info.Decode(data, out _);
            var key = info.AuthenticatedSafe.SelectMany(s => s.GetBags()).OfType<Pkcs12ShroudedKeyBag>().Single();
            Assert.IsNotNull(key, "the key is encrypted");
        }

        private string LeafThumbprint()
        {
            var collection = X509CertificateLoader.LoadPkcs12CollectionFromFile(_pfxPath, "");
            return collection.Single(c => c.HasPrivateKey).Thumbprint;
        }

        /// <summary>
        /// A PKCS12 file of another certificate, as added on the management center by hand (with encrypted certificates)
        /// </summary>
        private static byte[] OtherPkcs12()
        {
            using var key = RSA.Create(2048);
            using var cert = new CertificateRequest("CN=vpn.example.com", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1).CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-90), DateTimeOffset.UtcNow.AddDays(1));
            return cert.Export(X509ContentType.Pkcs12, "cisco123");
        }

        private static string Messages(List<ActionResult> results) => string.Join("; ", results.Select(r => r.Message));

        private async Task<List<ActionResult>> Execute(bool isPreviewOnly = false, string password = "secret", string certificatePath = null, string devices = null, string domain = null)
        {
            var execParams = CreateParams(_fmc.Address, EnrollmentName, password, isPreviewOnly, devices, domain);
            if (certificatePath != null)
            {
                ((ManagedCertificate)execParams.Subject).CertificatePath = certificatePath;
            }

            return await new CiscoFmc().Execute(execParams);
        }

        private DeploymentTaskExecutionParams CreateParams(string address, string enrollmentName, string password, bool isPreviewOnly, string devices, string domain)
        {
            var config = new DeploymentTaskConfig
            {
                TaskTypeId = CiscoFmc.Definition.Id,
                TaskName = "Cisco FMC test",
                ChallengeProvider = StandardAuthTypes.STANDARD_AUTH_GENERIC,
                Parameters = new List<ProviderParameterSetting>
                {
                    new ProviderParameterSetting("fmc_address", address),
                    new ProviderParameterSetting("enrollment_name", enrollmentName)
                }
            };

            if (devices != null)
            {
                config.Parameters.Add(new ProviderParameterSetting("devices", devices));
            }

            if (domain != null)
            {
                config.Parameters.Add(new ProviderParameterSetting("domain", domain));
            }

            var managedCert = GetMockManagedCertificate("CiscoFmcTest", "1", "vpn.example.com", PrimaryIISRoot);
            managedCert.CertificatePath = _pfxPath;

            var credentials = new Dictionary<string, string> { { "username", "certify" }, { "password", password } };
            return new DeploymentTaskExecutionParams(_log, null, managedCert, config, credentials, isPreviewOnly, CiscoFmc.Definition, new DeploymentContext(), CancellationToken.None);
        }

        /// <summary>
        /// Stand-in for the FMC REST API: token sign in and sign out, server version, certificate enrollments, device records, device certificates,
        /// managecertificates and task status
        /// </summary>
        private sealed class FakeFmc : IDisposable
        {
            public const string GlobalDomain = "e276abec-e0f2-11e3-8169-6d9ed49b625f";
            public const string BranchDomain = "7c2d2a54-5b9f-11ee-8c99-0242ac120002";

            private readonly FakeHttpServer _server;
            private readonly string _username;
            private readonly string _password;
            private readonly Dictionary<string, (string Domain, string Name)> _devices = new();
            private readonly Dictionary<string, (int Polls, string DeviceId, string EnrollmentId, string Action)> _tasks = new();
            private string _token;
            private int _tokens;
            private int _ids;
            private int _requestsWithToken;

            public string Address => _server.Address;
            public List<FakeHttpRequest> Requests => _server.Requests;

            public Dictionary<string, JsonObject> Enrollments { get; } = new();
            public HashSet<(string DeviceId, string EnrollmentId)> Installed { get; } = new();
            public List<JsonObject> ManageRequests { get; } = new();
            public Dictionary<string, string> TaskFailures { get; } = new();

            public string ServerVersion { get; set; } = "7.7.0 (build 91)";
            public string SaveError { get; set; }
            public int TaskRunningPolls { get; set; }
            public int ExpireTokenAfterRequests { get; set; }
            public bool ForbidChanges { get; set; }

            public FakeFmc(string username, string password)
            {
                _username = username;
                _password = password;
                _server = new FakeHttpServer(Handle);
            }

            public void AddDevice(string domain, string id, string name) => _devices[id] = (domain, name);

            public string AddEnrollment(string domain, string name, string type, byte[] pkcs12)
            {
                var id = $"enr-{++_ids}";
                Enrollments[id] = new JsonObject
                {
                    ["id"] = id,
                    ["name"] = name,
                    ["type"] = "CertEnrollment",
                    ["enrollmentType"] = type,
                    ["domain"] = domain,
                    ["links"] = new JsonObject { ["self"] = $"https://fmc/api/fmc_config/v1/domain/{domain}/object/certenrollments/{id}" },
                    ["metadata"] = new JsonObject { ["readOnly"] = new JsonObject { ["state"] = false } }
                };

                if (pkcs12 != null)
                {
                    Enrollments[id]["pkcs12Content"] = new JsonObject { ["base64Certificate"] = Convert.ToBase64String(pkcs12), ["passPhrase"] = "********" };
                }

                return id;
            }

            private FakeHttpResponse Handle(FakeHttpRequest r)
            {
                if (r.Path == "/api/fmc_platform/v1/auth/generatetoken" && r.Method == "POST")
                {
                    var expected = "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes($"{_username}:{_password}"));
                    if (r.Header("Authorization") != expected)
                    {
                        return Error(401, "Invalid credentials.");
                    }

                    _token = $"token-{++_tokens}";
                    _requestsWithToken = 0;

                    return new FakeHttpResponse(204, "application/json", "", new Dictionary<string, string>
                    {
                        ["X-auth-access-token"] = _token,
                        ["X-auth-refresh-token"] = "refresh-" + _token,
                        ["DOMAIN_UUID"] = GlobalDomain,
                        ["DOMAINS"] = $"[{{\"name\":\"Global\",\"uuid\":\"{GlobalDomain}\"}},{{\"name\":\"Global/Branch\",\"uuid\":\"{BranchDomain}\"}}]"
                    });
                }

                if (r.Header("X-auth-access-token") != _token || _token == null)
                {
                    return Error(401, "Access token invalid.");
                }

                if (r.Path == "/api/fmc_platform/v1/auth/revokeaccess")
                {
                    _token = null;
                    return new FakeHttpResponse(204, "application/json", "");
                }

                if (ExpireTokenAfterRequests > 0 && ++_requestsWithToken > ExpireTokenAfterRequests)
                {
                    ExpireTokenAfterRequests = 0;
                    _token = null;
                    return Error(401, "Access token invalid.");
                }

                if (r.Path == "/api/fmc_platform/v1/info/serverversion")
                {
                    return Json(new JsonObject { ["items"] = new JsonArray(new JsonObject { ["serverVersion"] = ServerVersion }) });
                }

                var prefix = "/api/fmc_config/v1/domain/";
                if (!r.Path.StartsWith(prefix))
                {
                    return Error(404, "Not found.");
                }

                var rest = r.Path[prefix.Length..];
                var domain = rest[..rest.IndexOf('/')];
                var path = rest[(domain.Length + 1)..];

                if (domain != GlobalDomain && domain != BranchDomain)
                {
                    return Error(404, "Domain not found.");
                }

                if (ForbidChanges && r.Method != "GET")
                {
                    return Error(403, "User does not have permission.");
                }

                if (path == "object/certenrollments" && r.Method == "GET")
                {
                    return Page(r, Enrollments.Values.Where(e => e["domain"].ToString() == domain).Select(e => new JsonObject { ["id"] = e["id"].ToString(), ["name"] = e["name"].ToString(), ["type"] = "CertEnrollment" }));
                }

                if (path == "object/certenrollments" && r.Method == "POST")
                {
                    if (SaveError != null)
                    {
                        return Error(400, SaveError);
                    }

                    var body = JsonNode.Parse(r.Body).AsObject();
                    var id = AddEnrollment(domain, body["name"].ToString(), body["enrollmentType"].ToString(), Convert.FromBase64String(body["pkcs12Content"]["base64Certificate"].ToString()));
                    return Json(Enrollments[id], 201);
                }

                if (path.StartsWith("object/certenrollments/"))
                {
                    var id = path["object/certenrollments/".Length..];
                    if (!Enrollments.TryGetValue(id, out var enrollment) || enrollment["domain"].ToString() != domain)
                    {
                        return Error(404, "Object not found.");
                    }

                    if (r.Method == "GET")
                    {
                        return Json(enrollment);
                    }

                    if (r.Method == "PUT")
                    {
                        if (SaveError != null)
                        {
                            return Error(400, SaveError);
                        }

                        var body = JsonNode.Parse(r.Body).AsObject();
                        enrollment["pkcs12Content"] = new JsonObject { ["base64Certificate"] = body["pkcs12Content"]["base64Certificate"].ToString(), ["passPhrase"] = "********" };
                        return Json(enrollment);
                    }
                }

                if (path == "devices/devicerecords" && r.Method == "GET")
                {
                    return Page(r, _devices.Where(d => d.Value.Domain == domain).Select(d => new JsonObject { ["id"] = d.Key, ["name"] = d.Value.Name, ["type"] = "Device" }));
                }

                if (path == "devices/certificates" && r.Method == "GET")
                {
                    var filter = r.Query.GetValueOrDefault("filter") ?? "";
                    var deviceId = filter.StartsWith("deviceId:") ? filter["deviceId:".Length..] : null;

                    return Page(r, Installed.Where(i => deviceId == null || i.DeviceId == deviceId).Select(i => new JsonObject
                    {
                        ["id"] = $"{i.DeviceId}-{i.EnrollmentId}",
                        ["type"] = "DeviceCertificate",
                        ["deviceId"] = i.DeviceId,
                        ["enrolledCertificates"] = new JsonArray(new JsonObject
                        {
                            ["certificate"] = new JsonObject { ["id"] = i.EnrollmentId, ["name"] = Enrollments[i.EnrollmentId]["name"].ToString(), ["type"] = "CertEnrollment" }
                        })
                    }));
                }

                if (path == "devices/operational/managecertificates" && r.Method == "POST")
                {
                    var body = JsonNode.Parse(r.Body).AsObject();
                    ManageRequests.Add(body);

                    var section = body["deviceCertificates"][0];
                    var taskId = (_tasks.Count + 1).ToString();
                    _tasks[taskId] = (0, section["deviceId"].ToString(), section["certificates"][0]["certificate"]["id"].ToString(), body["action"].ToString());

                    var response = (JsonObject)body.DeepClone();
                    response["metadata"] = new JsonObject { ["task"] = new JsonObject { ["id"] = taskId, ["taskType"] = "MANAGE_CERTIFICATE", ["status"] = "200" } };
                    return Json(response, 202);
                }

                if (path.StartsWith("job/taskstatuses/") && r.Method == "GET")
                {
                    var taskId = path["job/taskstatuses/".Length..];
                    if (!_tasks.TryGetValue(taskId, out var task))
                    {
                        return Error(404, "Task not found.");
                    }

                    _tasks[taskId] = task with { Polls = task.Polls + 1 };
                    if (task.Polls < TaskRunningPolls)
                    {
                        return Json(new JsonObject { ["id"] = taskId, ["taskType"] = "MANAGE_CERTIFICATE", ["status"] = "RUNNING" });
                    }

                    if (TaskFailures.TryGetValue(task.DeviceId, out var failure))
                    {
                        return Json(new JsonObject { ["id"] = taskId, ["taskType"] = "MANAGE_CERTIFICATE", ["status"] = "FAILED", ["message"] = failure });
                    }

                    Installed.Add((task.DeviceId, task.EnrollmentId));
                    return Json(new JsonObject { ["id"] = taskId, ["taskType"] = "MANAGE_CERTIFICATE", ["status"] = "SUCCESS", ["message"] = "Certificate enrollment completed." });
                }

                return Error(404, $"No handler for {r.Method} {r.Path}");
            }

            private static FakeHttpResponse Page(FakeHttpRequest r, IEnumerable<JsonObject> all)
            {
                var items = all.ToList();
                var offset = int.Parse(r.Query.GetValueOrDefault("offset") ?? "0");
                var limit = int.Parse(r.Query.GetValueOrDefault("limit") ?? "25");
                var page = items.Skip(offset).Take(limit).ToList();

                var body = new JsonObject { ["paging"] = new JsonObject { ["offset"] = offset, ["limit"] = limit, ["count"] = items.Count, ["pages"] = (items.Count + limit - 1) / limit } };
                if (page.Any())
                {
                    body["items"] = new JsonArray(page.Select(i => (JsonNode)i.DeepClone()).ToArray());
                }

                return Json(body);
            }

            private static FakeHttpResponse Json(JsonObject body, int status = 200) => new FakeHttpResponse(status, "application/json", body.ToJsonString());

            private static FakeHttpResponse Error(int status, string description)
                => Json(new JsonObject
                {
                    ["error"] = new JsonObject
                    {
                        ["category"] = "FRAMEWORK",
                        ["messages"] = new JsonArray(new JsonObject { ["description"] = description }),
                        ["severity"] = "ERROR"
                    }
                }, status);

            public void Dispose() => _server.Dispose();
        }
    }
}
