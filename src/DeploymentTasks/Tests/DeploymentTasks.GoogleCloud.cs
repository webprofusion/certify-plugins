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
    /// Runs the Google Cloud Secret Manager task against a local stand-in for Google's token endpoint and the Secret Manager API
    /// </summary>
    [TestClass]
    public class DeploymentTasksGoogleSecretManager : IntegrationTestBase
    {
        private const string SecretId = "www-example-com-tls";

        private FakeGoogleCloud _gcp;
        private string _pfxPath;
        private ManagedCertificate _managedCert;

        [TestInitialize]
        public override void Setup()
        {
            base.Setup();

            _gcp = new FakeGoogleCloud();
            (_pfxPath, _) = TestCertificates.CreatePfxWithChain(1);
            _managedCert = GetMockManagedCertificate("GoogleSecretManagerTest", "1", "www.example.com", PrimaryIISRoot);
            _managedCert.CertificatePath = _pfxPath;
        }

        [TestCleanup]
        public void Cleanup()
        {
            _gcp?.Dispose();
            if (_pfxPath != null && File.Exists(_pfxPath))
            {
                File.Delete(_pfxPath);
            }
        }

        [TestMethod, TestCategory("GoogleSecretManager")]
        public async Task FirstDeploymentCreatesSecretWithCertificate()
        {
            var results = await Execute(kmsKeyName: "projects/my-project-123/locations/global/keyRings/certs/cryptoKeys/certs");

            Assert.IsTrue(results.All(r => r.IsSuccess && !r.IsWarning), Messages(results));
            var secret = _gcp.Secrets.Values.Single();
            StringAssert.Contains(results.Single().Message, "created secret and added the certificate as projects/123456789012/secrets/www-example-com-tls/versions/1, now the latest version");
            Assert.AreEqual("projects/my-project-123/locations/global/keyRings/certs/cryptoKeys/certs", (string)secret.Resource["replication"]["automatic"]["customerManagedEncryption"]["kmsKeyName"]);

            var annotations = secret.Resource["annotations"];
            Assert.AreEqual(_managedCert.Id, (string)annotations[GoogleSecretManager.ManagedCertificateAnnotation]);
            Assert.AreEqual("projects/123456789012/secrets/www-example-com-tls/versions/1", (string)annotations[GoogleSecretManager.VersionAnnotation]);
            Assert.AreEqual(64, ((string)annotations[GoogleSecretManager.ValueHashAnnotation]).Length);

            var value = JsonNode.Parse(secret.Versions.Single().Value);
            using (var cert = X509Certificate2.CreateFromPem((string)value["certificate"], (string)value["private_key"]))
            {
                Assert.AreEqual(LeafSerial(), cert.SerialNumber);
            }

            StringAssert.StartsWith((string)value["private_key"], "-----BEGIN PRIVATE KEY-----");
            Assert.AreEqual(1, Regex.Matches((string)value["chain"], "BEGIN CERTIFICATE").Count);
            Assert.AreEqual(1, _gcp.TokenRequests, "signs in once");
        }

        [TestMethod, TestCategory("GoogleSecretManager")]
        public async Task RenewalAddsVersionKeepingOtherAnnotations()
        {
            var secret = _gcp.AddSecret(SecretId, "{}", new() { ["team"] = "web" });

            var results = await Execute();

            Assert.IsTrue(results.All(r => r.IsSuccess && !r.IsWarning), Messages(results));
            StringAssert.Contains(results.Single().Message, "added the certificate as projects/123456789012/secrets/www-example-com-tls/versions/2");
            Assert.AreEqual(2, secret.Versions.Count);
            Assert.AreEqual("web", (string)secret.Resource["annotations"]["team"]);
            Assert.AreEqual(_managedCert.Id, (string)secret.Resource["annotations"][GoogleSecretManager.ManagedCertificateAnnotation]);
            Assert.AreEqual("annotations", _gcp.Requests.Single(r => r.Method == "PATCH").Query["updateMask"]);
        }

        [TestMethod, TestCategory("GoogleSecretManager")]
        public async Task UpToDateSecretIsNotWritten()
        {
            await Execute();

            var results = await Execute();

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
            StringAssert.Contains(results.Single().Message, "is already up to date");
            Assert.AreEqual(1, _gcp.Secrets.Values.Single().Versions.Count);
        }

        [TestMethod, TestCategory("GoogleSecretManager")]
        public async Task CertificateIsAddedAgainWhenAnotherVersionWasAdded()
        {
            await Execute();
            var secret = _gcp.Secrets.Values.Single();
            secret.Versions.Add(("projects/123456789012/secrets/www-example-com-tls/versions/2", "{\"changed\":true}", "ENABLED"));

            var results = await Execute();

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
            StringAssert.Contains(results.Single().Message, "added the certificate as projects/123456789012/secrets/www-example-com-tls/versions/3");
        }

        [TestMethod, TestCategory("GoogleSecretManager")]
        public async Task SecretOfAnotherManagedCertificateIsRefused()
        {
            _gcp.AddSecret(SecretId, "{}", new() { [GoogleSecretManager.ManagedCertificateAnnotation] = "another-managed-certificate" });

            var results = await Execute();

            StringAssert.Contains(results.Single(r => !r.IsSuccess).Message, "holds the certificate of a different managed certificate");
            Assert.IsFalse(_gcp.Requests.Any(r => r.Path.EndsWith(":addVersion")));
        }

        [TestMethod, TestCategory("GoogleSecretManager")]
        public async Task PreviewMakesNoChangesAndChecksPermissions()
        {
            var secret = _gcp.AddSecret(SecretId, "{}");
            _gcp.Denied.Add("secretmanager.versions.add");

            var results = await Execute(isPreviewOnly: true);

            StringAssert.Contains(results[0].Message, $"Connected to Google Secret Manager in project my-project-123. Would add the certificate as the latest version of secret {SecretId}.");
            StringAssert.Contains(results.Single(r => !r.IsSuccess).Message, "the service account doesn't have the secretmanager.versions.add permission for secret www-example-com-tls");
            Assert.AreEqual(1, secret.Versions.Count);
        }

        [TestMethod, TestCategory("GoogleSecretManager")]
        public async Task PreviewBeforeCertificateIssuedChecksConnection()
        {
            _managedCert.CertificatePath = "";

            var results = await Execute(isPreviewOnly: true);

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
            StringAssert.Contains(results.Single().Message, $"No certificate has been issued yet. Deploying would create secret {SecretId} holding the certificate.");
        }

        [TestMethod, TestCategory("GoogleSecretManager")]
        public async Task ProjectIdSettingOverridesKeyProject()
        {
            var results = await Execute(projectId: "other-project-456");

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
            Assert.IsTrue(_gcp.Requests.Where(r => r.Path.StartsWith("/v1/")).All(r => r.Path.Contains("/projects/other-project-456/") || r.Path.Contains("/projects/123456789012/")));
            Assert.IsTrue(_gcp.Secrets.ContainsKey("other-project-456/www-example-com-tls"));
        }

        [TestMethod, TestCategory("GoogleSecretManager")]
        public async Task ReportsRejectedKey()
        {
            _gcp.RejectKey = true;

            var results = await Execute();

            StringAssert.Contains(results.Single(r => !r.IsSuccess).Message, "Google Cloud didn't accept the service account key (Invalid JWT Signature)");
        }

        [TestMethod, TestCategory("GoogleSecretManager")]
        public async Task ReportsMissingPermission()
        {
            _gcp.Denied.Add("secretmanager.secrets.create");

            var results = await Execute();

            var failure = results.Single(r => !r.IsSuccess).Message;
            StringAssert.Contains(failure, "could not create secret projects/my-project-123/secrets/www-example-com-tls: access denied (Permission 'secretmanager.secrets.create' denied");
            StringAssert.Contains(failure, "The service account needs the secretmanager.secrets.get, secretmanager.secrets.create, secretmanager.secrets.update, secretmanager.versions.add and secretmanager.versions.get permissions");
        }

        [TestMethod, TestCategory("GoogleSecretManager")]
        public async Task ReportsApiNotEnabled()
        {
            _gcp.ApiDisabled = true;

            var results = await Execute();

            StringAssert.Contains(results.Single(r => !r.IsSuccess).Message, "Secret Manager API has not been used in project 123456789012 before or it is disabled.");
        }

        [TestMethod, TestCategory("GoogleSecretManager")]
        public async Task ValidatesSettings()
        {
            Assert.IsTrue((await Execute(key: "")).Any(r => r.Message.Contains("A Google Cloud Service Account Key credential is required")));
            Assert.IsTrue((await Execute(key: "not json")).Any(r => r.Message.Contains("must be the contents of a service account's JSON key file")));
            Assert.IsTrue((await Execute(key: "{\"type\":\"authorized_user\"}")).Any(r => r.Message.Contains("must be the contents of a service account's JSON key file")));
            Assert.IsTrue((await Execute(key: _gcp.KeyJson(projectId: null))).Any(r => r.Message.Contains("Project ID is required, as the service account key doesn't give one")));
            Assert.IsTrue((await Execute(projectId: "My Project")).Any(r => r.Message.Contains("isn't a Google Cloud project ID")));
            Assert.IsTrue((await Execute(secretId: null)).Any(r => r.Message.Contains("Secret ID is required")));
            Assert.IsTrue((await Execute(secretId: "www.example.com")).Any(r => r.Message.Contains("Secret ID can only contain")));
            Assert.IsTrue((await Execute(kmsKeyName: "certs")).Any(r => r.Message.Contains("KMS Key must be a Cloud KMS key name")));
            Assert.IsTrue((await Execute(endpoint: "secretmanager")).Any(r => r.Message.Contains("API Endpoint must be blank or a full URL")));

            Assert.AreEqual(0, _gcp.Requests.Count, "invalid settings never reach Google Cloud");
        }

        private string LeafSerial()
        {
            var collection = X509CertificateLoader.LoadPkcs12CollectionFromFile(_pfxPath, "");
            return collection.Single(c => c.HasPrivateKey).SerialNumber;
        }

        private static string Messages(List<ActionResult> results) => string.Join("; ", results.Select(r => r.Message));

        private async Task<List<ActionResult>> Execute(bool isPreviewOnly = false, string projectId = null, string secretId = SecretId, string kmsKeyName = null, string endpoint = null, string key = null)
        {
            var config = new DeploymentTaskConfig
            {
                TaskTypeId = GoogleSecretManager.Definition.Id,
                ChallengeProvider = CredentialTypes.GoogleServiceAccountKey,
                Parameters = new List<ProviderParameterSetting>
                {
                    new ProviderParameterSetting("project_id", projectId),
                    new ProviderParameterSetting("secret_id", secretId),
                    new ProviderParameterSetting("kms_key_name", kmsKeyName),
                    new ProviderParameterSetting("api_endpoint", endpoint ?? _gcp.Address)
                }
            };

            var credentials = new Dictionary<string, string> { ["service_account_key"] = key ?? _gcp.KeyJson() };
            var execParams = new DeploymentTaskExecutionParams(_log, null, _managedCert, config, credentials, isPreviewOnly, GoogleSecretManager.Definition, new DeploymentContext(), CancellationToken.None);
            return await new GoogleSecretManager().Execute(execParams);
        }
    }

    /// <summary>
    /// Runs the Google Cloud Certificate Manager task against a local stand-in for Google's token endpoint and the Certificate Manager API
    /// </summary>
    [TestClass]
    public class DeploymentTasksGoogleCertificateManager : IntegrationTestBase
    {
        private const string CertificateId = "www-example-com";

        private FakeGoogleCloud _gcp;
        private string _pfxPath;
        private ManagedCertificate _managedCert;

        [TestInitialize]
        public override void Setup()
        {
            base.Setup();

            _gcp = new FakeGoogleCloud();
            (_pfxPath, _) = TestCertificates.CreatePfxWithChain(1);
            _managedCert = GetMockManagedCertificate("GoogleCertificateManagerTest", "1", "www.example.com", PrimaryIISRoot);
            _managedCert.CertificatePath = _pfxPath;
        }

        [TestCleanup]
        public void Cleanup()
        {
            _gcp?.Dispose();
            if (_pfxPath != null && File.Exists(_pfxPath))
            {
                File.Delete(_pfxPath);
            }
        }

        [TestMethod, TestCategory("GoogleCertificateManager")]
        public async Task FirstDeploymentCreatesSelfManagedCertificate()
        {
            _gcp.PendingPolls = 1;

            var results = await Execute();

            Assert.IsTrue(results.All(r => r.IsSuccess && !r.IsWarning), Messages(results));
            StringAssert.Contains(results.Single().Message, "created certificate projects/my-project-123/locations/global/certificates/www-example-com. Add it to a certificate map entry or target proxy");

            var certificate = _gcp.Certificates["my-project-123/global/www-example-com"];
            Assert.AreEqual(LeafSerial(), X509Certificate2.CreateFromPem((string)certificate["pemCertificate"]).SerialNumber);
            Assert.AreEqual(2, Regex.Matches((string)certificate["pemCertificate"], "BEGIN CERTIFICATE").Count, "certificate and intermediate");
            Assert.AreEqual(_managedCert.Id, (string)certificate["labels"][GoogleCertificateManager.ManagedCertificateLabel]);
            Assert.AreEqual(2, _gcp.Requests.Count(r => r.Path.Contains("/operations/")), "polls the operation until it is done");
        }

        [TestMethod, TestCategory("GoogleCertificateManager")]
        public async Task RenewalUpdatesCertificate()
        {
            var existing = _gcp.AddCertificate("global", CertificateId, OtherCertPem());

            var results = await Execute();

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
            StringAssert.Contains(results.Single().Message, "updated certificate projects/my-project-123/locations/global/certificates/www-example-com, so the load balancers using it pick up the renewed certificate");
            Assert.AreEqual(LeafSerial(), X509Certificate2.CreateFromPem((string)existing["pemCertificate"]).SerialNumber);
            Assert.AreEqual("selfManaged", _gcp.Requests.Single(r => r.Method == "PATCH").Query["updateMask"]);
        }

        [TestMethod, TestCategory("GoogleCertificateManager")]
        public async Task UpToDateCertificateIsNotUpdated()
        {
            await Execute();

            var results = await Execute();

            StringAssert.Contains(results.Single().Message, "is already up to date");
            Assert.IsFalse(_gcp.Requests.Any(r => r.Method == "PATCH"));
        }

        [TestMethod, TestCategory("GoogleCertificateManager")]
        public async Task RegionalCertificateIsCreatedInItsLocation()
        {
            var results = await Execute(location: "europe-west1");

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
            Assert.IsTrue(_gcp.Certificates.ContainsKey("my-project-123/europe-west1/www-example-com"));
        }

        [TestMethod, TestCategory("GoogleCertificateManager")]
        public async Task GoogleManagedCertificateIsRefused()
        {
            _gcp.AddCertificate("global", CertificateId, null)["managed"] = new JsonObject { ["domains"] = new JsonArray("www.example.com") };

            var results = await Execute();

            StringAssert.Contains(results.Single(r => !r.IsSuccess).Message, "is a Google-managed certificate");
            Assert.IsFalse(_gcp.Requests.Any(r => r.Method == "PATCH"));
        }

        [TestMethod, TestCategory("GoogleCertificateManager")]
        public async Task CertificateOfAnotherManagedCertificateIsRefused()
        {
            _gcp.AddCertificate("global", CertificateId, OtherCertPem())["labels"] = new JsonObject { [GoogleCertificateManager.ManagedCertificateLabel] = "another" };

            var results = await Execute();

            StringAssert.Contains(results.Single(r => !r.IsSuccess).Message, "holds the certificate of a different managed certificate");
        }

        [TestMethod, TestCategory("GoogleCertificateManager")]
        public async Task ReportsOperationFailure()
        {
            _gcp.OperationError = "The private key doesn't match the certificate.";

            var results = await Execute();

            StringAssert.Contains(results.Single(r => !r.IsSuccess).Message, "could not create certificate projects/my-project-123/locations/global/certificates/www-example-com: The private key doesn't match the certificate.");
        }

        [TestMethod, TestCategory("GoogleCertificateManager")]
        public async Task PreviewMakesNoChanges()
        {
            _gcp.AddCertificate("global", CertificateId, OtherCertPem());

            var results = await Execute(isPreviewOnly: true);

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
            StringAssert.Contains(results.Single().Message, $"Connected to Google Certificate Manager in project my-project-123. Would update certificate {CertificateId}, so the load balancers using it pick up the renewed certificate.");
            Assert.IsFalse(_gcp.Requests.Any(r => r.Method != "GET" && !r.Path.EndsWith("/token")));
        }

        [TestMethod, TestCategory("GoogleCertificateManager")]
        public async Task ValidatesSettings()
        {
            Assert.IsTrue((await Execute(location: "Europe")).Any(r => r.Message.Contains("Location must be 'global', or a region")));
            Assert.IsTrue((await Execute(certificateId: null)).Any(r => r.Message.Contains("Certificate ID is required")));
            Assert.IsTrue((await Execute(certificateId: "1-www")).Any(r => r.Message.Contains("Certificate ID must start with a lower case letter")));
            Assert.IsTrue((await Execute(key: "")).Any(r => r.Message.Contains("A Google Cloud Service Account Key credential is required")));

            Assert.AreEqual(0, _gcp.Requests.Count, "invalid settings never reach Google Cloud");
        }

        private string LeafSerial()
        {
            var collection = X509CertificateLoader.LoadPkcs12CollectionFromFile(_pfxPath, "");
            return collection.Single(c => c.HasPrivateKey).SerialNumber;
        }

        private static string OtherCertPem()
        {
            using var key = RSA.Create(2048);
            using var cert = new CertificateRequest("CN=www.example.com", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1).CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-90), DateTimeOffset.UtcNow.AddDays(1));
            return cert.ExportCertificatePem();
        }

        private static string Messages(List<ActionResult> results) => string.Join("; ", results.Select(r => r.Message));

        private async Task<List<ActionResult>> Execute(bool isPreviewOnly = false, string location = null, string certificateId = CertificateId, string key = null)
        {
            var config = new DeploymentTaskConfig
            {
                TaskTypeId = GoogleCertificateManager.Definition.Id,
                ChallengeProvider = CredentialTypes.GoogleServiceAccountKey,
                Parameters = new List<ProviderParameterSetting>
                {
                    new ProviderParameterSetting("location", location),
                    new ProviderParameterSetting("certificate_id", certificateId),
                    new ProviderParameterSetting("api_endpoint", _gcp.Address)
                }
            };

            var credentials = new Dictionary<string, string> { ["service_account_key"] = key ?? _gcp.KeyJson() };
            var execParams = new DeploymentTaskExecutionParams(_log, null, _managedCert, config, credentials, isPreviewOnly, GoogleCertificateManager.Definition, new DeploymentContext(), CancellationToken.None);
            return await new GoogleCertificateManager().Execute(execParams);
        }
    }

    /// <summary>
    /// Stand-in for Google Cloud: the OAuth token endpoint (JWT bearer grant, checking the JWT is signed by the service account key), and the
    /// Secret Manager and Certificate Manager REST APIs, with Google's error format. Resource names in responses use the project number, as
    /// Google's do. Permissions in Denied are refused, and left out of testIamPermissions results.
    /// </summary>
    internal sealed class FakeGoogleCloud : IDisposable
    {
        public const string ProjectNumber = "123456789012";
        private const string AccessToken = "test-access-token";

        private readonly FakeHttpServer _server;
        private readonly RSA _key = RSA.Create(2048);
        private int _operations;

        public sealed class FakeSecret
        {
            public JsonObject Resource { get; init; }
            public List<(string Name, string Value, string State)> Versions { get; } = new();
        }

        public Dictionary<string, FakeSecret> Secrets { get; } = new();
        public Dictionary<string, JsonObject> Certificates { get; } = new();
        public HashSet<string> Denied { get; } = new();
        public List<FakeHttpRequest> Requests => _server.Requests.ToList();
        public string Address => _server.Address;
        public int TokenRequests => Requests.Count(r => r.Path == "/token");
        public bool RejectKey { get; set; }
        public bool ApiDisabled { get; set; }
        public int PendingPolls { get; set; }
        public string OperationError { get; set; }

        private readonly Dictionary<string, (int PollsLeft, JsonObject Result)> _pending = new();

        public FakeGoogleCloud()
        {
            _server = new FakeHttpServer(Handle);
        }

        /// <summary>
        /// A service account JSON key file for the stand-in, with its token endpoint
        /// </summary>
        public string KeyJson(string projectId = "my-project-123")
        {
            var key = new JsonObject
            {
                ["type"] = "service_account",
                ["private_key_id"] = "abc123",
                ["private_key"] = _key.ExportPkcs8PrivateKeyPem() + "\n",
                ["client_email"] = "certify@my-project-123.iam.gserviceaccount.com",
                ["client_id"] = "1234567890",
                ["token_uri"] = Address + "/token"
            };

            if (projectId != null)
            {
                key["project_id"] = projectId;
            }

            return key.ToJsonString();
        }

        public FakeSecret AddSecret(string id, string value, Dictionary<string, string> annotations = null, string project = "my-project-123")
        {
            var secret = new FakeSecret
            {
                Resource = new JsonObject
                {
                    ["name"] = $"projects/{ProjectNumber}/secrets/{id}",
                    ["replication"] = new JsonObject { ["automatic"] = new JsonObject() },
                    ["annotations"] = new JsonObject((annotations ?? new()).Select(a => KeyValuePair.Create(a.Key, (JsonNode)a.Value)))
                }
            };

            secret.Versions.Add(($"projects/{ProjectNumber}/secrets/{id}/versions/1", value, "ENABLED"));
            Secrets[$"{project}/{id}"] = secret;
            return secret;
        }

        public JsonObject AddCertificate(string location, string id, string pemChain, string project = "my-project-123")
        {
            var certificate = new JsonObject { ["name"] = $"projects/{project}/locations/{location}/certificates/{id}" };
            if (pemChain != null)
            {
                certificate["selfManaged"] = new JsonObject();
                certificate["pemCertificate"] = pemChain;
            }

            Certificates[$"{project}/{location}/{id}"] = certificate;
            return certificate;
        }

        private FakeHttpResponse Handle(FakeHttpRequest request)
        {
            lock (Secrets)
            {
                if (request.Path == "/token")
                {
                    return Token(request);
                }

                if (request.Header("Authorization") != $"Bearer {AccessToken}")
                {
                    return Error(401, "UNAUTHENTICATED", "Request had invalid authentication credentials.");
                }

                if (ApiDisabled)
                {
                    return Error(403, "PERMISSION_DENIED", $"Secret Manager API has not been used in project {ProjectNumber} before or it is disabled. Enable it by visiting https://console.developers.google.com/apis/api/secretmanager.googleapis.com/overview?project={ProjectNumber} then retry.");
                }

                var body = string.IsNullOrEmpty(request.Body) ? null : JsonNode.Parse(request.Body);

                var secretMatch = Regex.Match(request.Path, "^/v1/projects/([^/]+)/secrets(?:/([^/:]+))?(/versions/latest|:addVersion|:testIamPermissions)?$");
                if (secretMatch.Success)
                {
                    return HandleSecret(request, body, secretMatch.Groups[1].Value, secretMatch.Groups[2].Value, secretMatch.Groups[3].Value);
                }

                var certMatch = Regex.Match(request.Path, "^/v1/projects/([^/]+)/locations/([^/]+)/(certificates|operations)(?:/([^/]+))?$");
                if (certMatch.Success)
                {
                    return HandleCertificate(request, body, certMatch.Groups[1].Value, certMatch.Groups[2].Value, certMatch.Groups[3].Value, certMatch.Groups[4].Value);
                }

                return Error(404, "NOT_FOUND", "Not found");
            }
        }

        private FakeHttpResponse Token(FakeHttpRequest request)
        {
            var form = System.Web.HttpUtility.ParseQueryString(request.Body);
            if (form["grant_type"] != "urn:ietf:params:oauth:grant-type:jwt-bearer" || RejectKey)
            {
                return new FakeHttpResponse(400, "application/json", "{\"error\":\"invalid_grant\",\"error_description\":\"Invalid JWT Signature.\"}");
            }

            // the JWT must be signed by the service account key, for this token endpoint
            var parts = form["assertion"].Split('.');
            var valid = _key.VerifyData(Encoding.ASCII.GetBytes($"{parts[0]}.{parts[1]}"), FromBase64Url(parts[2]), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var header = JsonNode.Parse(FromBase64Url(parts[0]));
            var claims = JsonNode.Parse(FromBase64Url(parts[1]));
            if (!valid || (string)header["alg"] != "RS256" || (string)header["kid"] != "abc123" || (string)claims["iss"] != "certify@my-project-123.iam.gserviceaccount.com"
                || (string)claims["aud"] != Address + "/token" || (string)claims["scope"] != "https://www.googleapis.com/auth/cloud-platform" || (long)claims["exp"] - (long)claims["iat"] > 3600)
            {
                return new FakeHttpResponse(400, "application/json", "{\"error\":\"invalid_grant\",\"error_description\":\"Invalid JWT.\"}");
            }

            return new FakeHttpResponse(200, "application/json", $"{{\"access_token\":\"{AccessToken}\",\"expires_in\":3599,\"token_type\":\"Bearer\"}}");
        }

        private FakeHttpResponse HandleSecret(FakeHttpRequest request, JsonNode body, string project, string id, string action)
        {
            var key = $"{project}/{id}";
            Secrets.TryGetValue(key, out var secret);
            var resourceName = $"projects/{project}/secrets/{id}";

            if (request.Method == "POST" && id == "" && action == "")
            {
                if (Denied.Contains("secretmanager.secrets.create"))
                {
                    return Denied403("secretmanager.secrets.create", $"projects/{project}");
                }

                id = request.Query["secretId"];
                var created = new FakeSecret { Resource = body.DeepClone().AsObject() };
                created.Resource["name"] = $"projects/{ProjectNumber}/secrets/{id}";
                Secrets[$"{project}/{id}"] = created;
                return Ok(created.Resource);
            }

            if (secret == null)
            {
                return Error(404, "NOT_FOUND", $"Secret [{resourceName}] not found.");
            }

            switch (request.Method, action)
            {
                case ("GET", ""):
                    return Ok(secret.Resource);

                case ("GET", "/versions/latest"):
                    var latest = secret.Versions.Last();
                    return Ok(new JsonObject { ["name"] = latest.Name, ["state"] = latest.State });

                case ("POST", ":addVersion"):
                    if (Denied.Contains("secretmanager.versions.add"))
                    {
                        return Denied403("secretmanager.versions.add", resourceName);
                    }

                    var name = $"projects/{ProjectNumber}/secrets/{id}/versions/{secret.Versions.Count + 1}";
                    secret.Versions.Add((name, Encoding.UTF8.GetString(Convert.FromBase64String((string)body["payload"]["data"])), "ENABLED"));
                    return Ok(new JsonObject { ["name"] = name, ["state"] = "ENABLED" });

                case ("PATCH", ""):
                    if (request.Query.GetValueOrDefault("updateMask") != "annotations")
                    {
                        return Error(400, "INVALID_ARGUMENT", "Unexpected update mask.");
                    }

                    secret.Resource["annotations"] = body["annotations"].DeepClone();
                    return Ok(secret.Resource);

                case ("POST", ":testIamPermissions"):
                    return Ok(new JsonObject { ["permissions"] = new JsonArray(body["permissions"].AsArray().Select(p => (string)p).Where(p => !Denied.Contains(p)).Select(p => (JsonNode)p).ToArray()) });
            }

            return Error(404, "NOT_FOUND", "Not found");
        }

        private FakeHttpResponse HandleCertificate(FakeHttpRequest request, JsonNode body, string project, string location, string collection, string id)
        {
            if (collection == "operations")
            {
                var (pollsLeft, result) = _pending[id];
                if (pollsLeft > 0)
                {
                    _pending[id] = (pollsLeft - 1, result);
                    return Ok(new JsonObject { ["name"] = $"projects/{project}/locations/{location}/operations/{id}", ["done"] = false });
                }

                return Ok(result);
            }

            var key = $"{project}/{location}/{id}";
            Certificates.TryGetValue(key, out var certificate);

            if (request.Method == "GET")
            {
                return certificate == null ? Error(404, "NOT_FOUND", $"Resource 'projects/{project}/locations/{location}/certificates/{id}' was not found") : Ok(certificate);
            }

            if (request.Method == "POST")
            {
                id = request.Query["certificateId"];
                key = $"{project}/{location}/{id}";
                certificate = new JsonObject { ["name"] = $"projects/{project}/locations/{location}/certificates/{id}", ["labels"] = body["labels"].DeepClone() };
            }
            else if (request.Method == "PATCH" && certificate != null && request.Query.GetValueOrDefault("updateMask") != "selfManaged")
            {
                return Error(400, "INVALID_ARGUMENT", "Unexpected update mask.");
            }
            else if (certificate == null)
            {
                return Error(404, "NOT_FOUND", "Not found");
            }

            var operationId = $"operation-{++_operations}";
            JsonObject done;
            if (OperationError != null)
            {
                done = new JsonObject { ["name"] = operationId, ["done"] = true, ["error"] = new JsonObject { ["code"] = 3, ["message"] = OperationError } };
            }
            else
            {
                // the key must match the certificate
                var chain = (string)body["selfManaged"]["pemCertificate"];
                using (X509Certificate2.CreateFromPem(chain, (string)body["selfManaged"]["pemPrivateKey"]))
                {
                }

                certificate["selfManaged"] = new JsonObject();
                certificate["pemCertificate"] = chain;
                Certificates[key] = certificate;
                done = new JsonObject { ["name"] = operationId, ["done"] = true, ["response"] = certificate.DeepClone() };
            }

            var operationName = $"projects/{project}/locations/{location}/operations/{operationId}";
            done["name"] = operationName;
            _pending[operationId] = (PendingPolls, done);

            return Ok(PendingPolls > 0 ? new JsonObject { ["name"] = operationName, ["done"] = false } : done);
        }

        private static byte[] FromBase64Url(string value)
        {
            var base64 = value.Replace('-', '+').Replace('_', '/');
            return Convert.FromBase64String(base64.PadRight(base64.Length + (4 - base64.Length % 4) % 4, '='));
        }

        private static FakeHttpResponse Ok(JsonNode body) => new FakeHttpResponse(200, "application/json", body.ToJsonString());

        private static FakeHttpResponse Denied403(string permission, string resource)
            => Error(403, "PERMISSION_DENIED", $"Permission '{permission}' denied for resource '{resource}' (or it may not exist).");

        private static FakeHttpResponse Error(int code, string status, string message)
            => new FakeHttpResponse(code, "application/json", new JsonObject { ["error"] = new JsonObject { ["code"] = code, ["message"] = message, ["status"] = status } }.ToJsonString());

        public void Dispose()
        {
            _server.Dispose();
            _key.Dispose();
        }
    }
}
