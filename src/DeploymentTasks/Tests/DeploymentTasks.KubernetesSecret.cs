using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
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
    /// Runs the Kubernetes TLS secret task against a local stand-in for the Kubernetes API: secrets (get, server side apply) and workloads
    /// (get, strategic merge patch), with Kubernetes Status errors. The TLS tests serve it over HTTPS with a certificate from a test cluster CA.
    /// </summary>
    [TestClass]
    public class DeploymentTasksKubernetesSecret : IntegrationTestBase
    {
        private const string Token = "test-service-account-token";
        private const string Namespace = "web";
        private const string SecretName = "www-example-com-tls";

        private FakeKubernetes _k8s;
        private string _pfxPath;
        private ManagedCertificate _managedCert;

        [TestInitialize]
        public override void Setup()
        {
            base.Setup();

            _k8s = new FakeKubernetes();
            (_pfxPath, _) = TestCertificates.CreatePfxWithChain(1);
            _managedCert = GetMockManagedCertificate("KubernetesTest", "1", "www.example.com", PrimaryIISRoot);
            _managedCert.CertificatePath = _pfxPath;
        }

        [TestCleanup]
        public void Cleanup()
        {
            _k8s?.Dispose();
            if (_pfxPath != null && File.Exists(_pfxPath))
            {
                File.Delete(_pfxPath);
            }
        }

        [TestMethod, TestCategory("KubernetesSecret")]
        public async Task FirstDeploymentCreatesTlsSecret()
        {
            var results = await Execute();

            Assert.IsTrue(results.All(r => r.IsSuccess && !r.IsWarning), Messages(results));
            StringAssert.Contains(results.Single().Message, $"created TLS secret {Namespace}/{SecretName}");

            var secret = _k8s.Secrets[$"{Namespace}/{SecretName}"];
            Assert.AreEqual("kubernetes.io/tls", (string)secret["type"]);

            var crt = Data(secret, "tls.crt");
            var key = Data(secret, "tls.key");
            Assert.AreEqual(2, Regex.Matches(crt, "BEGIN CERTIFICATE").Count, "certificate and intermediate, root excluded");
            StringAssert.StartsWith(key, "-----BEGIN PRIVATE KEY-----", "key is PKCS#8");
            using (var cert = X509Certificate2.CreateFromPem(crt, key))
            {
                Assert.AreEqual(LeafSerial(), cert.SerialNumber, "certificate comes first, and the key matches it");
            }

            var annotations = secret["metadata"]["annotations"];
            Assert.AreEqual(_managedCert.Id, (string)annotations[KubernetesSecret.ManagedCertificateAnnotation]);
            Assert.AreEqual(LeafSerial(), (string)annotations[KubernetesSecret.SerialAnnotation]);
            Assert.IsNotNull((string)annotations[KubernetesSecret.ExpiryAnnotation]);

            var apply = _k8s.Requests.Single(r => r.Method == "PATCH");
            Assert.AreEqual("application/apply-patch+yaml", apply.Header("Content-Type").Split(';')[0]);
            Assert.AreEqual("certify-the-web", apply.Query["fieldManager"]);
            Assert.AreEqual("true", apply.Query["force"]);
            Assert.IsTrue(_k8s.Requests.All(r => r.Header("Authorization") == $"Bearer {Token}"));
        }

        [TestMethod, TestCategory("KubernetesSecret")]
        public async Task RenewalUpdatesSecretKeepingItsOtherKeysAndLabels()
        {
            var existing = _k8s.AddSecret(Namespace, SecretName, "kubernetes.io/tls", new() { ["tls.crt"] = "old", ["tls.key"] = "old", ["ca.crt"] = "client ca" }, labels: new() { ["app"] = "web" });

            var results = await Execute();

            Assert.IsTrue(results.All(r => r.IsSuccess && !r.IsWarning), Messages(results));
            StringAssert.Contains(results.Single().Message, $"updated TLS secret {Namespace}/{SecretName}");
            Assert.AreEqual(LeafSerial(), X509Certificate2.CreateFromPem(Data(existing, "tls.crt")).SerialNumber);
            Assert.AreEqual("client ca", Data(existing, "ca.crt"));
            Assert.AreEqual("web", (string)existing["metadata"]["labels"]["app"]);
        }

        [TestMethod, TestCategory("KubernetesSecret")]
        public async Task UpToDateSecretIsNotWrittenAndWorkloadsAreNotRestarted()
        {
            _k8s.AddWorkload(Namespace, "deployment", "web");
            await Execute(workloads: "web");
            var patches = _k8s.Requests.Count(r => r.Method == "PATCH");

            var results = await Execute(workloads: "web");

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
            StringAssert.Contains(results.Single().Message, $"secret {Namespace}/{SecretName} is already up to date");
            Assert.AreEqual(patches, _k8s.Requests.Count(r => r.Method == "PATCH"));
        }

        [TestMethod, TestCategory("KubernetesSecret")]
        public async Task RestartsWorkloadsWhenCertificateChanges()
        {
            var web = _k8s.AddWorkload(Namespace, "deployment", "web");
            var db = _k8s.AddWorkload(Namespace, "statefulset", "db");
            var agent = _k8s.AddWorkload(Namespace, "daemonset", "agent");

            var results = await Execute(workloads: "web, sts/db; daemonset/agent");

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
            CollectionAssert.AreEqual(new[] { "Kubernetes: restarted deployment/web.", "Kubernetes: restarted statefulset/db.", "Kubernetes: restarted daemonset/agent." }, results.Skip(1).Select(r => r.Message).ToArray());
            foreach (var workload in new[] { web, db, agent })
            {
                Assert.IsNotNull((string)workload["spec"]["template"]["metadata"]["annotations"]["kubectl.kubernetes.io/restartedAt"]);
            }

            Assert.IsTrue(_k8s.Requests.Where(r => r.Method == "PATCH" && r.Path.StartsWith("/apis/apps/")).All(r => r.Header("Content-Type").StartsWith("application/strategic-merge-patch+json")));
        }

        [TestMethod, TestCategory("KubernetesSecret")]
        public async Task MissingWorkloadIsReportedAfterSecretIsUpdated()
        {
            var results = await Execute(workloads: "missing");

            Assert.IsTrue(results[0].IsSuccess, Messages(results));
            var failure = results.Single(r => !r.IsSuccess).Message;
            StringAssert.Contains(failure, "the secret was updated, but deployment/missing could not be restarted: there is no deployment/missing in namespace web");
            StringAssert.Contains(failure, "Restart it yourself");
        }

        [TestMethod, TestCategory("KubernetesSecret")]
        public async Task ServerWithPathIsUsed()
        {
            var results = await Execute(server: _k8s.Address + "/k8s/clusters/c-abc12");

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
            Assert.IsTrue(_k8s.Requests.All(r => r.Path.StartsWith("/k8s/clusters/c-abc12/api/v1/")));
        }

        [TestMethod, TestCategory("KubernetesSecret")]
        public async Task PreviewMakesNoChangesAndChecksWorkloads()
        {
            _k8s.AddWorkload(Namespace, "deployment", "web");

            var results = await Execute(isPreviewOnly: true, workloads: "web, statefulset/missing");

            StringAssert.Contains(results[0].Message, $"Connected to the Kubernetes API server at {_k8s.Address}/. Would create TLS secret {Namespace}/{SecretName}, then restart deployment/web, statefulset/missing.");
            StringAssert.Contains(results.Single(r => !r.IsSuccess).Message, "there is no statefulset/missing in namespace web");
            Assert.IsFalse(_k8s.Requests.Any(r => r.Method == "PATCH"));
            Assert.AreEqual(0, _k8s.Secrets.Count);
        }

        [TestMethod, TestCategory("KubernetesSecret")]
        public async Task PreviewReportsMissingPermissions()
        {
            _k8s.AddWorkload(Namespace, "deployment", "web");
            _k8s.Denied.Add("create secrets");
            _k8s.Denied.Add("patch deployments/web");

            var results = await Execute(isPreviewOnly: true, workloads: "web");

            var failures = results.Where(r => !r.IsSuccess).Select(r => r.Message).ToList();
            CollectionAssert.AreEqual(new[]
            {
                "Kubernetes: the service account isn't allowed to create secret www-example-com-tls in namespace web, which deploying needs. Add the permission to its Role.",
                "Kubernetes: the service account isn't allowed to patch deployment/web in namespace web, which deploying needs. Add the permission to its Role."
            }, failures);

            var create = JsonNode.Parse(_k8s.Requests.First(r => r.Path.EndsWith("/selfsubjectaccessreviews")).Body)["spec"]["resourceAttributes"];
            Assert.AreEqual(SecretName, (string)create["name"], "server side apply creates by name, so create is checked for the name");
        }

        [TestMethod, TestCategory("KubernetesSecret")]
        public async Task PreviewWithoutAccessReviewsStillWorks()
        {
            _k8s.AccessReviewsUnavailable = true;

            var results = await Execute(isPreviewOnly: true);

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
        }

        [TestMethod, TestCategory("KubernetesSecret")]
        public async Task PreviewOfExistingSecretDoesNotNeedCreate()
        {
            _k8s.AddSecret(Namespace, SecretName, "kubernetes.io/tls", new() { ["tls.crt"] = "old", ["tls.key"] = "old" });
            _k8s.Denied.Add("create secrets");

            var results = await Execute(isPreviewOnly: true);

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
            StringAssert.Contains(results.Single().Message, $"Would update TLS secret {Namespace}/{SecretName}.");
        }

        [TestMethod, TestCategory("KubernetesSecret")]
        public async Task PreviewBeforeCertificateIssuedChecksConnection()
        {
            _managedCert.CertificatePath = "";

            var results = await Execute(isPreviewOnly: true);

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
            StringAssert.Contains(results.Single().Message, $"No certificate has been issued yet. Deploying would create TLS secret {Namespace}/{SecretName}.");
        }

        [TestMethod, TestCategory("KubernetesSecret")]
        public async Task SecretOfAnotherTypeIsRefused()
        {
            _k8s.AddSecret(Namespace, SecretName, "Opaque", new() { ["password"] = "x" });

            var results = await Execute();

            StringAssert.Contains(results.Single(r => !r.IsSuccess).Message, "has type Opaque, not kubernetes.io/tls");
            Assert.IsFalse(_k8s.Requests.Any(r => r.Method == "PATCH"));
        }

        [TestMethod, TestCategory("KubernetesSecret")]
        public async Task ImmutableSecretIsRefused()
        {
            _k8s.AddSecret(Namespace, SecretName, "kubernetes.io/tls", new() { ["tls.crt"] = "old", ["tls.key"] = "old" })["immutable"] = true;

            var results = await Execute();

            StringAssert.Contains(results.Single(r => !r.IsSuccess).Message, "is immutable");
            Assert.IsFalse(_k8s.Requests.Any(r => r.Method == "PATCH"));
        }

        [TestMethod, TestCategory("KubernetesSecret")]
        public async Task CertManagerSecretIsRefused()
        {
            _k8s.AddSecret(Namespace, SecretName, "kubernetes.io/tls", new() { ["tls.crt"] = "old", ["tls.key"] = "old" }, annotations: new() { ["cert-manager.io/certificate-name"] = "www" });

            var results = await Execute();

            StringAssert.Contains(results.Single(r => !r.IsSuccess).Message, "is managed by cert-manager (Certificate www)");
            Assert.IsFalse(_k8s.Requests.Any(r => r.Method == "PATCH"));
        }

        [TestMethod, TestCategory("KubernetesSecret")]
        public async Task SecretOfAnotherManagedCertificateIsRefused()
        {
            _k8s.AddSecret(Namespace, SecretName, "kubernetes.io/tls", new() { ["tls.crt"] = "old", ["tls.key"] = "old" }, annotations: new() { [KubernetesSecret.ManagedCertificateAnnotation] = "another-managed-certificate" });

            var results = await Execute();

            StringAssert.Contains(results.Single(r => !r.IsSuccess).Message, "holds the certificate of a different managed certificate");
            Assert.IsFalse(_k8s.Requests.Any(r => r.Method == "PATCH"));
        }

        [TestMethod, TestCategory("KubernetesSecret")]
        public async Task HelmSecretIsWarnedAbout()
        {
            _k8s.AddSecret(Namespace, SecretName, "kubernetes.io/tls", new() { ["tls.crt"] = "old", ["tls.key"] = "old" }, annotations: new() { ["meta.helm.sh/release-name"] = "web" });

            var results = await Execute();

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
            StringAssert.Contains(results.Single(r => r.IsWarning).Message, "is part of Helm release web");
            Assert.AreEqual(1, _k8s.Requests.Count(r => r.Method == "PATCH"));
        }

        [TestMethod, TestCategory("KubernetesSecret")]
        public async Task ReportsInvalidToken()
        {
            var results = await Execute(token: "wrong");

            StringAssert.Contains(results.Single(r => !r.IsSuccess).Message, "the API server didn't accept the token (401 Unauthorized)");
        }

        [TestMethod, TestCategory("KubernetesSecret")]
        public async Task ReportsMissingPermission()
        {
            _k8s.DenyPatch = true;

            var results = await Execute();

            var failure = results.Single(r => !r.IsSuccess).Message;
            StringAssert.Contains(failure, "could not create secret web/www-example-com-tls: access denied (secrets \"www-example-com-tls\" is forbidden: User \"system:serviceaccount:certify:certify\" cannot patch resource \"secrets\"");
            StringAssert.Contains(failure, "Check the Role and RoleBinding of the service account");
        }

        [TestMethod, TestCategory("KubernetesSecret")]
        public async Task TrustsClusterCaFromKubeconfig()
        {
            using var tls = TlsServer();
            var caData = Convert.ToBase64String(Encoding.ASCII.GetBytes(tls.CaPem));

            var results = await Execute(server: tls.Server.Address, caData: caData);

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
            StringAssert.Contains(results.Single().Message, "created TLS secret");
        }

        [TestMethod, TestCategory("KubernetesSecret")]
        public async Task TrustsClusterCaPemWithLineBreaksLost()
        {
            using var tls = TlsServer();

            var results = await Execute(server: tls.Server.Address, caData: tls.CaPem.Replace("\n", " "));

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
        }

        [TestMethod, TestCategory("KubernetesSecret")]
        public async Task RefusesServerNotIssuedByClusterCa()
        {
            using var tls = TlsServer();
            using var otherCa = CreateCa();

            var withoutCa = await Execute(server: tls.Server.Address);
            var withOtherCa = await Execute(server: tls.Server.Address, caData: otherCa.ExportCertificatePem());

            foreach (var results in new[] { withoutCa, withOtherCa })
            {
                var failure = results.Single(r => !r.IsSuccess).Message;
                StringAssert.Contains(failure, "could not connect to the API server");
                StringAssert.Contains(failure, "Set the Cluster CA Certificate of the credential");
            }

            Assert.AreEqual(0, _k8s.Secrets.Count);
        }

        [TestMethod, TestCategory("KubernetesSecret")]
        public async Task AllowInvalidTlsSkipsCertificateCheck()
        {
            using var tls = TlsServer();

            var results = await Execute(server: tls.Server.Address, allowInvalidTls: true);

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
        }

        [TestMethod, TestCategory("KubernetesSecret")]
        public async Task ValidatesSettings()
        {
            Assert.IsTrue((await Execute(ns: null)).Any(r => r.Message.Contains("Namespace is required")));
            Assert.IsTrue((await Execute(ns: "Web_Apps")).Any(r => r.Message.Contains("Namespace must be a Kubernetes namespace name")));
            Assert.IsTrue((await Execute(secretName: null)).Any(r => r.Message.Contains("Secret Name is required")));
            Assert.IsTrue((await Execute(secretName: "WWW TLS")).Any(r => r.Message.Contains("Secret Name must be a Kubernetes object name")));
            Assert.IsTrue((await Execute(workloads: "web, pod/web")).Any(r => r.Message.Contains("'pod/web' isn't a workload")));
            Assert.IsTrue((await Execute(server: "k8s.example.com")).Any(r => r.Message.Contains("API Server of the Kubernetes API Token credential must be a full URL")));
            Assert.IsTrue((await Execute(caData: "not a certificate")).Any(r => r.Message.Contains("Cluster CA Certificate of the Kubernetes API Token credential must be PEM certificates")));
            Assert.IsTrue((await Execute(token: null)).Any(r => r.Message.Contains("A Kubernetes API Token credential is required")));

            Assert.AreEqual(0, _k8s.Requests.Count, "invalid settings never reach the API server");
        }

        private string LeafSerial()
        {
            var collection = X509CertificateLoader.LoadPkcs12CollectionFromFile(_pfxPath, "");
            return collection.Single(c => c.HasPrivateKey).SerialNumber;
        }

        private static string Data(JsonNode secret, string key) => Encoding.ASCII.GetString(Convert.FromBase64String((string)secret["data"][key]));

        private static string Messages(List<ActionResult> results) => string.Join("; ", results.Select(r => r.Message));

        private async Task<List<ActionResult>> Execute(bool isPreviewOnly = false, string ns = Namespace, string secretName = SecretName, string workloads = null,
            string server = null, string token = Token, string caData = null, bool allowInvalidTls = false)
        {
            var config = new DeploymentTaskConfig
            {
                TaskTypeId = KubernetesSecret.Definition.Id,
                TaskName = "Kubernetes test",
                ChallengeProvider = CredentialTypes.KubernetesToken,
                Parameters = new List<ProviderParameterSetting>
                {
                    new ProviderParameterSetting("namespace", ns),
                    new ProviderParameterSetting("secret_name", secretName),
                    new ProviderParameterSetting("restart_workloads", workloads)
                }
            };

            var credentials = token == null ? null : new Dictionary<string, string>
            {
                ["server"] = server ?? _k8s.Address,
                ["token"] = token,
                ["ca_data"] = caData,
                ["allow_invalid_tls"] = allowInvalidTls.ToString().ToLowerInvariant()
            };

            var execParams = new DeploymentTaskExecutionParams(_log, null, _managedCert, config, credentials, isPreviewOnly, KubernetesSecret.Definition, new DeploymentContext(), CancellationToken.None);
            return await new KubernetesSecret().Execute(execParams);
        }

        private static X509Certificate2 CreateCa()
        {
            using var key = RSA.Create(2048);
            var request = new CertificateRequest("CN=kubernetes", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        }

        private sealed class TlsFakeKubernetes : IDisposable
        {
            public FakeKubernetes Server { get; init; }
            public string CaPem { get; init; }

            public void Dispose() => Server.Dispose();
        }

        /// <summary>
        /// The fake API served over HTTPS, with a certificate for 127.0.0.1 issued by a test cluster CA, as kubeadm sets up
        /// </summary>
        private TlsFakeKubernetes TlsServer()
        {
            using var ca = CreateCa();
            using var key = RSA.Create(2048);
            var request = new CertificateRequest("CN=kube-apiserver", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var san = new SubjectAlternativeNameBuilder();
            san.AddIpAddress(IPAddress.Loopback);
            san.AddDnsName("kubernetes.default.svc");
            request.CertificateExtensions.Add(san.Build());
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, false));
            using var issued = request.Create(ca, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(10), new byte[] { 9, 8, 7, 6 });
            using var withKey = issued.CopyWithPrivateKey(key);

            // reload from PKCS#12, as SChannel can't use an ephemeral key
            var serverCertificate = X509CertificateLoader.LoadPkcs12(withKey.Export(X509ContentType.Pkcs12), null);

            _k8s.Dispose();
            _k8s = new FakeKubernetes(serverCertificate);
            return new TlsFakeKubernetes { Server = _k8s, CaPem = ca.ExportCertificatePem() };
        }

        /// <summary>
        /// Stand-in for the Kubernetes API: get and server side apply of secrets (type can't change, immutable secrets can't be updated),
        /// and get and strategic merge patch of apps/v1 workloads. Paths may have a prefix, as when reached through a proxy.
        /// </summary>
        private sealed class FakeKubernetes : IDisposable
        {
            private readonly FakeHttpServer _server;
            private static readonly Regex SecretPath = new Regex("/api/v1/namespaces/([^/]+)/secrets/([^/]+)$");
            private static readonly Regex WorkloadPath = new Regex("/apis/apps/v1/namespaces/([^/]+)/(deployments|statefulsets|daemonsets)/([^/]+)$");

            public Dictionary<string, JsonObject> Secrets { get; } = new();
            public Dictionary<string, JsonObject> Workloads { get; } = new();
            public List<FakeHttpRequest> Requests => _server.Requests.ToList();
            public string Address => _server.Address;
            public bool DenyPatch { get; set; }

            /// <summary>
            /// Requests access reviews deny, as "verb resource" or "verb resource/name"
            /// </summary>
            public HashSet<string> Denied { get; } = new();
            public bool AccessReviewsUnavailable { get; set; }

            public FakeKubernetes(X509Certificate2 serverCertificate = null)
            {
                _server = new FakeHttpServer(Handle, serverCertificate);
            }

            public JsonObject AddSecret(string ns, string name, string type, Dictionary<string, string> data, Dictionary<string, string> labels = null, Dictionary<string, string> annotations = null)
            {
                var secret = new JsonObject
                {
                    ["apiVersion"] = "v1",
                    ["kind"] = "Secret",
                    ["metadata"] = new JsonObject
                    {
                        ["name"] = name,
                        ["namespace"] = ns,
                        ["labels"] = Map(labels),
                        ["annotations"] = Map(annotations)
                    },
                    ["type"] = type,
                    ["data"] = Map(data.ToDictionary(d => d.Key, d => Convert.ToBase64String(Encoding.ASCII.GetBytes(d.Value))))
                };

                Secrets[$"{ns}/{name}"] = secret;
                return secret;
            }

            public JsonObject AddWorkload(string ns, string kind, string name)
            {
                var workload = new JsonObject
                {
                    ["metadata"] = new JsonObject { ["name"] = name, ["namespace"] = ns },
                    ["spec"] = new JsonObject { ["template"] = new JsonObject { ["metadata"] = new JsonObject { ["annotations"] = new JsonObject() } } }
                };

                Workloads[$"{ns}/{kind}s/{name}"] = workload;
                return workload;
            }

            private static JsonObject Map(Dictionary<string, string> values)
                => new JsonObject((values ?? new()).Select(v => KeyValuePair.Create(v.Key, (JsonNode)v.Value)));

            private FakeHttpResponse Handle(FakeHttpRequest request)
            {
                lock (Secrets)
                {
                    if (request.Header("Authorization") != $"Bearer {Token}")
                    {
                        return Status(401, "Unauthorized", "Unauthorized");
                    }

                    var body = string.IsNullOrEmpty(request.Body) ? null : JsonNode.Parse(request.Body);

                    if (request.Method == "POST" && request.Path.EndsWith("/apis/authorization.k8s.io/v1/selfsubjectaccessreviews"))
                    {
                        if (AccessReviewsUnavailable)
                        {
                            return Status(404, "NotFound", "the server could not find the requested resource");
                        }

                        var attributes = body["spec"]["resourceAttributes"];
                        var reviewed = $"{attributes["verb"]} {attributes["resource"]}";
                        var allowed = !Denied.Contains(reviewed) && !(attributes["name"] != null && Denied.Contains($"{reviewed}/{attributes["name"]}"));
                        return Ok(new JsonObject { ["kind"] = "SelfSubjectAccessReview", ["status"] = new JsonObject { ["allowed"] = allowed } });
                    }

                    var secretPath = SecretPath.Match(request.Path);
                    if (secretPath.Success)
                    {
                        var key = $"{secretPath.Groups[1].Value}/{secretPath.Groups[2].Value}";
                        var name = secretPath.Groups[2].Value;
                        Secrets.TryGetValue(key, out var secret);

                        switch (request.Method)
                        {
                            case "GET":
                                return secret == null ? Status(404, "NotFound", $"secrets \"{name}\" not found") : Ok(secret);

                            case "PATCH" when request.Header("Content-Type")?.StartsWith("application/apply-patch+yaml") == true:
                                if (DenyPatch)
                                {
                                    return Status(403, "Forbidden", $"secrets \"{name}\" is forbidden: User \"system:serviceaccount:certify:certify\" cannot patch resource \"secrets\" in API group \"\" in the namespace \"{secretPath.Groups[1].Value}\"");
                                }

                                if (request.Query.GetValueOrDefault("fieldManager") == null)
                                {
                                    return Status(400, "BadRequest", "PATCH requests with an apply patch must include a field manager");
                                }

                                if (secret == null)
                                {
                                    secret = new JsonObject { ["metadata"] = new JsonObject { ["name"] = name, ["annotations"] = new JsonObject() }, ["data"] = new JsonObject(), ["type"] = (string)body["type"] };
                                    Secrets[key] = secret;
                                }
                                else if ((string)secret["type"] != (string)body["type"])
                                {
                                    return Status(422, "Invalid", $"Secret \"{name}\" is invalid: type: Invalid value: \"{body["type"]}\": field is immutable");
                                }
                                else if ((bool?)secret["immutable"] == true)
                                {
                                    return Status(422, "Invalid", $"Secret \"{name}\" is invalid: data: Forbidden: field is immutable when `immutable` is set");
                                }

                                foreach (var annotation in body["metadata"]["annotations"].AsObject())
                                {
                                    secret["metadata"]["annotations"][annotation.Key] = annotation.Value.DeepClone();
                                }

                                foreach (var data in body["data"].AsObject())
                                {
                                    secret["data"][data.Key] = data.Value.DeepClone();
                                }

                                return Ok(secret);
                        }
                    }

                    var workloadPath = WorkloadPath.Match(request.Path);
                    if (workloadPath.Success)
                    {
                        var key = $"{workloadPath.Groups[1].Value}/{workloadPath.Groups[2].Value}/{workloadPath.Groups[3].Value}";
                        if (!Workloads.TryGetValue(key, out var workload))
                        {
                            return Status(404, "NotFound", $"{workloadPath.Groups[2].Value}.apps \"{workloadPath.Groups[3].Value}\" not found");
                        }

                        switch (request.Method)
                        {
                            case "GET":
                                return Ok(workload);

                            case "PATCH" when request.Header("Content-Type")?.StartsWith("application/strategic-merge-patch+json") == true:
                                foreach (var annotation in body["spec"]["template"]["metadata"]["annotations"].AsObject())
                                {
                                    workload["spec"]["template"]["metadata"]["annotations"][annotation.Key] = annotation.Value.DeepClone();
                                }

                                return Ok(workload);
                        }
                    }

                    return Status(404, "NotFound", "the server could not find the requested resource");
                }
            }

            private static FakeHttpResponse Ok(JsonNode body) => new FakeHttpResponse(200, "application/json", body.ToJsonString());

            private static FakeHttpResponse Status(int code, string reason, string message)
                => new FakeHttpResponse(code, "application/json", new JsonObject { ["kind"] = "Status", ["apiVersion"] = "v1", ["status"] = "Failure", ["message"] = message, ["reason"] = reason, ["code"] = code }.ToJsonString());

            public void Dispose() => _server.Dispose();
        }
    }
}
