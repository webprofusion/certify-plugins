using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Certify.Models;
using Certify.Models.Config;
using Certify.Models.Providers;
using Certify.Providers.Deployment.Core.Shared;

namespace Certify.Providers.DeploymentTasks
{
    /// <summary>
    /// Stores the certificate as a Kubernetes TLS secret (type kubernetes.io/tls, keys tls.crt and tls.key), using server side apply so
    /// other keys, labels and annotations on the secret are kept. Optionally restarts workloads after the certificate changes, as
    /// 'kubectl rollout restart' does. Talks to the Kubernetes API directly over HTTPS with a service account token.
    /// </summary>
    public class KubernetesSecret : IDeploymentTaskProvider
    {
        public static DeploymentProviderDefinition Definition { get; }
        public DeploymentProviderDefinition GetDefinition(DeploymentProviderDefinition currentDefinition = null) => (currentDefinition ?? Definition);

        /// <summary>
        /// Annotation holding the managed certificate ID, so a secret is not shared by two managed certificates
        /// </summary>
        public const string ManagedCertificateAnnotation = "certifytheweb.com/managed-certificate-id";
        public const string SerialAnnotation = "certifytheweb.com/certificate-serial";
        public const string ExpiryAnnotation = "certifytheweb.com/certificate-expiry";

        private const string TlsSecretType = "kubernetes.io/tls";
        private const string FieldManager = "certify-the-web";
        private const string RestartedAtAnnotation = "kubectl.kubernetes.io/restartedAt";

        private static readonly Regex ValidName = new Regex(@"^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$", RegexOptions.Compiled);
        private static readonly Regex ValidNamespace = new Regex(@"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$", RegexOptions.Compiled);
        private static readonly Regex PemCertificate = new Regex("-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----", RegexOptions.Compiled | RegexOptions.Singleline);

        /// <summary>
        /// Workload kinds that can be restarted, by the names accepted in the setting
        /// </summary>
        private static readonly Dictionary<string, string> WorkloadKinds = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["deployment"] = "deployment", ["deployments"] = "deployment", ["deploy"] = "deployment",
            ["statefulset"] = "statefulset", ["statefulsets"] = "statefulset", ["sts"] = "statefulset",
            ["daemonset"] = "daemonset", ["daemonsets"] = "daemonset", ["ds"] = "daemonset"
        };

        static KubernetesSecret()
        {
            Definition = new DeploymentProviderDefinition
            {
                Id = "Certify.Providers.DeploymentTasks.KubernetesSecret",
                Title = "Deploy to Kubernetes TLS Secret",
                IsExperimental = false,
                UsageType = DeploymentProviderUsage.PostRequest,
                SupportedContexts = DeploymentContextType.ExternalCredential,
                ExternalCredentialType = CredentialTypes.KubernetesToken,
                RequiresManagementHub = true,
                Description = "Store the certificate and key as a Kubernetes TLS secret, for ingress controllers, gateways and pods. Optionally restart the workloads that use it.",
                ProviderParameters = new List<ProviderParameter>
                {
                    new ProviderParameter{ Key="namespace", Name="Namespace", IsRequired=true, IsCredential=false, Type= OptionType.String, Value="default", Description="Namespace of the secret, e.g. default" },
                    new ProviderParameter{ Key="secret_name", Name="Secret Name", IsRequired=true, IsCredential=false, Type= OptionType.String, Description="e.g. www-example-com-tls. The secret is created if there isn't one." },
                    new ProviderParameter{ Key="restart_workloads", Name="Workloads to Restart", IsRequired=false, IsCredential=false, Type= OptionType.String, Description="(optional) Workloads in the namespace to restart when the certificate changes, comma separated, e.g. web, statefulset/db, daemonset/agent. A name on its own is a Deployment. Not needed for ingress controllers, which pick up the change themselves." },
                }
            };
        }

        public async Task<List<ActionResult>> Execute(DeploymentTaskExecutionParams execParams)
        {
            var results = await Validate(execParams);
            if (execParams.IsPreviewOnly || results.Any(r => !r.IsSuccess))
            {
                return results;
            }

            return await Deploy(execParams, apply: true);
        }

        /// <summary>
        /// Check the task settings and credential. In preview, also connect to the API server and report what deploying would change.
        /// </summary>
        public async Task<List<ActionResult>> Validate(DeploymentTaskExecutionParams execParams)
        {
            var results = new List<ActionResult>();
            var settings = GetSettings(execParams);

            if (settings.Namespace == null)
            {
                results.Add(new ActionResult("Namespace is required.", false));
            }
            else if (settings.Namespace.Length > 63 || !ValidNamespace.IsMatch(settings.Namespace))
            {
                results.Add(new ActionResult("Namespace must be a Kubernetes namespace name: lower case letters, numbers and '-', up to 63 characters.", false));
            }

            if (settings.SecretName == null)
            {
                results.Add(new ActionResult("Secret Name is required.", false));
            }
            else if (settings.SecretName.Length > 253 || !ValidName.IsMatch(settings.SecretName))
            {
                results.Add(new ActionResult("Secret Name must be a Kubernetes object name: lower case letters, numbers, '-' and '.', up to 253 characters.", false));
            }

            foreach (var invalid in settings.Workloads.Where(w => w.Kind == null || w.Name.Length > 253 || !ValidName.IsMatch(w.Name)))
            {
                results.Add(new ActionResult($"Workloads to Restart: '{invalid.Setting}' isn't a workload. Give a Deployment name, or kind/name where the kind is deployment, statefulset or daemonset.", false));
            }

            var credential = GetCredential(execParams);
            if (credential == null)
            {
                results.Add(new ActionResult("A Kubernetes API Token credential is required.", false));
            }
            else
            {
                if (credential.Server == null)
                {
                    results.Add(new ActionResult("The API Server of the Kubernetes API Token credential must be a full URL, e.g. https://k8s.example.com:6443.", false));
                }

                if (credential.CaText != null && credential.CaCertificates == null)
                {
                    results.Add(new ActionResult("The Cluster CA Certificate of the Kubernetes API Token credential must be PEM certificates, or base64 encoded PEM as in the certificate-authority-data of a kubeconfig file.", false));
                }
            }

            if (execParams.IsPreviewOnly && !results.Any(r => !r.IsSuccess))
            {
                results.AddRange(await Deploy(execParams, apply: false));
            }

            return results;
        }

        /// <summary>
        /// Read the secret and check it can be written to, then (if applying) write the certificate and restart the workloads
        /// </summary>
        private static async Task<List<ActionResult>> Deploy(DeploymentTaskExecutionParams execParams, bool apply)
        {
            var results = new List<ActionResult>();
            var settings = GetSettings(execParams);
            var credential = GetCredential(execParams);
            var log = execParams.Log;
            var cancellationToken = execParams.CancellationToken;
            var managedCert = ManagedCertificate.GetManagedCertificate(execParams.Subject);
            var secretRef = $"{settings.Namespace}/{settings.SecretName}";

            var certificate = await NetworkDevice.LoadCertificate(execParams);
            if (!certificate.IsSuccess)
            {
                results.Add(new ActionResult(certificate.Message, false));
                return results;
            }

            var cert = certificate.Result;
            if (cert == null && apply)
            {
                results.Add(new ActionResult("No certificate to deploy.", false));
                return results;
            }

            var tlsCrt = cert == null ? null : Convert.ToBase64String(Encoding.ASCII.GetBytes(cert.FullChainPem));
            var tlsKey = cert == null ? null : Convert.ToBase64String(Encoding.ASCII.GetBytes(cert.Pkcs8KeyPem()));

            try
            {
                using var api = new Api(credential);

                var existing = await api.Send(HttpMethod.Get, SecretPath(settings.Namespace, settings.SecretName), null, null, cancellationToken);
                if (existing.Status != HttpStatusCode.NotFound && !existing.IsSuccess)
                {
                    results.Add(new ActionResult($"Kubernetes: could not read secret {secretRef}: {existing.Error}", false));
                    return results;
                }

                var secret = existing.IsSuccess ? existing.Body : null;
                if (secret != null)
                {
                    var problem = CheckWritable(secret, secretRef, managedCert.Id);
                    if (problem != null)
                    {
                        results.Add(new ActionResult($"Kubernetes: {problem}", false));
                        return results;
                    }

                    if (secret["metadata"]?["annotations"]?["meta.helm.sh/release-name"] != null)
                    {
                        results.Add(new ActionResult($"Kubernetes: secret {secretRef} is part of Helm release {secret["metadata"]["annotations"]["meta.helm.sh/release-name"]}, so upgrading the release may replace the certificate. Leave the secret out of the Helm chart.", true) { IsWarning = true });
                    }
                }

                var upToDate = secret != null && tlsCrt != null && (string)secret["data"]?["tls.crt"] == tlsCrt && (string)secret["data"]?["tls.key"] == tlsKey;

                if (!apply)
                {
                    var preview = new StringBuilder($"Connected to the Kubernetes API server at {credential.Server}. ");
                    if (upToDate)
                    {
                        preview.Append($"Secret {secretRef} already holds this certificate, so deploying would change nothing.");
                    }
                    else
                    {
                        preview.Append(cert == null ? "No certificate has been issued yet. Deploying would " : "Would ");
                        preview.Append(secret == null ? $"create TLS secret {secretRef}" : $"update TLS secret {secretRef}");
                        preview.Append(settings.Workloads.Any() ? $", then restart {string.Join(", ", settings.Workloads.Select(w => w.Display))}." : ".");
                    }

                    // check the workloads exist, so a wrong name shows up before a renewal depends on it
                    foreach (var workload in settings.Workloads)
                    {
                        var found = await api.Send(HttpMethod.Get, WorkloadPath(settings.Namespace, workload), null, null, cancellationToken);
                        if (!found.IsSuccess)
                        {
                            results.Add(new ActionResult(found.Status == HttpStatusCode.NotFound
                                ? $"Kubernetes: there is no {workload.Display} in namespace {settings.Namespace}."
                                : $"Kubernetes: could not read {workload.Display}: {found.Error}", false));
                        }
                    }

                    // check the service account may make the changes deploying needs, now and on renewal
                    var needed = new List<(string Verb, string Group, string Resource, string Name, string Display)>();
                    if (secret == null)
                    {
                        // server side apply creates by name, so a create permission limited to the secret's name is enough
                        needed.Add(("create", "", "secrets", settings.SecretName, $"secret {settings.SecretName}"));
                    }

                    needed.Add(("patch", "", "secrets", settings.SecretName, $"secret {settings.SecretName}"));
                    needed.AddRange(settings.Workloads.Select(w => ("patch", "apps", $"{w.Kind}s", w.Name, w.Display)));

                    foreach (var (verb, group, resource, name, display) in needed)
                    {
                        if (await api.IsAllowed(verb, group, resource, settings.Namespace, name, cancellationToken) == false)
                        {
                            results.Add(new ActionResult($"Kubernetes: the service account isn't allowed to {verb} {display} in namespace {settings.Namespace}, which deploying needs. Add the permission to its Role.", false));
                        }
                    }

                    results.Insert(0, new ActionResult(preview.ToString(), true));
                    return results;
                }

                if (upToDate)
                {
                    results.Add(new ActionResult($"Kubernetes: secret {secretRef} is already up to date.", true));
                    return results;
                }

                using var leaf = X509Certificate2.CreateFromPem(cert.CertPem);
                var applied = new JsonObject
                {
                    ["apiVersion"] = "v1",
                    ["kind"] = "Secret",
                    ["metadata"] = new JsonObject
                    {
                        ["name"] = settings.SecretName,
                        ["namespace"] = settings.Namespace,
                        ["annotations"] = new JsonObject
                        {
                            [ManagedCertificateAnnotation] = managedCert.Id,
                            [SerialAnnotation] = leaf.SerialNumber,
                            [ExpiryAnnotation] = leaf.NotAfter.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
                        }
                    },
                    ["type"] = TlsSecretType,
                    ["data"] = new JsonObject
                    {
                        ["tls.crt"] = tlsCrt,
                        ["tls.key"] = tlsKey
                    }
                };

                log?.Information($"Kubernetes: {(secret == null ? "creating" : "updating")} TLS secret {secretRef}");

                // server side apply creates or updates only the fields given; force takes them over from other field managers such as kubectl
                var written = await api.Send(HttpMethod.Patch, $"{SecretPath(settings.Namespace, settings.SecretName)}?fieldManager={FieldManager}&force=true", applied, "application/apply-patch+yaml", cancellationToken);
                if (!written.IsSuccess)
                {
                    results.Add(new ActionResult($"Kubernetes: could not {(secret == null ? "create" : "update")} secret {secretRef}: {written.Error}", false));
                    return results;
                }

                results.Add(new ActionResult($"Kubernetes: {(secret == null ? "created" : "updated")} TLS secret {secretRef}.", true));

                var restartedAt = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
                foreach (var workload in settings.Workloads)
                {
                    var restart = new JsonObject { ["spec"] = new JsonObject { ["template"] = new JsonObject { ["metadata"] = new JsonObject { ["annotations"] = new JsonObject { [RestartedAtAnnotation] = restartedAt } } } } };

                    log?.Information($"Kubernetes: restarting {workload.Display}");

                    var restarted = await api.Send(HttpMethod.Patch, WorkloadPath(settings.Namespace, workload), restart, "application/strategic-merge-patch+json", cancellationToken);
                    results.Add(restarted.IsSuccess
                        ? new ActionResult($"Kubernetes: restarted {workload.Display}.", true)
                        : new ActionResult($"Kubernetes: the secret was updated, but {workload.Display} could not be restarted: {(restarted.Status == HttpStatusCode.NotFound ? $"there is no {workload.Display} in namespace {settings.Namespace}." : restarted.Error)} Restart it yourself to use the new certificate.", false));
                }

                return results;
            }
            catch (HttpRequestException exp)
            {
                results.Add(new ActionResult(exp.InnerException is AuthenticationException
                    ? $"Kubernetes: could not connect to the API server at {credential.Server}, as its TLS certificate isn't trusted. Set the Cluster CA Certificate of the credential to the cluster's CA certificate."
                    : $"Kubernetes: could not connect to the API server at {credential.Server}: {exp.Message}", false));
                return results;
            }
            catch (TaskCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                results.Add(new ActionResult($"Kubernetes: request to the API server at {credential.Server} timed out.", false));
                return results;
            }
        }

        /// <summary>
        /// Why the certificate can't be written to an existing secret, or null if it can
        /// </summary>
        private static string CheckWritable(JsonNode secret, string secretRef, string managedCertificateId)
        {
            var type = (string)secret["type"];
            if (type != TlsSecretType)
            {
                return $"secret {secretRef} has type {type}, not {TlsSecretType}, and the type of a secret can't be changed. Use a different secret name, or delete the secret so it can be created again.";
            }

            if ((bool?)secret["immutable"] == true)
            {
                return $"secret {secretRef} is immutable, so it can't be updated. Use a different secret name, or delete the secret so it can be created again.";
            }

            var annotations = secret["metadata"]?["annotations"];
            if (annotations?["cert-manager.io/certificate-name"] != null)
            {
                return $"secret {secretRef} is managed by cert-manager (Certificate {annotations["cert-manager.io/certificate-name"]}), which would replace the certificate. Use a different secret name, or to move the certificate from cert-manager to Certify, delete the Certificate and remove the cert-manager.io annotations from the secret.";
            }

            var owner = (string)annotations?[ManagedCertificateAnnotation];
            if (owner != null && owner != managedCertificateId)
            {
                return $"secret {secretRef} holds the certificate of a different managed certificate (its '{ManagedCertificateAnnotation}' annotation is {owner}). Use a different secret for each managed certificate.";
            }

            return null;
        }

        private static string SecretPath(string ns, string name) => $"/api/v1/namespaces/{ns}/secrets/{name}";

        private static string WorkloadPath(string ns, Workload workload) => $"/apis/apps/v1/namespaces/{ns}/{workload.Kind}s/{workload.Name}";

        private sealed record Workload(string Setting, string Kind, string Name)
        {
            public string Display => $"{Kind}/{Name}";
        }

        private sealed record Settings(string Namespace, string SecretName, List<Workload> Workloads);

        private static Settings GetSettings(DeploymentTaskExecutionParams execParams)
        {
            var parameters = execParams.Settings.Parameters;
            string value(string key) => parameters.FirstOrDefault(c => c.Key == key)?.Value?.Trim() is { Length: > 0 } v ? v : null;

            var workloads = (value("restart_workloads") ?? "")
                .Split(new[] { ',', ';', '\n' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select(w =>
                {
                    var parts = w.Split('/', 2);
                    var kind = parts.Length == 1 ? "deployment" : WorkloadKinds.GetValueOrDefault(parts[0]);
                    return new Workload(w, kind, parts[^1]);
                })
                .ToList();

            return new Settings(value("namespace"), value("secret_name"), workloads);
        }

        private sealed record Credential(Uri Server, string Token, string CaText, X509Certificate2Collection CaCertificates, bool AllowInvalidTls);

        private static Credential GetCredential(DeploymentTaskExecutionParams execParams)
        {
            var credentials = execParams.Credentials;
            string value(string key) => credentials?.TryGetValue(key, out var v) == true && !string.IsNullOrWhiteSpace(v) ? v.Trim() : null;

            var token = value("token");
            var serverText = value("server");
            if (token == null || serverText == null)
            {
                return null;
            }

            var caText = value("ca_data");
            _ = bool.TryParse(value("allow_invalid_tls"), out var allowInvalidTls);

            return new Credential(NetworkDevice.ParseAddress(serverText), token, caText, caText == null ? null : ParseCaCertificates(caText), allowInvalidTls);
        }

        /// <summary>
        /// CA certificates from PEM, or from base64 encoded PEM as in a kubeconfig file. Line breaks in the PEM are not needed, as they may be
        /// lost when pasted into a single line field. Null if there are none or they can't be read.
        /// </summary>
        public static X509Certificate2Collection ParseCaCertificates(string text)
        {
            if (!text.Contains("-----BEGIN"))
            {
                try
                {
                    text = Encoding.ASCII.GetString(Convert.FromBase64String(Regex.Replace(text, @"\s", "")));
                }
                catch (FormatException)
                {
                    return null;
                }
            }

            try
            {
                var collection = new X509Certificate2Collection();
                foreach (Match pem in PemCertificate.Matches(text))
                {
                    collection.Add(X509CertificateLoader.LoadCertificate(Convert.FromBase64String(Regex.Replace(pem.Groups[1].Value, @"\s", ""))));
                }

                return collection.Count > 0 ? collection : null;
            }
            catch (Exception exp) when (exp is FormatException || exp is CryptographicException)
            {
                return null;
            }
        }

        /// <summary>
        /// Whether to accept the API server's TLS certificate. With CA certificates, only a chain to one of them is trusted (as kubectl does),
        /// otherwise the system's trusted roots are used. The name must match either way.
        /// </summary>
        public static bool IsServerCertificateTrusted(X509Certificate2 certificate, X509Chain chain, SslPolicyErrors errors, X509Certificate2Collection caCertificates, bool allowInvalidTls)
        {
            if (allowInvalidTls)
            {
                return true;
            }

            if (caCertificates == null)
            {
                return errors == SslPolicyErrors.None;
            }

            if ((errors & ~SslPolicyErrors.RemoteCertificateChainErrors) != SslPolicyErrors.None)
            {
                return false;
            }

            using var custom = new X509Chain();
            custom.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            custom.ChainPolicy.CustomTrustStore.AddRange(caCertificates);
            custom.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            foreach (var element in chain?.ChainElements.Cast<X509ChainElement>() ?? Enumerable.Empty<X509ChainElement>())
            {
                custom.ChainPolicy.ExtraStore.Add(element.Certificate);
            }

            return custom.Build(certificate);
        }

        private sealed record ApiResponse(HttpStatusCode Status, JsonNode Body, string Error)
        {
            public bool IsSuccess => (int)Status >= 200 && (int)Status < 300;
        }

        /// <summary>
        /// Client for the Kubernetes API: bearer token, JSON bodies, and Status objects turned into error messages
        /// </summary>
        private sealed class Api : IDisposable
        {
            private readonly HttpClient _http;
            private readonly string _server;

            public Api(Credential credential)
            {
                var handler = new HttpClientHandler
                {
                    ServerCertificateCustomValidationCallback = (_, certificate, chain, errors) => IsServerCertificateTrusted(certificate, chain, errors, credential.CaCertificates, credential.AllowInvalidTls)
                };

                _http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(60) };
                _http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", credential.Token);
                _http.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

                // the server may have a path, e.g. when reached through a proxy such as Rancher
                _server = credential.Server.ToString().TrimEnd('/');
            }

            public async Task<ApiResponse> Send(HttpMethod method, string path, JsonNode body, string contentType, CancellationToken cancellationToken)
            {
                using var request = new HttpRequestMessage(method, _server + path);
                if (body != null)
                {
                    request.Content = new StringContent(body.ToJsonString(), Encoding.UTF8);
                    request.Content.Headers.ContentType = new MediaTypeHeaderValue(contentType);
                }

                using var response = await _http.SendAsync(request, cancellationToken);
                var text = await response.Content.ReadAsStringAsync(cancellationToken);

                JsonNode json = null;
                try
                {
                    json = string.IsNullOrWhiteSpace(text) ? null : JsonNode.Parse(text);
                }
                catch (JsonException)
                {
                    // not JSON, e.g. a proxy's error page
                }

                if (response.IsSuccessStatusCode)
                {
                    return new ApiResponse(response.StatusCode, json, null);
                }

                var message = (string)json?["message"] ?? $"{(int)response.StatusCode} {response.ReasonPhrase}";
                var error = response.StatusCode switch
                {
                    HttpStatusCode.Unauthorized => "the API server didn't accept the token (401 Unauthorized). Check the Token of the Kubernetes API Token credential, which may have expired.",
                    HttpStatusCode.Forbidden => $"access denied ({message}). Check the Role and RoleBinding of the service account.",
                    _ => $"{message.TrimEnd('.')}."
                };

                return new ApiResponse(response.StatusCode, json, error);
            }

            /// <summary>
            /// Whether the service account may make a request, from a SelfSubjectAccessReview (which every authenticated user may create).
            /// Null if the review itself fails, so callers don't report a problem they can't confirm.
            /// </summary>
            public async Task<bool?> IsAllowed(string verb, string group, string resource, string ns, string name, CancellationToken cancellationToken)
            {
                var attributes = new JsonObject { ["namespace"] = ns, ["verb"] = verb, ["group"] = group, ["resource"] = resource };
                if (name != null)
                {
                    attributes["name"] = name;
                }

                var review = new JsonObject
                {
                    ["apiVersion"] = "authorization.k8s.io/v1",
                    ["kind"] = "SelfSubjectAccessReview",
                    ["spec"] = new JsonObject { ["resourceAttributes"] = attributes }
                };

                var response = await Send(HttpMethod.Post, "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", review, "application/json", cancellationToken);
                return response.IsSuccess ? (bool?)response.Body?["status"]?["allowed"] : null;
            }

            public void Dispose() => _http.Dispose();
        }
    }
}
