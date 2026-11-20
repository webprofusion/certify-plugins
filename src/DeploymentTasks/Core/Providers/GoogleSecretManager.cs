using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Certify.Models;
using Certify.Models.Config;
using Certify.Models.Providers;
using Certify.Providers.Deployment.Core.Shared;

namespace Certify.Providers.DeploymentTasks
{
    /// <summary>
    /// Stores the certificate in Google Cloud Secret Manager as a JSON secret (certificate, private_key, chain, fullchain and optionally pfx),
    /// adding a new version for each new certificate. The secret's annotations record the version this task added and a hash of its value,
    /// so the task can tell the secret is up to date without reading the value back.
    /// </summary>
    public class GoogleSecretManager : IDeploymentTaskProvider
    {
        public static DeploymentProviderDefinition Definition { get; }
        public DeploymentProviderDefinition GetDefinition(DeploymentProviderDefinition currentDefinition = null) => (currentDefinition ?? Definition);

        public const string ManagedCertificateAnnotation = "certify-managed-certificate-id";
        public const string VersionAnnotation = "certify-version";
        public const string ValueHashAnnotation = "certify-value-sha256";

        private const string DefaultEndpoint = "https://secretmanager.googleapis.com";

        private static readonly Regex ValidSecretId = new Regex("^[A-Za-z0-9_-]{1,255}$", RegexOptions.Compiled);
        private static readonly Regex ValidKmsKey = new Regex("^projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+$", RegexOptions.Compiled);

        private static readonly string[] Permissions = { "secretmanager.secrets.get", "secretmanager.secrets.create", "secretmanager.secrets.update", "secretmanager.versions.add", "secretmanager.versions.get" };

        static GoogleSecretManager()
        {
            Definition = new DeploymentProviderDefinition
            {
                Id = "Certify.Providers.DeploymentTasks.GoogleSecretManager",
                Title = "Deploy to Google Cloud Secret Manager",
                IsExperimental = false,
                UsageType = DeploymentProviderUsage.PostRequest,
                SupportedContexts = DeploymentContextType.ExternalCredential,
                ExternalCredentialType = CredentialTypes.GoogleServiceAccountKey,
                RequiresManagementHub = true,
                Description = "Store the certificate, private key and chain as a JSON secret in Google Cloud Secret Manager. Each renewal is added as the latest version of the secret.",
                ProviderParameters = new List<ProviderParameter>
                {
                    new ProviderParameter{ Key="project_id", Name="Project ID", IsRequired=false, IsCredential=false, Type= OptionType.String, Description="(optional) Project of the secret, e.g. my-project-123456. Leave blank to use the project of the service account key." },
                    new ProviderParameter{ Key="secret_id", Name="Secret ID", IsRequired=true, IsCredential=false, Type= OptionType.String, Description="e.g. www-example-com-tls. A secret with this ID is created if there isn't one." },
                    new ProviderParameter{ Key="kms_key_name", Name="KMS Key", IsRequired=false, IsCredential=false, Type= OptionType.String, Description="(optional) Cloud KMS key to encrypt the secret with, used when the secret is created, e.g. projects/my-project/locations/global/keyRings/certs/cryptoKeys/certs. Leave blank for Google-managed encryption." },
                    new ProviderParameter{ Key="include_pfx", Name="Include PFX", IsRequired=false, IsCredential=false, Type= OptionType.Boolean, Value="false", Description="Also store the certificate as a base64 encoded PFX (PKCS#12) file in the 'pfx' field. It has the certificate's PFX password, if one is set." },
                    new ProviderParameter{ Key="api_endpoint", Name="API Endpoint", IsRequired=false, IsCredential=false, Type= OptionType.String, Description="(optional) Custom Secret Manager endpoint URL, such as a Private Service Connect endpoint. Leave blank to use https://secretmanager.googleapis.com." },
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
        /// Check the task settings. In preview, also connect to Secret Manager and report what deploying would change.
        /// </summary>
        public async Task<List<ActionResult>> Validate(DeploymentTaskExecutionParams execParams)
        {
            var results = new List<ActionResult>();
            var (key, keyProblem) = GoogleCloud.GetKey(execParams);
            var settings = GetSettings(execParams, key);

            if (keyProblem != null)
            {
                results.Add(new ActionResult(keyProblem, false));
            }
            else
            {
                GoogleCloud.ValidateProjectId(settings.ProjectId, results);
            }

            if (settings.SecretId == null)
            {
                results.Add(new ActionResult("Secret ID is required.", false));
            }
            else if (!ValidSecretId.IsMatch(settings.SecretId))
            {
                results.Add(new ActionResult("Secret ID can only contain letters, numbers, '-' and '_', and can be up to 255 characters long.", false));
            }

            if (settings.KmsKeyName != null && !ValidKmsKey.IsMatch(settings.KmsKeyName))
            {
                results.Add(new ActionResult("KMS Key must be a Cloud KMS key name, e.g. projects/my-project/locations/global/keyRings/certs/cryptoKeys/certs.", false));
            }

            if (settings.Endpoint == null)
            {
                results.Add(new ActionResult("API Endpoint must be blank or a full URL, e.g. https://secretmanager.googleapis.com.", false));
            }

            if (execParams.IsPreviewOnly && !results.Any(r => !r.IsSuccess))
            {
                results.AddRange(await Deploy(execParams, apply: false));
            }

            return results;
        }

        /// <summary>
        /// Find the secret and check it can be written to, then (if applying) create it and add the certificate as its latest version
        /// </summary>
        private static async Task<List<ActionResult>> Deploy(DeploymentTaskExecutionParams execParams, bool apply)
        {
            var results = new List<ActionResult>();
            var (key, _) = GoogleCloud.GetKey(execParams);
            var settings = GetSettings(execParams, key);
            var log = execParams.Log;
            var cancellationToken = execParams.CancellationToken;
            var managedCert = ManagedCertificate.GetManagedCertificate(execParams.Subject);
            var secretName = $"projects/{settings.ProjectId}/secrets/{settings.SecretId}";

            var certificate = await NetworkDevice.LoadCertificate(execParams);
            if (!certificate.IsSuccess)
            {
                results.Add(new ActionResult(certificate.Message, false));
                return results;
            }

            if (certificate.Result == null && apply)
            {
                results.Add(new ActionResult("No certificate to deploy.", false));
                return results;
            }

            var value = certificate.Result?.SecretJson(certificate.Result != null && settings.IncludePfx ? await File.ReadAllBytesAsync(managedCert.CertificatePath, cancellationToken) : null);
            var valueHash = value == null ? null : Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();

            try
            {
                using var api = new GoogleCloud.Api(key, Permissions);
                var signInProblem = await api.SignIn(cancellationToken);
                if (signInProblem != null)
                {
                    results.Add(new ActionResult($"Google Secret Manager: {signInProblem}", false));
                    return results;
                }

                var existing = await api.Send(HttpMethod.Get, $"{settings.Endpoint}/v1/{secretName}", null, cancellationToken);
                if (!existing.IsSuccess && existing.Status != HttpStatusCode.NotFound)
                {
                    results.Add(new ActionResult($"Google Secret Manager: could not read secret {secretName}: {existing.Error}", false));
                    return results;
                }

                var secret = existing.IsSuccess ? existing.Body : null;
                var annotations = secret?["annotations"]?.AsObject();

                var owner = (string)annotations?[ManagedCertificateAnnotation];
                if (owner != null && owner != managedCert.Id)
                {
                    results.Add(new ActionResult($"Google Secret Manager: secret {secretName} holds the certificate of a different managed certificate (its '{ManagedCertificateAnnotation}' annotation is {owner}). Use a different secret for each managed certificate.", false));
                    return results;
                }

                var upToDate = false;
                if (secret != null && valueHash != null && (string)annotations?[ValueHashAnnotation] == valueHash)
                {
                    // the version this task added must still be the latest, and enabled
                    var latest = await api.Send(HttpMethod.Get, $"{settings.Endpoint}/v1/{secretName}/versions/latest", null, cancellationToken);
                    upToDate = latest.IsSuccess && (string)latest.Body?["name"] == (string)annotations?[VersionAnnotation] && (string)latest.Body?["state"] == "ENABLED";
                }

                if (!apply)
                {
                    var preview = new StringBuilder($"Connected to Google Secret Manager in project {settings.ProjectId}. ");
                    if (upToDate)
                    {
                        preview.Append($"Secret {settings.SecretId} already holds this certificate, so deploying would change nothing.");
                    }
                    else
                    {
                        preview.Append(value == null ? "No certificate has been issued yet. Deploying would " : "Would ");
                        preview.Append(secret == null
                            ? $"create secret {settings.SecretId} holding the certificate{(settings.KmsKeyName != null ? $", encrypted with KMS key {settings.KmsKeyName}" : "")}."
                            : $"add the certificate as the latest version of secret {settings.SecretId}.");
                    }

                    results.Add(new ActionResult(preview.ToString(), true));

                    if (secret != null)
                    {
                        // check the service account may add versions and record them, as it may only be allowed to read the secret
                        var tested = await api.Send(HttpMethod.Post, $"{settings.Endpoint}/v1/{secretName}:testIamPermissions",
                            new JsonObject { ["permissions"] = new JsonArray("secretmanager.versions.add", "secretmanager.secrets.update") }, cancellationToken);
                        if (tested.IsSuccess)
                        {
                            var granted = tested.Body?["permissions"]?.AsArray().Select(p => (string)p).ToList() ?? new List<string>();
                            var missing = new[] { "secretmanager.versions.add", "secretmanager.secrets.update" }.Where(p => !granted.Contains(p)).ToList();
                            if (missing.Any())
                            {
                                results.Add(new ActionResult($"Google Secret Manager: the service account doesn't have the {string.Join(" and ", missing)} permission{(missing.Count > 1 ? "s" : "")} for secret {settings.SecretId}, which deploying needs.", false));
                            }
                        }
                    }

                    return results;
                }

                if (upToDate)
                {
                    results.Add(new ActionResult($"Google Secret Manager: secret {secretName} is already up to date.", true));
                    return results;
                }

                if (secret == null)
                {
                    log?.Information($"Google Secret Manager: creating secret {secretName}");

                    var automatic = new JsonObject();
                    if (settings.KmsKeyName != null)
                    {
                        automatic["customerManagedEncryption"] = new JsonObject { ["kmsKeyName"] = settings.KmsKeyName };
                    }

                    var created = await api.Send(HttpMethod.Post, $"{settings.Endpoint}/v1/projects/{settings.ProjectId}/secrets?secretId={Uri.EscapeDataString(settings.SecretId)}",
                        new JsonObject
                        {
                            ["replication"] = new JsonObject { ["automatic"] = automatic },
                            ["annotations"] = new JsonObject { [ManagedCertificateAnnotation] = managedCert.Id }
                        }, cancellationToken);

                    if (!created.IsSuccess)
                    {
                        results.Add(new ActionResult($"Google Secret Manager: could not create secret {secretName}: {created.Error}", false));
                        return results;
                    }

                    secret = created.Body;
                }

                log?.Information($"Google Secret Manager: adding a new version of secret {secretName}");

                var added = await api.Send(HttpMethod.Post, $"{settings.Endpoint}/v1/{secretName}:addVersion",
                    new JsonObject { ["payload"] = new JsonObject { ["data"] = Convert.ToBase64String(Encoding.UTF8.GetBytes(value)) } }, cancellationToken);

                if (!added.IsSuccess)
                {
                    results.Add(new ActionResult($"Google Secret Manager: could not add the certificate to secret {secretName}: {added.Error}", false));
                    return results;
                }

                var versionName = (string)added.Body?["name"];

                // record the version and its value hash, keeping the secret's other annotations
                var updatedAnnotations = secret?["annotations"]?.DeepClone().AsObject() ?? new JsonObject();
                updatedAnnotations[ManagedCertificateAnnotation] = managedCert.Id;
                updatedAnnotations[VersionAnnotation] = versionName;
                updatedAnnotations[ValueHashAnnotation] = valueHash;

                var recorded = await api.Send(HttpMethod.Patch, $"{settings.Endpoint}/v1/{secretName}?updateMask=annotations", new JsonObject { ["annotations"] = updatedAnnotations }, cancellationToken);

                results.Add(new ActionResult($"Google Secret Manager: {(existing.IsSuccess ? "added" : "created secret and added")} the certificate as {versionName}, now the latest version.", true));

                if (!recorded.IsSuccess)
                {
                    results.Add(new ActionResult($"Google Secret Manager: the certificate was added, but the secret's annotations could not be updated, so the next deployment will add it again: {recorded.Error}", true) { IsWarning = true });
                }

                return results;
            }
            catch (HttpRequestException exp)
            {
                results.Add(new ActionResult($"Google Secret Manager: could not connect to Google Cloud: {exp.Message}", false));
                return results;
            }
            catch (TaskCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                results.Add(new ActionResult("Google Secret Manager: request to Google Cloud timed out.", false));
                return results;
            }
        }

        private sealed record Settings(string ProjectId, string SecretId, string KmsKeyName, bool IncludePfx, string Endpoint);

        private static Settings GetSettings(DeploymentTaskExecutionParams execParams, GoogleCloud.ServiceAccountKey key)
        {
            var parameters = execParams.Settings.Parameters;
            string value(string k) => parameters.FirstOrDefault(c => c.Key == k)?.Value?.Trim() is { Length: > 0 } v ? v : null;

            _ = bool.TryParse(value("include_pfx"), out var includePfx);
            var endpoint = value("api_endpoint") is string e ? NetworkDevice.ParseAddress(e)?.ToString().TrimEnd('/') : DefaultEndpoint;

            return new Settings(value("project_id") ?? key?.ProjectId, value("secret_id"), value("kms_key_name"), includePfx, endpoint);
        }
    }
}
