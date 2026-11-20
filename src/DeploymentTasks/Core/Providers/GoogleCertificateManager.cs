using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Text;
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
    /// Deploys the certificate to Google Cloud Certificate Manager as a self-managed certificate. Renewals update the same certificate
    /// resource, so the certificate maps and load balancers using it pick up each renewal.
    /// </summary>
    public class GoogleCertificateManager : IDeploymentTaskProvider
    {
        public static DeploymentProviderDefinition Definition { get; }
        public DeploymentProviderDefinition GetDefinition(DeploymentProviderDefinition currentDefinition = null) => (currentDefinition ?? Definition);

        /// <summary>
        /// Label holding the managed certificate ID (as a label value), so a certificate is not shared by two managed certificates
        /// </summary>
        public const string ManagedCertificateLabel = "certify-managed-certificate-id";

        private const string DefaultEndpoint = "https://certificatemanager.googleapis.com";

        private static readonly Regex ValidCertificateId = new Regex("^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$", RegexOptions.Compiled);
        private static readonly Regex ValidLocation = new Regex("^(global|[a-z]+-[a-z]+[0-9]+)$", RegexOptions.Compiled);

        private static readonly string[] Permissions = { "certificatemanager.certs.get", "certificatemanager.certs.create", "certificatemanager.certs.update", "certificatemanager.operations.get" };

        /// <summary>
        /// How often to check whether a create or update has finished, and how long to wait for it
        /// </summary>
        private static readonly TimeSpan OperationPollInterval = TimeSpan.FromSeconds(2);
        private static readonly TimeSpan OperationTimeout = TimeSpan.FromMinutes(5);

        static GoogleCertificateManager()
        {
            Definition = new DeploymentProviderDefinition
            {
                Id = "Certify.Providers.DeploymentTasks.GoogleCertificateManager",
                Title = "Deploy to Google Cloud Certificate Manager",
                IsExperimental = false,
                UsageType = DeploymentProviderUsage.PostRequest,
                SupportedContexts = DeploymentContextType.ExternalCredential,
                ExternalCredentialType = CredentialTypes.GoogleServiceAccountKey,
                RequiresManagementHub = true,
                Description = "Deploy the certificate to Google Cloud Certificate Manager as a self-managed certificate. Renewals update the same certificate, so the load balancers using it pick up each renewal.",
                ProviderParameters = new List<ProviderParameter>
                {
                    new ProviderParameter{ Key="project_id", Name="Project ID", IsRequired=false, IsCredential=false, Type= OptionType.String, Description="(optional) Project of the certificate, e.g. my-project-123456. Leave blank to use the project of the service account key." },
                    new ProviderParameter{ Key="location", Name="Location", IsRequired=false, IsCredential=false, Type= OptionType.String, Value="global", Description="'global' for global load balancers, or the region of a regional load balancer, e.g. europe-west1." },
                    new ProviderParameter{ Key="certificate_id", Name="Certificate ID", IsRequired=true, IsCredential=false, Type= OptionType.String, Description="e.g. www-example-com. A certificate with this ID is created if there isn't one." },
                    new ProviderParameter{ Key="api_endpoint", Name="API Endpoint", IsRequired=false, IsCredential=false, Type= OptionType.String, Description="(optional) Custom Certificate Manager endpoint URL, such as a Private Service Connect endpoint. Leave blank to use https://certificatemanager.googleapis.com." },
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
        /// Check the task settings. In preview, also connect to Certificate Manager and report what deploying would change.
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

            if (!ValidLocation.IsMatch(settings.Location))
            {
                results.Add(new ActionResult("Location must be 'global', or a region, e.g. europe-west1.", false));
            }

            if (settings.CertificateId == null)
            {
                results.Add(new ActionResult("Certificate ID is required.", false));
            }
            else if (!ValidCertificateId.IsMatch(settings.CertificateId))
            {
                results.Add(new ActionResult("Certificate ID must start with a lower case letter, and can only contain lower case letters, numbers and '-', up to 63 characters.", false));
            }

            if (settings.Endpoint == null)
            {
                results.Add(new ActionResult("API Endpoint must be blank or a full URL, e.g. https://certificatemanager.googleapis.com.", false));
            }

            if (execParams.IsPreviewOnly && !results.Any(r => !r.IsSuccess))
            {
                results.AddRange(await Deploy(execParams, apply: false));
            }

            return results;
        }

        /// <summary>
        /// Find the certificate and check it can be replaced, then (if applying) create or update it
        /// </summary>
        private static async Task<List<ActionResult>> Deploy(DeploymentTaskExecutionParams execParams, bool apply)
        {
            var results = new List<ActionResult>();
            var (key, _) = GoogleCloud.GetKey(execParams);
            var settings = GetSettings(execParams, key);
            var log = execParams.Log;
            var cancellationToken = execParams.CancellationToken;
            var managedCert = ManagedCertificate.GetManagedCertificate(execParams.Subject);
            var parent = $"projects/{settings.ProjectId}/locations/{settings.Location}";
            var name = $"{parent}/certificates/{settings.CertificateId}";

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

            using var leaf = cert == null ? null : X509Certificate2.CreateFromPem(cert.CertPem);

            try
            {
                using var api = new GoogleCloud.Api(key, Permissions);
                var signInProblem = await api.SignIn(cancellationToken);
                if (signInProblem != null)
                {
                    results.Add(new ActionResult($"Google Certificate Manager: {signInProblem}", false));
                    return results;
                }

                var found = await api.Send(HttpMethod.Get, $"{settings.Endpoint}/v1/{name}", null, cancellationToken);
                if (!found.IsSuccess && found.Status != HttpStatusCode.NotFound)
                {
                    results.Add(new ActionResult($"Google Certificate Manager: could not read certificate {name}: {found.Error}", false));
                    return results;
                }

                var existing = found.IsSuccess ? found.Body : null;
                if (existing != null)
                {
                    if (existing["managed"] != null)
                    {
                        results.Add(new ActionResult($"Google Certificate Manager: certificate {name} is a Google-managed certificate, so it can't be replaced with a certificate from Certify. Use the ID of a self-managed certificate, or a new ID.", false));
                        return results;
                    }

                    var owner = (string)existing["labels"]?[ManagedCertificateLabel];
                    if (owner != null && owner != GoogleCloud.LabelValue(managedCert.Id))
                    {
                        results.Add(new ActionResult($"Google Certificate Manager: certificate {name} holds the certificate of a different managed certificate (its '{ManagedCertificateLabel}' label is {owner}). Use a different certificate for each managed certificate.", false));
                        return results;
                    }
                }

                var upToDate = existing != null && leaf != null && SerialOf((string)existing["pemCertificate"]) == leaf.SerialNumber;

                if (!apply)
                {
                    var preview = new StringBuilder($"Connected to Google Certificate Manager in project {settings.ProjectId}. ");
                    if (upToDate)
                    {
                        preview.Append($"Certificate {settings.CertificateId} is already this certificate, so deploying would change nothing.");
                    }
                    else
                    {
                        preview.Append(cert == null ? "No certificate has been issued yet. Deploying would " : "Would ");
                        preview.Append(existing == null
                            ? $"create self-managed certificate {settings.CertificateId} in {settings.Location}."
                            : $"update certificate {settings.CertificateId}, so the load balancers using it pick up the renewed certificate.");
                    }

                    results.Add(new ActionResult(preview.ToString(), true));
                    return results;
                }

                if (upToDate)
                {
                    results.Add(new ActionResult($"Google Certificate Manager: certificate {name} is already up to date.", true));
                    return results;
                }

                var selfManaged = new JsonObject { ["pemCertificate"] = cert.FullChainPem, ["pemPrivateKey"] = cert.Pkcs8KeyPem() };

                GoogleCloud.ApiResponse started;
                if (existing == null)
                {
                    log?.Information($"Google Certificate Manager: creating certificate {name}");

                    started = await api.Send(HttpMethod.Post, $"{settings.Endpoint}/v1/{parent}/certificates?certificateId={settings.CertificateId}", new JsonObject
                    {
                        ["description"] = "Deployed by Certify The Web",
                        ["labels"] = new JsonObject { [ManagedCertificateLabel] = GoogleCloud.LabelValue(managedCert.Id) },
                        ["selfManaged"] = selfManaged
                    }, cancellationToken);
                }
                else
                {
                    log?.Information($"Google Certificate Manager: updating certificate {name}");

                    started = await api.Send(HttpMethod.Patch, $"{settings.Endpoint}/v1/{name}?updateMask=selfManaged", new JsonObject { ["selfManaged"] = selfManaged }, cancellationToken);
                }

                var problem = started.IsSuccess ? await WaitForOperation(api, settings.Endpoint, started.Body, cancellationToken) : started.Error;
                if (problem != null)
                {
                    results.Add(new ActionResult($"Google Certificate Manager: could not {(existing == null ? "create" : "update")} certificate {name}: {problem}", false));
                    return results;
                }

                results.Add(new ActionResult(existing == null
                    ? $"Google Certificate Manager: created certificate {name}. Add it to a certificate map entry or target proxy where it should be used. Later renewals update it."
                    : $"Google Certificate Manager: updated certificate {name}, so the load balancers using it pick up the renewed certificate.", true));

                return results;
            }
            catch (HttpRequestException exp)
            {
                results.Add(new ActionResult($"Google Certificate Manager: could not connect to Google Cloud: {exp.Message}", false));
                return results;
            }
            catch (TaskCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                results.Add(new ActionResult("Google Certificate Manager: request to Google Cloud timed out.", false));
                return results;
            }
        }

        /// <summary>
        /// Wait for a long-running operation to finish. Result is null if it succeeded, otherwise why not.
        /// </summary>
        private static async Task<string> WaitForOperation(GoogleCloud.Api api, string endpoint, JsonNode operation, CancellationToken cancellationToken)
        {
            var deadline = DateTime.UtcNow + OperationTimeout;

            while ((bool?)operation?["done"] != true)
            {
                if (DateTime.UtcNow > deadline)
                {
                    return $"Google Cloud is still working on it after {OperationTimeout.TotalMinutes} minutes (operation {operation?["name"]}). Check the certificate in the Google Cloud console.";
                }

                await Task.Delay(OperationPollInterval, cancellationToken);

                var polled = await api.Send(HttpMethod.Get, $"{endpoint}/v1/{operation?["name"]}", null, cancellationToken);
                if (!polled.IsSuccess)
                {
                    return polled.Error;
                }

                operation = polled.Body;
            }

            var error = operation["error"];
            return error == null ? null : $"{((string)error["message"])?.TrimEnd('.')}.";
        }

        /// <summary>
        /// Serial number of the first certificate in a PEM chain, or null
        /// </summary>
        private static string SerialOf(string pemChain)
        {
            if (string.IsNullOrEmpty(pemChain))
            {
                return null;
            }

            try
            {
                using var first = X509Certificate2.CreateFromPem(pemChain);
                return first.SerialNumber;
            }
            catch (System.Security.Cryptography.CryptographicException)
            {
                return null;
            }
        }

        private sealed record Settings(string ProjectId, string Location, string CertificateId, string Endpoint);

        private static Settings GetSettings(DeploymentTaskExecutionParams execParams, GoogleCloud.ServiceAccountKey key)
        {
            var parameters = execParams.Settings.Parameters;
            string value(string k) => parameters.FirstOrDefault(c => c.Key == k)?.Value?.Trim() is { Length: > 0 } v ? v : null;

            var endpoint = value("api_endpoint") is string e ? NetworkDevice.ParseAddress(e)?.ToString().TrimEnd('/') : DefaultEndpoint;

            return new Settings(value("project_id") ?? key?.ProjectId, value("location")?.ToLowerInvariant() ?? "global", value("certificate_id"), endpoint);
        }
    }
}
