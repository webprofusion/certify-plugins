using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Certify.Models;
using Certify.Models.Config;
using Certify.Providers.Deployment.Core.Shared;

namespace Certify.Providers.DeploymentTasks
{
    /// <summary>
    /// Deploys a certificate to a FortiGate using the FortiOS REST API with an API token.
    /// FortiOS cannot replace a local certificate in place, so each deployment imports the certificate under a new name ({name}_{yyMMddHHmmss}),
    /// moves every reference to the previous certificate (admin interface, SSL VPN, virtual IPs, SSL inspection profiles etc) to it, then deletes
    /// the previous certificate.
    /// </summary>
    public class FortiGate : IDeploymentTaskProvider
    {
        public static DeploymentProviderDefinition Definition { get; }
        public DeploymentProviderDefinition GetDefinition(DeploymentProviderDefinition currentDefinition = null) => (currentDefinition ?? Definition);

        // local certificate names are limited to 35 characters, leaving room for the _yyMMddHHmmss suffix
        private const int MaxNameLength = 22;
        private static readonly Regex ValidName = new Regex($"^[A-Za-z0-9_][A-Za-z0-9_.-]{{0,{MaxNameLength - 1}}}$", RegexOptions.Compiled);
        private static readonly Regex ValidVdom = new Regex("^[A-Za-z0-9_.-]{1,31}$", RegexOptions.Compiled);

        static FortiGate()
        {
            Definition = new DeploymentProviderDefinition
            {
                Id = "Certify.Providers.DeploymentTasks.FortiGate",
                Title = "Deploy to FortiGate",
                IsExperimental = false,
                UsageType = DeploymentProviderUsage.PostRequest,
                SupportedContexts = DeploymentContextType.ExternalCredential,
                ExternalCredentialType = StandardAuthTypes.STANDARD_AUTH_API_TOKEN,
                Description = "Import the certificate to a FortiGate using the FortiOS REST API, and move everything that used the previous certificate (admin interface, SSL VPN, virtual IPs, SSL inspection profiles etc) to it.",
                ProviderParameters = new List<ProviderParameter>
                {
                    new ProviderParameter{ Key="fgt_address", Name="FortiGate Address", IsRequired=true, IsCredential=false, Type= OptionType.String, Description="Management address, e.g. https://192.168.1.99 or https://fw.example.com:10443" },
                    new ProviderParameter{ Key="cert_name", Name="Certificate Name", IsRequired=true, IsCredential=false, Type= OptionType.String, Description="Base name of the local certificate, e.g. www_example_com (up to 22 characters). Each deployment is imported as <name>_<date and time>, replacing the previous one." },
                    new ProviderParameter{ Key="vdom", Name="VDOM", IsRequired=false, IsCredential=false, Type= OptionType.String, Value="root", Description="The VDOM to import the certificate into. Use root unless multiple VDOMs are enabled." },
                    new ProviderParameter{ Key="allow_invalid_tls", Name="Allow Untrusted FortiGate Certificate", IsRequired=false, IsCredential=false, Type= OptionType.Boolean, Value="false", Description="Connect even if the FortiGate management certificate is not trusted (e.g. the default self-signed certificate)." },
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
        /// Check the task settings. In preview, also connect to the FortiGate and report what deploying would change.
        /// </summary>
        public async Task<List<ActionResult>> Validate(DeploymentTaskExecutionParams execParams)
        {
            var results = new List<ActionResult>();
            var settings = GetSettings(execParams);

            NetworkDevice.ValidateAddress(settings.AddressText, "FortiGate Address", results);

            if (string.IsNullOrWhiteSpace(settings.CertName))
            {
                results.Add(new ActionResult("Certificate Name is required.", false));
            }
            else if (!ValidName.IsMatch(settings.CertName))
            {
                results.Add(new ActionResult($"Certificate Name may only contain letters, numbers, '.', '-' and '_', up to {MaxNameLength} characters.", false));
            }

            if (!ValidVdom.IsMatch(settings.Vdom))
            {
                results.Add(new ActionResult("VDOM must be a VDOM name, e.g. root.", false));
            }

            if (string.IsNullOrWhiteSpace(GetApiToken(execParams)))
            {
                results.Add(new ActionResult("A FortiGate REST API token credential is required.", false));
            }

            if (execParams.IsPreviewOnly && !results.Any(r => !r.IsSuccess))
            {
                results.AddRange(await Deploy(execParams, apply: false));
            }

            return results;
        }

        /// <summary>
        /// Find the previous certificates and what uses them, then (if applying) import the new certificate, move the references and delete the previous certificates
        /// </summary>
        private static async Task<List<ActionResult>> Deploy(DeploymentTaskExecutionParams execParams, bool apply)
        {
            var results = new List<ActionResult>();
            var settings = GetSettings(execParams);
            var log = execParams.Log;
            var cancellationToken = execParams.CancellationToken;

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

            using var client = new FortiOsClient(settings.Address, GetApiToken(execParams).Trim(), settings.Vdom, settings.AllowInvalidTls);

            try
            {
                // previous deployments are named {name}_{yyMMddHHmmss}; a certificate named exactly {name} (e.g. imported by hand) is replaced too
                var previousName = new Regex($"^{Regex.Escape(settings.CertName)}(_\\d{{12}})?$");
                var previous = (await client.ListCertificates(cancellationToken))
                    .Where(c => previousName.IsMatch(c.Name) && c.Source != "factory")
                    .ToList();

                var references = new List<CertificateReference>();
                foreach (var old in previous)
                {
                    references.AddRange(await client.FindReferences(old, cancellationToken));
                }

                var newName = $"{settings.CertName}_{DateTime.UtcNow:yyMMddHHmmss}";

                if (!apply)
                {
                    var preview = new StringBuilder($"Connected to FortiGate {settings.Address} (VDOM {settings.Vdom}). ");
                    preview.Append(cert == null ? "No certificate has been issued yet. Deploying would import" : "Would import");
                    preview.Append($" it as local certificate '{newName}'");

                    if (references.Any())
                    {
                        preview.Append($", move {references.Count} reference(s) to it ({string.Join(", ", references.Select(r => r.Description))})");
                    }

                    if (previous.Any())
                    {
                        preview.Append($", then delete {string.Join(", ", previous.Select(p => $"'{p.Name}'"))}");
                    }

                    preview.Append('.');
                    results.Add(new ActionResult(preview.ToString(), true));
                    return results;
                }

                // intermediates are imported as CA certificates, so the FortiGate sends the full chain
                foreach (var intermediate in cert.Intermediates)
                {
                    var ca = await client.Monitor("vpn-certificate/ca/import", new JsonObject
                    {
                        ["import_method"] = "file",
                        ["scope"] = "vdom",
                        ["file_content"] = Base64(intermediate.Pem)
                    }, cancellationToken);

                    // -328: the CA certificate already exists
                    if (!ca.IsSuccess && ca.ErrorCode != -328)
                    {
                        var msg = $"FortiGate: could not import intermediate certificate {intermediate.Subject}: {ca.Message}";
                        log?.Warning(msg);
                        results.Add(new ActionResult(msg, true) { IsWarning = true });
                    }
                }

                log?.Information($"FortiGate: importing certificate as '{newName}' on {settings.Address}");

                var import = await client.Monitor("vpn-certificate/local/import", new JsonObject
                {
                    ["type"] = "regular",
                    ["certname"] = newName,
                    ["scope"] = "vdom",
                    ["file_content"] = Base64(cert.CertPem + string.Concat(cert.Intermediates.Select(i => i.Pem))),
                    ["key_file_content"] = Base64(cert.KeyPem)
                }, cancellationToken);

                if (!import.IsSuccess)
                {
                    results.Add(new ActionResult($"FortiGate: failed to import certificate '{newName}', nothing was changed: {import.Message}", false));
                    return results;
                }

                // the admin interface last, as changing it restarts the HTTPS service this task is connected to
                var stillUsed = new HashSet<string>();
                foreach (var reference in references.OrderBy(r => r.IsAdminServerCert))
                {
                    log?.Information($"FortiGate: moving {reference.Description} from '{reference.Certificate}' to '{newName}'");

                    var moved = await client.MoveReference(reference, newName, cancellationToken);
                    if (!moved.IsSuccess)
                    {
                        stillUsed.Add(reference.Certificate);
                        results.Add(new ActionResult($"FortiGate: certificate '{newName}' was imported, but {reference.Description} could not be changed to use it, so it still uses '{reference.Certificate}': {moved.Message}", false));
                    }
                }

                foreach (var old in previous.Where(p => !stillUsed.Contains(p.Name)))
                {
                    var deleted = await client.DeleteCertificate(old.Name, cancellationToken);
                    if (!deleted.IsSuccess)
                    {
                        var msg = $"FortiGate: could not delete previous certificate '{old.Name}': {deleted.Message}";
                        log?.Warning(msg);
                        results.Add(new ActionResult(msg, true) { IsWarning = true });
                    }
                }

                if (!results.Any(r => !r.IsSuccess))
                {
                    var done = new StringBuilder($"FortiGate: imported certificate '{newName}'");
                    done.Append(references.Any() ? $" and moved {references.Count} reference(s) to it ({string.Join(", ", references.Select(r => r.Description))})." : ".");

                    if (!references.Any())
                    {
                        done.Append(" Nothing used the previous certificate, so select it where it should be used on the FortiGate. Later renewals move those settings automatically.");
                    }

                    results.Add(new ActionResult(done.ToString(), true));
                }

                return results;
            }
            catch (FortiOsApiException exp)
            {
                results.Add(new ActionResult($"FortiGate: {exp.Message}", false));
                return results;
            }
            catch (HttpRequestException exp)
            {
                results.Add(new ActionResult($"FortiGate: could not connect to {settings.Address}: {exp.Message}" + NetworkDevice.ConnectionFailureHint(settings.AllowInvalidTls, "Allow Untrusted FortiGate Certificate"), false));
                return results;
            }
            catch (TaskCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                results.Add(new ActionResult($"FortiGate: request to {settings.Address} timed out.", false));
                return results;
            }
        }

        private static string Base64(string pem) => Convert.ToBase64String(Encoding.ASCII.GetBytes(pem));

        private static string GetApiToken(DeploymentTaskExecutionParams execParams) => execParams.Credentials?.GetValueOrDefault("api_token");

        private static (string AddressText, Uri Address, string CertName, string Vdom, bool AllowInvalidTls) GetSettings(DeploymentTaskExecutionParams execParams)
        {
            var parameters = execParams.Settings.Parameters;
            var addressText = parameters.FirstOrDefault(c => c.Key == "fgt_address")?.Value?.Trim();
            var certName = parameters.FirstOrDefault(c => c.Key == "cert_name")?.Value?.Trim();
            var vdom = parameters.FirstOrDefault(c => c.Key == "vdom")?.Value?.Trim();
            _ = bool.TryParse(parameters.FirstOrDefault(c => c.Key == "allow_invalid_tls")?.Value, out var allowInvalidTls);

            return (addressText, NetworkDevice.ParseAddress(addressText), certName, string.IsNullOrEmpty(vdom) ? "root" : vdom, allowInvalidTls);
        }

        private sealed record LocalCertificate(string Name, string Source, int QType);

        /// <summary>
        /// A setting which uses a certificate: the attribute of a configuration object (path/name, plus mkey for a table entry)
        /// </summary>
        private sealed record CertificateReference(string Certificate, string Path, string Name, string MKey, string Attribute)
        {
            public bool IsAdminServerCert => Path == "system" && Name == "global" && Attribute == "admin-server-cert";

            public string Description => IsAdminServerCert ? "the admin interface" : $"{Path}.{Name}{(MKey != null ? $" '{MKey}'" : "")} {Attribute}";
        }

        private sealed class FortiOsApiException : Exception
        {
            public FortiOsApiException(string message) : base(message) { }
        }

        private sealed record FortiOsResult(bool IsSuccess, int? ErrorCode, string Message, JsonNode Body);

        /// <summary>
        /// Minimal client for the FortiOS REST API (/api/v2), authenticating with an API token as a bearer token.
        /// Responses are JSON: { "status": "success" | "error", "http_status": 200, "error": -23, "results": ... }
        /// </summary>
        private sealed class FortiOsClient : IDisposable
        {
            private readonly HttpClient _http;
            private readonly string _vdom;

            public FortiOsClient(Uri address, string apiToken, string vdom, bool allowInvalidTls)
            {
                _vdom = vdom;
                _http = NetworkDevice.CreateHttpClient(new Uri(address.GetLeftPart(UriPartial.Authority) + "/api/v2/"), allowInvalidTls);
                _http.DefaultRequestHeaders.TryAddWithoutValidation("Authorization", "Bearer " + apiToken);
            }

            public async Task<List<LocalCertificate>> ListCertificates(CancellationToken cancellationToken)
            {
                var result = await Send(HttpMethod.Get, "monitor/system/available-certificates", null, null, cancellationToken);
                if (!result.IsSuccess)
                {
                    throw new FortiOsApiException($"could not list certificates: {result.Message}");
                }

                return (result.Body?["results"] as JsonArray ?? new JsonArray())
                    .OfType<JsonObject>()
                    .Where(c => c["name"] != null)
                    .Select(c => new LocalCertificate(c["name"].ToString(), c["source"]?.ToString(), int.TryParse(c["q_type"]?.ToString(), out var qType) ? qType : 0))
                    .ToList();
            }

            /// <summary>
            /// Settings using a certificate: those reported by the object usage API, plus the admin interface certificate (which that API does not report)
            /// </summary>
            public async Task<List<CertificateReference>> FindReferences(LocalCertificate certificate, CancellationToken cancellationToken)
            {
                var references = new List<CertificateReference>();

                var usage = await Send(HttpMethod.Get, "monitor/system/object/usage", $"mkey={Uri.EscapeDataString(certificate.Name)}&qtypes={Uri.EscapeDataString($"[{certificate.QType}]")}", null, cancellationToken);
                if (!usage.IsSuccess)
                {
                    throw new FortiOsApiException($"could not check where certificate '{certificate.Name}' is used: {usage.Message}");
                }

                foreach (var item in (usage.Body?["results"]?["currently_using"] as JsonArray ?? new JsonArray()).OfType<JsonObject>())
                {
                    var path = item["path"]?.ToString();
                    var name = item["name"]?.ToString();
                    var attribute = item["attribute"]?.ToString();
                    if (!string.IsNullOrEmpty(path) && !string.IsNullOrEmpty(name) && !string.IsNullOrEmpty(attribute))
                    {
                        var mkey = item["mkey"]?.ToString();
                        references.Add(new CertificateReference(certificate.Name, path, name, string.IsNullOrEmpty(mkey) ? null : mkey, attribute));
                    }
                }

                if (!references.Any(r => r.IsAdminServerCert))
                {
                    var global = await Send(HttpMethod.Get, "cmdb/system/global", null, null, cancellationToken);
                    if (ReadAttribute(global.Body, "admin-server-cert") is JsonNode admin && Names(admin).Contains(certificate.Name))
                    {
                        references.Add(new CertificateReference(certificate.Name, "system", "global", null, "admin-server-cert"));
                    }
                }

                return references;
            }

            /// <summary>
            /// Change a setting from the previous certificate to the new one. For a list of certificates, only the previous certificate is replaced.
            /// </summary>
            public async Task<FortiOsResult> MoveReference(CertificateReference reference, string newName, CancellationToken cancellationToken)
            {
                var objectPath = $"cmdb/{reference.Path}/{reference.Name}{(reference.MKey != null ? "/" + Uri.EscapeDataString(reference.MKey) : "")}";

                var current = await Send(HttpMethod.Get, objectPath, null, null, cancellationToken);
                if (!current.IsSuccess)
                {
                    return current;
                }

                JsonNode value = ReadAttribute(current.Body, reference.Attribute) switch
                {
                    JsonArray list => new JsonArray(list.Select(i => (JsonNode)new JsonObject { ["name"] = Names(i).Contains(reference.Certificate) ? newName : Names(i).FirstOrDefault() }).ToArray()),
                    _ => JsonValue.Create(newName)
                };

                return await Send(HttpMethod.Put, objectPath, null, new JsonObject { [reference.Attribute] = value }, cancellationToken);
            }

            public async Task<FortiOsResult> DeleteCertificate(string name, CancellationToken cancellationToken)
            {
                try
                {
                    return await Send(HttpMethod.Delete, $"cmdb/vpn.certificate/local/{Uri.EscapeDataString(name)}", null, null, cancellationToken);
                }
                catch (HttpRequestException exp)
                {
                    // e.g. the connection was reset as the admin interface certificate changed
                    return new FortiOsResult(false, null, exp.Message, null);
                }
            }

            public Task<FortiOsResult> Monitor(string path, JsonObject body, CancellationToken cancellationToken) => Send(HttpMethod.Post, "monitor/" + path, null, body, cancellationToken);

            /// <summary>
            /// The attribute of the first result of a CMDB read: results is an object for a single item, or an array
            /// </summary>
            private static JsonNode ReadAttribute(JsonNode body, string attribute)
            {
                var results = body?["results"];
                var item = results is JsonArray array ? array.FirstOrDefault() : results;
                return item is JsonObject o ? o[attribute] : null;
            }

            /// <summary>
            /// Certificate names in an attribute value: a string, or an object or list of objects with name / q_origin_key
            /// </summary>
            private static List<string> Names(JsonNode value) => value switch
            {
                JsonValue v => new List<string> { v.ToString() },
                JsonObject o => new[] { o["name"]?.ToString(), o["q_origin_key"]?.ToString() }.Where(n => n != null).ToList(),
                JsonArray a => a.SelectMany(Names).ToList(),
                _ => new List<string>()
            };

            private async Task<FortiOsResult> Send(HttpMethod method, string path, string query, JsonObject body, CancellationToken cancellationToken)
            {
                using var request = new HttpRequestMessage(method, $"{path}?vdom={Uri.EscapeDataString(_vdom)}{(query != null ? "&" + query : "")}");
                if (body != null)
                {
                    request.Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json");
                }

                using var response = await _http.SendAsync(request, cancellationToken);
                var text = await response.Content.ReadAsStringAsync();

                JsonNode json = null;
                try
                {
                    json = string.IsNullOrWhiteSpace(text) ? null : JsonNode.Parse(text);
                }
                catch (System.Text.Json.JsonException)
                {
                    // not a FortiOS API response, e.g. the address is not the FortiGate management interface
                }

                if (response.StatusCode == HttpStatusCode.Unauthorized || response.StatusCode == HttpStatusCode.Forbidden)
                {
                    throw new FortiOsApiException($"access denied ({(int)response.StatusCode}). Check the API token, that the REST API administrator's trusted hosts include this computer, and that its admin profile allows reading and changing the configuration.");
                }

                if (json is not JsonObject)
                {
                    throw new FortiOsApiException($"unexpected response to '{path}' (HTTP {(int)response.StatusCode}). Check the FortiGate Address is the management address, including the admin HTTPS port.");
                }

                var errorCode = int.TryParse(json["error"]?.ToString(), out var code) ? code : (int?)null;
                if (response.IsSuccessStatusCode && json["status"]?.ToString() != "error")
                {
                    return new FortiOsResult(true, null, null, json);
                }

                var detail = json["cli_error"]?.ToString()?.Trim();
                if (string.IsNullOrEmpty(detail))
                {
                    detail = json["message"]?.ToString()?.Trim();
                }

                var message = (string.IsNullOrEmpty(detail) ? $"HTTP {(int)response.StatusCode}" : detail) + (errorCode != null ? $" (error {errorCode})" : "");
                return new FortiOsResult(false, errorCode, message, json);
            }

            public void Dispose() => _http.Dispose();
        }
    }
}
