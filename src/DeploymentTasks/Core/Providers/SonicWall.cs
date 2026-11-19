using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
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
    /// Deploys a certificate to a SonicWall firewall (SonicOS 7) using the SonicOS API, signing in with HTTP Digest or Basic authentication.
    /// The certificate is imported under a new name each time ({name}_{yyMMddHHmmss}), the HTTPS management and SSL VPN certificates are
    /// moved from the previous certificate to it, then the previous certificate is deleted.
    /// </summary>
    public class SonicWall : IDeploymentTaskProvider
    {
        public static DeploymentProviderDefinition Definition { get; }
        public DeploymentProviderDefinition GetDefinition(DeploymentProviderDefinition currentDefinition = null) => (currentDefinition ?? Definition);

        private const int MaxNameLength = 30;
        private static readonly Regex ValidName = new Regex($"^[A-Za-z0-9_][A-Za-z0-9_.-]{{0,{MaxNameLength - 1}}}$", RegexOptions.Compiled);

        static SonicWall()
        {
            Definition = new DeploymentProviderDefinition
            {
                Id = "Certify.Providers.DeploymentTasks.SonicWall",
                Title = "Deploy to SonicWall",
                IsExperimental = false,
                UsageType = DeploymentProviderUsage.PostRequest,
                SupportedContexts = DeploymentContextType.ExternalCredential,
                ExternalCredentialType = StandardAuthTypes.STANDARD_AUTH_GENERIC,
                RequiresManagementHub = true,
                Description = "Import the certificate to a SonicWall firewall (SonicOS 7) using the SonicOS API, and switch the HTTPS management and SSL VPN certificates from the previous certificate to it.",
                ProviderParameters = new List<ProviderParameter>
                {
                    new ProviderParameter{ Key="sonicwall_address", Name="SonicWall Address", IsRequired=true, IsCredential=false, Type= OptionType.String, Description="Management address, e.g. https://192.168.168.168 or https://fw.example.com:4433" },
                    new ProviderParameter{ Key="cert_name", Name="Certificate Name", IsRequired=true, IsCredential=false, Type= OptionType.String, Description="Base name of the certificate, e.g. www_example_com (up to 30 characters). Each deployment is imported as <name>_<date and time>, replacing the previous one." },
                    new ProviderParameter{ Key="delete_previous", Name="Delete Previous Certificates", IsRequired=false, IsCredential=false, Type= OptionType.Boolean, Value="true", Description="Delete the previous certificate once the HTTPS management and SSL VPN settings no longer use it. Turn off if you also use it elsewhere, e.g. in IPsec VPN policies." },
                    new ProviderParameter{ Key="override_admin", Name="Take Over Management", IsRequired=false, IsCredential=false, Type= OptionType.Boolean, Value="false", Description="If another administrator is managing the firewall, end their session so the task can make its changes. Their unsaved changes are lost." },
                    new ProviderParameter{ Key="allow_invalid_tls", Name="Allow Untrusted SonicWall Certificate", IsRequired=false, IsCredential=false, Type= OptionType.Boolean, Value="false", Description="Connect even if the SonicWall management certificate is not trusted (e.g. the default self-signed certificate)." },
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
        /// Check the task settings. In preview, also sign in to the SonicWall and report what deploying would change.
        /// </summary>
        public async Task<List<ActionResult>> Validate(DeploymentTaskExecutionParams execParams)
        {
            var results = new List<ActionResult>();
            var settings = GetSettings(execParams);

            NetworkDevice.ValidateAddress(settings.AddressText, "SonicWall Address", results);

            if (string.IsNullOrWhiteSpace(settings.CertName))
            {
                results.Add(new ActionResult("Certificate Name is required.", false));
            }
            else if (!ValidName.IsMatch(settings.CertName))
            {
                results.Add(new ActionResult($"Certificate Name may only contain letters, numbers, '.', '-' and '_', up to {MaxNameLength} characters.", false));
            }

            if (GetCredentials(execParams) == null)
            {
                results.Add(new ActionResult("A username and password credential for the SonicWall is required.", false));
            }

            if (execParams.IsPreviewOnly && !results.Any(r => !r.IsSuccess))
            {
                results.AddRange(await Deploy(execParams, apply: false));
            }

            return results;
        }

        /// <summary>
        /// Find the previous certificates and the settings using them, then (if applying) import the new certificate, move the settings and delete the previous certificates
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

            var (username, password) = GetCredentials(execParams).Value;
            using var client = new SonicOsClient(settings.Address, username, password, settings.AllowInvalidTls);

            try
            {
                // a preview never ends another administrator's session
                await client.SignIn(apply && settings.OverrideAdmin, cancellationToken);

                try
                {
                    // previous deployments are named {name}_{yyMMddHHmmss}; a certificate named exactly {name} (e.g. imported by hand) is replaced too
                    var previousName = new Regex($"^{Regex.Escape(settings.CertName)}(_\\d{{12}})?$");
                    var previous = (await client.ListCertificates(cancellationToken)).Where(n => previousName.IsMatch(n)).Distinct().ToList();
                    var references = (await client.FindReferences(cancellationToken)).Where(r => previous.Contains(r.Certificate)).ToList();

                    var newName = $"{settings.CertName}_{DateTime.UtcNow:yyMMddHHmmss}";

                    if (!apply)
                    {
                        var preview = new StringBuilder($"Connected to SonicWall {settings.Address} as '{username}'. ");
                        preview.Append(cert == null ? "No certificate has been issued yet. Deploying would import" : "Would import");
                        preview.Append($" it as certificate '{newName}'");

                        if (references.Any())
                        {
                            preview.Append($", switch {string.Join(" and ", references.Select(r => r.Description))} to it");
                        }

                        if (previous.Any() && settings.DeletePrevious)
                        {
                            preview.Append($", then delete {string.Join(", ", previous.Select(p => $"'{p}'"))}");
                        }

                        preview.Append('.');
                        results.Add(new ActionResult(preview.ToString(), true));
                        return results;
                    }

                    await client.EnterConfigMode(cancellationToken);

                    log?.Information($"SonicWall: importing certificate as '{newName}' on {settings.Address}");

                    var import = await client.ImportCertificate(newName, cert, cancellationToken);
                    if (!import.IsSuccess)
                    {
                        results.Add(new ActionResult($"SonicWall: failed to import certificate '{newName}', nothing was changed: {import.Message}", false));
                        return results;
                    }

                    // the HTTPS management certificate last, as the firewall restarts its management web server when that is saved
                    var stillUsed = new HashSet<string>();
                    var moved = new List<CertificateReference>();
                    foreach (var reference in references.OrderBy(r => r.Setting == ReferenceSetting.HttpsManagement))
                    {
                        log?.Information($"SonicWall: switching {reference.Description} from '{reference.Certificate}' to '{newName}'");

                        var result = await client.MoveReference(reference, newName, cancellationToken);
                        if (result.IsSuccess)
                        {
                            moved.Add(reference);
                        }
                        else
                        {
                            stillUsed.Add(reference.Certificate);
                            results.Add(new ActionResult($"SonicWall: certificate '{newName}' was imported, but {reference.Description} could not be switched to it, so it still uses '{reference.Certificate}': {result.Message}", false));
                        }
                    }

                    SonicOsResult commit;
                    try
                    {
                        commit = await client.CommitPending(cancellationToken);
                    }
                    catch (Exception exp) when (moved.Any(r => r.Setting == ReferenceSetting.HttpsManagement) && (exp is HttpRequestException || (exp is TaskCanceledException && !cancellationToken.IsCancellationRequested)))
                    {
                        results.Add(new ActionResult($"SonicWall: the connection closed while saving the switch of the HTTPS management certificate to '{newName}', which can happen as the firewall restarts its management web server. Check the SonicWall uses '{newName}'. The previous certificate was kept.", false));
                        return results;
                    }

                    if (!commit.IsSuccess)
                    {
                        results.Add(new ActionResult($"SonicWall: could not save the changes, so the SonicWall still uses the previous certificate: {commit.Message}", false));
                        return results;
                    }

                    if (settings.DeletePrevious)
                    {
                        await DeletePrevious(client, previous.Where(p => !stillUsed.Contains(p)).ToList(), results, log, cancellationToken);
                    }

                    if (!results.Any(r => !r.IsSuccess))
                    {
                        var done = new StringBuilder($"SonicWall: imported certificate '{newName}'");
                        done.Append(moved.Any() ? $" and switched {string.Join(" and ", moved.Select(r => r.Description))} to it." : ".");

                        if (!references.Any())
                        {
                            done.Append(" Nothing used the previous certificate, so select it where it should be used on the SonicWall, e.g. for HTTPS management or SSL VPN. Later renewals switch those settings automatically.");
                        }

                        results.Add(new ActionResult(done.ToString(), true));
                    }

                    return results;
                }
                finally
                {
                    await client.SignOut();
                }
            }
            catch (SonicOsApiException exp)
            {
                results.Add(new ActionResult($"SonicWall: {exp.Message}", false));
                return results;
            }
            catch (HttpRequestException exp)
            {
                results.Add(new ActionResult($"SonicWall: could not connect to {settings.Address}: {exp.Message}" + NetworkDevice.ConnectionFailureHint(settings.AllowInvalidTls, "Allow Untrusted SonicWall Certificate"), false));
                return results;
            }
            catch (TaskCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                results.Add(new ActionResult($"SonicWall: request to {settings.Address} timed out.", false));
                return results;
            }
        }

        /// <summary>
        /// Delete the previous certificates and save. A certificate the SonicWall refuses to delete (e.g. still used by an IPsec VPN policy) is a warning.
        /// </summary>
        private static async Task DeletePrevious(SonicOsClient client, List<string> previous, List<ActionResult> results, Certify.Models.Providers.ILog log, CancellationToken cancellationToken)
        {
            var deleted = 0;
            foreach (var old in previous)
            {
                var result = await client.DeleteCertificate(old, cancellationToken);
                if (result.IsSuccess)
                {
                    deleted++;
                }
                else
                {
                    var msg = $"SonicWall: could not delete previous certificate '{old}': {result.Message}";
                    log?.Warning(msg);
                    results.Add(new ActionResult(msg, true) { IsWarning = true });
                }
            }

            if (deleted > 0)
            {
                var commit = await client.CommitPending(cancellationToken);
                if (!commit.IsSuccess)
                {
                    var msg = $"SonicWall: could not save the deletion of the previous certificate: {commit.Message}";
                    log?.Warning(msg);
                    results.Add(new ActionResult(msg, true) { IsWarning = true });
                }
            }
        }

        private static (string Username, string Password)? GetCredentials(DeploymentTaskExecutionParams execParams)
        {
            var credentials = execParams.Credentials;
            if (credentials != null
                && credentials.TryGetValue("username", out var username) && !string.IsNullOrWhiteSpace(username)
                && credentials.TryGetValue("password", out var password) && !string.IsNullOrEmpty(password))
            {
                return (username.Trim(), password);
            }

            return null;
        }

        private static (string AddressText, Uri Address, string CertName, bool DeletePrevious, bool OverrideAdmin, bool AllowInvalidTls) GetSettings(DeploymentTaskExecutionParams execParams)
        {
            var parameters = execParams.Settings.Parameters;
            var addressText = parameters.FirstOrDefault(c => c.Key == "sonicwall_address")?.Value?.Trim();
            var certName = parameters.FirstOrDefault(c => c.Key == "cert_name")?.Value?.Trim();
            var deletePrevious = !bool.TryParse(parameters.FirstOrDefault(c => c.Key == "delete_previous")?.Value, out var delete) || delete;
            _ = bool.TryParse(parameters.FirstOrDefault(c => c.Key == "override_admin")?.Value, out var overrideAdmin);
            _ = bool.TryParse(parameters.FirstOrDefault(c => c.Key == "allow_invalid_tls")?.Value, out var allowInvalidTls);

            return (addressText, NetworkDevice.ParseAddress(addressText), certName, deletePrevious, overrideAdmin, allowInvalidTls);
        }

        private enum ReferenceSetting
        {
            SslVpn,
            HttpsManagement
        }

        private sealed record CertificateReference(string Certificate, ReferenceSetting Setting)
        {
            public string Description => Setting == ReferenceSetting.HttpsManagement ? "the HTTPS management certificate" : "the SSL VPN certificate";
        }

        private sealed class SonicOsApiException : Exception
        {
            public SonicOsApiException(string message) : base(message) { }
        }

        private sealed record SonicOsResult(bool IsSuccess, HttpStatusCode StatusCode, string Message, JsonNode Body);

        /// <summary>
        /// Minimal client for the SonicOS API (/api/sonicos/). The HTTP client answers the Digest (or Basic) challenges of sign in itself, and also
        /// those of session security, which checks a digest on every request after sign in. Changes are staged until committed.
        /// Responses are JSON; changes and errors return { "status": { "success": bool, "info": [ { "level", "code", "message" } ] } }
        /// </summary>
        private sealed class SonicOsClient : IDisposable
        {
            private readonly HttpClient _http;
            private bool _signedIn;

            public SonicOsClient(Uri address, string username, string password, bool allowInvalidTls)
            {
                _http = NetworkDevice.CreateHttpClient(new Uri(address.GetLeftPart(UriPartial.Authority) + "/api/sonicos/"), allowInvalidTls, new NetworkCredential(username, password));
            }

            public async Task SignIn(bool overrideAdmin, CancellationToken cancellationToken)
            {
                var result = await Send(HttpMethod.Post, "auth", Json(new JsonObject { ["override"] = overrideAdmin }), cancellationToken);
                if (!result.IsSuccess)
                {
                    throw new SonicOsApiException($"could not sign in: {result.Message}. Check the SonicWall Address, and that the SonicOS API is enabled.");
                }

                _signedIn = true;
            }

            public async Task SignOut()
            {
                if (!_signedIn)
                {
                    return;
                }

                try
                {
                    // also discards anything not committed
                    await Send(HttpMethod.Delete, "auth", null, CancellationToken.None);
                }
                catch (Exception)
                {
                    // the session ends anyway after a period of inactivity
                }
            }

            /// <summary>
            /// Enter config mode. An administrator other than the built-in admin must start a management session first.
            /// </summary>
            public async Task EnterConfigMode(CancellationToken cancellationToken)
            {
                var result = await Send(HttpMethod.Post, "config-mode", null, cancellationToken);
                if (!result.IsSuccess)
                {
                    await Send(HttpMethod.Post, "start-management", null, cancellationToken);
                    result = await Send(HttpMethod.Post, "config-mode", null, cancellationToken);
                }

                if (!result.IsSuccess)
                {
                    throw new SonicOsApiException($"could not start making changes: {result.Message}. If another administrator is managing the SonicWall, enable Take Over Management, or try again later.");
                }
            }

            public async Task<List<string>> ListCertificates(CancellationToken cancellationToken)
            {
                var result = await Send(HttpMethod.Get, "reporting/certificates", null, cancellationToken);
                if (!result.IsSuccess)
                {
                    throw new SonicOsApiException($"could not list certificates: {result.Message}");
                }

                return CertificateNames(result.Body).ToList();
            }

            /// <summary>
            /// The certificates selected for HTTPS management and SSL VPN (SSL VPN may be unavailable, e.g. not licensed)
            /// </summary>
            public async Task<List<CertificateReference>> FindReferences(CancellationToken cancellationToken)
            {
                var references = new List<CertificateReference>();

                var admin = await Send(HttpMethod.Get, "administration/global", null, cancellationToken);
                if (!admin.IsSuccess)
                {
                    throw new SonicOsApiException($"could not read the HTTPS management settings: {admin.Message}");
                }

                if (admin.Body?["administration"]?["web_management"]?["certificate"]?["name"]?.ToString() is string managementCert)
                {
                    references.Add(new CertificateReference(managementCert, ReferenceSetting.HttpsManagement));
                }

                var sslVpn = await Send(HttpMethod.Get, "ssl-vpn/server/base", null, cancellationToken);
                if (sslVpn.IsSuccess && sslVpn.Body?["ssl_vpn"]?["server"]?["certificate"]?["name"]?.ToString() is string sslVpnCert)
                {
                    references.Add(new CertificateReference(sslVpnCert, ReferenceSetting.SslVpn));
                }

                return references;
            }

            public Task<SonicOsResult> MoveReference(CertificateReference reference, string newName, CancellationToken cancellationToken)
            {
                var certificate = new JsonObject { ["certificate"] = new JsonObject { ["name"] = newName } };

                return reference.Setting == ReferenceSetting.HttpsManagement
                    ? Send(HttpMethod.Put, "administration/global", Json(new JsonObject { ["administration"] = new JsonObject { ["web_management"] = certificate } }), cancellationToken)
                    : Send(HttpMethod.Put, "ssl-vpn/server/base", Json(new JsonObject { ["ssl_vpn"] = new JsonObject { ["server"] = certificate } }), cancellationToken);
            }

            /// <summary>
            /// Import the key, certificate and chain as a PKCS#12 file. SonicOS 7.3 takes the file password in the form;
            /// earlier versions of SonicOS 7 don't have that endpoint, and take the password in the path instead.
            /// </summary>
            public async Task<SonicOsResult> ImportCertificate(string name, DeviceCertificate cert, CancellationToken cancellationToken)
            {
                var password = Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
                var pfx = ExportPkcs12(cert, password);

                using var content = NetworkDevice.MultipartForm(("certPasswd", null, Encoding.ASCII.GetBytes(password)), ("certificate.exp", $"{name}.p12", pfx));
                var result = await Send(HttpMethod.Put, $"import/certificates/cert-key-pair/name/{name}", content, cancellationToken);

                if (result.StatusCode == HttpStatusCode.NotFound || result.StatusCode == HttpStatusCode.MethodNotAllowed)
                {
                    using var legacy = NetworkDevice.MultipartForm(("file", $"{name}.p12", pfx));
                    result = await Send(HttpMethod.Put, $"import/certificates/cert-key-pair/name/{name}/password/{password}", legacy, cancellationToken);
                }

                return result;
            }

            public Task<SonicOsResult> DeleteCertificate(string name, CancellationToken cancellationToken)
                => Send(HttpMethod.Delete, $"certificates/name/{Uri.EscapeDataString(name)}", null, cancellationToken);

            /// <summary>
            /// Commit the staged changes, if there are any
            /// </summary>
            public async Task<SonicOsResult> CommitPending(CancellationToken cancellationToken)
            {
                var pending = await Send(HttpMethod.Get, "config/pending", null, cancellationToken);
                if (pending.IsSuccess && pending.Body is JsonObject changes && !changes.Any(c => c.Key != "status"))
                {
                    return pending;
                }

                return await Send(HttpMethod.Post, "config/pending", null, cancellationToken);
            }

            /// <summary>
            /// PKCS#12 of the key, certificate and intermediates, with 3DES/SHA1 encryption for older SonicOS versions
            /// </summary>
            private static byte[] ExportPkcs12(DeviceCertificate cert, string password)
            {
                using var leaf = X509Certificate2.CreateFromPem(cert.CertPem, cert.KeyPem);
                var collection = new X509Certificate2Collection(leaf);
                foreach (var intermediate in cert.Intermediates)
                {
                    collection.Add(X509Certificate2.CreateFromPem(intermediate.Pem));
                }

                try
                {
                    return collection.ExportPkcs12(Pkcs12ExportPbeParameters.Pkcs12TripleDesSha1, password);
                }
                finally
                {
                    foreach (var c in collection.Skip(1))
                    {
                        c.Dispose();
                    }
                }
            }

            /// <summary>
            /// Certificate names in a certificate list: every object's "certificate" value, wherever the list is in the response
            /// </summary>
            private static IEnumerable<string> CertificateNames(JsonNode node) => node switch
            {
                JsonArray a => a.SelectMany(CertificateNames),
                JsonObject o => o.SelectMany(p => p.Key == "certificate" && p.Value is JsonValue v ? new[] { v.ToString() } : CertificateNames(p.Value)),
                _ => Enumerable.Empty<string>()
            };

            private static StringContent Json(JsonObject body) => new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json");

            private async Task<SonicOsResult> Send(HttpMethod method, string path, HttpContent content, CancellationToken cancellationToken)
            {
                using var request = new HttpRequestMessage(method, path) { Content = content };
                request.Headers.Accept.ParseAdd("application/json");

                using var response = await _http.SendAsync(request, cancellationToken);
                var text = await response.Content.ReadAsStringAsync(cancellationToken);

                JsonNode json = null;
                try
                {
                    json = string.IsNullOrWhiteSpace(text) ? null : JsonNode.Parse(text);
                }
                catch (System.Text.Json.JsonException)
                {
                    // not a SonicOS API response, e.g. the address is not the SonicWall management interface
                }

                var messages = ((json as JsonObject)?["status"]?["info"] as JsonArray ?? new JsonArray())
                    .Select(i => i?["message"]?.ToString()?.Trim().TrimEnd('.'))
                    .Where(m => !string.IsNullOrEmpty(m))
                    .ToList();
                var message = messages.Any() ? string.Join("; ", messages) : $"HTTP {(int)response.StatusCode}";

                if (response.StatusCode == HttpStatusCode.Unauthorized || response.StatusCode == HttpStatusCode.Forbidden)
                {
                    throw new SonicOsApiException($"access denied ({message}). Check the username and password, that the SonicOS API is enabled with RFC-7616 HTTP Digest or HTTP Basic authentication, and that the user is an administrator.");
                }

                if (json == null && !(response.IsSuccessStatusCode && string.IsNullOrWhiteSpace(text)))
                {
                    if (response.StatusCode == HttpStatusCode.NotFound || response.StatusCode == HttpStatusCode.MethodNotAllowed)
                    {
                        return new SonicOsResult(false, response.StatusCode, message, null);
                    }

                    throw new SonicOsApiException($"unexpected response to '{path}' (HTTP {(int)response.StatusCode}). Check the SonicWall Address is the management address, including the management HTTPS port.");
                }

                var failed = (json as JsonObject)?["status"]?["success"] is JsonValue success && success.TryGetValue<bool>(out var ok) && !ok;
                return new SonicOsResult(response.IsSuccessStatusCode && !failed, response.StatusCode, message, json);
            }

            public void Dispose() => _http.Dispose();
        }
    }
}
