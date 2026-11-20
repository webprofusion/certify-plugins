using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using Certify.Models;
using Certify.Models.Config;
using Certify.Models.Providers;
using Certify.Providers.Deployment.Core.Shared;

namespace Certify.Providers.DeploymentTasks
{
    /// <summary>
    /// Stores the certificate in CyberArk Conjur variables under a path: certificate, private_key, chain, fullchain and optionally pfx. The variables
    /// must be declared in Conjur policy, with the task's host permitted to update them. The certificate variable is written last, so when it
    /// already holds this certificate the others do too, and nothing needs writing.
    /// </summary>
    public class CyberArkConjur : IDeploymentTaskProvider
    {
        public static DeploymentProviderDefinition Definition { get; }
        public DeploymentProviderDefinition GetDefinition(DeploymentProviderDefinition currentDefinition = null) => (currentDefinition ?? Definition);

        static CyberArkConjur()
        {
            Definition = new DeploymentProviderDefinition
            {
                Id = "Certify.Providers.DeploymentTasks.CyberArkConjur",
                Title = "Deploy to CyberArk Conjur",
                IsExperimental = false,
                UsageType = DeploymentProviderUsage.PostRequest,
                SupportedContexts = DeploymentContextType.ExternalCredential,
                ExternalCredentialType = CredentialTypes.ConjurApiKey,
                RequiresManagementHub = true,
                Description = "Store the certificate, private key and chain in CyberArk Conjur variables declared in Conjur policy.",
                ProviderParameters = new List<ProviderParameter>
                {
                    new ProviderParameter{ Key="variable_path", Name="Variable Path", IsRequired=true, IsCredential=false, Type= OptionType.String, Description="Path of the variables, e.g. certs/www-example-com for variables certs/www-example-com/certificate, .../private_key, .../chain and .../fullchain." },
                    new ProviderParameter{ Key="include_pfx", Name="Include PFX", IsRequired=false, IsCredential=false, Type= OptionType.Boolean, Value="false", Description="Also store the certificate as a base64 encoded PFX (PKCS#12) file in the variable .../pfx. It has the certificate's PFX password, if one is set." },
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
        /// Check the task settings and credential. In preview, also sign in to Conjur and check the variables can be written.
        /// </summary>
        public async Task<List<ActionResult>> Validate(DeploymentTaskExecutionParams execParams)
        {
            var results = new List<ActionResult>();
            var settings = GetSettings(execParams);

            if (settings.VariablePath == null)
            {
                results.Add(new ActionResult("Variable Path is required.", false));
            }
            else if (settings.VariablePath.Any(char.IsWhiteSpace) || settings.VariablePath.StartsWith('/') || settings.VariablePath.EndsWith('/'))
            {
                results.Add(new ActionResult("Variable Path must be a Conjur variable path without spaces, and can't start or end with '/', e.g. certs/www-example-com.", false));
            }

            var credential = GetCredential(execParams);
            if (credential == null)
            {
                results.Add(new ActionResult("A CyberArk Conjur API Key credential is required, with the Conjur URL, Account, Login and API Key.", false));
            }
            else
            {
                if (credential.Url == null)
                {
                    results.Add(new ActionResult("The Conjur URL of the CyberArk Conjur API Key credential must be a full URL, e.g. https://conjur.example.com.", false));
                }

                if (credential.CaText != null && credential.CaCertificates == null)
                {
                    results.Add(new ActionResult("The CA Certificate of the CyberArk Conjur API Key credential must be a certificate in PEM format.", false));
                }
            }

            if (execParams.IsPreviewOnly && !results.Any(r => !r.IsSuccess))
            {
                results.AddRange(await Deploy(execParams, apply: false));
            }

            return results;
        }

        /// <summary>
        /// Sign in and check whether the variables already hold the certificate, then (if applying) write them
        /// </summary>
        private static async Task<List<ActionResult>> Deploy(DeploymentTaskExecutionParams execParams, bool apply)
        {
            var results = new List<ActionResult>();
            var settings = GetSettings(execParams);
            var credential = GetCredential(execParams);
            var log = execParams.Log;
            var cancellationToken = execParams.CancellationToken;
            var managedCert = ManagedCertificate.GetManagedCertificate(execParams.Subject);

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

            // the certificate variable last, as writing it marks the others as written
            var names = new List<string> { "private_key", "chain", "fullchain" };
            if (settings.IncludePfx)
            {
                names.Add("pfx");
            }

            names.Add("certificate");

            try
            {
                using var conjur = new Api(credential);

                var signInProblem = await conjur.SignIn(cancellationToken);
                if (signInProblem != null)
                {
                    results.Add(new ActionResult($"Conjur: {signInProblem}", false));
                    return results;
                }

                // reading the certificate back needs the execute privilege on its variable. Without it, the variables are written every time.
                var current = await conjur.Send(HttpMethod.Get, conjur.SecretPath(settings.Variable("certificate")), null, cancellationToken);
                var upToDate = cert != null && current.IsSuccess && current.Text == cert.CertPem;

                if (!apply)
                {
                    var preview = new StringBuilder($"Connected to Conjur at {credential.Address} as {credential.Login}. ");
                    if (upToDate)
                    {
                        preview.Append($"Variable {settings.Variable("certificate")} already holds this certificate, so deploying would change nothing.");
                    }
                    else
                    {
                        preview.Append(cert == null ? "No certificate has been issued yet. Deploying would " : "Would ");
                        preview.Append($"write the certificate to the variables {string.Join(", ", names.Select(settings.Variable))}.");
                    }

                    results.Add(new ActionResult(preview.ToString(), true));

                    // the variables must be declared in policy, and updatable by this host
                    foreach (var name in names)
                    {
                        var variable = settings.Variable(name);
                        var check = await conjur.Send(HttpMethod.Get, $"{conjur.ResourcePath(variable)}?check=true&privilege=update", null, cancellationToken);
                        if (!check.IsSuccess)
                        {
                            results.Add(new ActionResult(check.Status == HttpStatusCode.NotFound || check.Status == HttpStatusCode.Forbidden
                                ? $"Conjur: {credential.Login} can't update variable {variable}, or it isn't declared in policy. Declare it, and permit {credential.Login} to update it."
                                : $"Conjur: could not check variable {variable}: {check.Error}", false));
                        }
                    }

                    return results;
                }

                if (upToDate)
                {
                    results.Add(new ActionResult($"Conjur: the variables under {settings.VariablePath} are already up to date.", true));
                    return results;
                }

                var values = new Dictionary<string, string>
                {
                    ["private_key"] = cert.Pkcs8KeyPem(),
                    ["chain"] = cert.ChainPem,
                    ["fullchain"] = cert.FullChainPem,
                    ["certificate"] = cert.CertPem
                };

                if (settings.IncludePfx)
                {
                    values["pfx"] = Convert.ToBase64String(await File.ReadAllBytesAsync(managedCert.CertificatePath, cancellationToken));
                }

                foreach (var name in names)
                {
                    var variable = settings.Variable(name);
                    if (string.IsNullOrEmpty(values[name]))
                    {
                        // Conjur doesn't store empty values, e.g. the chain of a certificate with no intermediates
                        log?.Information($"Conjur: skipping variable {variable}, which would be empty");
                        continue;
                    }

                    log?.Information($"Conjur: writing variable {variable}");

                    var written = await conjur.Send(HttpMethod.Post, conjur.SecretPath(variable), values[name], cancellationToken);
                    if (!written.IsSuccess)
                    {
                        results.Add(new ActionResult(written.Status == HttpStatusCode.NotFound || written.Status == HttpStatusCode.Forbidden
                            ? $"Conjur: could not write variable {variable}: {credential.Login} can't update it, or it isn't declared in policy. Declare it, and permit {credential.Login} to update it."
                            : $"Conjur: could not write variable {variable}: {written.Error}", false));
                        return results;
                    }
                }

                results.Add(new ActionResult($"Conjur: wrote the certificate to the variables under {settings.VariablePath}.", true));
                return results;
            }
            catch (HttpRequestException exp)
            {
                results.Add(new ActionResult(exp.InnerException is AuthenticationException
                    ? $"Conjur: could not connect to {credential.Address}, as its TLS certificate isn't trusted. Set the CA Certificate of the credential to the Conjur server's CA certificate."
                    : $"Conjur: could not connect to {credential.Address}: {exp.Message}", false));
                return results;
            }
            catch (TaskCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                results.Add(new ActionResult($"Conjur: request to {credential.Address} timed out.", false));
                return results;
            }
        }

        private sealed record Settings(string VariablePath, bool IncludePfx)
        {
            public string Variable(string name) => $"{VariablePath}/{name}";
        }

        private static Settings GetSettings(DeploymentTaskExecutionParams execParams)
        {
            var parameters = execParams.Settings.Parameters;
            string value(string key) => parameters.FirstOrDefault(c => c.Key == key)?.Value?.Trim() is { Length: > 0 } v ? v : null;

            _ = bool.TryParse(value("include_pfx"), out var includePfx);
            return new Settings(value("variable_path"), includePfx);
        }

        private sealed record Credential(Uri Url, string Account, string Login, string ApiKey, string CaText, X509Certificate2Collection CaCertificates, bool AllowInvalidTls)
        {
            public string Address => Url.ToString().TrimEnd('/');
        }

        private static Credential GetCredential(DeploymentTaskExecutionParams execParams)
        {
            var credentials = execParams.Credentials;
            string value(string key) => credentials?.TryGetValue(key, out var v) == true && !string.IsNullOrWhiteSpace(v) ? v.Trim() : null;

            var url = value("url");
            var account = value("account");
            var login = value("login");
            var apiKey = value("api_key");
            if (url == null || account == null || login == null || apiKey == null)
            {
                return null;
            }

            var caText = value("ca_data");
            _ = bool.TryParse(value("allow_invalid_tls"), out var allowInvalidTls);

            return new Credential(NetworkDevice.ParseAddress(url), account, login, apiKey, caText, caText == null ? null : TlsTrust.ParseCaCertificates(caText), allowInvalidTls);
        }

        private sealed record ApiResponse(HttpStatusCode Status, string Text, string Error)
        {
            public bool IsSuccess => (int)Status >= 200 && (int)Status < 300;
        }

        /// <summary>
        /// Client for the Conjur REST API: API key sign in, the access token on each request, and Conjur errors turned into messages
        /// </summary>
        private sealed class Api : IDisposable
        {
            private readonly HttpClient _http;
            private readonly Credential _credential;
            private readonly string _url;

            public Api(Credential credential)
            {
                _credential = credential;
                var handler = new HttpClientHandler
                {
                    ServerCertificateCustomValidationCallback = (_, certificate, chain, errors) => TlsTrust.IsServerCertificateTrusted(certificate, chain, errors, credential.CaCertificates, credential.AllowInvalidTls)
                };

                _http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(60) };

                // the URL may have a path, e.g. https://tenant.secretsmgr.cyberark.cloud/api for Conjur Cloud
                _url = credential.Address;
            }

            private string Account => Uri.EscapeDataString(_credential.Account);

            /// <summary>
            /// Path of a variable's value. IDs are escaped whole, so the '/' in them is sent as %2F, as Conjur expects.
            /// </summary>
            public string SecretPath(string variable) => $"/secrets/{Account}/variable/{Uri.EscapeDataString(variable)}";

            public string ResourcePath(string variable) => $"/resources/{Account}/variable/{Uri.EscapeDataString(variable)}";

            /// <summary>
            /// Exchange the API key for an access token. Result is null if signed in, otherwise why not.
            /// </summary>
            public async Task<string> SignIn(CancellationToken cancellationToken)
            {
                using var request = new HttpRequestMessage(HttpMethod.Post, $"{_url}/authn/{Account}/{Uri.EscapeDataString(_credential.Login)}/authenticate")
                {
                    Content = new StringContent(_credential.ApiKey, Encoding.UTF8, "text/plain")
                };

                using var response = await _http.SendAsync(request, cancellationToken);
                var token = await response.Content.ReadAsByteArrayAsync(cancellationToken);

                if (response.IsSuccessStatusCode)
                {
                    _http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Token", $"token=\"{Convert.ToBase64String(token)}\"");
                    return null;
                }

                return response.StatusCode == HttpStatusCode.Unauthorized
                    ? $"Conjur didn't accept the API key of {_credential.Login} (401 Unauthorized). Check the Account, Login and API Key of the credential, and that the API key hasn't been rotated."
                    : $"could not sign in as {_credential.Login}: {Describe(response.StatusCode, response.ReasonPhrase, Encoding.UTF8.GetString(token))}";
            }

            public async Task<ApiResponse> Send(HttpMethod method, string path, string body, CancellationToken cancellationToken)
            {
                using var request = new HttpRequestMessage(method, _url + path);
                if (body != null)
                {
                    request.Content = new StringContent(body, Encoding.UTF8);
                    request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
                }

                using var response = await _http.SendAsync(request, cancellationToken);
                var text = await response.Content.ReadAsStringAsync(cancellationToken);

                return response.IsSuccessStatusCode
                    ? new ApiResponse(response.StatusCode, text, null)
                    : new ApiResponse(response.StatusCode, null, Describe(response.StatusCode, response.ReasonPhrase, text));
            }

            /// <summary>
            /// Conjur's error message from an error response, e.g. {"error":{"code":"not_found","message":"..."}}
            /// </summary>
            private static string Describe(HttpStatusCode status, string reason, string text)
            {
                string message = null;
                try
                {
                    message = (string)JsonNode.Parse(text)?["error"]?["message"];
                }
                catch (JsonException)
                {
                    // not JSON, e.g. a proxy's error page
                }

                return $"{(message ?? $"{(int)status} {reason}").TrimEnd('.')}.";
            }

            public void Dispose() => _http.Dispose();
        }
    }
}
