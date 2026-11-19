using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Linq;
using Certify.Models;
using Certify.Models.Config;
using Certify.Providers.Deployment.Core.Shared;

namespace Certify.Providers.DeploymentTasks
{
    /// <summary>
    /// Deploys a certificate to a Palo Alto Networks firewall using the PAN-OS XML API, signing in with a username and password for an API key.
    /// The certificate and key are imported under a fixed name, replacing the previous certificate in place so the settings that use it
    /// (SSL/TLS service profiles, decryption etc) pick it up, then the changes made by this administrator are committed.
    /// </summary>
    public class PaloAlto : IDeploymentTaskProvider
    {
        public static DeploymentProviderDefinition Definition { get; }
        public DeploymentProviderDefinition GetDefinition(DeploymentProviderDefinition currentDefinition = null) => (currentDefinition ?? Definition);

        private static readonly Regex ValidName = new Regex("^[A-Za-z0-9_][A-Za-z0-9_.-]{0,62}$", RegexOptions.Compiled);
        private static readonly Regex ValidVsys = new Regex("^vsys[0-9]{1,3}$", RegexOptions.Compiled);
        private static readonly Regex PemCertBlock = new Regex("-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----", RegexOptions.Compiled);

        // commits of a large configuration can take several minutes
        private static readonly TimeSpan CommitTimeout = TimeSpan.FromMinutes(20);

        static PaloAlto()
        {
            Definition = new DeploymentProviderDefinition
            {
                Id = "Certify.Providers.DeploymentTasks.PaloAlto",
                Title = "Deploy to Palo Alto Networks Firewall",
                IsExperimental = false,
                UsageType = DeploymentProviderUsage.PostRequest,
                SupportedContexts = DeploymentContextType.ExternalCredential,
                ExternalCredentialType = StandardAuthTypes.STANDARD_AUTH_GENERIC,
                Description = "Import the certificate to a Palo Alto Networks firewall (PAN-OS) using the XML API, replacing the named certificate, then commit the change. Settings which use the certificate, such as SSL/TLS service profiles, pick up each renewal.",
                ProviderParameters = new List<ProviderParameter>
                {
                    new ProviderParameter{ Key="panos_address", Name="Firewall Address", IsRequired=true, IsCredential=false, Type= OptionType.String, Description="Management address, e.g. https://192.168.1.1 or https://fw.example.com" },
                    new ProviderParameter{ Key="cert_name", Name="Certificate Name", IsRequired=true, IsCredential=false, Type= OptionType.String, Description="Name of the certificate on the firewall, e.g. www.example.com. It is added if it doesn't exist, otherwise replaced." },
                    new ProviderParameter{ Key="vsys", Name="Virtual System", IsRequired=false, IsCredential=false, Type= OptionType.String, Description="Leave blank to import to Shared. On a firewall with multiple virtual systems, the virtual system to import into instead, e.g. vsys1." },
                    new ProviderParameter{ Key="allow_invalid_tls", Name="Allow Untrusted Firewall Certificate", IsRequired=false, IsCredential=false, Type= OptionType.Boolean, Value="false", Description="Connect even if the firewall management certificate is not trusted (e.g. the default self-signed certificate)." },
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
        /// Check the task settings. In preview, also sign in to the firewall and report what deploying would change.
        /// </summary>
        public async Task<List<ActionResult>> Validate(DeploymentTaskExecutionParams execParams)
        {
            var results = new List<ActionResult>();
            var settings = GetSettings(execParams);

            NetworkDevice.ValidateAddress(settings.AddressText, "Firewall Address", results);

            if (string.IsNullOrWhiteSpace(settings.CertName))
            {
                results.Add(new ActionResult("Certificate Name is required.", false));
            }
            else if (!ValidName.IsMatch(settings.CertName))
            {
                results.Add(new ActionResult("Certificate Name may only contain letters, numbers, '.', '-' and '_', up to 63 characters.", false));
            }

            if (settings.Vsys != null && !ValidVsys.IsMatch(settings.Vsys))
            {
                results.Add(new ActionResult("Virtual System must be blank (Shared) or a virtual system ID, e.g. vsys1.", false));
            }

            if (GetCredentials(execParams) == null)
            {
                results.Add(new ActionResult("A username and password credential for the firewall is required.", false));
            }

            if (execParams.IsPreviewOnly && !results.Any(r => !r.IsSuccess))
            {
                results.AddRange(await Deploy(execParams, apply: false));
            }

            return results;
        }

        /// <summary>
        /// Sign in and check the running certificate, then (if applying) import the certificate and key and commit
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
            var location = settings.Vsys == null ? "Shared" : $"virtual system {settings.Vsys}";
            var imported = false;

            using var client = new PanOsClient(settings.Address, settings.AllowInvalidTls);

            string failure(string message) => imported
                ? $"Palo Alto: certificate '{settings.CertName}' was imported, but committing it failed, so the firewall isn't using it yet: {message}"
                : $"Palo Alto: {message}";

            try
            {
                await client.SignIn(username, password, cancellationToken);

                var existing = await client.GetRunningCertificate(settings.CertName, settings.Vsys, cancellationToken);
                var upToDate = cert != null && existing != null && existing.HasPrivateKey && existing.Thumbprint == Thumbprint(cert.CertPem);

                if (!apply)
                {
                    var preview = new StringBuilder($"Connected to firewall {settings.Address} as '{username}'. ");
                    if (upToDate)
                    {
                        preview.Append($"Certificate '{settings.CertName}' in {location} is already this certificate, so deploying would change nothing.");
                    }
                    else
                    {
                        preview.Append(cert == null ? "No certificate has been issued yet. Deploying would " : "Would ");
                        preview.Append(existing != null ? $"replace certificate '{settings.CertName}' in {location}" : $"add certificate '{settings.CertName}' to {location}");
                        preview.Append($", then commit the changes made by '{username}'.");
                    }

                    results.Add(new ActionResult(preview.ToString(), true));
                    return results;
                }

                if (upToDate)
                {
                    results.Add(new ActionResult($"Palo Alto: certificate '{settings.CertName}' in {location} is already up to date.", true));
                    return results;
                }

                log?.Information($"Palo Alto: importing certificate '{settings.CertName}' to {location} on {settings.Address}");

                // the key and certificate with its chain in one file, so the key and certificate change together
                var import = await client.ImportKeyPair(settings.CertName, settings.Vsys, cert.KeyPem + cert.CertPem + string.Concat(cert.Intermediates.Select(i => i.Pem)), cancellationToken);
                if (!import.IsSuccess)
                {
                    results.Add(new ActionResult($"Palo Alto: failed to import certificate '{settings.CertName}', nothing was changed: {import.Message}", false));
                    return results;
                }

                imported = true;
                log?.Information($"Palo Alto: committing changes made by '{username}'");

                var commit = await client.Commit(username, CommitTimeout, cancellationToken);
                if (!commit.IsSuccess)
                {
                    results.Add(new ActionResult(failure(commit.Message), false));
                    return results;
                }

                var done = new StringBuilder($"Palo Alto: {(existing != null ? $"replaced certificate '{settings.CertName}' in" : $"added certificate '{settings.CertName}' to")} {location} and committed the change.");
                if (existing == null)
                {
                    done.Append(" Select it where it should be used on the firewall, for example in an SSL/TLS service profile. Later renewals replace it in place.");
                }

                results.Add(new ActionResult(done.ToString(), true));
                return results;
            }
            catch (PanOsApiException exp)
            {
                results.Add(new ActionResult(failure(exp.Message), false));
                return results;
            }
            catch (HttpRequestException exp)
            {
                results.Add(new ActionResult(failure($"could not connect to {settings.Address}: {exp.Message}" + NetworkDevice.ConnectionFailureHint(settings.AllowInvalidTls, "Allow Untrusted Firewall Certificate")), false));
                return results;
            }
            catch (TaskCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                results.Add(new ActionResult(failure($"request to {settings.Address} timed out."), false));
                return results;
            }
        }

        /// <summary>
        /// SHA-1 thumbprint of the first certificate in PEM text, or null if there isn't one
        /// </summary>
        private static string Thumbprint(string pem)
        {
            var block = PemCertBlock.Match(pem ?? "");
            if (!block.Success)
            {
                return null;
            }

            try
            {
                using var cert = X509Certificate2.CreateFromPem(block.Value);
                return cert.Thumbprint;
            }
            catch (CryptographicException)
            {
                return null;
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

        private static (string AddressText, Uri Address, string CertName, string Vsys, bool AllowInvalidTls) GetSettings(DeploymentTaskExecutionParams execParams)
        {
            var parameters = execParams.Settings.Parameters;
            var addressText = parameters.FirstOrDefault(c => c.Key == "panos_address")?.Value?.Trim();
            var certName = parameters.FirstOrDefault(c => c.Key == "cert_name")?.Value?.Trim();
            var vsys = parameters.FirstOrDefault(c => c.Key == "vsys")?.Value?.Trim();
            _ = bool.TryParse(parameters.FirstOrDefault(c => c.Key == "allow_invalid_tls")?.Value, out var allowInvalidTls);

            return (addressText, NetworkDevice.ParseAddress(addressText), certName, string.IsNullOrEmpty(vsys) ? null : vsys, allowInvalidTls);
        }

        private sealed record RunningCertificate(string Thumbprint, bool HasPrivateKey);

        private sealed class PanOsApiException : Exception
        {
            public PanOsApiException(string message) : base(message) { }
        }

        private sealed record PanOsResult(bool IsSuccess, string Code, string Message, XElement Body);

        /// <summary>
        /// Minimal client for the PAN-OS XML API (/api/). Every request is a POST, so the password and API key are never in a URL.
        /// Responses are XML: &lt;response status="success" | "error" code="..."&gt;&lt;result&gt;...&lt;/result&gt;&lt;msg&gt;...&lt;/msg&gt;&lt;/response&gt;
        /// </summary>
        private sealed class PanOsClient : IDisposable
        {
            private readonly HttpClient _http;
            private string _apiKey;

            public PanOsClient(Uri address, bool allowInvalidTls)
            {
                _http = NetworkDevice.CreateHttpClient(new Uri(address.GetLeftPart(UriPartial.Authority) + "/api/"), allowInvalidTls);
            }

            public async Task SignIn(string username, string password, CancellationToken cancellationToken)
            {
                var result = await Send(new Dictionary<string, string> { ["type"] = "keygen", ["user"] = username, ["password"] = password }, cancellationToken);
                _apiKey = result.IsSuccess ? result.Body.Descendants("key").FirstOrDefault()?.Value?.Trim() : null;

                if (string.IsNullOrEmpty(_apiKey))
                {
                    throw new PanOsApiException($"could not sign in: {result.Message ?? "no API key was returned"}");
                }
            }

            /// <summary>
            /// The certificate of that name in the running configuration, or null if there isn't one
            /// </summary>
            public async Task<RunningCertificate> GetRunningCertificate(string name, string vsys, CancellationToken cancellationToken)
            {
                var location = vsys == null ? "/config/shared" : $"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='{vsys}']";

                var result = await Send(new Dictionary<string, string> { ["type"] = "config", ["action"] = "show", ["xpath"] = $"{location}/certificate/entry[@name='{name}']" }, cancellationToken);
                if (!result.IsSuccess)
                {
                    // code 7: no such object
                    if (result.Code == "7")
                    {
                        return null;
                    }

                    throw new PanOsApiException($"could not read certificate '{name}': {result.Message}");
                }

                var entry = result.Body.Descendants("entry").FirstOrDefault(e => (string)e.Attribute("name") == name);
                return entry == null ? null : new RunningCertificate(Thumbprint(entry.Element("public-key")?.Value), !string.IsNullOrWhiteSpace(entry.Element("private-key")?.Value));
            }

            /// <summary>
            /// Import a PEM file of the private key, certificate and chain to the candidate configuration, replacing any certificate of that name.
            /// PAN-OS requires a passphrase, which is not used as the key is not encrypted.
            /// </summary>
            public async Task<PanOsResult> ImportKeyPair(string name, string vsys, string pem, CancellationToken cancellationToken)
            {
                var query = $"?type=import&category=keypair&certificate-name={Uri.EscapeDataString(name)}&format=pem{(vsys != null ? "&vsys=" + Uri.EscapeDataString(vsys) : "")}";

                var fields = new Dictionary<string, string>
                {
                    ["key"] = _apiKey,
                    ["passphrase"] = Convert.ToHexString(RandomNumberGenerator.GetBytes(16))
                };

                // built by hand, as PAN-OS does not accept the quoted boundary HttpClient's MultipartFormDataContent uses
                var boundary = "certify" + Guid.NewGuid().ToString("N");
                var body = new StringBuilder();
                foreach (var (field, value) in fields)
                {
                    body.Append($"--{boundary}\r\nContent-Disposition: form-data; name=\"{field}\"\r\n\r\n{value}\r\n");
                }

                body.Append($"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}.pem\"\r\nContent-Type: application/octet-stream\r\n\r\n{pem}\r\n--{boundary}--\r\n");

                using var content = new ByteArrayContent(Encoding.ASCII.GetBytes(body.ToString()));
                content.Headers.TryAddWithoutValidation("Content-Type", $"multipart/form-data; boundary={boundary}");

                return await Post(query, content, cancellationToken);
            }

            /// <summary>
            /// Commit the changes made by this administrator (not other administrators' pending changes), and wait for the commit job to finish
            /// </summary>
            public async Task<PanOsResult> Commit(string admin, TimeSpan timeout, CancellationToken cancellationToken)
            {
                var result = await Send(new Dictionary<string, string>
                {
                    ["type"] = "commit",
                    ["action"] = "partial",
                    ["cmd"] = $"<commit><partial><admin><member>{SecurityElement.Escape(admin)}</member></admin></partial></commit>"
                }, cancellationToken);

                var jobId = result.Body?.Descendants("job").FirstOrDefault()?.Value?.Trim();
                if (!result.IsSuccess || string.IsNullOrEmpty(jobId))
                {
                    // without a job there was nothing to commit
                    return result;
                }

                var deadline = DateTime.UtcNow + timeout;
                var delay = TimeSpan.Zero;

                while (true)
                {
                    await Task.Delay(delay, cancellationToken);
                    delay = TimeSpan.FromSeconds(Math.Clamp(delay.TotalSeconds * 2, 1, 5));

                    PanOsResult status;
                    try
                    {
                        status = await Send(new Dictionary<string, string> { ["type"] = "op", ["cmd"] = $"<show><jobs><id>{SecurityElement.Escape(jobId)}</id></jobs></show>" }, cancellationToken);
                    }
                    catch (Exception exp) when ((exp is HttpRequestException || (exp is TaskCanceledException && !cancellationToken.IsCancellationRequested)) && DateTime.UtcNow < deadline)
                    {
                        // the management web server restarts when the commit changes its own certificate
                        continue;
                    }

                    if (!status.IsSuccess)
                    {
                        return status with { Message = $"could not check commit job {jobId}: {status.Message}" };
                    }

                    var job = status.Body.Descendants("job").FirstOrDefault();
                    var state = job?.Element("status")?.Value?.Trim();
                    if (state == "FIN" || state == "FAIL")
                    {
                        if (job.Element("result")?.Value?.Trim() == "OK")
                        {
                            return status;
                        }

                        var details = job.Element("details")?.Descendants("line").Select(l => l.Value.Trim()).Where(l => l.Length > 0).ToList() ?? new List<string>();
                        return new PanOsResult(false, null, $"commit job {jobId} failed{(details.Any() ? ": " + string.Join("; ", details) : ".")}", status.Body);
                    }

                    if (job == null)
                    {
                        return new PanOsResult(false, null, $"commit job {jobId} was not found.", status.Body);
                    }

                    if (DateTime.UtcNow >= deadline)
                    {
                        return new PanOsResult(false, null, $"commit job {jobId} was still running after {timeout.TotalMinutes} minutes. Check its result under Tasks on the firewall.", status.Body);
                    }
                }
            }

            private Task<PanOsResult> Send(Dictionary<string, string> fields, CancellationToken cancellationToken)
            {
                if (_apiKey != null)
                {
                    fields["key"] = _apiKey;
                }

                return Post("", new FormUrlEncodedContent(fields), cancellationToken);
            }

            private async Task<PanOsResult> Post(string query, HttpContent content, CancellationToken cancellationToken)
            {
                using var response = await _http.PostAsync(query, content, cancellationToken);
                var text = await response.Content.ReadAsStringAsync();

                XElement root = null;
                try
                {
                    root = string.IsNullOrWhiteSpace(text) ? null : XDocument.Parse(text).Root;
                }
                catch (XmlException)
                {
                    // not a PAN-OS API response, e.g. the address is not the firewall management interface
                }

                var accessDenied = response.StatusCode == HttpStatusCode.Unauthorized || response.StatusCode == HttpStatusCode.Forbidden;

                if (root?.Name != "response")
                {
                    if (accessDenied)
                    {
                        throw AccessDenied($"HTTP {(int)response.StatusCode}");
                    }

                    throw new PanOsApiException($"unexpected response from the XML API (HTTP {(int)response.StatusCode}). Check the Firewall Address is the management address, and that the XML API is enabled.");
                }

                var code = (string)root.Attribute("code");
                if (response.IsSuccessStatusCode && (string)root.Attribute("status") == "success")
                {
                    return new PanOsResult(true, code, null, root);
                }

                var lines = root.Descendants("line").Select(l => l.Value.Trim()).Where(l => l.Length > 0).ToList();
                var message = lines.Any() ? string.Join("; ", lines) : (root.Descendants("msg").FirstOrDefault()?.Value ?? root.Value).Trim();
                if (string.IsNullOrEmpty(message))
                {
                    message = $"HTTP {(int)response.StatusCode}";
                }

                if (accessDenied || code == "403")
                {
                    throw AccessDenied(message);
                }

                return new PanOsResult(false, code, message, root);
            }

            private static PanOsApiException AccessDenied(string detail)
                => new PanOsApiException($"access denied ({detail}). Check the username and password, and that the administrator's role allows the XML API for Configuration, Operational Requests, Commit and Import.");

            public void Dispose() => _http.Dispose();
        }
    }
}
