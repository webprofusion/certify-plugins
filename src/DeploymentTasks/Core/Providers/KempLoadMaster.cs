using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Xml.Linq;
using Certify.Models;
using Certify.Models.Config;
using Certify.Shared.Core.Utils.PKI;

namespace Certify.Providers.DeploymentTasks
{
    /// <summary>
    /// Deploys a certificate to a Progress Kemp LoadMaster using the LoadMaster RESTful API (/access).
    /// The certificate is added (or replaced in place, keeping Virtual Service assignments) under a fixed name,
    /// and any intermediate certificates missing from the LoadMaster's intermediate store are added first.
    /// </summary>
    public class KempLoadMaster : IDeploymentTaskProvider
    {
        public static DeploymentProviderDefinition Definition { get; }
        public DeploymentProviderDefinition GetDefinition(DeploymentProviderDefinition currentDefinition = null) => (currentDefinition ?? Definition);

        // certificate names on the LoadMaster may only use these characters, and must not contain API parameter names
        private static readonly Regex ValidCertName = new Regex("^[A-Za-z0-9._-]{1,128}$", RegexOptions.Compiled);
        private static readonly string[] ReservedCertNameWords = { "ident", "cfile", "kfile", "ffile", "replace", "password" };

        private static readonly Regex PemCertBlock = new Regex("-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----", RegexOptions.Compiled);

        static KempLoadMaster()
        {
            Definition = new DeploymentProviderDefinition
            {
                Id = "Certify.Providers.DeploymentTasks.KempLoadMaster",
                Title = "Deploy to Kemp LoadMaster",
                IsExperimental = false,
                UsageType = DeploymentProviderUsage.PostRequest,
                SupportedContexts = DeploymentContextType.ExternalCredential,
                ExternalCredentialType = CredentialTypes.KempLoadMaster,
                Description = "Add or replace a named SSL certificate on a Progress Kemp LoadMaster using its API. Virtual Services using the certificate pick up the new one automatically.",
                ProviderParameters = new List<ProviderParameter>
                {
                    new ProviderParameter{ Key="lm_address", Name="LoadMaster Address", IsRequired=true, IsCredential=false, Type= OptionType.String, Description="Management address, e.g. https://192.168.1.10 or https://lm.example.com:8443" },
                    new ProviderParameter{ Key="cert_name", Name="Certificate Name", IsRequired=true, IsCredential=false, Type= OptionType.String, Description="Name of the certificate on the LoadMaster, e.g. www.example.com. An existing certificate with this name is replaced." },
                    new ProviderParameter{ Key="allow_invalid_tls", Name="Allow Untrusted LoadMaster Certificate", IsRequired=false, IsCredential=false, Type= OptionType.Boolean, Value="false", Description="Connect even if the LoadMaster management certificate is not trusted (e.g. the default self-signed certificate)." },
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
        /// Check the task settings. In preview, also sign in to the LoadMaster and report what deploying would change.
        /// </summary>
        public async Task<List<ActionResult>> Validate(DeploymentTaskExecutionParams execParams)
        {
            var results = new List<ActionResult>();
            var settings = GetSettings(execParams);

            if (string.IsNullOrWhiteSpace(settings.AddressText))
            {
                results.Add(new ActionResult("LoadMaster Address is required.", false));
            }
            else if (settings.Address == null)
            {
                results.Add(new ActionResult("LoadMaster Address must be a full URL, e.g. https://192.168.1.10", false));
            }

            if (string.IsNullOrWhiteSpace(settings.CertName))
            {
                results.Add(new ActionResult("Certificate Name is required.", false));
            }
            else if (!ValidCertName.IsMatch(settings.CertName))
            {
                results.Add(new ActionResult("Certificate Name may only contain letters, numbers, '.', '-' and '_'.", false));
            }
            else if (ReservedCertNameWords.Any(w => settings.CertName.Contains(w, StringComparison.OrdinalIgnoreCase)))
            {
                results.Add(new ActionResult($"Certificate Name cannot contain any of the words the LoadMaster reserves: {string.Join(", ", ReservedCertNameWords)}.", false));
            }

            if (SignIn.FromCredentials(execParams.Credentials) == null)
            {
                results.Add(new ActionResult("A Kemp LoadMaster API credential with an API key, or a username and password, is required.", false));
            }

            if (execParams.IsPreviewOnly && !results.Any(r => !r.IsSuccess))
            {
                results.AddRange(await Deploy(execParams, apply: false));
            }

            return results;
        }

        /// <summary>
        /// Sign in, compare the certificate and its intermediates with what the LoadMaster has, then (if applying) add or replace them
        /// </summary>
        private static async Task<List<ActionResult>> Deploy(DeploymentTaskExecutionParams execParams, bool apply)
        {
            var results = new List<ActionResult>();
            var settings = GetSettings(execParams);
            var log = execParams.Log;
            var cancellationToken = execParams.CancellationToken;

            var managedCert = ManagedCertificate.GetManagedCertificate(execParams.Subject);
            var hasCertificate = !string.IsNullOrEmpty(managedCert?.CertificatePath) && File.Exists(managedCert.CertificatePath);

            if (!hasCertificate && apply)
            {
                results.Add(new ActionResult("No certificate to deploy.", false));
                return results;
            }

            string certAndKeyPem = null;
            var intermediates = new List<(string Name, string Subject, string Pem)>();

            if (hasCertificate)
            {
                var pfxData = await File.ReadAllBytesAsync(managedCert.CertificatePath, cancellationToken);
                var pfxPwd = "";

                if (!string.IsNullOrWhiteSpace(managedCert.CertificatePasswordCredentialId))
                {
                    var pwdCred = await execParams.CredentialsManager.GetUnlockedCredentialsDictionary(managedCert.CertificatePasswordCredentialId);
                    if (pwdCred != null)
                    {
                        pfxPwd = pwdCred["password"];
                    }
                }

                certAndKeyPem = CertUtils.GetCertComponentsAsPEMString(pfxData, pfxPwd, ExportFlags.PrivateKey | ExportFlags.EndEntityCertificate);
                intermediates = GetIntermediates(pfxData, pfxPwd);
            }

            var signIn = SignIn.FromCredentials(execParams.Credentials);
            using var client = new LoadMasterClient(settings.Address, signIn, settings.AllowInvalidTls);

            try
            {
                var existingCerts = await client.ListNames("listcert", cancellationToken);
                var existingIntermediates = await client.ListNames("listintermediate", cancellationToken);

                var replace = existingCerts.Contains(settings.CertName, StringComparer.OrdinalIgnoreCase);
                var missingIntermediates = intermediates.Where(i => !existingIntermediates.Contains(i.Name, StringComparer.OrdinalIgnoreCase)).ToList();

                if (!apply)
                {
                    var preview = new StringBuilder($"Signed in to LoadMaster {settings.Address} using {signIn.Description}. ");

                    if (!hasCertificate)
                    {
                        preview.Append($"No certificate has been issued yet; certificate '{settings.CertName}' {(replace ? "exists and would be replaced" : "would be added")}.");
                    }
                    else
                    {
                        preview.Append(replace ? $"Would replace certificate '{settings.CertName}'" : $"Would add new certificate '{settings.CertName}'");

                        if (missingIntermediates.Any())
                        {
                            preview.Append($" and add {missingIntermediates.Count} intermediate certificate(s): {string.Join(", ", missingIntermediates.Select(i => i.Subject))}");
                        }

                        preview.Append('.');
                    }

                    results.Add(new ActionResult(preview.ToString(), true));
                    return results;
                }

                // add intermediates first so the chain is complete as soon as the certificate changes
                foreach (var intermediate in missingIntermediates)
                {
                    log?.Information($"Kemp LoadMaster: adding intermediate certificate {intermediate.Subject} as '{intermediate.Name}'");

                    var addIntermediate = await client.Post("addintermediate", new Dictionary<string, string> { { "cert", intermediate.Name } }, intermediate.Pem, cancellationToken);

                    if (!addIntermediate.IsSuccess)
                    {
                        // the same intermediate may already be present under another name, so this does not stop the certificate update
                        var msg = $"Kemp LoadMaster: could not add intermediate certificate {intermediate.Subject}: {addIntermediate.Message}";
                        log?.Warning(msg);
                        results.Add(new ActionResult(msg, true) { IsWarning = true });
                    }
                }

                log?.Information($"Kemp LoadMaster: {(replace ? "replacing" : "adding")} certificate '{settings.CertName}' on {settings.Address}");

                var addCert = await client.Post("addcert", new Dictionary<string, string> { { "cert", settings.CertName }, { "replace", replace ? "1" : "0" } }, certAndKeyPem, cancellationToken);

                if (!addCert.IsSuccess)
                {
                    results.Add(new ActionResult($"Kemp LoadMaster: failed to {(replace ? "replace" : "add")} certificate '{settings.CertName}': {addCert.Message}", false));
                    return results;
                }

                results.Add(new ActionResult($"Kemp LoadMaster: certificate '{settings.CertName}' {(replace ? "replaced" : "added")}. {(replace ? "" : "Assign it to the required Virtual Services on the LoadMaster.")}".Trim(), true));
                return results;
            }
            catch (LoadMasterApiException exp)
            {
                results.Add(new ActionResult($"Kemp LoadMaster: {exp.Message}", false));
                return results;
            }
            catch (HttpRequestException exp)
            {
                results.Add(new ActionResult($"Kemp LoadMaster: could not connect to {settings.Address}: {exp.Message}" + (settings.AllowInvalidTls ? "" : " If the LoadMaster uses a self-signed management certificate, enable 'Allow Untrusted LoadMaster Certificate'."), false));
                return results;
            }
            catch (TaskCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                results.Add(new ActionResult($"Kemp LoadMaster: request to {settings.Address} timed out.", false));
                return results;
            }
        }

        private static (string AddressText, Uri Address, string CertName, bool AllowInvalidTls) GetSettings(DeploymentTaskExecutionParams execParams)
        {
            var parameters = execParams.Settings.Parameters;
            var addressText = parameters.FirstOrDefault(c => c.Key == "lm_address")?.Value?.Trim();
            var certName = parameters.FirstOrDefault(c => c.Key == "cert_name")?.Value?.Trim();
            _ = bool.TryParse(parameters.FirstOrDefault(c => c.Key == "allow_invalid_tls")?.Value, out var allowInvalidTls);

            Uri address = null;
            if (Uri.TryCreate(addressText?.TrimEnd('/'), UriKind.Absolute, out var parsed) && (parsed.Scheme == Uri.UriSchemeHttps || parsed.Scheme == Uri.UriSchemeHttp))
            {
                address = parsed;
            }

            return (addressText, address, certName, allowInvalidTls);
        }

        /// <summary>
        /// Intermediate certificates from the PFX chain, named by thumbprint so the same intermediate is only ever added once
        /// </summary>
        private static List<(string Name, string Subject, string Pem)> GetIntermediates(byte[] pfxData, string pfxPwd)
        {
            var pem = CertUtils.GetCertComponentsAsPEMString(pfxData, pfxPwd, ExportFlags.IntermediateCertificates);

            return PemCertBlock.Matches(pem)
                .Select(m =>
                {
                    using var cert = X509Certificate2.CreateFromPem(m.Value);
                    return (Name: $"certify-ca-{cert.Thumbprint.ToLowerInvariant()}", Subject: cert.GetNameInfo(X509NameType.SimpleName, false), Pem: m.Value + "\n");
                })
                .ToList();
        }

        /// <summary>
        /// How to sign in to the LoadMaster API: an API key if the credential has one, otherwise basic authentication with username and password
        /// </summary>
        private sealed class SignIn
        {
            public string ApiKey { get; private init; }
            public string Username { get; private init; }
            public string Password { get; private init; }

            public bool UsesApiKey => ApiKey != null;
            public string Description => UsesApiKey ? "an API key" : $"user '{Username}'";

            public static SignIn FromCredentials(Dictionary<string, string> credentials)
            {
                string value(string key) => credentials != null && credentials.TryGetValue(key, out var v) && !string.IsNullOrWhiteSpace(v) ? v.Trim() : null;

                if (value("api_key") is string apiKey)
                {
                    return new SignIn { ApiKey = apiKey };
                }

                if (value("username") is string username && credentials.TryGetValue("password", out var password) && !string.IsNullOrEmpty(password))
                {
                    return new SignIn { Username = username, Password = password };
                }

                return null;
            }
        }

        private sealed class LoadMasterApiException : Exception
        {
            public LoadMasterApiException(string message) : base(message) { }
        }

        /// <summary>
        /// Minimal client for the LoadMaster RESTful API (/access/{command}), which returns XML: &lt;Response stat="200" code="ok"&gt;...
        /// </summary>
        private sealed class LoadMasterClient : IDisposable
        {
            private readonly HttpClient _http;
            private readonly SignIn _signIn;

            public LoadMasterClient(Uri address, SignIn signIn, bool allowInvalidTls)
            {
                _signIn = signIn;

                var handler = new HttpClientHandler();
                if (allowInvalidTls)
                {
                    handler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
                }

                _http = new HttpClient(handler)
                {
                    BaseAddress = new Uri(address.GetLeftPart(UriPartial.Authority) + "/access/"),
                    Timeout = TimeSpan.FromSeconds(60)
                };

                if (!signIn.UsesApiKey)
                {
                    _http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"{signIn.Username}:{signIn.Password}")));
                }
            }

            public async Task<List<string>> ListNames(string command, CancellationToken cancellationToken)
            {
                using var response = await _http.GetAsync(GetRequestUri(command, null), cancellationToken);
                var result = await ReadResult(command, response);

                if (!result.IsSuccess)
                {
                    throw new LoadMasterApiException(result.Message);
                }

                // <Success><Data><cert><name>example</name>...</cert>...</Data></Success>
                return result.Xml?.Descendants("cert").Select(c => c.Element("name")?.Value).Where(n => !string.IsNullOrEmpty(n)).ToList() ?? new List<string>();
            }

            public async Task<(bool IsSuccess, string Message, XDocument Xml)> Post(string command, Dictionary<string, string> query, string body, CancellationToken cancellationToken)
            {
                using var content = new ByteArrayContent(Encoding.ASCII.GetBytes(body));
                using var response = await _http.PostAsync(GetRequestUri(command, query), content, cancellationToken);

                return await ReadResult(command, response);
            }

            /// <summary>
            /// The classic API takes the API key as the apikey query parameter
            /// </summary>
            private string GetRequestUri(string command, Dictionary<string, string> query)
            {
                var parameters = new List<KeyValuePair<string, string>>();
                if (_signIn.UsesApiKey)
                {
                    parameters.Add(new KeyValuePair<string, string>("apikey", _signIn.ApiKey));
                }

                parameters.AddRange(query ?? new Dictionary<string, string>());

                return parameters.Any() ? command + "?" + string.Join("&", parameters.Select(q => $"{Uri.EscapeDataString(q.Key)}={Uri.EscapeDataString(q.Value)}")) : command;
            }

            private async Task<(bool IsSuccess, string Message, XDocument Xml)> ReadResult(string command, HttpResponseMessage response)
            {
                var body = await response.Content.ReadAsStringAsync();

                XDocument xml = null;
                try
                {
                    xml = XDocument.Parse(body);
                }
                catch (System.Xml.XmlException)
                {
                    // not an API response, e.g. the address is not a LoadMaster or the API interface is disabled
                }

                var root = xml?.Root;
                var error = root?.Element("Error")?.Value?.Trim();

                if (response.StatusCode == HttpStatusCode.Unauthorized || response.StatusCode == HttpStatusCode.Forbidden)
                {
                    var check = _signIn.UsesApiKey ? "the API key" : "the username and password";
                    throw new LoadMasterApiException($"access denied ({(int)response.StatusCode}{(string.IsNullOrEmpty(error) ? "" : ": " + error)}). Check {check}, that the user can manage certificates, and that the API interface is enabled (Certificates & Security > Remote Access).");
                }

                if (root == null || root.Name.LocalName != "Response")
                {
                    throw new LoadMasterApiException($"unexpected response to '{command}' (HTTP {(int)response.StatusCode}). Check the LoadMaster Address and that the API interface is enabled (Certificates & Security > Remote Access).");
                }

                if (string.Equals((string)root.Attribute("code"), "ok", StringComparison.OrdinalIgnoreCase))
                {
                    return (true, root.Element("Success")?.Value, xml);
                }

                return (false, string.IsNullOrWhiteSpace(error) ? $"'{command}' failed (HTTP {(int)response.StatusCode})" : error, xml);
            }

            public void Dispose() => _http.Dispose();
        }
    }
}
