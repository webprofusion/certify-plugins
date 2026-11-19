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
    /// Deploys a certificate to a NetScaler ADC (formerly Citrix ADC) using the NITRO REST API.
    /// The key and certificate are uploaded to /nsconfig/ssl as new files, then the named certificate-key pair is updated to use them
    /// (or added), which keeps its virtual server bindings. Intermediates are added as their own certificate-key pairs and linked,
    /// then the configuration is saved.
    /// </summary>
    public class NetScaler : IDeploymentTaskProvider
    {
        public static DeploymentProviderDefinition Definition { get; }
        public DeploymentProviderDefinition GetDefinition(DeploymentProviderDefinition currentDefinition = null) => (currentDefinition ?? Definition);

        private const string SslFolder = "/nsconfig/ssl";

        // NetScaler entity names: start with a letter, number or underscore, then letters, numbers and _ # . space : @ = -
        private static readonly Regex ValidCertKeyName = new Regex("^[A-Za-z0-9_][A-Za-z0-9_#. :@=-]{0,62}$", RegexOptions.Compiled);

        static NetScaler()
        {
            Definition = new DeploymentProviderDefinition
            {
                Id = "Certify.Providers.DeploymentTasks.NetScaler",
                Title = "Deploy to NetScaler ADC",
                IsExperimental = false,
                UsageType = DeploymentProviderUsage.PostRequest,
                SupportedContexts = DeploymentContextType.ExternalCredential,
                ExternalCredentialType = StandardAuthTypes.STANDARD_AUTH_GENERIC,
                RequiresManagementHub = true,
                Description = "Add or update a named certificate-key pair on a NetScaler ADC (Citrix ADC) using the NITRO API. Virtual servers bound to it pick up the new certificate automatically.",
                ProviderParameters = new List<ProviderParameter>
                {
                    new ProviderParameter{ Key="ns_address", Name="NetScaler Address", IsRequired=true, IsCredential=false, Type= OptionType.String, Description="Management address (NSIP), e.g. https://192.168.1.10" },
                    new ProviderParameter{ Key="certkey_name", Name="Certificate-Key Pair Name", IsRequired=true, IsCredential=false, Type= OptionType.String, Description="Name of the certificate-key pair on the NetScaler, e.g. www_example_com. An existing pair with this name is updated." },
                    new ProviderParameter{ Key="save_config", Name="Save Configuration", IsRequired=false, IsCredential=false, Type= OptionType.Boolean, Value="true", Description="Save the running configuration afterwards, so the change survives a restart. This also saves any other unsaved changes." },
                    new ProviderParameter{ Key="allow_invalid_tls", Name="Allow Untrusted NetScaler Certificate", IsRequired=false, IsCredential=false, Type= OptionType.Boolean, Value="false", Description="Connect even if the NetScaler management certificate is not trusted (e.g. the default self-signed certificate)." },
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
        /// Check the task settings. In preview, also sign in to the NetScaler and report what deploying would change.
        /// </summary>
        public async Task<List<ActionResult>> Validate(DeploymentTaskExecutionParams execParams)
        {
            var results = new List<ActionResult>();
            var settings = GetSettings(execParams);

            NetworkDevice.ValidateAddress(settings.AddressText, "NetScaler Address", results);

            if (string.IsNullOrWhiteSpace(settings.CertKeyName))
            {
                results.Add(new ActionResult("Certificate-Key Pair Name is required.", false));
            }
            else if (!ValidCertKeyName.IsMatch(settings.CertKeyName))
            {
                results.Add(new ActionResult("Certificate-Key Pair Name must start with a letter, number or underscore, and may only contain letters, numbers, spaces and _ # . : @ = - (up to 63 characters).", false));
            }

            if (GetCredentials(execParams) == null)
            {
                results.Add(new ActionResult("A NetScaler username and password credential is required.", false));
            }

            if (execParams.IsPreviewOnly && !results.Any(r => !r.IsSuccess))
            {
                results.AddRange(await Deploy(execParams, apply: false));
            }

            return results;
        }

        /// <summary>
        /// Sign in, compare the certificate and its intermediates with what the NetScaler has, then (if applying) upload, update, link and save
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
            using var client = new NitroClient(settings.Address, username, password, settings.AllowInvalidTls);

            try
            {
                var certKeys = await client.ListCertKeys(cancellationToken);
                certKeys.TryGetValue(settings.CertKeyName, out var existing);

                // intermediates are named by thumbprint, kept within the 31 character limit of older NetScaler versions
                var chain = (cert?.Intermediates ?? new List<DeviceCaCertificate>())
                    .Select(i => (Name: $"certify-ca-{i.Thumbprint[..16]}", i.Subject, i.Pem))
                    .ToList();
                var missingIntermediates = chain.Where(i => !certKeys.ContainsKey(i.Name)).ToList();

                if (!apply)
                {
                    var preview = new StringBuilder($"Signed in to NetScaler {settings.Address} as '{username}'. ");

                    if (cert == null)
                    {
                        preview.Append($"No certificate has been issued yet; certificate-key pair '{settings.CertKeyName}' {(existing != null ? "exists and would be updated" : "would be added")}.");
                    }
                    else
                    {
                        preview.Append(existing != null ? $"Would update certificate-key pair '{settings.CertKeyName}'" : $"Would add new certificate-key pair '{settings.CertKeyName}'");

                        if (missingIntermediates.Any())
                        {
                            preview.Append($", add {missingIntermediates.Count} intermediate certificate(s): {string.Join(", ", missingIntermediates.Select(i => i.Subject))}");
                        }

                        preview.Append(settings.SaveConfig ? " and save the configuration." : ". The configuration would not be saved.");
                    }

                    results.Add(new ActionResult(preview.ToString(), true));
                    return results;
                }

                // add intermediates first so they can be linked as soon as the certificate changes
                foreach (var intermediate in missingIntermediates)
                {
                    log?.Information($"NetScaler: adding intermediate certificate {intermediate.Subject} as '{intermediate.Name}'");

                    var file = intermediate.Name + ".crt";
                    var upload = await client.UploadFile(file, intermediate.Pem, cancellationToken);
                    var add = upload.IsSuccess || upload.AlreadyExists
                        ? await client.Post("sslcertkey", null, new JsonObject { ["certkey"] = intermediate.Name, ["cert"] = file, ["inform"] = "PEM" }, cancellationToken)
                        : upload;

                    if (add.IsSuccess || add.AlreadyExists)
                    {
                        certKeys[intermediate.Name] = new CertKey(intermediate.Name, file, null, null);
                    }
                    else
                    {
                        // the same intermediate may already be installed under another name, so carry on; links to it are skipped below
                        var msg = $"NetScaler: could not add intermediate certificate {intermediate.Subject}: {add.Message}";
                        log?.Warning(msg);
                        results.Add(new ActionResult(msg, true) { IsWarning = true });
                    }
                }

                // upload the certificate and key as new files, so the files currently in use are never overwritten
                var fileBase = GetFileBase(settings.CertKeyName);
                var stamp = DateTime.UtcNow.ToString("yyyyMMdd-HHmmssfff");
                var certFile = $"{fileBase}-{stamp}.crt";
                var keyFile = $"{fileBase}-{stamp}.key";
                var uploaded = new List<string>();

                foreach (var (file, content) in new[] { (certFile, cert.CertPem), (keyFile, cert.KeyPem) })
                {
                    var upload = await client.UploadFile(file, content, cancellationToken);
                    if (!upload.IsSuccess)
                    {
                        results.Add(new ActionResult($"NetScaler: failed to upload {file} to {SslFolder}: {upload.Message}", false));
                        await DeleteFiles(client, uploaded, cancellationToken);
                        return results;
                    }

                    uploaded.Add(file);
                }

                log?.Information($"NetScaler: {(existing != null ? "updating" : "adding")} certificate-key pair '{settings.CertKeyName}' on {settings.Address}");

                var certKey = new JsonObject { ["certkey"] = settings.CertKeyName, ["cert"] = certFile, ["key"] = keyFile, ["inform"] = "PEM" };
                if (existing != null)
                {
                    // the update action changes the files of the pair in place, keeping its bindings
                    certKey["nodomaincheck"] = true;
                }

                var update = await client.Post("sslcertkey", existing != null ? "update" : null, certKey, cancellationToken);
                if (!update.IsSuccess)
                {
                    results.Add(new ActionResult($"NetScaler: failed to {(existing != null ? "update" : "add")} certificate-key pair '{settings.CertKeyName}': {update.Message}", false));
                    await DeleteFiles(client, uploaded, cancellationToken);
                    return results;
                }

                // link each certificate in the chain to its issuer: the certificate to the first intermediate, that to the next and so on.
                // Pairs for intermediates which could not be added (already warned about) are skipped, leaving any existing link in place.
                var linkFailed = false;
                var links = new[] { settings.CertKeyName }.Concat(chain.Select(i => i.Name)).Zip(chain.Select(i => i.Name));
                foreach (var (from, to) in links)
                {
                    if (!certKeys.ContainsKey(to) || (from != settings.CertKeyName && !certKeys.ContainsKey(from)))
                    {
                        continue;
                    }

                    var current = certKeys.GetValueOrDefault(from)?.LinkedTo;
                    if (current == to)
                    {
                        continue;
                    }

                    if (!string.IsNullOrEmpty(current))
                    {
                        await client.Post("sslcertkey", "unlink", new JsonObject { ["certkey"] = from }, cancellationToken);
                    }

                    var link = await client.Post("sslcertkey", "link", new JsonObject { ["certkey"] = from, ["linkcertkeyname"] = to }, cancellationToken);
                    if (!link.IsSuccess)
                    {
                        linkFailed = true;
                        results.Add(new ActionResult($"NetScaler: certificate-key pair '{settings.CertKeyName}' was {(existing != null ? "updated" : "added")}, but '{from}' could not be linked to its issuer '{to}', so clients may not receive the full certificate chain: {link.Message}", false));
                    }
                }

                if (settings.SaveConfig)
                {
                    var save = await client.Post("nsconfig", "save", new JsonObject(), cancellationToken);
                    if (!save.IsSuccess)
                    {
                        // the saved configuration still refers to the previous files, so they are kept
                        results.Add(new ActionResult($"NetScaler: the certificate is in use, but saving the configuration failed, so the change will be lost when the NetScaler restarts: {save.Message}", false));
                        return results;
                    }
                }

                // remove the files this task uploaded for the previous certificate, now nothing uses them
                if (existing != null)
                {
                    var previousFiles = new[] { existing.CertFile, existing.KeyFile }
                        .Where(f => f != null && f != certFile && f != keyFile && IsUploadedFile(fileBase, f))
                        .ToList();

                    foreach (var file in previousFiles)
                    {
                        var delete = await client.DeleteFile(file, cancellationToken);
                        if (!delete.IsSuccess)
                        {
                            results.Add(new ActionResult($"NetScaler: could not remove previous file {SslFolder}/{file}: {delete.Message}", true) { IsWarning = true });
                        }
                    }
                }

                if (!linkFailed)
                {
                    results.Add(new ActionResult($"NetScaler: certificate-key pair '{settings.CertKeyName}' {(existing != null ? "updated" : "added")}{(settings.SaveConfig ? " and configuration saved" : "")}. {(existing != null ? "" : "Bind it to the required virtual servers on the NetScaler.")}".Trim(), true));
                }

                return results;
            }
            catch (NitroApiException exp)
            {
                results.Add(new ActionResult($"NetScaler: {exp.Message}", false));
                return results;
            }
            catch (HttpRequestException exp)
            {
                results.Add(new ActionResult($"NetScaler: could not connect to {settings.Address}: {exp.Message}" + NetworkDevice.ConnectionFailureHint(settings.AllowInvalidTls, "Allow Untrusted NetScaler Certificate"), false));
                return results;
            }
            catch (TaskCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                results.Add(new ActionResult($"NetScaler: request to {settings.Address} timed out.", false));
                return results;
            }
        }

        private static async Task DeleteFiles(NitroClient client, IEnumerable<string> files, CancellationToken cancellationToken)
        {
            foreach (var file in files)
            {
                await client.DeleteFile(file, cancellationToken);
            }
        }

        /// <summary>
        /// Start of the names of the files uploaded for a certificate-key pair: the pair name using only file name safe characters
        /// </summary>
        private static string GetFileBase(string certKeyName)
        {
            var safe = Regex.Replace(certKeyName, "[^A-Za-z0-9_.-]", "_");
            return safe.Length > 40 ? safe[..40] : safe;
        }

        /// <summary>
        /// True if a file name is one this task uploads for the pair: {base}-{yyyyMMdd}-{HHmmssfff}.crt or .key
        /// </summary>
        private static bool IsUploadedFile(string fileBase, string file) => Regex.IsMatch(file, $"^{Regex.Escape(fileBase)}-\\d{{8}}-\\d{{9}}\\.(crt|key)$");

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

        private static (string AddressText, Uri Address, string CertKeyName, bool SaveConfig, bool AllowInvalidTls) GetSettings(DeploymentTaskExecutionParams execParams)
        {
            var parameters = execParams.Settings.Parameters;
            var addressText = parameters.FirstOrDefault(c => c.Key == "ns_address")?.Value?.Trim();
            var certKeyName = parameters.FirstOrDefault(c => c.Key == "certkey_name")?.Value?.Trim();

            // save by default, including for tasks saved before the setting existed
            var saveConfig = !bool.TryParse(parameters.FirstOrDefault(c => c.Key == "save_config")?.Value, out var save) || save;
            _ = bool.TryParse(parameters.FirstOrDefault(c => c.Key == "allow_invalid_tls")?.Value, out var allowInvalidTls);

            return (addressText, NetworkDevice.ParseAddress(addressText), certKeyName, saveConfig, allowInvalidTls);
        }

        private sealed record CertKey(string Name, string CertFile, string KeyFile, string LinkedTo);

        private sealed class NitroApiException : Exception
        {
            public NitroApiException(string message) : base(message) { }
        }

        private sealed record NitroResult(bool IsSuccess, bool AlreadyExists, string Message, JsonNode Body);

        /// <summary>
        /// Minimal client for the NITRO configuration API (/nitro/v1/config), authenticating each request with the X-NITRO-USER and X-NITRO-PASS headers.
        /// Responses are JSON: { "errorcode": 0, "message": "Done", ... }
        /// </summary>
        private sealed class NitroClient : IDisposable
        {
            private readonly HttpClient _http;

            public NitroClient(Uri address, string username, string password, bool allowInvalidTls)
            {
                _http = NetworkDevice.CreateHttpClient(new Uri(address.GetLeftPart(UriPartial.Authority) + "/nitro/v1/config/"), allowInvalidTls);
                _http.DefaultRequestHeaders.TryAddWithoutValidation("X-NITRO-USER", username);
                _http.DefaultRequestHeaders.TryAddWithoutValidation("X-NITRO-PASS", password);
            }

            /// <summary>
            /// All certificate-key pairs, by name
            /// </summary>
            public async Task<Dictionary<string, CertKey>> ListCertKeys(CancellationToken cancellationToken)
            {
                using var response = await _http.GetAsync("sslcertkey", cancellationToken);
                var result = await ReadResult("sslcertkey", response);

                if (!result.IsSuccess)
                {
                    throw new NitroApiException($"could not list certificate-key pairs: {result.Message}");
                }

                static string fileName(JsonNode path) => path?.GetValue<string>() is string p && p.Length > 0 ? p[(p.LastIndexOf('/') + 1)..] : null;

                return (result.Body?["sslcertkey"] as JsonArray ?? new JsonArray())
                    .Where(c => c?["certkey"] != null)
                    .Select(c => new CertKey(c["certkey"].GetValue<string>(), fileName(c["cert"]), fileName(c["key"]), c["linkcertkeyname"]?.GetValue<string>()))
                    .ToDictionary(c => c.Name, StringComparer.Ordinal);
            }

            public async Task<NitroResult> UploadFile(string fileName, string content, CancellationToken cancellationToken)
            {
                var file = new JsonObject
                {
                    ["filename"] = fileName,
                    ["filelocation"] = SslFolder,
                    ["filecontent"] = Convert.ToBase64String(Encoding.ASCII.GetBytes(content)),
                    ["fileencoding"] = "BASE64"
                };

                return await Post("systemfile", null, file, cancellationToken);
            }

            public async Task<NitroResult> DeleteFile(string fileName, CancellationToken cancellationToken)
            {
                using var response = await _http.DeleteAsync($"systemfile/{Uri.EscapeDataString(fileName)}?args=filelocation:{Uri.EscapeDataString(SslFolder)}", cancellationToken);
                return await ReadResult("systemfile", response);
            }

            /// <summary>
            /// POST { resource: properties } to the resource, optionally as an action (e.g. ?action=update)
            /// </summary>
            public async Task<NitroResult> Post(string resource, string action, JsonObject properties, CancellationToken cancellationToken)
            {
                var body = new JsonObject { [resource] = properties };
                using var content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json");
                using var response = await _http.PostAsync(action == null ? resource : $"{resource}?action={action}", content, cancellationToken);

                return await ReadResult(resource, response);
            }

            private static async Task<NitroResult> ReadResult(string resource, HttpResponseMessage response)
            {
                var text = await response.Content.ReadAsStringAsync();

                JsonNode body = null;
                try
                {
                    body = string.IsNullOrWhiteSpace(text) ? null : JsonNode.Parse(text);
                }
                catch (System.Text.Json.JsonException)
                {
                    // not a NITRO response, e.g. the address is not a NetScaler management interface
                }

                var message = body?["message"]?.GetValue<string>()?.Trim();
                var errorCode = body?["errorcode"]?.GetValue<int>() ?? 0;

                if (response.StatusCode == HttpStatusCode.Unauthorized || response.StatusCode == HttpStatusCode.Forbidden)
                {
                    throw new NitroApiException($"access denied ({(int)response.StatusCode}{(string.IsNullOrEmpty(message) ? "" : ": " + message)}). Check the username and password, and that the user's command policy allows managing SSL certificates and files.");
                }

                // some NITRO versions answer a successful add or delete with no body
                if (body is not JsonObject && !(response.IsSuccessStatusCode && string.IsNullOrWhiteSpace(text)))
                {
                    throw new NitroApiException($"unexpected response to '{resource}' (HTTP {(int)response.StatusCode}). Check the NetScaler Address is the management address (NSIP).");
                }

                if (response.IsSuccessStatusCode && errorCode == 0)
                {
                    return new NitroResult(true, false, message, body);
                }

                var detail = string.IsNullOrEmpty(message) ? $"HTTP {(int)response.StatusCode}" : $"{message} (errorcode {errorCode})";
                return new NitroResult(false, response.StatusCode == HttpStatusCode.Conflict, detail, body);
            }

            public void Dispose() => _http.Dispose();
        }
    }
}
