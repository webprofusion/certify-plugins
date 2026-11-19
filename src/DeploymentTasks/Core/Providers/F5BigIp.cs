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
    /// Deploys a certificate to an F5 BIG-IP using the iControl REST API. The key, certificate and intermediate chain are uploaded,
    /// then the named SSL key, certificate and chain certificate objects are created or updated together in one transaction, so client SSL
    /// profiles that use them pick up the new certificate without ever seeing a mismatched key and certificate.
    /// </summary>
    public class F5BigIp : IDeploymentTaskProvider
    {
        public static DeploymentProviderDefinition Definition { get; }
        public DeploymentProviderDefinition GetDefinition(DeploymentProviderDefinition currentDefinition = null) => (currentDefinition ?? Definition);

        private const string Partition = "Common";
        private const string UploadFolder = "/var/config/rest/downloads";

        // BIG-IP object names: start with a letter or underscore, then letters, numbers and _ . -
        private static readonly Regex ValidObjectName = new Regex("^[A-Za-z_][A-Za-z0-9_.-]{0,99}$", RegexOptions.Compiled);

        static F5BigIp()
        {
            Definition = new DeploymentProviderDefinition
            {
                Id = "Certify.Providers.DeploymentTasks.F5BigIp",
                Title = "Deploy to F5 BIG-IP",
                IsExperimental = false,
                UsageType = DeploymentProviderUsage.PostRequest,
                SupportedContexts = DeploymentContextType.ExternalCredential,
                ExternalCredentialType = StandardAuthTypes.STANDARD_AUTH_GENERIC,
                RequiresManagementHub = true,
                Description = "Add or update a named SSL certificate, key and chain on an F5 BIG-IP using the iControl REST API. Client SSL profiles using them pick up the new certificate automatically.",
                ProviderParameters = new List<ProviderParameter>
                {
                    new ProviderParameter{ Key="bigip_address", Name="BIG-IP Address", IsRequired=true, IsCredential=false, Type= OptionType.String, Description="Management address, e.g. https://192.168.1.245" },
                    new ProviderParameter{ Key="cert_name", Name="Certificate Name", IsRequired=true, IsCredential=false, Type= OptionType.String, Description="Name of the SSL certificate and key on the BIG-IP (in the Common partition), e.g. www.example.com. The chain is stored as <name>_chain. Existing objects with these names are updated." },
                    new ProviderParameter{ Key="save_config", Name="Save Configuration", IsRequired=false, IsCredential=false, Type= OptionType.Boolean, Value="true", Description="Save the running configuration afterwards, so the change survives a restart. This also saves any other unsaved changes." },
                    new ProviderParameter{ Key="sync_group", Name="Sync to Device Group", IsRequired=false, IsCredential=false, Type= OptionType.String, Description="Optional. For an HA pair or cluster, the device group to sync the configuration to afterwards (config-sync to-group). Leave blank if the group syncs automatically or you sync manually." },
                    new ProviderParameter{ Key="allow_invalid_tls", Name="Allow Untrusted BIG-IP Certificate", IsRequired=false, IsCredential=false, Type= OptionType.Boolean, Value="false", Description="Connect even if the BIG-IP management certificate is not trusted (e.g. the default self-signed certificate)." },
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
        /// Check the task settings. In preview, also sign in to the BIG-IP and report what deploying would change.
        /// </summary>
        public async Task<List<ActionResult>> Validate(DeploymentTaskExecutionParams execParams)
        {
            var results = new List<ActionResult>();
            var settings = GetSettings(execParams);

            NetworkDevice.ValidateAddress(settings.AddressText, "BIG-IP Address", results);

            if (string.IsNullOrWhiteSpace(settings.CertName))
            {
                results.Add(new ActionResult("Certificate Name is required.", false));
            }
            else if (!ValidObjectName.IsMatch(settings.CertName))
            {
                results.Add(new ActionResult("Certificate Name must start with a letter or underscore, and may only contain letters, numbers, '.', '-' and '_' (up to 100 characters).", false));
            }

            if (!string.IsNullOrEmpty(settings.SyncGroup) && !ValidObjectName.IsMatch(settings.SyncGroup))
            {
                results.Add(new ActionResult("Sync to Device Group must be a device group name, e.g. failover-group.", false));
            }

            if (GetCredentials(execParams) == null)
            {
                results.Add(new ActionResult("A BIG-IP username and password credential is required.", false));
            }

            if (execParams.IsPreviewOnly && !results.Any(r => !r.IsSuccess))
            {
                results.AddRange(await Deploy(execParams, apply: false));
            }

            return results;
        }

        /// <summary>
        /// Sign in, check which objects exist, then (if applying) upload, install in a transaction, clean up, save and sync
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
            using var client = new IControlClient(settings.Address, settings.AllowInvalidTls);

            try
            {
                await client.SignIn(username, password, cancellationToken);

                try
                {
                    var chainName = settings.CertName + "_chain";
                    var hasChain = cert?.Intermediates.Any() == true;

                    // each object to install: its type, name and content
                    var objects = new List<(string Type, string Name, string Content)>
                    {
                        ("ssl-key", settings.CertName, cert?.KeyPem),
                        ("ssl-cert", settings.CertName, cert?.CertPem)
                    };

                    if (hasChain)
                    {
                        objects.Add(("ssl-cert", chainName, string.Concat(cert.Intermediates.Select(i => i.Pem))));
                    }

                    var existing = new HashSet<(string Type, string Name)>();
                    foreach (var (type, name, _) in objects)
                    {
                        if (await client.Exists(type, name, cancellationToken))
                        {
                            existing.Add((type, name));
                        }
                    }

                    var certExists = existing.Contains(("ssl-cert", settings.CertName));

                    if (!apply)
                    {
                        var preview = new StringBuilder($"Signed in to BIG-IP {settings.Address} as '{username}'. ");

                        if (cert == null)
                        {
                            preview.Append($"No certificate has been issued yet; certificate '{settings.CertName}' {(certExists ? "exists and would be updated" : "would be added")}.");
                        }
                        else
                        {
                            preview.Append(certExists ? $"Would update certificate and key '{settings.CertName}'" : $"Would add new certificate and key '{settings.CertName}'");

                            if (hasChain)
                            {
                                preview.Append($", {(existing.Contains(("ssl-cert", chainName)) ? "update" : "add")} chain '{chainName}' ({string.Join(", ", cert.Intermediates.Select(i => i.Subject))})");
                            }

                            preview.Append(settings.SaveConfig ? " and save the configuration" : "");
                            preview.Append(string.IsNullOrEmpty(settings.SyncGroup) ? "." : $", then sync to device group '{settings.SyncGroup}'.");
                        }

                        results.Add(new ActionResult(preview.ToString(), true));
                        return results;
                    }

                    // upload under random names, so a failed or concurrent deployment never installs another's files
                    var uploads = objects.Select(o => (o.Type, o.Name, o.Content, File: $"certify-{Guid.NewGuid():N}{(o.Type == "ssl-key" ? ".key" : ".crt")}")).ToList();
                    var uploaded = new List<string>();

                    try
                    {
                        foreach (var upload in uploads)
                        {
                            await client.Upload(upload.File, upload.Content, cancellationToken);
                            uploaded.Add(upload.File);
                        }

                        log?.Information($"BIG-IP: {(certExists ? "updating" : "adding")} certificate and key '{settings.CertName}' on {settings.Address}");

                        // the key and certificate change together, so profiles using them never see a key which doesn't match the certificate
                        var transaction = await client.BeginTransaction(cancellationToken);
                        foreach (var upload in uploads)
                        {
                            var sourcePath = $"file://{UploadFolder}/{upload.File}";
                            var queued = existing.Contains((upload.Type, upload.Name))
                                ? await client.Send(HttpMethod.Patch, $"sys/file/{upload.Type}/~{Partition}~{upload.Name}", new JsonObject { ["sourcePath"] = sourcePath }, cancellationToken, transaction)
                                : await client.Send(HttpMethod.Post, $"sys/file/{upload.Type}", new JsonObject { ["name"] = upload.Name, ["partition"] = Partition, ["sourcePath"] = sourcePath }, cancellationToken, transaction);

                            if (!queued.IsSuccess)
                            {
                                await client.DiscardTransaction(transaction);
                                results.Add(new ActionResult($"BIG-IP: failed to {(existing.Contains((upload.Type, upload.Name)) ? "update" : "add")} {upload.Type} '{upload.Name}', nothing was changed: {queued.Message}", false));
                                return results;
                            }
                        }

                        var commit = await client.CommitTransaction(transaction, cancellationToken);
                        if (!commit.IsSuccess)
                        {
                            results.Add(new ActionResult($"BIG-IP: failed to {(certExists ? "update" : "add")} certificate and key '{settings.CertName}', nothing was changed: {commit.Message}", false));
                            return results;
                        }
                    }
                    finally
                    {
                        // the uploaded files include the private key, so they must not be left behind
                        foreach (var file in uploaded)
                        {
                            var removed = await client.RemoveUpload($"{UploadFolder}/{file}");
                            if (!removed.IsSuccess)
                            {
                                var msg = $"BIG-IP: could not remove uploaded file {UploadFolder}/{file}{(file.EndsWith(".key") ? ", which contains the private key" : "")}. Remove it manually, or allow the user to run unix-rm: {removed.Message}";
                                log?.Warning(msg);
                                results.Add(new ActionResult(msg, true) { IsWarning = true });
                            }
                        }
                    }

                    if (settings.SaveConfig)
                    {
                        var save = await client.Send(HttpMethod.Post, "sys/config", new JsonObject { ["command"] = "save" }, cancellationToken);
                        if (!save.IsSuccess)
                        {
                            results.Add(new ActionResult($"BIG-IP: the certificate is in use, but saving the configuration failed, so the change will be lost when the BIG-IP restarts: {save.Message}", false));
                            return results;
                        }
                    }

                    if (!string.IsNullOrEmpty(settings.SyncGroup))
                    {
                        var sync = await client.Send(HttpMethod.Post, "cm", new JsonObject { ["command"] = "run", ["utilCmdArgs"] = $"config-sync to-group {settings.SyncGroup}" }, cancellationToken);
                        if (!sync.IsSuccess)
                        {
                            results.Add(new ActionResult($"BIG-IP: the certificate is in use on this device, but syncing to device group '{settings.SyncGroup}' failed: {sync.Message}", false));
                            return results;
                        }
                    }

                    var done = new StringBuilder($"BIG-IP: certificate and key '{settings.CertName}' {(certExists ? "updated" : "added")}");
                    if (hasChain)
                    {
                        done.Append($", with chain '{chainName}'");
                    }

                    done.Append(settings.SaveConfig ? ", configuration saved" : "");
                    done.Append(string.IsNullOrEmpty(settings.SyncGroup) ? "." : $" and synced to '{settings.SyncGroup}'.");

                    if (!certExists)
                    {
                        done.Append($" Select it{(hasChain ? $" and chain '{chainName}'" : "")} in the client SSL profiles that should use it.");
                    }

                    results.Add(new ActionResult(done.ToString(), true));
                    return results;
                }
                finally
                {
                    await client.SignOut();
                }
            }
            catch (IControlApiException exp)
            {
                results.Add(new ActionResult($"BIG-IP: {exp.Message}", false));
                return results;
            }
            catch (HttpRequestException exp)
            {
                results.Add(new ActionResult($"BIG-IP: could not connect to {settings.Address}: {exp.Message}" + NetworkDevice.ConnectionFailureHint(settings.AllowInvalidTls, "Allow Untrusted BIG-IP Certificate"), false));
                return results;
            }
            catch (TaskCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                results.Add(new ActionResult($"BIG-IP: request to {settings.Address} timed out.", false));
                return results;
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

        private static (string AddressText, Uri Address, string CertName, bool SaveConfig, string SyncGroup, bool AllowInvalidTls) GetSettings(DeploymentTaskExecutionParams execParams)
        {
            var parameters = execParams.Settings.Parameters;
            var addressText = parameters.FirstOrDefault(c => c.Key == "bigip_address")?.Value?.Trim();
            var certName = parameters.FirstOrDefault(c => c.Key == "cert_name")?.Value?.Trim();
            var syncGroup = parameters.FirstOrDefault(c => c.Key == "sync_group")?.Value?.Trim();

            // save by default, including for tasks saved before the setting existed
            var saveConfig = !bool.TryParse(parameters.FirstOrDefault(c => c.Key == "save_config")?.Value, out var save) || save;
            _ = bool.TryParse(parameters.FirstOrDefault(c => c.Key == "allow_invalid_tls")?.Value, out var allowInvalidTls);

            return (addressText, NetworkDevice.ParseAddress(addressText), certName, saveConfig, syncGroup, allowInvalidTls);
        }

        private sealed class IControlApiException : Exception
        {
            public IControlApiException(string message) : base(message) { }
        }

        private sealed record IControlResult(bool IsSuccess, string Message, JsonNode Body);

        /// <summary>
        /// Minimal client for the iControl REST API (/mgmt), signing in for a token which is sent as X-F5-Auth-Token.
        /// Errors are JSON: { "code": 400, "message": "..." }
        /// </summary>
        private sealed class IControlClient : IDisposable
        {
            private readonly HttpClient _http;
            private string _token;

            public IControlClient(Uri address, bool allowInvalidTls)
            {
                _http = NetworkDevice.CreateHttpClient(new Uri(address.GetLeftPart(UriPartial.Authority) + "/mgmt/"), allowInvalidTls);
            }

            /// <summary>
            /// Get a token for the user. Token sign in works for local and remote (e.g. LDAP, RADIUS) users, unlike basic authentication.
            /// </summary>
            public async Task SignIn(string username, string password, CancellationToken cancellationToken)
            {
                var login = new JsonObject { ["username"] = username, ["password"] = password, ["loginProviderName"] = "tmos" };
                using var content = new StringContent(login.ToJsonString(), Encoding.UTF8, "application/json");
                using var response = await _http.PostAsync("shared/authn/login", content, cancellationToken);
                var result = await ReadResult("sign in", response);

                var token = result.Body?["token"]?["token"]?.GetValue<string>();
                if (!result.IsSuccess || string.IsNullOrEmpty(token))
                {
                    throw new IControlApiException($"sign in failed: {result.Message}");
                }

                _token = token;
                _http.DefaultRequestHeaders.TryAddWithoutValidation("X-F5-Auth-Token", token);
            }

            /// <summary>
            /// Remove the token, rather than leave it until it expires
            /// </summary>
            public async Task SignOut()
            {
                if (_token == null)
                {
                    return;
                }

                try
                {
                    using var response = await _http.DeleteAsync($"shared/authz/tokens/{Uri.EscapeDataString(_token)}");
                }
                catch (Exception)
                {
                    // the token expires anyway
                }
            }

            public async Task<bool> Exists(string type, string name, CancellationToken cancellationToken)
            {
                using var response = await _http.GetAsync($"tm/sys/file/{type}/~{Partition}~{name}", cancellationToken);
                if (response.StatusCode == HttpStatusCode.NotFound)
                {
                    return false;
                }

                var result = await ReadResult($"sys/file/{type}", response);
                if (!result.IsSuccess)
                {
                    throw new IControlApiException($"could not read {type} '{name}': {result.Message}");
                }

                return true;
            }

            /// <summary>
            /// Upload a file to /var/config/rest/downloads, as a single chunk
            /// </summary>
            public async Task Upload(string fileName, string text, CancellationToken cancellationToken)
            {
                var bytes = Encoding.ASCII.GetBytes(text);
                using var content = new ByteArrayContent(bytes);
                content.Headers.TryAddWithoutValidation("Content-Type", "application/octet-stream");
                content.Headers.TryAddWithoutValidation("Content-Range", $"0-{bytes.Length - 1}/{bytes.Length}");

                using var response = await _http.PostAsync($"shared/file-transfer/uploads/{fileName}", content, cancellationToken);
                var result = await ReadResult("file upload", response);
                if (!result.IsSuccess)
                {
                    throw new IControlApiException($"failed to upload {fileName}: {result.Message}");
                }
            }

            public async Task<string> BeginTransaction(CancellationToken cancellationToken)
            {
                var result = await Send(HttpMethod.Post, "transaction", new JsonObject(), cancellationToken);
                var id = result.Body?["transId"]?.ToString();
                if (!result.IsSuccess || string.IsNullOrEmpty(id))
                {
                    throw new IControlApiException($"could not start a transaction: {result.Message}");
                }

                return id;
            }

            /// <summary>
            /// Delete an uncommitted transaction and the requests queued in it. Best effort: it expires anyway.
            /// </summary>
            public async Task DiscardTransaction(string transaction)
            {
                try
                {
                    using var response = await _http.DeleteAsync($"tm/transaction/{transaction}");
                }
                catch (Exception)
                {
                }
            }

            /// <summary>
            /// Remove an uploaded file. Never throws, as it runs during clean up.
            /// </summary>
            public async Task<IControlResult> RemoveUpload(string path)
            {
                try
                {
                    return await Send(HttpMethod.Post, "util/unix-rm", new JsonObject { ["command"] = "run", ["utilCmdArgs"] = path }, CancellationToken.None);
                }
                catch (Exception exp) when (exp is IControlApiException || exp is HttpRequestException || exp is TaskCanceledException)
                {
                    return new IControlResult(false, exp.Message, null);
                }
            }

            public async Task<IControlResult> CommitTransaction(string transaction, CancellationToken cancellationToken)
            {
                var result = await Send(HttpMethod.Patch, $"transaction/{transaction}", new JsonObject { ["state"] = "VALIDATING" }, cancellationToken);
                var state = result.Body?["state"]?.GetValue<string>();

                if (result.IsSuccess && state != null && state != "COMPLETED")
                {
                    return new IControlResult(false, $"transaction {state.ToLowerInvariant()}{(result.Body?["failureReason"] is JsonNode reason ? ": " + reason : "")}", result.Body);
                }

                return result;
            }

            /// <summary>
            /// Send a request to /mgmt/tm/{path}, optionally as part of a transaction (queued until the transaction is committed)
            /// </summary>
            public async Task<IControlResult> Send(HttpMethod method, string path, JsonObject body, CancellationToken cancellationToken, string transaction = null)
            {
                using var request = new HttpRequestMessage(method, "tm/" + path)
                {
                    Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json")
                };

                if (transaction != null)
                {
                    request.Headers.TryAddWithoutValidation("X-F5-REST-Coordination-Id", transaction);
                }

                using var response = await _http.SendAsync(request, cancellationToken);
                return await ReadResult(path, response);
            }

            private static async Task<IControlResult> ReadResult(string resource, HttpResponseMessage response)
            {
                var text = await response.Content.ReadAsStringAsync();

                JsonNode body = null;
                try
                {
                    body = string.IsNullOrWhiteSpace(text) ? null : JsonNode.Parse(text);
                }
                catch (System.Text.Json.JsonException)
                {
                    // not an iControl REST response, e.g. the address is not a BIG-IP management interface
                }

                var message = body is JsonObject && body["message"] is JsonValue m ? m.ToString().Trim() : null;

                if (response.StatusCode == HttpStatusCode.Unauthorized || response.StatusCode == HttpStatusCode.Forbidden)
                {
                    throw new IControlApiException($"access denied ({(int)response.StatusCode}{(string.IsNullOrEmpty(message) ? "" : ": " + message)}). Check the username and password, and that the user's role allows managing SSL certificates and using the REST API.");
                }

                if (body is not JsonObject && !(response.IsSuccessStatusCode && string.IsNullOrWhiteSpace(text)))
                {
                    throw new IControlApiException($"unexpected response to '{resource}' (HTTP {(int)response.StatusCode}). Check the BIG-IP Address is the management address.");
                }

                if (response.IsSuccessStatusCode)
                {
                    return new IControlResult(true, message, body);
                }

                return new IControlResult(false, string.IsNullOrEmpty(message) ? $"HTTP {(int)response.StatusCode}" : message, body);
            }

            public void Dispose() => _http.Dispose();
        }
    }
}
