using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
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
    /// Deploys a certificate to Cisco Secure Firewall Threat Defense devices through Secure Firewall Management Center (FMC 7.7 or later), using the
    /// FMC REST API. The certificate and key replace the PKCS12 file of a certificate enrollment object, then the enrollment is installed again
    /// on each device it's installed on, so the trustpoint keeps its name and the settings that use it (remote access VPN etc) pick up each renewal.
    /// </summary>
    public class CiscoFmc : IDeploymentTaskProvider
    {
        public static DeploymentProviderDefinition Definition { get; }
        public DeploymentProviderDefinition GetDefinition(DeploymentProviderDefinition currentDefinition = null) => (currentDefinition ?? Definition);

        private static readonly Regex ValidName = new Regex("^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$", RegexOptions.Compiled);

        // installing a certificate on a device is a background task on the management center
        private static readonly TimeSpan TaskTimeout = TimeSpan.FromMinutes(15);

        // the management center does not accept larger PKCS12 files
        private const int MaxPkcs12Size = 24 * 1024;

        private static readonly Version MinimumVersion = new Version(7, 7);

        static CiscoFmc()
        {
            Definition = new DeploymentProviderDefinition
            {
                Id = "Certify.Providers.DeploymentTasks.CiscoFmc",
                Title = "Deploy to Cisco Secure Firewall (FMC)",
                IsExperimental = false,
                UsageType = DeploymentProviderUsage.PostRequest,
                SupportedContexts = DeploymentContextType.ExternalCredential,
                ExternalCredentialType = StandardAuthTypes.STANDARD_AUTH_GENERIC,
                RequiresManagementHub = true,
                Description = "Import the certificate to a PKCS12 certificate enrollment on Cisco Secure Firewall Management Center (7.7 or later), replacing its certificate, then install it again on the threat defense devices that use it. Settings which use the certificate, such as remote access VPN, pick up each renewal.",
                ProviderParameters = new List<ProviderParameter>
                {
                    new ProviderParameter{ Key="fmc_address", Name="Management Center Address", IsRequired=true, IsCredential=false, Type= OptionType.String, Description="Address of the management center, e.g. https://fmc.example.com" },
                    new ProviderParameter{ Key="enrollment_name", Name="Certificate Enrollment", IsRequired=true, IsCredential=false, Type= OptionType.String, Description="Name of the PKCS12 certificate enrollment object, e.g. vpn.example.com. It is added if it doesn't exist, otherwise its certificate is replaced." },
                    new ProviderParameter{ Key="devices", Name="Devices", IsRequired=false, IsCredential=false, Type= OptionType.String, Description="Optional names of threat defense devices to install the certificate on, separated by commas. Devices it's already installed on always get each renewal." },
                    new ProviderParameter{ Key="domain", Name="Domain", IsRequired=false, IsCredential=false, Type= OptionType.String, Description="Leave blank for the Global domain. On a multi-domain management center, the domain of the enrollment and devices instead, e.g. Global/Branch." },
                    new ProviderParameter{ Key="allow_invalid_tls", Name="Allow Untrusted Management Center Certificate", IsRequired=false, IsCredential=false, Type= OptionType.Boolean, Value="false", Description="Connect even if the management center's own certificate is not trusted (e.g. the default self-signed certificate)." },
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
        /// Check the task settings. In preview, also sign in to the management center and report what deploying would change.
        /// </summary>
        public async Task<List<ActionResult>> Validate(DeploymentTaskExecutionParams execParams)
        {
            var results = new List<ActionResult>();
            var settings = GetSettings(execParams);

            NetworkDevice.ValidateAddress(settings.AddressText, "Management Center Address", results);

            if (string.IsNullOrWhiteSpace(settings.EnrollmentName))
            {
                results.Add(new ActionResult("Certificate Enrollment is required.", false));
            }
            else if (!ValidName.IsMatch(settings.EnrollmentName))
            {
                results.Add(new ActionResult("Certificate Enrollment may only contain letters, numbers, '.', '-' and '_', up to 64 characters.", false));
            }

            if (GetCredentials(execParams) == null)
            {
                results.Add(new ActionResult("A username and password credential for the management center is required.", false));
            }

            if (execParams.IsPreviewOnly && !results.Any(r => !r.IsSuccess))
            {
                results.AddRange(await Deploy(execParams, apply: false));
            }

            return results;
        }

        /// <summary>
        /// Sign in and find the enrollment and devices, then (if applying) replace the enrollment's certificate and install it on the devices
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
            var name = settings.EnrollmentName;
            var updated = false;

            using var client = new FmcClient(settings.Address, settings.AllowInvalidTls, username, password);

            JsonObject enrollment = null;

            string failure(string message) => updated
                ? $"Cisco FMC: {(enrollment != null ? $"the certificate of enrollment '{name}' was replaced" : $"certificate enrollment '{name}' was added")}, but {message}"
                : $"Cisco FMC: {message}";

            try
            {
                await client.SignIn(cancellationToken);

                var version = await client.GetServerVersion(cancellationToken);
                if (version != null && version < MinimumVersion)
                {
                    results.Add(new ActionResult($"Cisco FMC: the management center is version {version}. Installing certificates on devices through its REST API needs version {MinimumVersion} or later.", false));
                    return results;
                }

                client.UseDomain(settings.Domain);

                enrollment = await client.FindEnrollment(name, cancellationToken);
                var enrollmentType = enrollment?["enrollmentType"]?.ToString();
                if (enrollment != null && !string.Equals(enrollmentType, "PKCS12", StringComparison.OrdinalIgnoreCase))
                {
                    results.Add(new ActionResult($"Cisco FMC: certificate enrollment '{name}' is a {enrollmentType ?? "unknown"} enrollment. This task only replaces PKCS12 enrollments: use a new enrollment name, and the task adds it.", false));
                    return results;
                }

                var devices = await client.ListDevices(cancellationToken);
                var missing = settings.Devices.Where(d => !devices.Any(device => string.Equals(device.Name, d, StringComparison.OrdinalIgnoreCase))).ToList();
                if (missing.Any())
                {
                    results.Add(new ActionResult($"Cisco FMC: no device named {Quoted(missing)} was found{(settings.Domain != null ? $" in domain '{settings.Domain}'" : "")}. Use the device names shown under Devices > Device Management.", false));
                    return results;
                }

                var enrollmentId = enrollment?["id"]?.ToString();
                var installedOn = enrollmentId == null ? new List<FmcDevice>() : await client.DevicesWithEnrollment(devices, enrollmentId, cancellationToken);
                var newDevices = devices.Where(d => settings.Devices.Contains(d.Name, StringComparer.OrdinalIgnoreCase) && !installedOn.Contains(d)).ToList();

                var upToDate = cert != null && enrollment != null && StoredThumbprints(enrollment).Contains(Thumbprint(cert.CertPem));

                if (!apply)
                {
                    var preview = new StringBuilder($"Connected to management center {settings.Address} as '{username}'. ");
                    if (upToDate)
                    {
                        preview.Append($"Certificate enrollment '{name}' already has this certificate. Deploying would ");
                    }
                    else
                    {
                        preview.Append(cert == null ? "No certificate has been issued yet. Deploying would " : "Would ");
                        preview.Append(enrollment != null ? $"replace the certificate of enrollment '{name}', then " : $"add certificate enrollment '{name}', then ");
                    }

                    preview.Append(DescribeInstalls(installedOn, newDevices, "install it again on", "install it on") ?? "not install it on any device, as it isn't installed on one yet");
                    preview.Append('.');

                    results.Add(new ActionResult(preview.ToString(), true));
                    return results;
                }

                if (!upToDate)
                {
                    var pkcs12 = CreatePkcs12(cert);
                    if (pkcs12.Data.Length > MaxPkcs12Size)
                    {
                        results.Add(new ActionResult($"Cisco FMC: the certificate and its chain are {pkcs12.Data.Length / 1024} KB as a PKCS12 file, larger than the management center accepts (24 KB). Nothing was changed.", false));
                        return results;
                    }

                    log?.Information($"Cisco FMC: {(enrollment != null ? "replacing the certificate of" : "adding")} certificate enrollment '{name}' on {settings.Address}");

                    enrollmentId = await client.SaveEnrollment(name, enrollment, pkcs12.Data, pkcs12.Passphrase, cancellationToken);
                    updated = true;
                }

                var installed = new List<FmcDevice>();
                var failed = new List<string>();

                foreach (var (device, isNew) in installedOn.Select(d => (d, false)).Concat(newDevices.Select(d => (d, true))))
                {
                    log?.Information($"Cisco FMC: installing certificate enrollment '{name}' on device '{device.Name}'");

                    var error = await client.InstallOnDevice(device, enrollmentId, isNew ? "ENROLL" : "RE_ENROLL", TaskTimeout, cancellationToken);
                    if (error == null)
                    {
                        installed.Add(device);
                    }
                    else
                    {
                        failed.Add($"device '{device.Name}': {error}");
                    }
                }

                if (failed.Any())
                {
                    var done = installed.Any() ? $" It was installed on {Quoted(installed.Select(d => d.Name))}." : "";
                    results.Add(new ActionResult(failure($"installing it failed for {string.Join("; ", failed).TrimEnd('.')}.{done}"), false));
                    return results;
                }

                var summary = new StringBuilder("Cisco FMC: ");
                summary.Append(upToDate ? $"certificate enrollment '{name}' already had this certificate" : enrollment != null ? $"replaced the certificate of enrollment '{name}'" : $"added certificate enrollment '{name}'");

                var installs = DescribeInstalls(installedOn, newDevices, "installed it again on", "installed it on");
                summary.Append(installs != null ? $", and {installs}." : ".");

                if (!installedOn.Any() && !newDevices.Any())
                {
                    summary.Append(" It isn't installed on any device: install it on the devices that should use it, under Devices > Certificates, or name them in Devices. Later renewals install it again wherever it's installed.");
                }

                results.Add(new ActionResult(summary.ToString(), true));
                return results;
            }
            catch (FmcApiException exp)
            {
                results.Add(new ActionResult(failure(exp.Message), false));
                return results;
            }
            catch (HttpRequestException exp)
            {
                results.Add(new ActionResult(failure($"could not connect to {settings.Address}: {exp.Message}" + NetworkDevice.ConnectionFailureHint(settings.AllowInvalidTls, "Allow Untrusted Management Center Certificate")), false));
                return results;
            }
            catch (TaskCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                results.Add(new ActionResult(failure($"request to {settings.Address} timed out."), false));
                return results;
            }
            finally
            {
                await client.SignOut();
            }
        }

        private static string DescribeInstalls(List<FmcDevice> installedOn, List<FmcDevice> newDevices, string again, string first)
        {
            var parts = new List<string>();
            if (installedOn.Any())
            {
                parts.Add($"{again} {Device(installedOn)}");
            }

            if (newDevices.Any())
            {
                parts.Add($"{first} {Device(newDevices)}");
            }

            return parts.Any() ? string.Join(" and ", parts) : null;
        }

        private static string Device(List<FmcDevice> devices) => (devices.Count == 1 ? "device " : "devices ") + Quoted(devices.Select(d => d.Name));

        private static string Quoted(IEnumerable<string> names) => string.Join(", ", names.Select(n => $"'{n}'"));

        /// <summary>
        /// The key, certificate and intermediates as a PKCS12 file with a random passphrase. The key is encrypted with 3DES and the file MAC uses SHA-1,
        /// which threat defense devices of every version can read. The certificates are not encrypted, so a later deployment can read which
        /// certificate the enrollment has.
        /// </summary>
        private static (byte[] Data, string Passphrase) CreatePkcs12(DeviceCertificate cert)
        {
            var passphrase = Convert.ToHexString(RandomNumberGenerator.GetBytes(16));

            using var leaf = X509Certificate2.CreateFromPem(cert.CertPem, cert.KeyPem);
            using var key = (AsymmetricAlgorithm)leaf.GetRSAPrivateKey() ?? leaf.GetECDsaPrivateKey();

            var localKeyId = new Pkcs9LocalKeyId(leaf.GetCertHash());

            var certs = new Pkcs12SafeContents();
            certs.AddCertificate(leaf).Attributes.Add(localKeyId);
            foreach (var intermediate in cert.Intermediates)
            {
                using var ca = X509Certificate2.CreateFromPem(intermediate.Pem);
                certs.AddCertificate(ca);
            }

            var keys = new Pkcs12SafeContents();
            keys.AddShroudedKey(key, passphrase, new PbeParameters(PbeEncryptionAlgorithm.TripleDes3KeyPkcs12, HashAlgorithmName.SHA1, 2048)).Attributes.Add(localKeyId);

            var builder = new Pkcs12Builder();
            builder.AddSafeContentsUnencrypted(certs);
            builder.AddSafeContentsUnencrypted(keys);
            builder.SealWithMac(passphrase, HashAlgorithmName.SHA1, 2048);

            return (builder.Encode(), passphrase);
        }

        /// <summary>
        /// Thumbprints of the unencrypted certificates in an enrollment's PKCS12 file, if the management center returns it. Files added by this
        /// task have unencrypted certificates; for any other file this is empty, and the certificate is replaced.
        /// </summary>
        private static List<string> StoredThumbprints(JsonObject enrollment)
        {
            var thumbprints = new List<string>();

            try
            {
                var data = Convert.FromBase64String(enrollment["pkcs12Content"]?["base64Certificate"]?.ToString() ?? "");
                var pfx = Pkcs12Info.Decode(data, out _, skipCopy: true);

                foreach (var safe in pfx.AuthenticatedSafe.Where(s => s.ConfidentialityMode == Pkcs12ConfidentialityMode.None))
                {
                    foreach (var bag in safe.GetBags().OfType<Pkcs12CertBag>().Where(b => b.IsX509Certificate))
                    {
                        using var stored = bag.GetCertificate();
                        thumbprints.Add(stored.Thumbprint);
                    }
                }
            }
            catch (Exception exp) when (exp is FormatException || exp is CryptographicException)
            {
                // masked or not a PKCS12 file
            }

            return thumbprints;
        }

        private static string Thumbprint(string pem)
        {
            using var cert = X509Certificate2.CreateFromPem(pem);
            return cert.Thumbprint;
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

        private static (string AddressText, Uri Address, string EnrollmentName, List<string> Devices, string Domain, bool AllowInvalidTls) GetSettings(DeploymentTaskExecutionParams execParams)
        {
            var parameters = execParams.Settings.Parameters;
            var addressText = parameters.FirstOrDefault(c => c.Key == "fmc_address")?.Value?.Trim();
            var enrollmentName = parameters.FirstOrDefault(c => c.Key == "enrollment_name")?.Value?.Trim();
            var devices = (parameters.FirstOrDefault(c => c.Key == "devices")?.Value ?? "")
                .Split(new[] { ',', ';', '\n' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
            var domain = parameters.FirstOrDefault(c => c.Key == "domain")?.Value?.Trim();
            _ = bool.TryParse(parameters.FirstOrDefault(c => c.Key == "allow_invalid_tls")?.Value, out var allowInvalidTls);

            return (addressText, NetworkDevice.ParseAddress(addressText), enrollmentName, devices, string.IsNullOrEmpty(domain) ? null : domain, allowInvalidTls);
        }

        private sealed record FmcDevice(string Id, string Name);

        private sealed class FmcApiException : Exception
        {
            public FmcApiException(string message) : base(message) { }
        }

        private sealed record FmcResult(bool IsSuccess, HttpStatusCode Status, string Message, JsonObject Body);

        /// <summary>
        /// Minimal client for the FMC REST API. Signing in with the username and password gives an access token (valid for 30 minutes) and the
        /// domains the user can access. Errors are JSON: {"error":{"category":"...","messages":[{"description":"..."}],"severity":"ERROR"}}
        /// </summary>
        private sealed class FmcClient : IDisposable
        {
            private const int PageSize = 1000;

            private readonly HttpClient _http;
            private readonly string _username;
            private readonly string _password;
            private string _accessToken;
            private string _defaultDomainId;
            private List<(string Name, string Id)> _domains = new();
            private string _domainId;

            public FmcClient(Uri address, bool allowInvalidTls, string username, string password)
            {
                _http = NetworkDevice.CreateHttpClient(new Uri(address.GetLeftPart(UriPartial.Authority) + "/api/"), allowInvalidTls);
                _username = username;
                _password = password;
            }

            public async Task SignIn(CancellationToken cancellationToken)
            {
                using var request = new HttpRequestMessage(HttpMethod.Post, "fmc_platform/v1/auth/generatetoken");
                request.Headers.TryAddWithoutValidation("Authorization", "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes($"{_username}:{_password}")));

                using var response = await _http.SendAsync(request, cancellationToken);
                var text = await response.Content.ReadAsStringAsync();

                if (response.StatusCode == HttpStatusCode.Unauthorized || response.StatusCode == HttpStatusCode.Forbidden)
                {
                    throw new FmcApiException($"could not sign in ({ErrorMessage(text) ?? $"HTTP {(int)response.StatusCode}"}). Check the username and password, and that the user is allowed to use the REST API.");
                }

                _accessToken = Header(response, "X-auth-access-token");
                if (!response.IsSuccessStatusCode || string.IsNullOrEmpty(_accessToken))
                {
                    throw new FmcApiException($"could not sign in: {ErrorMessage(text) ?? $"HTTP {(int)response.StatusCode}"}. Check the Management Center Address, and that the REST API is enabled under System > Configuration > REST API Preferences.");
                }

                _defaultDomainId = Header(response, "DOMAIN_UUID");
                _domains = new List<(string, string)>();

                try
                {
                    foreach (var domain in (JsonNode.Parse(Header(response, "DOMAINS") ?? "[]") as JsonArray ?? new JsonArray()).OfType<JsonObject>())
                    {
                        _domains.Add((domain["name"]?.ToString(), domain["uuid"]?.ToString()));
                    }
                }
                catch (System.Text.Json.JsonException)
                {
                    // domains are only needed to choose a domain by name
                }

                _domainId ??= _defaultDomainId;
            }

            /// <summary>
            /// End the session, so the access token can't be used again
            /// </summary>
            public async Task SignOut()
            {
                if (_accessToken == null)
                {
                    return;
                }

                try
                {
                    using var request = new HttpRequestMessage(HttpMethod.Post, "fmc_platform/v1/auth/revokeaccess");
                    request.Headers.TryAddWithoutValidation("X-auth-access-token", _accessToken);
                    using var response = await _http.SendAsync(request, CancellationToken.None);
                }
                catch (Exception exp) when (exp is HttpRequestException || exp is TaskCanceledException)
                {
                    // the token expires by itself
                }

                _accessToken = null;
            }

            /// <summary>
            /// Version of the management center, or null if it isn't reported
            /// </summary>
            public async Task<Version> GetServerVersion(CancellationToken cancellationToken)
            {
                var result = await Send(HttpMethod.Get, "fmc_platform/v1/info/serverversion", null, cancellationToken);
                var text = (result.Body?["items"] as JsonArray)?.OfType<JsonObject>().FirstOrDefault()?["serverVersion"]?.ToString();
                var match = Regex.Match(text ?? "", @"^\s*(\d+)\.(\d+)");

                return result.IsSuccess && match.Success ? new Version(int.Parse(match.Groups[1].Value), int.Parse(match.Groups[2].Value)) : null;
            }

            /// <summary>
            /// Use a domain by name (e.g. Global/Branch) instead of the user's default domain
            /// </summary>
            public void UseDomain(string name)
            {
                if (name == null)
                {
                    _domainId = _domains.FirstOrDefault(d => string.Equals(d.Name, "Global", StringComparison.OrdinalIgnoreCase)).Id ?? _defaultDomainId;
                    return;
                }

                var domain = _domains.FirstOrDefault(d => string.Equals(d.Name, name, StringComparison.OrdinalIgnoreCase));
                if (domain.Id == null)
                {
                    throw new FmcApiException($"domain '{name}' was not found. The user can access: {(_domains.Any() ? Quoted(_domains.Select(d => d.Name)) : "no listed domains")}.");
                }

                _domainId = domain.Id;
            }

            /// <summary>
            /// The certificate enrollment object of that name, with all its settings, or null if there isn't one
            /// </summary>
            public async Task<JsonObject> FindEnrollment(string name, CancellationToken cancellationToken)
            {
                var match = (await List("object/certenrollments", null, "list certificate enrollments", cancellationToken))
                    .FirstOrDefault(e => string.Equals(e["name"]?.ToString(), name, StringComparison.OrdinalIgnoreCase));

                if (match == null)
                {
                    return null;
                }

                var result = await Send(HttpMethod.Get, Domain($"object/certenrollments/{Uri.EscapeDataString(match["id"].ToString())}"), null, cancellationToken);
                if (!result.IsSuccess)
                {
                    throw new FmcApiException($"could not read certificate enrollment '{name}': {result.Message}");
                }

                return result.Body;
            }

            /// <summary>
            /// Add the enrollment, or replace the PKCS12 file of the existing one (keeping its other settings). Returns the enrollment ID.
            /// </summary>
            public async Task<string> SaveEnrollment(string name, JsonObject existing, byte[] pkcs12, string passphrase, CancellationToken cancellationToken)
            {
                var content = new JsonObject
                {
                    ["base64Certificate"] = Convert.ToBase64String(pkcs12),
                    ["passPhrase"] = passphrase
                };

                FmcResult result;
                if (existing == null)
                {
                    var body = new JsonObject
                    {
                        ["name"] = name,
                        ["type"] = "CertEnrollment",
                        ["enrollmentType"] = "PKCS12",
                        ["pkcs12Content"] = content
                    };

                    result = await Send(HttpMethod.Post, Domain("object/certenrollments"), body, cancellationToken);
                }
                else
                {
                    var body = (JsonObject)existing.DeepClone();
                    body.Remove("links");
                    body.Remove("metadata");
                    body["pkcs12Content"] = content;

                    result = await Send(HttpMethod.Put, Domain($"object/certenrollments/{Uri.EscapeDataString(existing["id"].ToString())}"), body, cancellationToken);
                }

                if (!result.IsSuccess)
                {
                    throw new FmcApiException($"could not {(existing == null ? "add" : "update")} certificate enrollment '{name}', nothing was changed: {result.Message}");
                }

                return existing?["id"]?.ToString() ?? result.Body?["id"]?.ToString()
                    ?? throw new FmcApiException($"certificate enrollment '{name}' was added, but no ID was returned.");
            }

            public async Task<List<FmcDevice>> ListDevices(CancellationToken cancellationToken)
            {
                return (await List("devices/devicerecords", null, "list devices", cancellationToken))
                    .Where(d => d["id"] != null && d["name"] != null)
                    .Select(d => new FmcDevice(d["id"].ToString(), d["name"].ToString()))
                    .ToList();
            }

            /// <summary>
            /// The devices the enrollment is installed on
            /// </summary>
            public async Task<List<FmcDevice>> DevicesWithEnrollment(List<FmcDevice> devices, string enrollmentId, CancellationToken cancellationToken)
            {
                var installed = new List<FmcDevice>();
                foreach (var device in devices)
                {
                    if (await IsInstalled(device, enrollmentId, cancellationToken))
                    {
                        installed.Add(device);
                    }
                }

                return installed;
            }

            /// <summary>
            /// Install the enrollment on a device (ENROLL), or install it again (RE_ENROLL), and wait for the task to finish. Returns null if it
            /// was installed, otherwise why not.
            /// </summary>
            public async Task<string> InstallOnDevice(FmcDevice device, string enrollmentId, string action, TimeSpan timeout, CancellationToken cancellationToken)
            {
                var body = new JsonObject
                {
                    ["action"] = action,
                    ["deviceCertificates"] = new JsonArray(new JsonObject
                    {
                        ["deviceId"] = device.Id,
                        ["certificates"] = new JsonArray(new JsonObject
                        {
                            ["certificate"] = new JsonObject { ["id"] = enrollmentId, ["type"] = "CertEnrollment" }
                        })
                    })
                };

                var result = await Send(HttpMethod.Post, Domain("devices/operational/managecertificates"), body, cancellationToken);
                if (!result.IsSuccess)
                {
                    return result.Message;
                }

                var taskId = result.Body?["metadata"]?["task"]?["id"]?.ToString();
                if (!string.IsNullOrEmpty(taskId))
                {
                    var error = await WaitForTask(taskId, timeout, cancellationToken);
                    if (error != null)
                    {
                        return error;
                    }
                }

                return await IsInstalled(device, enrollmentId, cancellationToken) ? null : "the management center reported the task finished, but the certificate isn't listed on the device. Check it under Devices > Certificates.";
            }

            /// <summary>
            /// Wait for a background task. Returns null if it succeeded, otherwise why not.
            /// </summary>
            private async Task<string> WaitForTask(string taskId, TimeSpan timeout, CancellationToken cancellationToken)
            {
                var deadline = DateTime.UtcNow + timeout;
                var delay = TimeSpan.Zero;

                while (true)
                {
                    await Task.Delay(delay, cancellationToken);
                    delay = TimeSpan.FromSeconds(Math.Clamp(delay.TotalSeconds * 2, 1, 5));

                    var result = await Send(HttpMethod.Get, Domain($"job/taskstatuses/{Uri.EscapeDataString(taskId)}"), null, cancellationToken);
                    if (!result.IsSuccess)
                    {
                        if (result.Status == HttpStatusCode.NotFound && DateTime.UtcNow < deadline)
                        {
                            // the task may not be listed yet
                            continue;
                        }

                        return $"could not check task {taskId}: {result.Message}";
                    }

                    var status = result.Body["status"]?.ToString()?.Trim().ToUpperInvariant() ?? "";
                    if (status.Contains("FAIL") || status.Contains("ERROR"))
                    {
                        var details = new[] { result.Body["message"]?.ToString(), result.Body["description"]?.ToString() }.Where(d => !string.IsNullOrWhiteSpace(d)).Distinct().ToList();
                        return $"task {taskId} failed{(details.Any() ? ": " + string.Join(" ", details) : ".")}";
                    }

                    if (!new[] { "", "PENDING", "QUEUED", "RUNNING", "IN_PROGRESS", "DEPLOYING", "UNKNOWN" }.Contains(status))
                    {
                        return null;
                    }

                    if (DateTime.UtcNow >= deadline)
                    {
                        return $"task {taskId} was still running after {timeout.TotalMinutes} minutes. Check it under Devices > Certificates.";
                    }
                }
            }

            private async Task<bool> IsInstalled(FmcDevice device, string enrollmentId, CancellationToken cancellationToken)
            {
                var items = await List("devices/certificates", $"filter=deviceId:{Uri.EscapeDataString(device.Id)}&expanded=true", $"list the certificates of device '{device.Name}'", cancellationToken);

                bool references(JsonNode node) => node?["certificate"]?["id"]?.ToString() == enrollmentId;

                return items.Any(i => (i["deviceId"] == null || i["deviceId"].ToString() == device.Id)
                    && (references(i) || (i["enrolledCertificates"] as JsonArray ?? new JsonArray()).Any(references)));
            }

            /// <summary>
            /// All items of a domain collection, a page at a time
            /// </summary>
            private async Task<List<JsonObject>> List(string path, string query, string action, CancellationToken cancellationToken)
            {
                var items = new List<JsonObject>();
                for (var offset = 0; ; offset += PageSize)
                {
                    var result = await Send(HttpMethod.Get, Domain(path) + $"?offset={offset}&limit={PageSize}{(query != null ? "&" + query : "")}", null, cancellationToken);
                    if (!result.IsSuccess)
                    {
                        if (result.Status == HttpStatusCode.NotFound && path == "devices/certificates")
                        {
                            throw new FmcApiException($"could not {action}: {result.Message}. Installing certificates on devices through the REST API needs management center version {MinimumVersion} or later.");
                        }

                        throw new FmcApiException($"could not {action}: {result.Message}");
                    }

                    var page = (result.Body?["items"] as JsonArray ?? new JsonArray()).OfType<JsonObject>().ToList();
                    items.AddRange(page);

                    var count = int.TryParse(result.Body?["paging"]?["count"]?.ToString(), out var total) ? total : 0;
                    if (page.Count < PageSize || offset + PageSize >= count)
                    {
                        return items;
                    }
                }
            }

            private string Domain(string path) => $"fmc_config/v1/domain/{_domainId}/{path}";

            private async Task<FmcResult> Send(HttpMethod method, string path, JsonObject body, CancellationToken cancellationToken)
            {
                var signedInAgain = false;

                for (var attempt = 1; ; attempt++)
                {
                    using var request = new HttpRequestMessage(method, path);
                    request.Headers.TryAddWithoutValidation("X-auth-access-token", _accessToken);
                    if (body != null)
                    {
                        request.Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json");
                    }

                    using var response = await _http.SendAsync(request, cancellationToken);
                    var text = await response.Content.ReadAsStringAsync();

                    if (response.StatusCode == HttpStatusCode.TooManyRequests && attempt < 5)
                    {
                        // the REST API allows 120 requests a minute
                        var wait = response.Headers.RetryAfter?.Delta ?? TimeSpan.FromSeconds(10);
                        await Task.Delay(wait < TimeSpan.FromMinutes(1) ? wait : TimeSpan.FromMinutes(1), cancellationToken);
                        continue;
                    }

                    if (response.StatusCode == HttpStatusCode.Unauthorized && !signedInAgain)
                    {
                        // the access token expires after 30 minutes
                        signedInAgain = true;
                        await SignIn(cancellationToken);
                        continue;
                    }

                    if (response.StatusCode == HttpStatusCode.Unauthorized || response.StatusCode == HttpStatusCode.Forbidden)
                    {
                        throw new FmcApiException($"access denied ({ErrorMessage(text) ?? $"HTTP {(int)response.StatusCode}"}). Check that the user's role can change PKI objects and device certificates, e.g. the Network Admin role, and has access to the domain.");
                    }

                    JsonObject json = null;
                    try
                    {
                        json = string.IsNullOrWhiteSpace(text) ? null : JsonNode.Parse(text) as JsonObject;
                    }
                    catch (System.Text.Json.JsonException)
                    {
                        // not an FMC REST API response
                    }

                    if (response.IsSuccessStatusCode)
                    {
                        return new FmcResult(true, response.StatusCode, null, json ?? new JsonObject());
                    }

                    if (json == null)
                    {
                        throw new FmcApiException($"unexpected response to '{path}' (HTTP {(int)response.StatusCode}). Check the Management Center Address is the management center.");
                    }

                    return new FmcResult(false, response.StatusCode, ErrorMessage(text) ?? $"HTTP {(int)response.StatusCode}", json);
                }
            }

            private static string ErrorMessage(string text)
            {
                try
                {
                    var messages = (JsonNode.Parse(text)?["error"]?["messages"] as JsonArray ?? new JsonArray())
                        .OfType<JsonObject>()
                        .Select(m => m["description"]?.ToString()?.Trim())
                        .Where(m => !string.IsNullOrEmpty(m))
                        .ToList();

                    return messages.Any() ? string.Join("; ", messages) : null;
                }
                catch (Exception exp) when (exp is System.Text.Json.JsonException || exp is ArgumentNullException)
                {
                    return null;
                }
            }

            private static string Header(HttpResponseMessage response, string name)
                => response.Headers.TryGetValues(name, out var values) ? values.FirstOrDefault() : null;

            public void Dispose() => _http.Dispose();
        }
    }
}
