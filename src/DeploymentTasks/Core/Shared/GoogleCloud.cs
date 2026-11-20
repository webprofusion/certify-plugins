using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Certify.Models.Config;
using Certify.Providers.DeploymentTasks;

namespace Certify.Providers.Deployment.Core.Shared
{
    /// <summary>
    /// Sign in and API calls shared by tasks which deploy to Google Cloud with a service account key (see <see cref="CredentialTypes.GoogleServiceAccountKey"/>).
    /// The service account signs a JWT with its key, which the token endpoint exchanges for an access token (the OAuth 2.0 JWT bearer grant).
    /// </summary>
    public static class GoogleCloud
    {
        private const string Scope = "https://www.googleapis.com/auth/cloud-platform";
        private const string DefaultTokenUri = "https://oauth2.googleapis.com/token";

        private static readonly Regex ValidProjectId = new Regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", RegexOptions.Compiled);

        /// <summary>
        /// The parts of a service account JSON key file that sign in uses
        /// </summary>
        public sealed record ServiceAccountKey(string ClientEmail, string PrivateKeyPem, string PrivateKeyId, Uri TokenUri, string ProjectId);

        /// <summary>
        /// The task's service account key, or null with the reason it can't be used
        /// </summary>
        public static (ServiceAccountKey Key, string Problem) GetKey(DeploymentTaskExecutionParams execParams)
        {
            var json = execParams.Credentials?.GetValueOrDefault("service_account_key");
            if (string.IsNullOrWhiteSpace(json))
            {
                return (null, "A Google Cloud Service Account Key credential is required.");
            }

            const string notAKey = "The Google Cloud Service Account Key credential must be the contents of a service account's JSON key file.";

            JsonNode key;
            try
            {
                key = JsonNode.Parse(json);
            }
            catch (JsonException)
            {
                return (null, notAKey);
            }

            if ((string)key?["type"] != "service_account" || string.IsNullOrEmpty((string)key["client_email"]) || string.IsNullOrEmpty((string)key["private_key"]))
            {
                return (null, notAKey);
            }

            try
            {
                using var rsa = RSA.Create();
                rsa.ImportFromPem((string)key["private_key"]);
            }
            catch (Exception exp) when (exp is ArgumentException || exp is CryptographicException)
            {
                return (null, "The private key in the Google Cloud Service Account Key credential can't be read. Paste the whole JSON key file again.");
            }

            var tokenUri = Uri.TryCreate((string)key["token_uri"] ?? DefaultTokenUri, UriKind.Absolute, out var uri) ? uri : new Uri(DefaultTokenUri);

            return (new ServiceAccountKey((string)key["client_email"], (string)key["private_key"], (string)key["private_key_id"], tokenUri, (string)key["project_id"]), null);
        }

        /// <summary>
        /// Check a project ID setting, adding a failure result if it isn't a project ID
        /// </summary>
        public static void ValidateProjectId(string projectId, List<ActionResult> results)
        {
            if (projectId == null)
            {
                results.Add(new ActionResult("Project ID is required, as the service account key doesn't give one.", false));
            }
            else if (!ValidProjectId.IsMatch(projectId))
            {
                results.Add(new ActionResult($"Project ID '{projectId}' isn't a Google Cloud project ID, e.g. my-project-123456.", false));
            }
        }

        /// <summary>
        /// A JWT for the service account, signed with its key, to exchange for an access token
        /// </summary>
        public static string CreateAssertion(ServiceAccountKey key, DateTimeOffset now)
        {
            var header = new JsonObject { ["alg"] = "RS256", ["typ"] = "JWT" };
            if (key.PrivateKeyId != null)
            {
                header["kid"] = key.PrivateKeyId;
            }

            var claims = new JsonObject
            {
                ["iss"] = key.ClientEmail,
                ["scope"] = Scope,
                ["aud"] = key.TokenUri.ToString(),
                ["iat"] = now.ToUnixTimeSeconds(),
                ["exp"] = now.AddMinutes(60).ToUnixTimeSeconds()
            };

            var unsigned = $"{Base64Url(Encoding.UTF8.GetBytes(header.ToJsonString()))}.{Base64Url(Encoding.UTF8.GetBytes(claims.ToJsonString()))}";

            using var rsa = RSA.Create();
            rsa.ImportFromPem(key.PrivateKeyPem);
            var signature = rsa.SignData(Encoding.ASCII.GetBytes(unsigned), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            return $"{unsigned}.{Base64Url(signature)}";
        }

        private static string Base64Url(byte[] data) => Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');

        /// <summary>
        /// Value for a Google Cloud label: lower case letters, numbers, '-' and '_', up to 63 characters
        /// </summary>
        public static string LabelValue(string value)
        {
            var label = Regex.Replace(value.ToLowerInvariant(), "[^a-z0-9_-]", "-");
            return label.Length > 63 ? label[..63] : label;
        }

        public sealed record ApiResponse(HttpStatusCode Status, JsonNode Body, string Error)
        {
            public bool IsSuccess => (int)Status >= 200 && (int)Status < 300;
        }

        /// <summary>
        /// Client for Google Cloud REST APIs, signed in as the service account. Errors are turned into messages, naming the permissions the task needs.
        /// </summary>
        public sealed class Api : IDisposable
        {
            private readonly HttpClient _http = new HttpClient { Timeout = TimeSpan.FromSeconds(60) };
            private readonly ServiceAccountKey _key;
            private readonly IReadOnlyList<string> _permissions;

            public Api(ServiceAccountKey key, IReadOnlyList<string> permissions)
            {
                _key = key;
                _permissions = permissions;
                _http.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            }

            /// <summary>
            /// Get an access token for the service account. Result is null if signed in, otherwise why not.
            /// </summary>
            public async Task<string> SignIn(CancellationToken cancellationToken)
            {
                using var content = new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    ["grant_type"] = "urn:ietf:params:oauth:grant-type:jwt-bearer",
                    ["assertion"] = CreateAssertion(_key, DateTimeOffset.UtcNow)
                });

                using var response = await _http.PostAsync(_key.TokenUri, content, cancellationToken);
                var json = Parse(await response.Content.ReadAsStringAsync(cancellationToken));

                var token = (string)json?["access_token"];
                if (response.IsSuccessStatusCode && token != null)
                {
                    _http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
                    return null;
                }

                var reason = (string)json?["error_description"] ?? (string)json?["error"] ?? $"{(int)response.StatusCode} {response.ReasonPhrase}";
                return $"Google Cloud didn't accept the service account key ({reason.TrimEnd('.')}). Check the key and its service account haven't been deleted or disabled.";
            }

            public async Task<ApiResponse> Send(HttpMethod method, string url, JsonNode body, CancellationToken cancellationToken)
            {
                using var request = new HttpRequestMessage(method, url);
                if (body != null)
                {
                    request.Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json");
                }

                using var response = await _http.SendAsync(request, cancellationToken);
                var json = Parse(await response.Content.ReadAsStringAsync(cancellationToken));

                if (response.IsSuccessStatusCode)
                {
                    return new ApiResponse(response.StatusCode, json, null);
                }

                var message = ((string)json?["error"]?["message"] ?? $"{(int)response.StatusCode} {response.ReasonPhrase}").TrimEnd('.');
                var error = response.StatusCode switch
                {
                    HttpStatusCode.Unauthorized => $"Google Cloud didn't accept the access token ({message}).",
                    HttpStatusCode.Forbidden when message.Contains("has not been used in project") || message.Contains("is disabled")
                        => $"{message}.",
                    HttpStatusCode.Forbidden => $"access denied ({message}). The service account needs the {JoinList(_permissions)} permissions.",
                    _ => $"{message}."
                };

                return new ApiResponse(response.StatusCode, json, error);
            }

            private static JsonNode Parse(string text)
            {
                try
                {
                    return string.IsNullOrWhiteSpace(text) ? null : JsonNode.Parse(text);
                }
                catch (JsonException)
                {
                    return null;
                }
            }

            private static string JoinList(IReadOnlyList<string> items)
                => items.Count <= 1 ? string.Concat(items) : $"{string.Join(", ", items.Take(items.Count - 1))} and {items.Last()}";

            public void Dispose() => _http.Dispose();
        }
    }
}
