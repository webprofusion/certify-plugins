using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Amazon;
using Amazon.Runtime;
using Amazon.SecurityToken;
using Certify.Models.Config;
using Certify.Providers.DeploymentTasks;
using AssumeRoleRequest = Amazon.SecurityToken.Model.AssumeRoleRequest;

namespace Certify.Providers.Deployment.Core.Shared
{
    /// <summary>
    /// Settings, sign in and error handling shared by tasks which deploy to AWS services with an AWS Access Key credential
    /// </summary>
    public static class Aws
    {
        public static readonly Regex ValidRegion = new Regex("^[a-z]{2}(-[a-z]+)+-[0-9]+$", RegexOptions.Compiled);

        /// <summary>
        /// An AWS Access Key credential (see <see cref="CredentialTypes.AwsAccessKey"/>)
        /// </summary>
        public sealed record AccessKey(string AccessKeyId, string SecretKey, bool AssumeRole, string RoleArn, string SessionName, string ExternalId);

        /// <summary>
        /// The task's AWS Access Key credential, or null if it has none
        /// </summary>
        public static AccessKey GetAccessKey(DeploymentTaskExecutionParams execParams)
        {
            var credentials = execParams.Credentials;
            string value(string key) => credentials?.TryGetValue(key, out var v) == true && !string.IsNullOrWhiteSpace(v) ? v.Trim() : null;

            var accessKeyId = value("accesskey");
            var secretKey = credentials?.GetValueOrDefault("secretaccesskey");
            if (accessKeyId == null || string.IsNullOrEmpty(secretKey))
            {
                return null;
            }

            _ = bool.TryParse(value("useassumerole"), out var assumeRole);

            return new AccessKey(accessKeyId, secretKey, assumeRole, value("rolearn"), value("rolesessionname") ?? "CertifyTheWeb", value("externalid"));
        }

        /// <summary>
        /// Check the task has a usable AWS Access Key credential, adding a failure result if not
        /// </summary>
        public static void ValidateAccessKey(AccessKey accessKey, List<ActionResult> results)
        {
            if (accessKey == null)
            {
                results.Add(new ActionResult("An AWS Access Key credential is required.", false));
            }
            else if (accessKey.AssumeRole && accessKey.RoleArn == null)
            {
                results.Add(new ActionResult("The AWS Access Key credential has Assume IAM role enabled, but no Role ARN.", false));
            }
        }

        /// <summary>
        /// Check a region setting, adding a failure result if it is set but is not a region code
        /// </summary>
        public static void ValidateRegion(string region, List<ActionResult> results)
        {
            if (region != null && !ValidRegion.IsMatch(region))
            {
                results.Add(new ActionResult("AWS Region must be a region code, e.g. us-east-1 or eu-west-1.", false));
            }
        }

        /// <summary>
        /// Parse a custom service endpoint setting (full http or https URL). Result is null if the setting is not valid.
        /// </summary>
        public static Uri ParseEndpoint(string endpoint)
            => Uri.TryCreate(endpoint, UriKind.Absolute, out var uri) && (uri.Scheme == Uri.UriSchemeHttps || uri.Scheme == Uri.UriSchemeHttp) ? uri : null;

        /// <summary>
        /// Apply the region, or a custom endpoint signed for the region, to a service client configuration
        /// </summary>
        public static T Configure<T>(T config, string region, Uri endpoint) where T : ClientConfig
        {
            if (endpoint != null)
            {
                config.ServiceURL = endpoint.ToString();
                config.AuthenticationRegion = region;
            }
            else
            {
                config.RegionEndpoint = RegionEndpoint.GetBySystemName(region);
            }

            return config;
        }

        /// <summary>
        /// AWS credentials for the access key, or for the IAM role it assumes
        /// </summary>
        public static async Task<AWSCredentials> SignIn(AccessKey accessKey, string region, CancellationToken cancellationToken)
        {
            AWSCredentials credentials = new BasicAWSCredentials(accessKey.AccessKeyId, accessKey.SecretKey);

            if (!accessKey.AssumeRole)
            {
                return credentials;
            }

            using var sts = new AmazonSecurityTokenServiceClient(credentials, new AmazonSecurityTokenServiceConfig { RegionEndpoint = RegionEndpoint.GetBySystemName(region) });

            var role = await sts.AssumeRoleAsync(new AssumeRoleRequest
            {
                RoleArn = accessKey.RoleArn,
                RoleSessionName = accessKey.SessionName,
                DurationSeconds = 900,
                ExternalId = accessKey.ExternalId
            }, cancellationToken);

            return new SessionAWSCredentials(role.Credentials.AccessKeyId, role.Credentials.SecretAccessKey, role.Credentials.SessionToken);
        }

        /// <summary>
        /// Error message for a failed AWS request. Sign in and permission failures say what to check, naming the permissions the task needs.
        /// </summary>
        public static string DescribeError(AmazonServiceException exp, IEnumerable<string> permissions)
        {
            var message = exp.Message?.TrimEnd('.');

            return exp.ErrorCode switch
            {
                "UnrecognizedClientException" or "InvalidClientTokenId" or "InvalidSignatureException" or "SignatureDoesNotMatch"
                    => $"access denied ({message}). Check the Access Key ID and Secret Access Key of the AWS Access Key credential.",
                "AccessDeniedException" or "AccessDenied"
                    => $"access denied ({message}). The IAM user or role needs the {JoinList(permissions.ToList())} permissions.",
                _ => $"{exp.ErrorCode}: {message}."
            };
        }

        private static string JoinList(List<string> items)
            => items.Count <= 1 ? string.Concat(items) : $"{string.Join(", ", items.Take(items.Count - 1))} and {items.Last()}";
    }
}
