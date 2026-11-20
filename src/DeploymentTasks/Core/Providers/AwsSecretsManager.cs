using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Amazon.Runtime;
using Amazon.SecretsManager;
using Amazon.SecretsManager.Model;
using Certify.Models;
using Certify.Models.Config;
using Certify.Models.Providers;
using Certify.Providers.Deployment.Core.Shared;

namespace Certify.Providers.DeploymentTasks
{
    /// <summary>
    /// Stores the certificate in AWS Secrets Manager as a JSON secret (certificate, private_key, chain, fullchain and optionally pfx). Each new
    /// certificate is added as a new version of the secret and becomes its current value. The version ID is derived from the secret value, so
    /// deploying the same certificate again changes nothing, and the task can tell the secret is up to date without reading its value.
    /// </summary>
    public class AwsSecretsManager : IDeploymentTaskProvider
    {
        public static DeploymentProviderDefinition Definition { get; }
        public DeploymentProviderDefinition GetDefinition(DeploymentProviderDefinition currentDefinition = null) => (currentDefinition ?? Definition);

        /// <summary>
        /// Tag added to secrets this task creates, holding the managed certificate ID, so a secret is not shared by two managed certificates
        /// </summary>
        public const string ManagedCertificateTag = "certify:managed-certificate-id";

        private const string CurrentStage = "AWSCURRENT";

        private static readonly Regex ValidArn = new Regex(@"^arn:[\w+=/,.@-]+:secretsmanager:([a-z0-9-]+):[0-9]{12}:secret:[\w/+=.@-]+$", RegexOptions.Compiled);
        private static readonly Regex ValidName = new Regex(@"^[\w/+=.@-]{1,512}$", RegexOptions.Compiled);

        private static readonly string[] Permissions = { "secretsmanager:DescribeSecret", "secretsmanager:CreateSecret", "secretsmanager:PutSecretValue", "secretsmanager:TagResource", "secretsmanager:UpdateSecretVersionStage" };

        private static readonly JsonSerializerOptions JsonOptions = new JsonSerializerOptions { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };

        static AwsSecretsManager()
        {
            Definition = new DeploymentProviderDefinition
            {
                Id = "Certify.Providers.DeploymentTasks.AwsSecretsManager",
                Title = "Deploy to AWS Secrets Manager",
                IsExperimental = false,
                UsageType = DeploymentProviderUsage.PostRequest,
                SupportedContexts = DeploymentContextType.ExternalCredential,
                ExternalCredentialType = CredentialTypes.AwsAccessKey,
                RequiresManagementHub = true,
                Description = "Store the certificate, private key and chain as a JSON secret in AWS Secrets Manager. Each renewal becomes the secret's current value, so applications reading the secret get the renewed certificate.",
                ProviderParameters = new List<ProviderParameter>
                {
                    new ProviderParameter{ Key="region", Name="AWS Region", IsRequired=false, IsCredential=false, Type= OptionType.String, Description="Region of the secret, e.g. eu-west-1. Not needed if the secret is given by ARN." },
                    new ProviderParameter{ Key="secret_id", Name="Secret Name or ARN", IsRequired=true, IsCredential=false, Type= OptionType.String, Description="e.g. prod/www.example.com/tls. A secret with this name is created if there isn't one." },
                    new ProviderParameter{ Key="kms_key_id", Name="KMS Key", IsRequired=false, IsCredential=false, Type= OptionType.String, Description="(optional) ID, ARN or alias of the KMS key to encrypt the secret with, used when the secret is created. Leave blank to use the AWS managed key (aws/secretsmanager)." },
                    new ProviderParameter{ Key="include_pfx", Name="Include PFX", IsRequired=false, IsCredential=false, Type= OptionType.Boolean, Value="false", Description="Also store the certificate as a base64 encoded PFX (PKCS#12) file in the 'pfx' field. It has the certificate's PFX password, if one is set." },
                    new ProviderParameter{ Key="secretsmanager_endpoint", Name="Secrets Manager Endpoint", IsRequired=false, IsCredential=false, Type= OptionType.String, Description="(optional) Custom Secrets Manager endpoint URL, such as a VPC endpoint or FIPS endpoint. Leave blank to use the standard endpoint for the region." },
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
        /// Check the task settings. In preview, also connect to Secrets Manager and report what deploying would change.
        /// </summary>
        public async Task<List<ActionResult>> Validate(DeploymentTaskExecutionParams execParams)
        {
            var results = new List<ActionResult>();
            var settings = GetSettings(execParams);

            if (settings.SecretId == null)
            {
                results.Add(new ActionResult("Secret Name or ARN is required.", false));
            }
            else if (settings.SecretId.StartsWith("arn:", StringComparison.Ordinal))
            {
                var arn = ValidArn.Match(settings.SecretId);
                if (!arn.Success)
                {
                    results.Add(new ActionResult("Secret ARN must be a Secrets Manager secret ARN, e.g. arn:aws:secretsmanager:eu-west-1:123456789012:secret:prod/www.example.com/tls-AbCdEf.", false));
                }
                else if (settings.RegionSetting != null && settings.RegionSetting != arn.Groups[1].Value)
                {
                    results.Add(new ActionResult($"AWS Region '{settings.RegionSetting}' doesn't match the region of the secret ARN ({arn.Groups[1].Value}). Leave AWS Region blank to use the region of the ARN.", false));
                }
            }
            else
            {
                if (!ValidName.IsMatch(settings.SecretId))
                {
                    results.Add(new ActionResult("Secret Name can only contain letters, numbers and the characters /_+=.@- and can be up to 512 characters long.", false));
                }

                if (settings.RegionSetting == null)
                {
                    results.Add(new ActionResult("AWS Region is required, unless the secret is given by ARN.", false));
                }
            }

            Aws.ValidateRegion(settings.RegionSetting, results);

            if (settings.EndpointText != null && settings.Endpoint == null)
            {
                results.Add(new ActionResult("Secrets Manager Endpoint must be blank or a full URL, e.g. https://secretsmanager-fips.us-east-1.amazonaws.com.", false));
            }

            Aws.ValidateAccessKey(Aws.GetAccessKey(execParams), results);

            if (execParams.IsPreviewOnly && !results.Any(r => !r.IsSuccess))
            {
                results.AddRange(await Deploy(execParams, apply: false));
            }

            return results;
        }

        /// <summary>
        /// Find the secret and check it can be written to, then (if applying) create it or make the certificate its current value
        /// </summary>
        private static async Task<List<ActionResult>> Deploy(DeploymentTaskExecutionParams execParams, bool apply)
        {
            var results = new List<ActionResult>();
            var settings = GetSettings(execParams);
            var log = execParams.Log;
            var cancellationToken = execParams.CancellationToken;
            var managedCert = ManagedCertificate.GetManagedCertificate(execParams.Subject);
            var region = settings.Region;

            var certificate = await NetworkDevice.LoadCertificate(execParams);
            if (!certificate.IsSuccess)
            {
                results.Add(new ActionResult(certificate.Message, false));
                return results;
            }

            if (certificate.Result == null && apply)
            {
                results.Add(new ActionResult("No certificate to deploy.", false));
                return results;
            }

            var secretValue = certificate.Result == null ? null : await SecretValue(certificate.Result, settings.IncludePfx ? managedCert.CertificatePath : null, cancellationToken);
            var versionId = secretValue == null ? null : VersionId(secretValue);

            try
            {
                using var client = new AmazonSecretsManagerClient(await Aws.SignIn(Aws.GetAccessKey(execParams), region, cancellationToken), Aws.Configure(new AmazonSecretsManagerConfig(), region, settings.Endpoint));

                var existing = await Describe(client, settings.SecretId, cancellationToken);

                if (existing == null && settings.IsArn)
                {
                    results.Add(new ActionResult($"AWS Secrets Manager: there is no secret {settings.SecretId}. Check the secret ARN, and that the access key belongs to the same AWS account.", false));
                    return results;
                }

                if (existing != null)
                {
                    var problem = CheckWritable(existing, managedCert.Id, region);
                    if (problem != null)
                    {
                        results.Add(new ActionResult($"AWS Secrets Manager: {problem}", false));
                        return results;
                    }

                    if (existing.RotationEnabled == true)
                    {
                        results.Add(new ActionResult($"AWS Secrets Manager: rotation is turned on for secret {existing.Name}, so its rotation function may replace the certificate. Turn off rotation for secrets that hold certificates.", true) { IsWarning = true });
                    }
                }

                var stages = existing?.VersionIdsToStages ?? new Dictionary<string, List<string>>();
                var hasVersion = versionId != null && stages.ContainsKey(versionId);
                var isCurrent = hasVersion && stages[versionId]?.Contains(CurrentStage) == true;
                var currentVersionId = stages.FirstOrDefault(s => s.Value?.Contains(CurrentStage) == true).Key;

                if (!apply)
                {
                    var preview = new StringBuilder($"Connected to AWS Secrets Manager in {region}. ");
                    if (isCurrent)
                    {
                        preview.Append($"Secret {existing.Name} already holds this certificate, so deploying would change nothing.");
                    }
                    else
                    {
                        preview.Append(secretValue == null ? "No certificate has been issued yet. Deploying would " : "Would ");
                        preview.Append(existing == null
                            ? $"create secret {settings.SecretId} holding the certificate{(settings.KmsKeyId != null ? $", encrypted with KMS key {settings.KmsKeyId}" : "")}."
                            : hasVersion
                                ? $"make version {versionId} of secret {existing.Name}, which already holds this certificate, its current value again."
                                : $"add the certificate as a new version of secret {existing.Name}, making it the current value.");
                    }

                    results.Add(new ActionResult(preview.ToString(), true));
                    return results;
                }

                if (existing == null)
                {
                    log?.Information($"AWS Secrets Manager: creating secret {settings.SecretId} in {region}");

                    var created = await client.CreateSecretAsync(new CreateSecretRequest
                    {
                        Name = settings.SecretId,
                        Description = "TLS certificate deployed by Certify The Web",
                        SecretString = secretValue,
                        ClientRequestToken = versionId,
                        KmsKeyId = settings.KmsKeyId,
                        Tags = new List<Tag> { new Tag { Key = ManagedCertificateTag, Value = managedCert.Id } }
                    }, cancellationToken);

                    results.Add(new ActionResult($"AWS Secrets Manager: created secret {created.ARN} holding the certificate. Later renewals become its current value.", true));
                }
                else if (isCurrent)
                {
                    results.Add(new ActionResult($"AWS Secrets Manager: secret {existing.ARN} is already up to date.", true));
                }
                else if (hasVersion)
                {
                    // putting a value again under an existing version ID is ignored, so move the current stage to that version instead
                    log?.Information($"AWS Secrets Manager: making version {versionId} of secret {existing.ARN} current again");

                    await client.UpdateSecretVersionStageAsync(new UpdateSecretVersionStageRequest
                    {
                        SecretId = existing.ARN,
                        VersionStage = CurrentStage,
                        MoveToVersionId = versionId,
                        RemoveFromVersionId = currentVersionId
                    }, cancellationToken);

                    results.Add(new ActionResult($"AWS Secrets Manager: secret {existing.ARN} already had this certificate as version {versionId}, which is now its current value again.", true));
                }
                else
                {
                    log?.Information($"AWS Secrets Manager: adding a new version of secret {existing.ARN}");

                    var put = await client.PutSecretValueAsync(new PutSecretValueRequest
                    {
                        SecretId = existing.ARN,
                        SecretString = secretValue,
                        ClientRequestToken = versionId
                    }, cancellationToken);

                    results.Add(new ActionResult($"AWS Secrets Manager: added the certificate to secret {put.ARN} as version {put.VersionId}, now its current value.", true));
                }

                return results;
            }
            catch (AmazonServiceException exp)
            {
                results.Add(new ActionResult($"AWS Secrets Manager: {Aws.DescribeError(exp, Permissions)}", false));
                return results;
            }
            catch (Exception exp) when (exp is AmazonClientException || exp is HttpRequestException)
            {
                results.Add(new ActionResult($"AWS Secrets Manager: could not connect to Secrets Manager in {region}: {exp.Message}", false));
                return results;
            }
            catch (TaskCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                results.Add(new ActionResult($"AWS Secrets Manager: request to Secrets Manager in {region} timed out.", false));
                return results;
            }
        }

        private static async Task<DescribeSecretResponse> Describe(AmazonSecretsManagerClient client, string secretId, CancellationToken cancellationToken)
        {
            try
            {
                return await client.DescribeSecretAsync(new DescribeSecretRequest { SecretId = secretId }, cancellationToken);
            }
            catch (ResourceNotFoundException)
            {
                return null;
            }
        }

        /// <summary>
        /// Why the certificate can't be written to an existing secret, or null if it can
        /// </summary>
        private static string CheckWritable(DescribeSecretResponse secret, string managedCertificateId, string region)
        {
            if (secret.DeletedDate != null)
            {
                return $"secret {secret.ARN} is scheduled for deletion. Restore it, or use a different secret name.";
            }

            if (!string.IsNullOrEmpty(secret.PrimaryRegion) && secret.PrimaryRegion != region)
            {
                return $"secret {secret.ARN} is a replica of a secret in {secret.PrimaryRegion}, so it can't be written to. Deploy to the secret in {secret.PrimaryRegion} instead, which updates its replicas.";
            }

            var owner = secret.Tags?.FirstOrDefault(t => t.Key == ManagedCertificateTag)?.Value;
            if (owner != null && owner != managedCertificateId)
            {
                return $"secret {secret.ARN} holds the certificate of a different managed certificate (its '{ManagedCertificateTag}' tag is {owner}). Use a different secret for each managed certificate.";
            }

            return null;
        }

        /// <summary>
        /// The secret value: a JSON object with the certificate, its private key (PKCS#8), the intermediates, the certificate and intermediates
        /// together, and optionally the PFX file. Roots are not included.
        /// </summary>
        private static async Task<string> SecretValue(DeviceCertificate cert, string pfxPath, CancellationToken cancellationToken)
        {
            var chain = string.Concat(cert.Intermediates.Select(i => i.Pem));

            var value = new JsonObject
            {
                ["certificate"] = cert.CertPem,
                ["private_key"] = Pkcs8PrivateKeyPem(cert.KeyPem),
                ["chain"] = chain,
                ["fullchain"] = cert.CertPem + chain
            };

            if (pfxPath != null)
            {
                value["pfx"] = Convert.ToBase64String(await File.ReadAllBytesAsync(pfxPath, cancellationToken));
            }

            return value.ToJsonString(JsonOptions);
        }

        /// <summary>
        /// Version ID for a secret value: a GUID from its hash, so the same value always has the same version ID
        /// </summary>
        private static string VersionId(string secretValue) => new Guid(SHA256.HashData(Encoding.UTF8.GetBytes(secretValue)).AsSpan(0, 16)).ToString();

        /// <summary>
        /// The key as PKCS#8 PEM, which applications and libraries most widely accept
        /// </summary>
        private static string Pkcs8PrivateKeyPem(string keyPem)
        {
            if (keyPem.Contains("BEGIN RSA PRIVATE KEY"))
            {
                using var rsa = RSA.Create();
                rsa.ImportFromPem(keyPem);
                return rsa.ExportPkcs8PrivateKeyPem();
            }

            if (keyPem.Contains("BEGIN EC PRIVATE KEY"))
            {
                using var ec = ECDsa.Create();
                ec.ImportFromPem(keyPem);
                return ec.ExportPkcs8PrivateKeyPem();
            }

            return keyPem;
        }

        private sealed record Settings(string RegionSetting, string SecretId, string KmsKeyId, bool IncludePfx, string EndpointText, Uri Endpoint)
        {
            public bool IsArn => SecretId?.StartsWith("arn:", StringComparison.Ordinal) == true;

            /// <summary>
            /// The region setting, or else the region of the secret ARN
            /// </summary>
            public string Region => RegionSetting ?? (IsArn && ValidArn.Match(SecretId) is { Success: true } m ? m.Groups[1].Value : null);
        }

        private static Settings GetSettings(DeploymentTaskExecutionParams execParams)
        {
            var parameters = execParams.Settings.Parameters;
            string value(string key) => parameters.FirstOrDefault(c => c.Key == key)?.Value?.Trim() is { Length: > 0 } v ? v : null;

            var endpointText = value("secretsmanager_endpoint");
            _ = bool.TryParse(value("include_pfx"), out var includePfx);

            return new Settings(value("region")?.ToLowerInvariant(), value("secret_id"), value("kms_key_id"), includePfx, endpointText, Aws.ParseEndpoint(endpointText));
        }
    }
}
