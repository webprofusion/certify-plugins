using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Amazon.CertificateManager;
using Amazon.CertificateManager.Model;
using Amazon.Runtime;
using Certify.Models;
using Certify.Models.Config;
using Certify.Models.Providers;
using Certify.Providers.Deployment.Core.Shared;

namespace Certify.Providers.DeploymentTasks
{
    /// <summary>
    /// Deploys a certificate to AWS Certificate Manager (ACM). Renewals re-import the certificate under the same ARN, so the AWS resources
    /// using it (load balancers, CloudFront distributions, API Gateway domains etc) pick it up. The certificate to re-import is the one
    /// given by ARN, otherwise the one this managed certificate was first imported as, found by a tag added on that first import.
    /// </summary>
    public class AwsCertificateManager : IDeploymentTaskProvider
    {
        public static DeploymentProviderDefinition Definition { get; }
        public DeploymentProviderDefinition GetDefinition(DeploymentProviderDefinition currentDefinition = null) => (currentDefinition ?? Definition);

        /// <summary>
        /// Tag added to certificates this task imports, holding the managed certificate ID, so renewals find the certificate to re-import
        /// </summary>
        public const string ManagedCertificateTag = "certify:managed-certificate-id";

        private static readonly Regex ValidArn = new Regex(@"^arn:[\w+=/,.@-]+:acm:([a-z0-9-]+):[0-9]{12}:certificate/[\w+=,.@-]+$", RegexOptions.Compiled);

        private static readonly string[] Permissions = { "acm:ListCertificates", "acm:ListTagsForCertificate", "acm:DescribeCertificate", "acm:ImportCertificate", "acm:AddTagsToCertificate" };

        // ListCertificates only returns RSA 2048 certificates unless other key types are asked for
        private static readonly List<string> AllKeyTypes = new List<string>
        {
            KeyAlgorithm.RSA_1024, KeyAlgorithm.RSA_2048, KeyAlgorithm.RSA_3072, KeyAlgorithm.RSA_4096,
            KeyAlgorithm.EC_prime256v1, KeyAlgorithm.EC_secp384r1, KeyAlgorithm.EC_secp521r1
        };

        static AwsCertificateManager()
        {
            Definition = new DeploymentProviderDefinition
            {
                Id = "Certify.Providers.DeploymentTasks.AwsCertificateManager",
                Title = "Deploy to AWS Certificate Manager",
                IsExperimental = false,
                UsageType = DeploymentProviderUsage.PostRequest,
                SupportedContexts = DeploymentContextType.ExternalCredential,
                ExternalCredentialType = CredentialTypes.AwsAccessKey,
                RequiresManagementHub = true,
                Description = "Import the certificate to AWS Certificate Manager (ACM). Renewals re-import it under the same ARN, so load balancers, CloudFront distributions and other AWS resources using it pick up each renewal.",
                ProviderParameters = new List<ProviderParameter>
                {
                    new ProviderParameter{ Key="region", Name="AWS Region", IsRequired=false, IsCredential=false, Type= OptionType.String, Description="Region to import the certificate to, e.g. eu-west-1. Use us-east-1 for CloudFront. Not needed if you set the Certificate ARN." },
                    new ProviderParameter{ Key="certificate_arn", Name="Certificate ARN", IsRequired=false, IsCredential=false, Type= OptionType.String, Description="(optional) ARN of an imported ACM certificate to replace, e.g. arn:aws:acm:eu-west-1:123456789012:certificate/... Leave blank to import a new certificate the first time, then re-import that one." },
                    new ProviderParameter{ Key="acm_endpoint", Name="ACM Endpoint", IsRequired=false, IsCredential=false, Type= OptionType.String, Description="(optional) Custom ACM endpoint URL, such as a VPC endpoint or FIPS endpoint. Leave blank to use the standard endpoint for the region." },
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
        /// Check the task settings. In preview, also connect to ACM and report what deploying would change.
        /// </summary>
        public async Task<List<ActionResult>> Validate(DeploymentTaskExecutionParams execParams)
        {
            var results = new List<ActionResult>();
            var settings = GetSettings(execParams);

            if (settings.Arn != null)
            {
                var arn = ValidArn.Match(settings.Arn);
                if (!arn.Success)
                {
                    results.Add(new ActionResult("Certificate ARN must be an ACM certificate ARN, e.g. arn:aws:acm:eu-west-1:123456789012:certificate/12345678-1234-1234-1234-123456789012.", false));
                }
                else if (settings.RegionSetting != null && settings.RegionSetting != arn.Groups[1].Value)
                {
                    results.Add(new ActionResult($"AWS Region '{settings.RegionSetting}' doesn't match the region of the Certificate ARN ({arn.Groups[1].Value}). Leave AWS Region blank to use the region of the ARN.", false));
                }
            }
            else if (settings.RegionSetting == null)
            {
                results.Add(new ActionResult("AWS Region is required, unless you set the Certificate ARN.", false));
            }

            Aws.ValidateRegion(settings.RegionSetting, results);

            if (settings.EndpointText != null && settings.Endpoint == null)
            {
                results.Add(new ActionResult("ACM Endpoint must be blank or a full URL, e.g. https://acm-fips.us-east-1.amazonaws.com.", false));
            }

            Aws.ValidateAccessKey(Aws.GetAccessKey(execParams), results);

            if (execParams.IsPreviewOnly && !results.Any(r => !r.IsSuccess))
            {
                results.AddRange(await Deploy(execParams, apply: false));
            }

            return results;
        }

        /// <summary>
        /// Find the certificate to re-import and check it can be, then (if applying) import the certificate
        /// </summary>
        private static async Task<List<ActionResult>> Deploy(DeploymentTaskExecutionParams execParams, bool apply)
        {
            var results = new List<ActionResult>();
            var settings = GetSettings(execParams);
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

            using var leaf = cert == null ? null : X509Certificate2.CreateFromPem(cert.CertPem);

            string keyAlgorithm = null;
            if (leaf != null)
            {
                keyAlgorithm = KeyAlgorithmOf(leaf);
                if (keyAlgorithm == null)
                {
                    results.Add(new ActionResult("AWS Certificate Manager: the certificate's key type isn't supported by ACM, which supports RSA 1024 to 4096 bit keys and EC P-256, P-384 and P-521 keys.", false));
                    return results;
                }
            }

            var region = settings.Region;
            var accessKey = Aws.GetAccessKey(execParams);

            try
            {
                using var client = new AmazonCertificateManagerClient(await Aws.SignIn(accessKey, region, cancellationToken), Aws.Configure(new AmazonCertificateManagerConfig(), region, settings.Endpoint));

                // the certificate to re-import, if there is one
                CertificateDetail existing;
                if (settings.Arn != null)
                {
                    existing = await Describe(client, settings.Arn, cancellationToken);
                    if (existing == null)
                    {
                        results.Add(new ActionResult($"AWS Certificate Manager: there is no certificate {settings.Arn}. Check the Certificate ARN, and that the access key belongs to the same AWS account.", false));
                        return results;
                    }

                    if (existing.Type != CertificateType.IMPORTED)
                    {
                        results.Add(new ActionResult($"AWS Certificate Manager: certificate {settings.Arn} was issued by AWS, not imported, so it can't be replaced by importing a certificate. Use the ARN of an imported certificate, or leave Certificate ARN blank to import a new one.", false));
                        return results;
                    }
                }
                else
                {
                    var found = await FindByTag(client, managedCert.Id, DomainNames(leaf, managedCert), log, cancellationToken);
                    existing = found == null ? null : await Describe(client, found, cancellationToken);
                }

                if (existing != null && keyAlgorithm != null && existing.KeyAlgorithm != keyAlgorithm)
                {
                    results.Add(new ActionResult($"AWS Certificate Manager: certificate {existing.CertificateArn} has an {DisplayName(existing.KeyAlgorithm)} key, but the new certificate has an {DisplayName(keyAlgorithm)} key. ACM can't change the key type of a certificate when it is re-imported. Change the key type of the managed certificate back to {DisplayName(existing.KeyAlgorithm)}, or import the certificate as a new ACM certificate by setting a new Certificate ARN or removing the '{ManagedCertificateTag}' tag from the existing one, then move the resources using it over.", false));
                    return results;
                }

                var upToDate = existing != null && leaf != null && SameSerial(existing.Serial, leaf.SerialNumber);
                var usedBy = existing == null ? "" : UsedBy(existing);

                if (!apply)
                {
                    var preview = new StringBuilder($"Connected to AWS Certificate Manager in {region}. ");
                    if (upToDate)
                    {
                        preview.Append($"Certificate {existing.CertificateArn} is already this certificate, so deploying would change nothing.");
                    }
                    else
                    {
                        preview.Append(cert == null ? "No certificate has been issued yet. Deploying would " : "Would ");
                        preview.Append(existing != null
                            ? $"re-import certificate {existing.CertificateArn} ({existing.DomainName}), keeping its ARN{usedBy}."
                            : $"import the certificate as a new ACM certificate, tagged so that renewals re-import it under the same ARN.");
                    }

                    results.Add(new ActionResult(preview.ToString(), true));
                    return results;
                }

                if (upToDate)
                {
                    results.Add(new ActionResult($"AWS Certificate Manager: certificate {existing.CertificateArn} is already up to date.", true));
                    return results;
                }

                var request = new ImportCertificateRequest
                {
                    Certificate = Pem(cert.CertPem),
                    PrivateKey = Pem(PrivateKeyPem(cert.KeyPem)),
                    CertificateChain = cert.Intermediates.Any() ? Pem(string.Concat(cert.Intermediates.Select(i => i.Pem))) : null
                };

                if (existing != null)
                {
                    // tags can't be applied when re-importing
                    request.CertificateArn = existing.CertificateArn;
                }
                else
                {
                    request.Tags = new List<Tag> { new Tag { Key = ManagedCertificateTag, Value = managedCert.Id } };
                }

                log?.Information(existing != null
                    ? $"AWS Certificate Manager: re-importing certificate {existing.CertificateArn}"
                    : $"AWS Certificate Manager: importing a new certificate in {region}");

                var response = await client.ImportCertificateAsync(request, cancellationToken);

                results.Add(new ActionResult(existing != null
                    ? $"AWS Certificate Manager: re-imported certificate {response.CertificateArn}{usedBy}."
                    : $"AWS Certificate Manager: imported the certificate as {response.CertificateArn}. Select it where it should be used, for example on a load balancer listener or CloudFront distribution. Later renewals re-import it under the same ARN.", true));

                return results;
            }
            catch (AmazonServiceException exp)
            {
                results.Add(new ActionResult($"AWS Certificate Manager: {Aws.DescribeError(exp, Permissions)}", false));
                return results;
            }
            catch (Exception exp) when (exp is AmazonClientException || exp is HttpRequestException)
            {
                results.Add(new ActionResult($"AWS Certificate Manager: could not connect to ACM in {region}: {exp.Message}", false));
                return results;
            }
            catch (TaskCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                results.Add(new ActionResult($"AWS Certificate Manager: request to ACM in {region} timed out.", false));
                return results;
            }
        }

        private static async Task<CertificateDetail> Describe(AmazonCertificateManagerClient client, string arn, CancellationToken cancellationToken)
        {
            try
            {
                return (await client.DescribeCertificateAsync(new DescribeCertificateRequest { CertificateArn = arn }, cancellationToken)).Certificate;
            }
            catch (ResourceNotFoundException)
            {
                return null;
            }
        }

        /// <summary>
        /// ARN of the imported certificate tagged with this managed certificate's ID. Only certificates sharing a domain name with it are
        /// checked, as each needs its own request for its tags. If there are several, the most recently imported one.
        /// </summary>
        private static async Task<string> FindByTag(AmazonCertificateManagerClient client, string managedCertificateId, HashSet<string> domains, ILog log, CancellationToken cancellationToken)
        {
            var candidates = new List<CertificateSummary>();
            string nextToken = null;

            do
            {
                var page = await client.ListCertificatesAsync(new ListCertificatesRequest
                {
                    Includes = new Filters { KeyTypes = AllKeyTypes },
                    NextToken = nextToken
                }, cancellationToken);

                candidates.AddRange((page.CertificateSummaryList ?? new List<CertificateSummary>())
                    .Where(c => c.Type == CertificateType.IMPORTED)
                    .Where(c => domains.Contains(c.DomainName ?? "") || (c.SubjectAlternativeNameSummaries ?? new List<string>()).Any(domains.Contains)));

                nextToken = page.NextToken;
            }
            while (!string.IsNullOrEmpty(nextToken));

            var tagged = new List<CertificateSummary>();
            foreach (var candidate in candidates)
            {
                var tags = await client.ListTagsForCertificateAsync(new ListTagsForCertificateRequest { CertificateArn = candidate.CertificateArn }, cancellationToken);
                if (tags.Tags?.Any(t => t.Key == ManagedCertificateTag && t.Value == managedCertificateId) == true)
                {
                    tagged.Add(candidate);
                }
            }

            if (tagged.Count > 1)
            {
                log?.Warning($"AWS Certificate Manager: {tagged.Count} certificates are tagged with this managed certificate, using the most recently imported one. Set the Certificate ARN to choose which one is re-imported.");
            }

            return tagged.OrderByDescending(c => c.ImportedAt ?? DateTime.MinValue).FirstOrDefault()?.CertificateArn;
        }

        /// <summary>
        /// Domain names of the certificate, or of the managed certificate if none has been issued yet
        /// </summary>
        private static HashSet<string> DomainNames(X509Certificate2 leaf, ManagedCertificate managedCert)
        {
            var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            if (leaf != null)
            {
                var cn = leaf.GetNameInfo(X509NameType.SimpleName, false);
                if (!string.IsNullOrEmpty(cn))
                {
                    names.Add(cn);
                }

                foreach (var san in leaf.Extensions.OfType<X509SubjectAlternativeNameExtension>())
                {
                    names.UnionWith(san.EnumerateDnsNames());
                }
            }
            else
            {
                names.UnionWith(managedCert.GetCertificateDomains());
            }

            return names;
        }

        /// <summary>
        /// ACM key algorithm name for the certificate's public key, or null if ACM doesn't support it
        /// </summary>
        private static string KeyAlgorithmOf(X509Certificate2 cert)
        {
            using var rsa = cert.GetRSAPublicKey();
            if (rsa != null)
            {
                return rsa.KeySize switch
                {
                    1024 => KeyAlgorithm.RSA_1024,
                    2048 => KeyAlgorithm.RSA_2048,
                    3072 => KeyAlgorithm.RSA_3072,
                    4096 => KeyAlgorithm.RSA_4096,
                    _ => null
                };
            }

            using var ec = cert.GetECDsaPublicKey();
            return ec?.ExportParameters(false).Curve.Oid.Value switch
            {
                "1.2.840.10045.3.1.7" => KeyAlgorithm.EC_prime256v1,
                "1.3.132.0.34" => KeyAlgorithm.EC_secp384r1,
                "1.3.132.0.35" => KeyAlgorithm.EC_secp521r1,
                _ => null
            };
        }

        private static string DisplayName(string keyAlgorithm) => keyAlgorithm switch
        {
            "EC_prime256v1" => "EC P-256",
            "EC_secp384r1" => "EC P-384",
            "EC_secp521r1" => "EC P-521",
            _ => keyAlgorithm?.Replace('_', ' ')
        };

        /// <summary>
        /// ACM shows serial numbers as colon separated hex bytes, e.g. 03:a1:...
        /// </summary>
        private static bool SameSerial(string acmSerial, string serialNumber)
            => !string.IsNullOrEmpty(acmSerial) && string.Equals(acmSerial.Replace(":", "").TrimStart('0'), serialNumber.TrimStart('0'), StringComparison.OrdinalIgnoreCase);

        private static string UsedBy(CertificateDetail detail)
        {
            var count = detail.InUseBy?.Count ?? 0;
            return count switch
            {
                0 => "",
                1 => ", so the AWS resource using it picks up the renewed certificate",
                _ => $", so the {count} AWS resources using it pick up the renewed certificate"
            };
        }

        /// <summary>
        /// The key as PEM, in the formats ACM documents: PKCS#8 for RSA keys, SEC1 for EC keys
        /// </summary>
        private static string PrivateKeyPem(string keyPem)
        {
            if (!keyPem.Contains("BEGIN RSA PRIVATE KEY"))
            {
                return keyPem;
            }

            using var rsa = RSA.Create();
            rsa.ImportFromPem(keyPem);
            return rsa.ExportPkcs8PrivateKeyPem();
        }

        private static MemoryStream Pem(string pem) => new MemoryStream(Encoding.ASCII.GetBytes(pem));

        private sealed record Settings(string RegionSetting, string Arn, string EndpointText, Uri Endpoint)
        {
            /// <summary>
            /// The region setting, or else the region of the certificate ARN
            /// </summary>
            public string Region => RegionSetting ?? (Arn == null ? null : ValidArn.Match(Arn) is { Success: true } m ? m.Groups[1].Value : null);
        }

        private static Settings GetSettings(DeploymentTaskExecutionParams execParams)
        {
            var parameters = execParams.Settings.Parameters;
            string value(string key) => parameters.FirstOrDefault(c => c.Key == key)?.Value?.Trim() is { Length: > 0 } v ? v : null;

            var endpointText = value("acm_endpoint");
            return new Settings(value("region")?.ToLowerInvariant(), value("certificate_arn"), endpointText, Aws.ParseEndpoint(endpointText));
        }
    }
}
