using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Certify.Models;
using Certify.Models.Config;
using Certify.Providers.DeploymentTasks;
using Certify.Shared.Core.Utils.PKI;

namespace Certify.Providers.Deployment.Core.Shared
{
    /// <summary>
    /// A certificate to deploy to a network device: the private key and end entity certificate as PEM, plus its intermediate certificates
    /// </summary>
    public class DeviceCertificate
    {
        /// <summary>
        /// Private key in PEM format (PKCS#1 for RSA, SEC1 for EC), unencrypted
        /// </summary>
        public string KeyPem { get; init; }

        /// <summary>
        /// End entity certificate in PEM format
        /// </summary>
        public string CertPem { get; init; }

        /// <summary>
        /// Intermediate certificates, in chain order from the issuer of the end entity certificate upwards (roots excluded)
        /// </summary>
        public List<DeviceCaCertificate> Intermediates { get; init; } = new();
    }

    public class DeviceCaCertificate
    {
        /// <summary>
        /// SHA-1 thumbprint, lower case hex. Used to name the certificate on the device, so the same intermediate is only added once
        /// </summary>
        public string Thumbprint { get; init; }
        public string Subject { get; init; }
        public string Pem { get; init; }
    }

    /// <summary>
    /// Settings and certificate handling shared by tasks which deploy to network devices (load balancers, firewalls etc) over their management API
    /// </summary>
    public static class NetworkDevice
    {
        private static readonly Regex PemCertBlock = new Regex("-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----", RegexOptions.Compiled);

        /// <summary>
        /// Parse a device management address (full http or https URL). Result is null if the address is not valid.
        /// </summary>
        public static Uri ParseAddress(string address)
        {
            if (Uri.TryCreate(address?.Trim().TrimEnd('/'), UriKind.Absolute, out var parsed) && (parsed.Scheme == Uri.UriSchemeHttps || parsed.Scheme == Uri.UriSchemeHttp))
            {
                return parsed;
            }

            return null;
        }

        /// <summary>
        /// Check a device address setting, adding a failure result if it is missing or not a full URL
        /// </summary>
        public static void ValidateAddress(string addressSetting, string settingName, List<ActionResult> results)
        {
            if (string.IsNullOrWhiteSpace(addressSetting))
            {
                results.Add(new ActionResult($"{settingName} is required.", false));
            }
            else if (ParseAddress(addressSetting) == null)
            {
                results.Add(new ActionResult($"{settingName} must be a full URL, e.g. https://192.168.1.10", false));
            }
        }

        /// <summary>
        /// HTTP client for a device management API. If allowed, the device's own TLS certificate is not checked (e.g. a default self-signed certificate).
        /// </summary>
        public static HttpClient CreateHttpClient(Uri baseAddress, bool allowInvalidTls)
        {
            var handler = new HttpClientHandler();
            if (allowInvalidTls)
            {
                handler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
            }

            return new HttpClient(handler)
            {
                BaseAddress = baseAddress,
                Timeout = TimeSpan.FromSeconds(60)
            };
        }

        /// <summary>
        /// Hint to add to a connection failure, when the device certificate may be the cause
        /// </summary>
        public static string ConnectionFailureHint(bool allowInvalidTls, string allowInvalidTlsSettingName)
            => allowInvalidTls ? "" : $" If the device uses a self-signed management certificate, enable '{allowInvalidTlsSettingName}'.";

        /// <summary>
        /// Load the managed certificate's key, certificate and intermediates. Result is null if no certificate has been issued yet.
        /// </summary>
        public static async Task<ActionResult<DeviceCertificate>> LoadCertificate(DeploymentTaskExecutionParams execParams)
        {
            var managedCert = ManagedCertificate.GetManagedCertificate(execParams.Subject);

            if (string.IsNullOrEmpty(managedCert?.CertificatePath) || !File.Exists(managedCert.CertificatePath))
            {
                return new ActionResult<DeviceCertificate> { IsSuccess = true };
            }

            var pwd = await ExportPassword.GetCertificatePassword(execParams, managedCert);
            if (!pwd.IsSuccess)
            {
                return new ActionResult<DeviceCertificate>(pwd.Message, false);
            }

            var pfxData = await File.ReadAllBytesAsync(managedCert.CertificatePath, execParams.CancellationToken);

            var intermediates = PemCertBlock.Matches(CertUtils.GetCertComponentsAsPEMString(pfxData, pwd.Result, ExportFlags.IntermediateCertificates))
                .Select(m =>
                {
                    using var cert = X509Certificate2.CreateFromPem(m.Value);
                    return new DeviceCaCertificate
                    {
                        Thumbprint = cert.Thumbprint.ToLowerInvariant(),
                        Subject = cert.GetNameInfo(X509NameType.SimpleName, false),
                        Pem = m.Value + "\n"
                    };
                })
                .ToList();

            return new ActionResult<DeviceCertificate>
            {
                IsSuccess = true,
                Result = new DeviceCertificate
                {
                    KeyPem = CertUtils.GetCertComponentsAsPEMString(pfxData, pwd.Result, ExportFlags.PrivateKey),
                    CertPem = CertUtils.GetCertComponentsAsPEMString(pfxData, pwd.Result, ExportFlags.EndEntityCertificate),
                    Intermediates = intermediates
                }
            };
        }
    }
}
