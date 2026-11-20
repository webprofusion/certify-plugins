using System;
using System.Linq;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;

namespace Certify.Providers.Deployment.Core.Shared
{
    /// <summary>
    /// Trusting a server's TLS certificate by a CA certificate given in a credential, for servers with a private CA (e.g. a Kubernetes cluster CA)
    /// </summary>
    public static class TlsTrust
    {
        private static readonly Regex PemCertificate = new Regex("-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----", RegexOptions.Compiled | RegexOptions.Singleline);

        /// <summary>
        /// CA certificates from PEM, or from base64 encoded PEM as in a kubeconfig file. Line breaks in the PEM are not needed, as they may be
        /// lost when pasted into a single line field. Null if there are none or they can't be read.
        /// </summary>
        public static X509Certificate2Collection ParseCaCertificates(string text)
        {
            if (!text.Contains("-----BEGIN"))
            {
                try
                {
                    text = Encoding.ASCII.GetString(Convert.FromBase64String(Regex.Replace(text, @"\s", "")));
                }
                catch (FormatException)
                {
                    return null;
                }
            }

            try
            {
                var collection = new X509Certificate2Collection();
                foreach (Match pem in PemCertificate.Matches(text))
                {
                    collection.Add(X509CertificateLoader.LoadCertificate(Convert.FromBase64String(Regex.Replace(pem.Groups[1].Value, @"\s", ""))));
                }

                return collection.Count > 0 ? collection : null;
            }
            catch (Exception exp) when (exp is FormatException || exp is CryptographicException)
            {
                return null;
            }
        }

        /// <summary>
        /// Whether to accept a server's TLS certificate. With CA certificates, only a chain to one of them is trusted (as kubectl does),
        /// otherwise the system's trusted roots are used. The name must match either way.
        /// </summary>
        public static bool IsServerCertificateTrusted(X509Certificate2 certificate, X509Chain chain, SslPolicyErrors errors, X509Certificate2Collection caCertificates, bool allowInvalidTls)
        {
            if (allowInvalidTls)
            {
                return true;
            }

            if (caCertificates == null)
            {
                return errors == SslPolicyErrors.None;
            }

            if ((errors & ~SslPolicyErrors.RemoteCertificateChainErrors) != SslPolicyErrors.None)
            {
                return false;
            }

            using var custom = new X509Chain();
            custom.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            custom.ChainPolicy.CustomTrustStore.AddRange(caCertificates);
            custom.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            foreach (var element in chain?.ChainElements.Cast<X509ChainElement>() ?? Enumerable.Empty<X509ChainElement>())
            {
                custom.ChainPolicy.ExtraStore.Add(element.Certificate);
            }

            return custom.Build(certificate);
        }
    }
}
