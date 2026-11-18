using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Certify.Models;

namespace Certify.Plugin.CertificateManagers.Utils
{
    /// <summary>
    /// Identifies the Certify certificate authority for an ACME endpoint recorded by another tool
    /// </summary>
    public static class CertificateAuthorityLookup
    {
        /// <summary>
        /// Find the certificate authority for an ACME endpoint. The endpoint can be a directory URL, a base URL, or
        /// a folder name derived from one (win-acme names its per-server folders after the host and path with the
        /// separators removed)
        /// </summary>
        /// <returns>The CA id and whether the endpoint is its staging endpoint, or null if no known CA matches</returns>
        public static (string CertificateAuthorityId, bool IsStaging)? FromEndpoint(string? endpoint) =>
            FromEndpoint(endpoint, CertificateAuthority.CoreCertificateAuthorities);

        /// <summary>
        /// Find the certificate authority for an ACME endpoint among the given certificate authorities, such as
        /// those configured on an instance
        /// </summary>
        public static (string CertificateAuthorityId, bool IsStaging)? FromEndpoint(string? endpoint, IEnumerable<CertificateAuthority> authorities)
        {
            if (string.IsNullOrWhiteSpace(endpoint))
            {
                return null;
            }

            var value = Normalise(endpoint);

            var exactMatches = new List<(string Id, bool IsStaging)>();
            var hostMatches = new List<(string Id, bool IsStaging)>();

            foreach (var ca in authorities.Where(c => !string.IsNullOrEmpty(c.Id)))
            {
                foreach (var (url, isStaging) in new[] { (ca.ProductionAPIEndpoint, false), (ca.StagingAPIEndpoint, true) })
                {
                    if (string.IsNullOrWhiteSpace(url) || !Uri.TryCreate(url, UriKind.Absolute, out var uri))
                    {
                        continue;
                    }

                    var path = uri.AbsolutePath.TrimEnd('/');
                    var basePath = path.EndsWith("/directory", StringComparison.OrdinalIgnoreCase) ? path[..^"/directory".Length] : path;

                    // the authority keeps a non default port, which win-acme also keeps in its folder names
                    if (value == Normalise(uri.Authority + path) || value == Normalise(uri.Authority + basePath))
                    {
                        exactMatches.Add((ca.Id!, isStaging));
                    }
                    else if (value == Normalise(uri.Host))
                    {
                        hostMatches.Add((ca.Id!, isStaging));
                    }
                }
            }

            if (exactMatches.Count > 0)
            {
                return exactMatches[0];
            }

            // several CAs can share a host (Sectigo DV, OV and EV), in which case the host alone does not say which
            return hostMatches.Select(m => m.Id).Distinct().Count() == 1 ? hostMatches[0] : null;
        }

        private static string Normalise(string value)
        {
            var text = value.Trim().ToLowerInvariant();
            var schemeEnd = text.IndexOf("://", StringComparison.Ordinal);

            if (schemeEnd >= 0)
            {
                text = text[(schemeEnd + 3)..];
            }

            var result = new StringBuilder(text.Length);

            foreach (var c in text)
            {
                if (char.IsLetterOrDigit(c) || c == '.' || c == '-')
                {
                    result.Append(c);
                }
            }

            return result.ToString();
        }
    }
}
