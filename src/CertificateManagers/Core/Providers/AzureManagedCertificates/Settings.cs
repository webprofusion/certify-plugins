using System.Collections.Generic;

namespace Certify.Plugin.CertificateManagers.Providers.AzureManagedCertificates
{
    /// <summary>
    /// Configuration settings for Azure Managed Certificates provider.
    /// </summary>
    public class AzureManagedCertificatesSettings
    {
        /// <summary>
        /// Azure Subscription ID to query for managed certificates.
        /// </summary>
        public string SubscriptionId { get; set; } = string.Empty;

        /// <summary>
        /// Optional: Specific resource groups to query. If empty, all resource groups will be queried.
        /// </summary>
        public List<string>? ResourceGroups { get; set; }

        /// <summary>
        /// Azure AD Tenant ID for service principal authentication.
        /// </summary>
        public string? TenantId { get; set; }

        /// <summary>
        /// Azure AD Client ID (Application ID) for service principal authentication.
        /// </summary>
        public string? ClientId { get; set; }

        /// <summary>
        /// Azure AD Client Secret for service principal authentication.
        /// </summary>
        public string? ClientSecret { get; set; }

        /// <summary>
        /// Client ID for managed identity authentication (optional).
        /// </summary>
        public string? ManagedIdentityClientId { get; set; }
    }
}
