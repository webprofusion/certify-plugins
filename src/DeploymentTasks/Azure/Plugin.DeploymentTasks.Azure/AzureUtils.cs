using System;
using Azure.Identity;
using Microsoft.Azure.Management.ResourceManager.Fluent;

namespace Plugin.DeploymentTasks.Azure
{
    internal class AzureUtils
    {

        internal static AzureEnvironment MapServiceToEnvironment(string service)
        {
            if (string.IsNullOrEmpty(service))
            {
                return AzureEnvironment.AzureGlobalCloud;
            }

            switch (service.Trim())
            {
                case "global":
                    return AzureEnvironment.AzureGlobalCloud;
                case "usgov":
                    return AzureEnvironment.AzureUSGovernment;
                case "china":
                    return AzureEnvironment.AzureChinaCloud;
                case "germany":
                    return AzureEnvironment.AzureGermanCloud;
                default:
                    return AzureEnvironment.FromName(service);
            }
        }

        /// <summary>
        /// True if the service has an authority host (blank uses the public cloud). Azure Germany has closed, so has none
        /// </summary>
        internal static bool IsSupportedAuthorityService(string service)
            => string.IsNullOrWhiteSpace(service) || service.Trim() is "global" or "usgov" or "china";

        internal static Uri MapServiceToAuthorityHost(string service)
        {
            if (string.IsNullOrEmpty(service))
            {
                return AzureAuthorityHosts.AzurePublicCloud;
            }

            switch (service.Trim())
            {
                case "global":
                    return AzureAuthorityHosts.AzurePublicCloud;
                case "usgov":
                    return AzureAuthorityHosts.AzureGovernment;
                case "china":
                    return AzureAuthorityHosts.AzureChina;
                case "germany":
                    throw new ArgumentException("Azure Germany has closed, choose Azure Cloud, Azure China or Azure US Government.", nameof(service));
                default:
                    return AzureAuthorityHosts.AzurePublicCloud;
            }
        }
    }
}
