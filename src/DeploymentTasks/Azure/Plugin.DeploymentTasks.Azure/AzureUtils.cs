using Azure.Identity;
using Microsoft.Azure.Management.ResourceManager.Fluent;
using System;

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
                    return AzureAuthorityHosts.AzureGermany;
                default:
                    return AzureAuthorityHosts.AzurePublicCloud;
            }
        }
    }
}
