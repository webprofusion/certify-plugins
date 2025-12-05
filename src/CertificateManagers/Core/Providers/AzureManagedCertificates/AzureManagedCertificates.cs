using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Azure.Core;
using Azure.Identity;
using Azure.ResourceManager;
using Azure.ResourceManager.AppService;
using Azure.ResourceManager.Resources;
using Certify.Models;
using Certify.Models.Config;
using Certify.Plugin.CertificateManagers.Utils;
using Certify.Providers.CertificateManagers;
using Microsoft.Extensions.Logging;

namespace Certify.Plugin.CertificateManagers.Providers.AzureManagedCertificates
{
    /// <summary>
    /// Certificate manager for Azure App Service Managed Certificates.
    /// </summary>
    public class AzureManagedCertificates : CertificateManagerBase, ICertificateManager
    {
        private ILogger _logger = default!;
        private AzureManagedCertificatesSettings _settings = new();
        private ArmClient? _armClient;

        /// <summary>
        /// Provider definition for Azure Managed Certificates.
        /// </summary>
        public static ProviderDefinition Definition => new ProviderDefinition
        {
            Id = "azure.managedcertificates",
            Title = "Azure Managed Certificates",
            Description = "Queries Azure for certificates managed by Azure App Service Managed Certificates",
            HelpUrl = "https://learn.microsoft.com/en-us/azure/app-service/configure-ssl-certificate#create-a-free-managed-certificate",
            IsEnabled = true
        };

        /// <inheritdoc />
        public override ProviderDefinition GetProviderDefinition() => Definition;

        /// <inheritdoc />
        public override void Init(ILogger logger, CertificateManagerPreference prefs)
        {
            _logger = logger;

            if (!string.IsNullOrEmpty(prefs?.ConfigPath))
            {
                try
                {
                    var settingsJson = File.ReadAllText(prefs.ConfigPath);
                    var settings = JsonUtils.Deserialize<AzureManagedCertificatesSettings>(settingsJson);

                    if (settings != null)
                    {
                        _settings = settings;
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError($"Failed to load Azure Managed Certificates settings from {prefs.ConfigPath}: {ex.Message}");
                }
            }
        }

        /// <inheritdoc />
        public override async Task<bool> IsPresent()
        {
            if (string.IsNullOrEmpty(_settings.SubscriptionId))
            {
                return false;
            }

            try
            {
                var client = GetArmClient();
                if (client == null)
                {
                    return false;
                }

                var subscription = await client.GetSubscriptionResource(
                    new ResourceIdentifier($"/subscriptions/{_settings.SubscriptionId}")
                ).GetAsync();

                return subscription != null;
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"Azure Managed Certificates: Unable to connect to Azure: {ex.Message}");
                return false;
            }
        }

        /// <inheritdoc />
        public override async Task<List<ManagedCertificate>> GetManagedCertificates(ManagedCertificateFilter? filter = null)
        {
            var managedCertificates = new List<ManagedCertificate>();

            if (!await IsPresent())
            {
                return managedCertificates;
            }

            try
            {
                var client = GetArmClient();
                if (client == null)
                {
                    _logger.LogError("Azure Managed Certificates: Failed to create ARM client");
                    return managedCertificates;
                }

                var subscriptionResource = client.GetSubscriptionResource(
                    new ResourceIdentifier($"/subscriptions/{_settings.SubscriptionId}")
                );

                // Get all resource groups or specific ones if configured
                var resourceGroups = new List<ResourceGroupResource>();

                if (_settings.ResourceGroups?.Any() == true)
                {
                    foreach (var rgName in _settings.ResourceGroups)
                    {
                        try
                        {
                            var rg = await subscriptionResource.GetResourceGroupAsync(rgName);
                            resourceGroups.Add(rg.Value);
                        }
                        catch (Exception ex)
                        {
                            _logger.LogWarning($"Azure Managed Certificates: Unable to access resource group {rgName}: {ex.Message}");
                        }
                    }
                }
                else
                {
                    await foreach (var rg in subscriptionResource.GetResourceGroups().GetAllAsync())
                    {
                        resourceGroups.Add(rg);
                    }
                }

                // Scan each resource group for App Service Managed Certificates
                foreach (var resourceGroup in resourceGroups)
                {
                    try
                    {

                        var certs = resourceGroup.GetAppCertificates().GetAllAsync();
                        await foreach (var cert in certs)
                        {
                            try
                            {
                                // Only process Azure Managed Certificates
                                if (cert.Data.ServerFarmId == null)
                                {
                                    continue;
                                }

                                var managedCert = new ManagedCertificate
                                {
                                    Id = $"ext-azure-mc-{Certify.Management.Util.ToUrlSafeBase64String(cert.Data.Id.ToString())}",
                                    Name = cert.Data.Name,
                                    ItemType = ManagedCertificateType.SSL_ExternallyManaged,
                                    SourceId = Definition.Id,
                                    SourceName = Definition.Title,
                                    Comments = $"Resource Group: {resourceGroup.Data.Name}"
                                };

                                // Populate certificate details
                                if (cert.Data.ExpireOn.HasValue)
                                {
                                    managedCert.DateExpiry = cert.Data.ExpireOn.Value;

                                    // Estimate issue date as 90 days before expiry (Azure certs are valid for 90 days)
                                    managedCert.DateStart = cert.Data.IssueOn;
                                    managedCert.DateRenewed = cert.Data.IssueOn;
                                    managedCert.DateLastRenewalAttempt = cert.Data.IssueOn;
                                }

                                managedCert.CertificateThumbprintHash = cert.Data.ThumbprintString;

                                // Determine renewal status based on expiry
                                if (cert.Data.ExpireOn.HasValue)
                                {
                                    var daysUntilExpiry = (cert.Data.ExpireOn.Value - DateTimeOffset.UtcNow).TotalDays;

                                    if (daysUntilExpiry < 30)
                                    {
                                        managedCert.LastRenewalStatus = RequestState.Error;
                                        managedCert.RenewalFailureMessage = $"Certificate expires in {(int)daysUntilExpiry} days. Azure Managed Certificates should auto-renew within 45 days of expiry.";
                                    }
                                    else
                                    {
                                        managedCert.LastRenewalStatus = RequestState.Success;
                                    }
                                }
                                else
                                {
                                    managedCert.LastRenewalStatus = RequestState.Success;
                                }

                                // Set domain information
                                managedCert.RequestConfig = new CertRequestConfig
                                {
                                    PrimaryDomain = cert.Data.SubjectName ?? cert.Data.Name
                                };

                                var sans = new List<string>();
                                if (cert.Data.HostNames != null)
                                {
                                    sans.AddRange(cert.Data.HostNames);
                                }

                                managedCert.RequestConfig.SubjectAlternativeNames = sans.ToArray();

                                managedCert.DomainOptions = new System.Collections.ObjectModel.ObservableCollection<DomainOption>
                                {
                                    new DomainOption
                                    {
                                        Domain = managedCert.RequestConfig.PrimaryDomain,
                                        IsPrimaryDomain = true,
                                        IsManualEntry = true,
                                        IsSelected = true
                                    }
                                };

                                managedCert.IsChanged = false;
                                managedCertificates.Add(managedCert);
                            }
                            catch (Exception ex)
                            {
                                _logger.LogError($"Azure Managed Certificates: Failed to process certificate {cert.Data.Name}: {ex.Message}");
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError($"Azure Managed Certificates: Failed to query certificates in resource group {resourceGroup.Data.Name}: {ex.Message}");
                    }
                }

                _logger.LogInformation($"Azure Managed Certificates: Found {managedCertificates.Count} managed certificates");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Azure Managed Certificates: Error querying certificates: {ex.Message}");
            }

            return managedCertificates;
        }

        /// <summary>
        /// Get or create the ARM client for Azure operations.
        /// </summary>
        private ArmClient? GetArmClient()
        {
            if (_armClient != null)
            {
                return _armClient;
            }

            try
            {
                TokenCredential credential;

                if (!string.IsNullOrEmpty(_settings.TenantId) &&
                    !string.IsNullOrEmpty(_settings.ClientId) &&
                    !string.IsNullOrEmpty(_settings.ClientSecret))
                {
                    // Use service principal authentication
                    credential = new ClientSecretCredential(
                        _settings.TenantId,
                        _settings.ClientId,
                        _settings.ClientSecret
                    );
                }
                else if (!string.IsNullOrEmpty(_settings.ManagedIdentityClientId))
                {
                    // Use managed identity
                    credential = new ManagedIdentityCredential(_settings.ManagedIdentityClientId);
                }
                else
                {
                    // Use default Azure credential (tries multiple methods)
                    credential = new DefaultAzureCredential();
                }

                _armClient = new ArmClient(credential);
                return _armClient;
            }
            catch (Exception ex)
            {
                _logger.LogError($"Azure Managed Certificates: Failed to create ARM client: {ex.Message}");
                return null;
            }
        }
    }
}
