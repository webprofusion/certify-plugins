using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Certify.Models;
using Certify.Models.Config;
using Certify.Plugin.CertificateManagers.Utils;
using Certify.Providers.CertificateManagers;
using Microsoft.Extensions.Logging;

namespace Certify.Plugin.CertificateManagers.Providers.PoshAcme
{
    /// <summary>
    /// Certificate manager for Posh-ACME (PowerShell) local config.
    /// </summary>
    public class PoshAcme : CertificateManagerBase, ICertificateManager
    {
        private string _settingsPath = string.Empty;
        private string _logPath = string.Empty;
        private ILogger _logger = default!;

        private const string ProviderId = "posh-acme";
        private const string ProviderTitle = "Posh-ACME";
        private const string OrderFileName = "order.json";

        /// <summary>
        /// Provider definition for Posh-ACME.
        /// </summary>
        public static ProviderDefinition Definition => new ProviderDefinition
        {
            Id = ProviderId,
            Title = ProviderTitle,
            Description = "Queries local config for certificates managed by Posh-ACME (PowerShell)",
            HelpUrl = "https://github.com/rmbolger/Posh-ACME"
        };

        /// <inheritdoc />
        public override void Init(ILogger logger, CertificateManagerPreference prefs)
        {
            _logger = logger;
            _settingsPath = prefs?.ConfigPath ?? "";
            _logPath = prefs?.LogPath ?? "";
        }

        /// <inheritdoc />
        public override ProviderDefinition GetProviderDefinition() => Definition;

        /// <inheritdoc />
        public override async Task<List<ManagedCertificate>> GetManagedCertificates(ManagedCertificateFilter? filter = null)
        {
            var managedCertificates = new List<ManagedCertificate>();

            if (!await IsPresent())
            {
                return managedCertificates;
            }

            var directorySearch = new DirectoryInfo(_settingsPath);
            var configFiles = directorySearch.GetFiles(OrderFileName, SearchOption.AllDirectories);

            foreach (var config in configFiles)
            {
                try
                {
                    var fileContent = File.ReadAllText(config.FullName);
                    var cfg = JsonUtils.Deserialize<ConfigSettings>(fileContent);

                    if (cfg is null)
                    {
                        continue;
                    }

                    var managedCert = new ManagedCertificate
                    {
                        Id = $"ext-posh-acme-{Certify.Management.Util.ToUrlSafeBase64String(cfg.Id)}",
                        Name = cfg.FriendlyName,
                        ItemType = ManagedCertificateType.SSL_ExternallyManaged,
                        SourceId = Definition.Id,
                        SourceName = Definition.Title,
                        DateRenewed = cfg.RenewAfter,
                        DateExpiry = cfg.CertExpires,
                        LastRenewalStatus = cfg.Status == "valid" ? RequestState.Success : cfg.Status != null ? RequestState.Error : null,
                        DateLastRenewalAttempt = config.LastWriteTime,
                        RequestConfig = new CertRequestConfig
                        {
                            PrimaryDomain = cfg.MainDomain,
                            SubjectAlternativeNames = cfg.SANs
                        },
                        DomainOptions = new System.Collections.ObjectModel.ObservableCollection<DomainOption>
                        {
                            new DomainOption
                            {
                                Domain = cfg.MainDomain,
                                IsPrimaryDomain = true,
                                IsManualEntry = true,
                                IsSelected = true
                            }
                        },
                        IsChanged = false
                    };

                    if (managedCert.RequestConfig.SubjectAlternativeNames is not null)
                    {
                        var domains = managedCert.RequestConfig.SubjectAlternativeNames
                            .Where(d => d != managedCert.RequestConfig.PrimaryDomain)
                            .Distinct();
                        foreach (var d in domains)
                        {
                            managedCert.DomainOptions.Add(new DomainOption
                            {
                                Domain = d,
                                IsManualEntry = true,
                                IsPrimaryDomain = false
                            });
                        }
                    }

                    var certDirectoryPath = Path.GetDirectoryName(config.FullName);
                    var certFileName = Path.Combine(certDirectoryPath, "cert.cer");
                    var certFile = new FileInfo(certFileName);

                    if (certFile.Exists)
                    {
                        PopulateManagedCertificateFromFile(_logger, managedCert, certFile);
                    }

                    managedCertificates.Add(managedCert);
                }
                catch (Exception exp)
                {
                    _logger?.LogWarning($"Failed to parse config: [{config.FullName}] {exp}");
                }
            }

            return managedCertificates;
        }

        /// <inheritdoc />
        public override async Task<bool> IsPresent()
        {
            if (!string.IsNullOrWhiteSpace(_settingsPath) && Directory.Exists(_settingsPath))
            {
                return true;
            }

            var settingsPath = Environment.GetEnvironmentVariable("POSHACME_HOME");

            if (string.IsNullOrEmpty(settingsPath))
            {
                var appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                settingsPath = Path.Combine(appDataPath, "Posh-ACME");
            }

            if (Directory.Exists(settingsPath))
            {
                _settingsPath = settingsPath;
                return true;
            }

            return false;
        }
    }
}
