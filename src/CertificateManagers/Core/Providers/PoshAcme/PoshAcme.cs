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
    public class PoshAcme : CertificateManagerBase, ICertificateManager
    {
        private string _settingsPath = "";
        private string _logPath = "";
        private ILogger _logger = default!;

        public static ProviderDefinition Definition
        {
            get
            {
                return new ProviderDefinition
                {
                    Id = "posh-acme",
                    Title = "Posh-ACME",
                    Description = "Queries local config for certificates managed by Posh-ACME (PowerShell)",
                    HelpUrl = "https://github.com/rmbolger/Posh-ACME"
                };
            }
        }

        public override void Init(ILogger logger, string settingsPath = "", string logPath = "")
        {
            _logger = logger;
            _settingsPath = settingsPath;
            _logPath = logPath;
        }

        public override ProviderDefinition GetProviderDefinition()
        {
            return Definition;
        }

        public override async Task<List<ManagedCertificate>> GetManagedCertificates(ManagedCertificateFilter? filter = null)
        {
            var list = new List<ManagedCertificate>();

            if (await IsPresent())
            {
                var directorySearch = new DirectoryInfo(_settingsPath);
                var configFiles = directorySearch.GetFiles("order.json", SearchOption.AllDirectories);

                foreach (var config in configFiles)
                {
                    try
                    {
                        var cfg = JsonUtils.Deserialize<ConfigSettings>(File.ReadAllText(config.FullName));

                        if (cfg != null)
                        {
                            var managedCert = new ManagedCertificate
                            {
                                Id = $"ext-posh-acme-{Certify.Management.Util.ToUrlSafeBase64String(cfg.Id)}",
                                Name = cfg.FriendlyName,
                                ItemType = ManagedCertificateType.SSL_ExternallyManaged,
                                SourceId = Definition.Id,
                                SourceName = Definition.Title,
                                //  CertificateThumbprintHash = lastSuccess?.Thumbprint,
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
                                new DomainOption{ Domain=cfg.MainDomain, IsPrimaryDomain=true, IsManualEntry=true, IsSelected = true}
                            }
                            };

                            if (managedCert.RequestConfig.SubjectAlternativeNames != null)
                            {
                                var domains = managedCert.RequestConfig.SubjectAlternativeNames.Where(d => d != managedCert.RequestConfig.PrimaryDomain).Distinct();
                                foreach (var d in domains)
                                {
                                    managedCert.DomainOptions.Add(new DomainOption { Domain = d, IsManualEntry = true, IsPrimaryDomain = false });
                                }
                            }

                            managedCert.IsChanged = false;
                            list.Add(managedCert);
                        }
                    }
                    catch (Exception exp)
                    {
                        System.Diagnostics.Debug.WriteLine($"Failed to parse config: [{config}] " + exp);
                    }
                }
            }

            return list;
        }

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
                return await Task.FromResult(true);
            }
            else
            {
                return await Task.FromResult(false);
            }
        }
    }
}
