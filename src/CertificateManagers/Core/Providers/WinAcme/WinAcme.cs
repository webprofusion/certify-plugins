using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Certify.Models;
using Certify.Models.Config;
using Certify.Models.Providers;
using Certify.Plugin.CertificateManagers.Utils;
using Certify.Plugin.CertificateManagers.WinAcme;
using Certify.Providers.CertificateManagers;
using Microsoft.Extensions.Logging;

namespace Certify.Plugin.CertificateManagers.Providers.WinAcme
{
    public class WinAcme : ICertificateManager
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
                    Id = "win-acme",
                    Title = "win-acme",
                    Description = "Queries local config for certificates managed by win-acme",
                    HelpUrl = "https://win-acme.com"
                };
            }
        }

        internal virtual string AppDataFolder => "win-acme";
        internal virtual string ProviderId => Definition.Id;
        internal virtual string ProviderTitle => Definition.Title;

        internal virtual string IdPrefix => Definition.Id;

        public void Init(ILogger logger, string settingsPath = "", string logPath = "")
        {
            _logger = logger;
            _settingsPath = settingsPath;
            _logPath = logPath;
        }

        public ProviderDefinition GetProviderDefinition()
        {
            return Definition;
        }

        public Task DeleteManagedCertificate(string id)
        {
            throw new NotImplementedException();
        }

        public Task<List<AccountDetails>> GetAccountRegistrations()
        {
            throw new NotImplementedException();
        }

        public Task<ManagedCertificate> GetManagedCertificate(string id)
        {
            throw new NotImplementedException();
        }

        private async Task<string> ReadAllTextAsync(string path)
        {
            using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, true))
            using (var reader = new StreamReader(stream))
            {
                return await reader.ReadToEndAsync().ConfigureAwait(false);
            }
        }

        public async Task<List<ManagedCertificate>> GetManagedCertificates(ManagedCertificateFilter? filter = null)
        {
            var list = new List<ManagedCertificate>();

            if (await IsPresent())
            {
                var directorySearch = new DirectoryInfo(_settingsPath);
                var configFiles = directorySearch.GetFiles("*.renewal.json", SearchOption.AllDirectories);

                foreach (var config in configFiles)
                {
                    try
                    {
                        var fileContent = await ReadAllTextAsync(config.FullName);
                        var cfg = JsonUtils.Deserialize<ConfigSettings>(fileContent);

                        if (cfg != null)
                        {
                            var lastStatus = cfg.History?.LastOrDefault();
                            var lastSuccess = cfg.History?.LastOrDefault(x => x.Success);

                            var managedCert = new ManagedCertificate
                            {
                                Id = $"ext-{IdPrefix}-{cfg.Id}",
                                Name = cfg.LastFriendlyName,
                                ItemType = ManagedCertificateType.SSL_ExternallyManaged,
                                SourceId = ProviderId,
                                SourceName = ProviderTitle,
                                CertificateThumbprintHash = lastSuccess?.Thumbprint,
                                DateRenewed = lastSuccess?.Date,
                                DateExpiry = lastSuccess?.Date != null ? lastSuccess.Date.Value.AddDays(90) : (DateTime?)null,
                                LastRenewalStatus = lastStatus?.Success == true ? RequestState.Success : (lastStatus != null ? RequestState.Error : (RequestState?)null),
                                DateLastRenewalAttempt = lastStatus?.Date,
                                RequestConfig = new CertRequestConfig
                                {
                                    PrimaryDomain = cfg.TargetPluginOptions?.CommonName,
                                    SubjectAlternativeNames = cfg.TargetPluginOptions?.AlternativeNames?.ToArray()
                                },
                                DomainOptions = new System.Collections.ObjectModel.ObservableCollection<DomainOption>
                        {
                            new DomainOption{ Domain=cfg.TargetPluginOptions?.CommonName, IsPrimaryDomain=true, IsManualEntry=true, IsSelected = true}
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
                        _logger.LogError(exp, $"Failed to parse config: [{config.FullName}]");
                    }
                }
            }

            return list;
        }

        public async Task<bool> IsPresent()
        {
            if (!string.IsNullOrWhiteSpace(_settingsPath) && Directory.Exists(_settingsPath))
            {
                return true;
            }

            var appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            var settingsPath = Path.Combine(appDataPath, AppDataFolder);

            if (Directory.Exists(settingsPath))
            {
                _settingsPath = settingsPath;
                return await Task.FromResult(true);
            }
            else
            {
                return false;
            }
        }

        public Task PerformCertificateCleanup()
        {
            throw new NotImplementedException();
        }

        public Task<CertificateRequestResult> PerformCertificateRequest(ILog log, ManagedCertificate managedCertificate, IProgress<RequestProgressState>? progress = null, bool resumePaused = false, bool skipRequest = false, bool failOnSkip = false)
        {
            throw new NotImplementedException();
        }

        public Task<List<CertificateRequestResult>> PerformRenewalAllManagedCertificates(RenewalSettings settings, Dictionary<string, Progress<RequestProgressState>>? progressTrackers = null)
        {
            throw new NotImplementedException();
        }

        public Task<ManagedCertificate> UpdateManagedCertificate(ManagedCertificate site)
        {
            throw new NotImplementedException();
        }
    }
}
