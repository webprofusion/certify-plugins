using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Certify.Models;
using Certify.Models.Config;
using Certify.Plugin.CertificateManagers.Utils;
using Certify.Plugin.CertificateManagers.WinAcme;
using Certify.Providers.CertificateManagers;
using Microsoft.Extensions.Logging;

namespace Certify.Plugin.CertificateManagers.Providers.WinAcme
{
    public class WinAcme : CertificateManagerBase, ICertificateManager
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

                var certsPath = Path.Combine(_settingsPath, "Certificates");
                var certsDirectorySearch = new DirectoryInfo(certsPath);

                var certFiles = directorySearch.GetFiles(" *.pem", SearchOption.AllDirectories);

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
                                DateStart = lastSuccess?.Date,
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

                            // find all files in the certificates folder that match this managed cert   
                            /*
                               if (certFiles.Length > 0)
                               {
                                   // use the first file found
                                   var certFile = new FileInfo(certFiles.OrderBy(f => f.[0]));
                                   managedCert.CertificatePath = certFile.FullName;
                                   managedCert.CertificatePEM = await ReadAllTextAsync(certFile.FullName);
                                   // populate certificate details
                                   PopulateManagedCertificateFromFile(_logger, managedCert, certFile);
                               }
                               else
                               {
                                   _logger.LogWarning($"No certificate file found for managed certificate: {managedCert.Name}");
                               }*/

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

        public override async Task<bool> IsPresent()
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
    }
}
