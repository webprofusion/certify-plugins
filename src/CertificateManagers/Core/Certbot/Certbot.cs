using Certify.Models;
using Certify.Models.Config;
using Certify.Models.Providers;
using Certify.Plugin.CertificateManagers.Certbot;
using Certify.Providers.CertificateManagers;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace Plugin.CertificateManagers
{
    public class Certbot : ICertificateManager
    {
        private string _settingsPath = "";
        public static ProviderDefinition Definition
        {
            get
            {
                return new ProviderDefinition
                {
                    Id = "Plugin.CertificateManagers.Certbot",
                    Title = "Certbot",
                    Description = "Queries local config for certificates managed by Certbot",
                    HelpUrl = "https://certbot.eff.org/",
                    IsEnabled = false
                };
            }
        }

        public Certbot()
        {

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

        public async Task<List<ManagedCertificate>> GetManagedCertificates(ManagedCertificateFilter filter = null)
        {
            var list = new List<ManagedCertificate>();

            if (await IsPresent())
            {
                var directorySearch = new DirectoryInfo(Path.Combine(_settingsPath,"renewal"));
                var configFiles = directorySearch.GetFiles("*.conf", SearchOption.AllDirectories);

                foreach (var config in configFiles)
                {
                    try
                    {
                        var id = config.Name.Replace(".conf", "");
                        var managedCert = new ManagedCertificate
                        {
                            Id = "certbot://" + id,
                            Name = id,
                            ItemType = ManagedCertificateType.SSL_ExternallyManaged,
                            SourceId = Definition.Id,
                            SourceName = Definition.Title
                        };
                        /*
                        var cfg = JsonConvert.DeserializeObject<ConfigSettings>(File.ReadAllText(config.FullName));

                        var lastStatus = cfg.History?.LastOrDefault();
                        var lastSuccess = cfg.History?.LastOrDefault(x => x.Success);

                        var managedCert = new ManagedCertificate
                        {
                            Id = "certbot://" + cfg.Id,
                            Name = cfg.LastFriendlyName,
                            ItemType = ManagedCertificateType.SSL_ExternallyManaged,
                            SourceId = Definition.Id,
                            SourceName = Definition.Title,
                            CertificateThumbprintHash = lastSuccess?.Thumbprint,
                            DateRenewed = lastSuccess?.Date,
                            DateExpiry = lastSuccess?.Date != null ? lastSuccess.Date.Value.AddDays(90) : (DateTime?)null,
                            LastRenewalStatus = lastStatus?.Success == true ? RequestState.Success : (lastStatus != null ? RequestState.Error : (RequestState?)null),
                            DateLastRenewalAttempt = lastStatus?.Date,
                            RequestConfig = new CertRequestConfig
                            {
                                PrimaryDomain = cfg.TargetPluginOptions?.CommonName,
                                SubjectAlternativeNames = cfg.TargetPluginOptions?.AlternativeNames.ToArray()
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


                        */
                        managedCert.IsChanged = false;
                        list.Add(managedCert);
                    }
                    catch (Exception exp)
                    {
                        System.Diagnostics.Debug.WriteLine($"Failed to parse config: [{config}] " + exp);
                    }
                }

            }
            return list;
        }


        public async Task<bool> IsPresent()
        {
            // certbot may use C:\Certbot or may have moved to appdata
            // https://github.com/certbot/certbot/issues/7872

            var settingsPath = "C:\\Certbot";

            if (Directory.Exists(settingsPath))
            {
                _settingsPath = settingsPath;
                return true;
            }

            // try app data
            var appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            settingsPath = Path.Combine(appDataPath, "certbot");

            if (Directory.Exists(settingsPath))
            {
                _settingsPath = settingsPath;
                return true;
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

        public Task<CertificateRequestResult> PerformCertificateRequest(ILog log, ManagedCertificate managedCertificate, IProgress<RequestProgressState> progress = null, bool resumePaused = false, bool skipRequest = false, bool failOnSkip = false)
        {
            throw new NotImplementedException();
        }

        public Task<List<CertificateRequestResult>> PerformRenewalAllManagedCertificates(RenewalSettings settings, Dictionary<string, Progress<RequestProgressState>> progressTrackers = null)
        {
            throw new NotImplementedException();
        }

        public Task<ManagedCertificate> UpdateManagedCertificate(ManagedCertificate site)
        {
            throw new NotImplementedException();
        }
    }
}
