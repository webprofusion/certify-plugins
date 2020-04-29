using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Certify.Models;
using Certify.Models.Providers;
using Certify.Plugin.CertificateManagers.WinAcme;
using Certify.Providers;
using Newtonsoft.Json;

namespace Plugin.CertificateManagers
{
    public class WinAcme : ICertificateManager
    {
        private string _settingsPath = "";

        public WinAcme()
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
            List<ManagedCertificate> list = new List<ManagedCertificate>();
            if (await IsPresent())
            {
                var directorySearch = new DirectoryInfo(_settingsPath);
                var configFiles = directorySearch.GetFiles("*.renewal.json", SearchOption.AllDirectories);

                foreach (var config in configFiles)
                {
                    var cfg = JsonConvert.DeserializeObject<ConfigSettings>(File.ReadAllText(config.FullName));

                    var lastStatus = cfg.History?.LastOrDefault();
                    var lastSuccess = cfg.History.LastOrDefault(x => x.Success);

                    var managedCert = new ManagedCertificate
                    {
                        Id = "wacs://" + cfg.Id,
                        Name = "[win-acme] " + cfg.LastFriendlyName,
                        CertificateThumbprintHash = lastSuccess?.Thumbprint,
                        LastRenewalStatus = lastStatus.Success ? RequestState.Success : (lastStatus != null ? RequestState.Error : (RequestState?)null),
                        RequestConfig = new CertRequestConfig
                        {
                            PrimaryDomain = cfg.TargetPluginOptions?.CommonName,
                            SubjectAlternativeNames = cfg.TargetPluginOptions?.AlternativeNames.ToArray()
                        }
                    };

                    list.Add(managedCert);
                }

            }
            return list;
        }


        public async Task<bool> IsPresent()
        {
            var appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            var settingsPath = Path.Combine(appDataPath, "win-acme");

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
