using Certify.Models;
using Certify.Models.Config;
using Certify.Models.Providers;
using Certify.Providers.CertificateManagers;
using System;
using System.Collections.Generic;
using System.Linq;
using System.IO;
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
                    IsEnabled = true
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
        private Dictionary<string, Dictionary<string, string>> ParseIni(string ini)
        {
            var content = new Dictionary<string, Dictionary<string, string>>();

            if (!string.IsNullOrEmpty(ini))
            {
                var section = "Global";
                var lines = ini.Split('\n');
                foreach (var l in lines)
                {
                    try
                    {
                        if (l.StartsWith("["))
                        {
                            section = l.Replace("[", "").Replace("]", "").Trim();
                        }
                        else
                        {
                            if (!string.IsNullOrEmpty(l) && l.Contains("="))
                            {
                                var kv = l.Split('=');
                                content.TryGetValue(section, out var values);
                                if (values == null) values = new Dictionary<string, string>();
                                values.Add(kv[0].Trim(), kv[1].Trim());
                                content[section] = values;
                            }
                        }
                    }
                    catch (Exception exp)
                    {
                        System.Diagnostics.Debug.WriteLine("Error parsing certbot config: " + exp);
                    }
                }
            }
            return content;
        }

        public async Task<List<ManagedCertificate>> GetManagedCertificates(ManagedCertificateFilter filter = null)
        {
            var list = new List<ManagedCertificate>();

            if (await IsPresent())
            {
                var directorySearch = new DirectoryInfo(Path.Combine(_settingsPath, "renewal"));
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

                        var certFile = new FileInfo(Path.Combine(_settingsPath, "live", id, "cert.pem"));
                        if (certFile.Exists)
                        {
                            try
                            {
                                var cert = Certify.Management.CertificateManager.ReadCertificateFromPem(certFile.FullName);
                                var parsedCert = new System.Security.Cryptography.X509Certificates.X509Certificate2(cert.GetEncoded()); managedCert.DateStart = cert.NotBefore;
                                managedCert.DateExpiry = cert.NotAfter;
                                managedCert.DateRenewed = cert.NotBefore;
                                managedCert.DateLastRenewalAttempt = cert.NotBefore;
                                managedCert.CertificateThumbprintHash = parsedCert.Thumbprint;
                                managedCert.CertificatePath = certFile.FullName;
                                managedCert.LastRenewalStatus = RequestState.Success;

                                if (cert.NotAfter<DateTime.Now.AddDays(29))
                                {
                                    // assume certs with less than 30 days left have failed to renew
                                    managedCert.LastRenewalStatus = RequestState.Error;
                                    managedCert.RenewalFailureMessage = "Check certbot configuration. This certificate will expire in less than 30 days and has not yet automatically renewed.";
                                }

                                managedCert.RequestConfig = new CertRequestConfig
                                {
                                    PrimaryDomain = parsedCert.SubjectName.Name
                                };

                                var sn = ((System.Collections.ArrayList)cert.GetSubjectAlternativeNames());

                                List<string> sans = new List<string>();
                                foreach (System.Collections.ArrayList s in sn)
                                {
                                    sans.Add(s[1].ToString());
                                }

                                managedCert.RequestConfig.SubjectAlternativeNames = sans.ToArray();

                                managedCert.DomainOptions = new System.Collections.ObjectModel.ObservableCollection<DomainOption>
                                    {
                                        new DomainOption{
                                            Domain=managedCert.RequestConfig.PrimaryDomain,
                                            IsPrimaryDomain=true,
                                            IsManualEntry=true,
                                            IsSelected = true
                                        }
                                    };

                             
                            }
                            catch (Exception exp)
                            {
                                System.Diagnostics.Debug.WriteLine("Failed to parse cert: " + exp);
                            }
                        }

                        //var cfg = ParseIni(File.ReadAllText(config.FullName));
                       
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
