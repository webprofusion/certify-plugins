using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Certify.Models;
using Certify.Models.Config;
using Certify.Models.Providers;
using Microsoft.Extensions.Logging;

namespace Certify.Plugin.CertificateManagers.Utils
{
    public class CertificateManagerBase
    {
        public virtual Task DeleteManagedCertificate(string id) => throw new NotImplementedException();
        public virtual Task<List<AccountDetails>> GetAccountRegistrations() => throw new NotImplementedException();
        public virtual Task<ManagedCertificate> GetManagedCertificate(string id) => throw new NotImplementedException();
        public virtual Task<List<ManagedCertificate>> GetManagedCertificates(ManagedCertificateFilter? filter = null) => throw new NotImplementedException();
        public virtual ProviderDefinition GetProviderDefinition() => throw new NotImplementedException();
        public virtual void Init(ILogger logger, string settingsPath = "", string logPath = "") => throw new NotImplementedException();
        public virtual Task<bool> IsPresent() => throw new NotImplementedException();
        public virtual Task PerformCertificateCleanup() => throw new NotImplementedException();
        public virtual Task<CertificateRequestResult> PerformCertificateRequest(ILog log, ManagedCertificate managedCertificate, IProgress<RequestProgressState> progress = null, bool resumePaused = false, bool skipRequest = false, bool failOnSkip = false) => throw new NotImplementedException();
        public virtual Task<List<CertificateRequestResult>> PerformRenewalAllManagedCertificates(RenewalSettings settings, Dictionary<string, Progress<RequestProgressState>>? progressTrackers = null) => throw new NotImplementedException();
        public virtual Task<ManagedCertificate> UpdateManagedCertificate(ManagedCertificate site) => throw new NotImplementedException();

        public void PopulateManagedCertificateFromFile(ILogger log, ManagedCertificate managedCert, FileInfo certFile)
        {
            try
            {
                var cert = Certify.Management.CertificateManager.ReadCertificateFromPem(certFile.FullName);

                var parsedCert = X509CertificateLoader.LoadCertificate(cert.GetEncoded());

                managedCert.DateStart = new DateTimeOffset(cert.NotBefore);
                managedCert.DateExpiry = new DateTimeOffset(cert.NotAfter);
                managedCert.DateRenewed = new DateTimeOffset(cert.NotBefore);
                managedCert.DateLastRenewalAttempt = new DateTimeOffset(cert.NotBefore);
                managedCert.CertificateThumbprintHash = parsedCert.Thumbprint;
                managedCert.CertificatePath = certFile.FullName;
                managedCert.LastRenewalStatus = RequestState.Success;
                managedCert.CertificatePEM = File.ReadAllText(certFile.FullName);

                if (cert.NotAfter < DateTime.UtcNow.AddDays(29))
                {
                    // assume certs with less than 30 days left have failed to renew
                    managedCert.LastRenewalStatus = RequestState.Error;
                    managedCert.RenewalFailureMessage = "Check acme.sh configuration. This certificate will expire in less than 30 days and has not yet automatically renewed.";
                }

                managedCert.RequestConfig = new CertRequestConfig
                {
                    PrimaryDomain = parsedCert.SubjectName.Name
                };

                var sn = cert.GetSubjectAlternativeNames();

                var sans = new List<string>();
                foreach (var s in sn)
                {
                    if (s[1] != null)
                    {
                        sans.Add(s[1].ToString()!);
                    }
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
                log.LogWarning("Failed to parse cert: {exp} ", exp);
            }
        }
    }
}

