using System;
using System.Collections.Generic;
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
    }
}

