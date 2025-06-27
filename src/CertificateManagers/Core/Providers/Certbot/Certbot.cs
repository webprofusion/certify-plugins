using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Certify.Models;
using Certify.Models.Config;
using Certify.Models.Providers;
using Certify.Plugin.CertificateManagers.Utils;
using Certify.Providers.CertificateManagers;
using Microsoft.Extensions.Logging;

namespace Certify.Plugin.CertificateManagers.Providers.Certbot
{
    public class Certbot : ICertificateManager
    {
        private string _settingsPath = "";
        private string _logPath = "";
        private ILogger _logger = default!;

        private string _nixLogPath = "/var/log/letsencrypt"; // sudo chmod 777 /var/log/letsencrypt/
        private string _nixSettingsPath = "/etc/letsencrypt";

        private string _winLogPath = "C:\\Certbot\\log";
        private string _winSettingsPath = "C:\\Certbot";

        public static ProviderDefinition Definition
        {
            get
            {
                return new ProviderDefinition
                {
                    Id = "certbot",
                    Title = "Certbot",
                    Description = "Queries local config for certificates managed by Certbot",
                    HelpUrl = "https://certbot.eff.org/",
                    IsEnabled = true
                };
            }
        }

        public ProviderDefinition GetProviderDefinition()
        {
            return Definition;
        }

        public void Init(ILogger logger, string settingsPath = "", string logPath = "")
        {
            _logger = logger;
            _settingsPath = settingsPath;
            _logPath = logPath;
        }

        private List<StatusLogResult> ParseLatestLogs(DateTimeOffset searchStart, List<string> searchIds)
        {
            var logPath = _logPath;

            var results = new List<StatusLogResult>();

            // parse recent log entries and associate them with item IDs

            var logDirectory = new DirectoryInfo(logPath);

            try
            {
                var logFiles = logDirectory.GetFiles("*.log.*", SearchOption.AllDirectories).OrderByDescending(f => f.LastWriteTime);

                // parse logs newest to oldest, stop when we find relevant entries for all search IDs
                foreach (var log in logFiles)
                {
                    var logContent = File.ReadAllText(log.FullName);

                    // parse log from end to start, attempting to identify success or failure status for each item with an associated ID and date/time

                    var logLines = logContent.Split('\n').Reverse();

                    var logResult = new StatusLogResult();

                    foreach (var line in logLines)
                    {
                        try
                        {
                            // parse log line

                            // check first item is a date, otherwise it is probably a continuation of the previous line
                            var firstItem = line.Split(',')[0];

                            if (DateTimeOffset.TryParse(firstItem, out var logDate))
                            {
                                logResult.StatusDate = logDate;

                                // look for status indicators, these vary between automated renewals and interactive cli usage
                                if (line.Contains(":Writing certificate to "))
                                {
                                    logResult.Status = "Success";

                                    foreach (var id in searchIds.Where(s => !results.Any(r => r.ItemId == s)))
                                    {
                                        if (line.Contains($"/{id}/"))
                                        {
                                            logResult.ItemId = id;
                                        }
                                    }
                                }
                                else if (line.Contains(":ERROR:") && line.Contains("Failed to renew"))
                                {
                                    logResult.Status = "Error";
                                    logResult.Message = line.Split(new[] { ".renewal:" }, StringSplitOptions.None)[1];

                                    foreach (var id in searchIds)
                                    {
                                        if (line.Contains($"Failed to renew certificate {id}"))
                                        {
                                            logResult.ItemId = id;
                                        }
                                    }
                                }

                                if (logResult.ItemId != null && !string.IsNullOrWhiteSpace(logResult.Status) && logResult.StatusDate != null)
                                {
                                    // add to results

                                    results.Add(logResult);

                                    logResult = new StatusLogResult();
                                }
                            }
                        }
                        catch (Exception exp)
                        {
                            _logger.LogError("Certbot: Error parsing log line: {line} {exp}", line, exp);
                        }
                    }
                }
            }
            catch (Exception exp)
            {
                _logger.LogError("Certbot: Error reading log files: {exp}", exp);
            }

            return results;
        }

        public async Task<List<ManagedCertificate>> GetManagedCertificates(ManagedCertificateFilter? filter = null)
        {
            var list = new List<ManagedCertificate>();

            if (await IsPresent())
            {
                var directorySearch = new DirectoryInfo(Path.Combine(_settingsPath, "renewal"));

                if (directorySearch.Exists)
                {
                    var configFiles = directorySearch.GetFiles("*.conf", SearchOption.AllDirectories);

                    foreach (var config in configFiles)
                    {
                        try
                        {
                            var id = config.Name.Replace(".conf", "");

                            var managedCert = new ManagedCertificate
                            {
                                Id = $"ext-certbot-{Certify.Management.Util.ToUrlSafeBase64String(id)}",
                                Name = id,
                                ItemType = ManagedCertificateType.SSL_ExternallyManaged,
                                SourceId = Definition.Id,
                                SourceName = Definition.Title
                            };

                            try
                            {
                                var renewalConfig = IniFileParser.Parse(File.ReadAllText(config.FullName), _logger);
                                managedCert.SourceName = $"certbot-{renewalConfig["_global"]["version"]}";
                            }
                            catch (Exception exp)
                            {
                                _logger.LogError("Failed to parse config: [{exp}] ", exp);
                            }

                            var certFile = new FileInfo(Path.Combine(_settingsPath, "live", id, "cert.pem"));
                            if (certFile.Exists)
                            {
                                try
                                {
                                    var cert = Certify.Management.CertificateManager.ReadCertificateFromPem(certFile.FullName);
                                    var certFileTimeUtc = certFile.LastWriteTimeUtc;

                                    var parsedCert = new System.Security.Cryptography.X509Certificates.X509Certificate2(cert.GetEncoded());

                                    managedCert.DateStart = new DateTimeOffset(cert.NotBefore);
                                    managedCert.DateExpiry = new DateTimeOffset(cert.NotAfter);
                                    managedCert.DateRenewed = new DateTimeOffset(certFileTimeUtc);
                                    managedCert.DateLastRenewalAttempt = new DateTimeOffset(certFileTimeUtc);
                                    managedCert.CertificateThumbprintHash = parsedCert.Thumbprint;
                                    managedCert.CertificatePath = certFile.FullName;
                                    managedCert.LastRenewalStatus = RequestState.Success;
                                    managedCert.CertificatePEM = File.ReadAllText(certFile.FullName);

                                    if (cert.NotAfter < DateTime.UtcNow.AddDays(29))
                                    {
                                        // assume certs with less than 30 days left have failed to renew
                                        managedCert.LastRenewalStatus = RequestState.Error;
                                        managedCert.RenewalFailureMessage = "Check certbot configuration. This certificate will expire in less than 30 days and has not yet automatically renewed.";
                                    }

                                    managedCert.RequestConfig = new CertRequestConfig
                                    {
                                        PrimaryDomain = parsedCert.SubjectName.Name.Replace("CN=", "").Trim()
                                    };

                                    var sn = cert.GetSubjectAlternativeNames();

                                    var sans = new List<string>();
                                    foreach (var s in sn)
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
                                    _logger.LogWarning("Failed to parse cert: {exp} ", exp);
                                }
                            }
                            else
                            {
                                _logger.LogWarning("Failed to access cert file {file}", certFile);
                            }

                            managedCert.IsChanged = false;
                            list.Add(managedCert);
                        }
                        catch (Exception exp)
                        {
                            _logger.LogError("Failed to parse config: [{exp}] " + exp);
                        }
                    }

                    // get latest log entries for each item
                    var lastLogResults = ParseLatestLogs(DateTimeOffset.UtcNow.AddDays(-1), list.Select(l => l.Name ?? "<none>").ToList()).OrderByDescending(l => l.StatusDate);

                    foreach (var item in list)
                    {
                        var logItem = lastLogResults.Where(l => l.ItemId == item.Name).FirstOrDefault(l => l.ItemId == item.Name);
                        if (logItem != null)
                        {
                            if (logItem.Status == "Success")
                            {
                                item.LastRenewalStatus = RequestState.Success;
                            }
                            else
                            {
                                item.LastRenewalStatus = RequestState.Error;
                                item.RenewalFailureMessage = logItem.Message;

                                // failure count is count of log items we found with final error status
                                item.RenewalFailureCount = lastLogResults.Where(l => l.ItemId == item.Name && l.Status == "Error").Count();
                            }
                        }
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

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                // certbot may use C:\Certbot or may have moved to appdata
                // https://github.com/certbot/certbot/issues/7872

                var settingsPath = _winSettingsPath;

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
                    return await Task.FromResult(true);
                }
                else
                {
                    return await Task.FromResult(false);
                }
            }
            else
            {
                var settingsPath = _nixSettingsPath;

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
    }
}
