using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Certify.Models;
using Certify.Models.Config;
using Certify.Plugin.CertificateManagers.Utils;
using Certify.Providers.CertificateManagers;
using Microsoft.Extensions.Logging;

namespace Certify.Plugin.CertificateManagers.Providers.Certbot
{
    /// <summary>
    /// Certificate manager for Certbot local config.
    /// </summary>
    public class Certbot : CertificateManagerBase, ICertificateManager
    {
        private string _settingsPath = string.Empty;
        private string _logPath = string.Empty;
        private ILogger _logger = default!;

        private const string NixLogPath = "/var/log/letsencrypt";
        private const string NixSettingsPath = "/etc/letsencrypt";
        private const string WinLogPath = "C:\\Certbot\\log";
        private const string WinSettingsPath = "C:\\Certbot";
        private const string RenewalFolder = "renewal";
        private const string LiveFolder = "live";
        private const string ConfigFilePattern = "*.conf";
        private const string CertFileName = "cert.pem";

        /// <summary>
        /// Provider definition for Certbot.
        /// </summary>
        public static ProviderDefinition Definition => new ProviderDefinition
        {
            Id = "certbot",
            Title = "Certbot",
            Description = "Queries local config for certificates managed by Certbot",
            HelpUrl = "https://certbot.eff.org/",
            IsEnabled = true
        };

        /// <inheritdoc />
        public override ProviderDefinition GetProviderDefinition() => Definition;

        /// <inheritdoc />
        public override void Init(ILogger logger, CertificateManagerPreference prefs)
        {
            _logger = logger;
            _settingsPath = prefs?.ConfigPath ?? "";
            _logPath = prefs?.LogPath ?? "";
        }

        /// <inheritdoc />
        public override async Task<List<ManagedCertificate>> GetManagedCertificates(ManagedCertificateFilter? filter = null)
        {

            if (!await IsPresent())
            {
                return [];
            }

            var renewalDir = new DirectoryInfo(Path.Combine(_settingsPath, RenewalFolder));

            if (!renewalDir.Exists)
            {
                _logger.LogWarning($"Certbot renewal directory not found: {renewalDir.FullName}");
                return [];
            }

            var managedCertificates = new List<ManagedCertificate>();

            var configFiles = renewalDir.GetFiles(ConfigFilePattern, SearchOption.AllDirectories);

            foreach (var config in configFiles)
            {
                try
                {
                    var id = config.Name.Replace(".conf", string.Empty);
                    var managedCert = new ManagedCertificate
                    {
                        Id = $"ext-certbot-{Certify.Management.Util.ToUrlSafeBase64String(id)}",
                        Name = id,
                        ItemType = ManagedCertificateType.SSL_ExternallyManaged,
                        SourceId = Definition.Id,
                        SourceName = Definition.Title
                    };

                    Dictionary<string, Dictionary<string, string>>? renewalConfig = null;

                    try
                    {
                        renewalConfig = IniFileParser.Parse(File.ReadAllText(config.FullName), _logger);

                        if (renewalConfig.TryGetValue("_global", out var globalConfig)
                            && globalConfig.TryGetValue("version", out var certbotVersion)
                            && !string.IsNullOrWhiteSpace(certbotVersion))
                        {
                            managedCert.SourceName = $"certbot-{certbotVersion}";
                        }
                    }
                    catch (Exception exp)
                    {
                        _logger.LogError($"Failed to parse config: [{config.FullName}] {exp}");
                    }

                    var certFilePath = Path.Combine(_settingsPath, LiveFolder, id, CertFileName);
                    string? configuredPath = null;

                    if (renewalConfig?.TryGetValue("_global", out var configItems) == true)
                    {
                        if (configItems.TryGetValue("cert", out var configuredCertPath) && !string.IsNullOrWhiteSpace(configuredCertPath))
                        {
                            configuredPath = configuredCertPath;
                        }
                        else if (configItems.TryGetValue("fullchain", out var configuredFullChainPath) && !string.IsNullOrWhiteSpace(configuredFullChainPath))
                        {
                            configuredPath = configuredFullChainPath;
                        }
                    }

                    if (!string.IsNullOrWhiteSpace(configuredPath))
                    {
                        var resolvedConfiguredPath = Path.IsPathRooted(configuredPath)
                            ? configuredPath
                            : Path.Combine(_settingsPath, configuredPath);

                        if (File.Exists(resolvedConfiguredPath))
                        {
                            certFilePath = resolvedConfiguredPath;
                        }
                        else
                        {
                            _logger.LogWarning($"Certbot configured cert path not found: {resolvedConfiguredPath}. Falling back to default live path for {id}.");
                        }
                    }

                    var certFile = new FileInfo(certFilePath);

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
                                // If cert has less than 30 days left, mark as failed to renew
                                managedCert.LastRenewalStatus = RequestState.Error;
                                managedCert.RenewalFailureMessage = "Check certbot configuration. This certificate will expire in less than 30 days and has not yet automatically renewed.";
                            }

                            managedCert.RequestConfig = new CertRequestConfig
                            {
                                PrimaryDomain = parsedCert.SubjectName.Name.Replace("CN=", string.Empty).Trim()
                            };

                            var sn = cert.GetSubjectAlternativeNames();
                            var sans = new List<string>();

                            foreach (var s in sn)
                            {
                                sans.Add(s[1].ToString());
                            }

                            managedCert.RequestConfig.SubjectAlternativeNames = sans.ToArray();

                            managedCert.DomainOptions =
                            [
                                new DomainOption
                                {
                                    Domain = managedCert.RequestConfig.PrimaryDomain,
                                    IsPrimaryDomain = true,
                                    IsManualEntry = true,
                                    IsSelected = true
                                }
                            ];
                        }
                        catch (Exception exp)
                        {
                            _logger.LogWarning($"Failed to parse cert: {exp}");
                        }
                    }
                    else
                    {
                        _logger.LogWarning($"Failed to access cert file {certFile.FullName}");
                    }

                    managedCert.IsChanged = false;
                    managedCertificates.Add(managedCert);
                }
                catch (Exception exp)
                {
                    _logger.LogError($"Failed to parse config: [{config.FullName}] {exp}");
                }
            }

            // Get latest log entries for each item
            try
            {
                var lastLogResults = ParseLatestLogs(DateTimeOffset.UtcNow.AddDays(-1), managedCertificates.Select(l => l.Name ?? "<none>").ToList())
                    .OrderByDescending(l => l.StatusDate);

                foreach (var item in managedCertificates)
                {
                    var logItem = lastLogResults.FirstOrDefault(l => l.ItemId == item.Name);

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
                            // Failure count is count of log items we found with final error status
                            item.RenewalFailureCount = lastLogResults.Count(l => l.ItemId == item.Name && l.Status == "Error");
                        }
                    }
                }
            }
            catch (Exception exp)
            {
                _logger.LogError($"Certbot: Error parsing logs from {_logPath}: {exp}");
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

            string settingsPath;

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                settingsPath = WinSettingsPath;

                if (Directory.Exists(settingsPath))
                {
                    _settingsPath = settingsPath;
                    _logPath = WinLogPath;
                    return true;
                }

                // Try app data
                var appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
                settingsPath = Path.Combine(appDataPath, "certbot");

                if (Directory.Exists(settingsPath))
                {
                    _settingsPath = settingsPath;
                    _logPath = Path.Combine(settingsPath, "log");
                    return true;
                }
            }
            else
            {
                settingsPath = NixSettingsPath;

                if (Directory.Exists(settingsPath))
                {
                    _settingsPath = settingsPath;
                    _logPath = NixLogPath;
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Parse recent log entries and associate them with item IDs.
        /// </summary>
        private List<StatusLogResult> ParseLatestLogs(DateTimeOffset searchStart, List<string> searchIds)
        {
            var logPath = _logPath;

            if (string.IsNullOrEmpty(logPath))
            {
                return [];
            }

            var logDirectory = new DirectoryInfo(logPath);

            if (!logDirectory.Exists)
            {
                return [];
            }

            var results = new List<StatusLogResult>();

            try
            {
                var logFiles = logDirectory.GetFiles("*.log.*", SearchOption.AllDirectories)
                    .OrderByDescending(f => f.LastWriteTime);

                foreach (var log in logFiles)
                {
                    var logContent = File.ReadAllText(log.FullName);

                    var logLines = logContent.Split('\n');
                    logLines.Reverse();

                    var logResult = new StatusLogResult();

                    foreach (var line in logLines)
                    {
                        try
                        {
                            // Parse log line for date and status
                            var firstItem = line.Split(',')[0];

                            if (DateTimeOffset.TryParse(firstItem, out var logDate))
                            {
                                logResult.StatusDate = logDate;

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
                                    var parts = line.Split(new[] { ".renewal:" }, StringSplitOptions.None);
                                    logResult.Message = parts.Length > 1 ? parts[1] : string.Empty;

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
                                    results.Add(logResult);
                                    logResult = new StatusLogResult();
                                }
                            }
                        }
                        catch (Exception exp)
                        {
                            _logger.LogError($"Certbot: Error parsing log line: {line} {exp}");
                        }
                    }
                }
            }
            catch (Exception exp)
            {
                _logger.LogError($"Certbot: Error reading log files: {exp}");
            }

            return results;
        }
    }
}
