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

            // items whose certificate file could not be read, so that a successful log entry does not replace the
            // reason the certificate itself is unavailable
            var certReadFailures = new HashSet<string>();

            var configFiles = renewalDir.GetFiles(ConfigFilePattern, SearchOption.AllDirectories);

            foreach (var config in configFiles)
            {
                try
                {
                    var id = config.Name.Replace(".conf", string.Empty);
                    var managedCert = new ManagedCertificate
                    {
                        Id = $"{ManagedCertificate.ExternalItemIdPrefix}certbot-{Certify.Management.Util.ToUrlSafeBase64String(id)}",
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

                            if (cert == null)
                            {
                                // the file could not be opened or did not contain a certificate we could read, so
                                // record the item with the reason and move on to the next renewal config
                                SetCertificateUnreadable(_logger, managedCert, certFile.FullName);
                                certReadFailures.Add(managedCert.Id!);

                                managedCert.IsChanged = false;
                                managedCertificates.Add(managedCert);
                                continue;
                            }

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
                            SetCertificateUnreadable(_logger, managedCert, certFile.FullName, exp);
                            certReadFailures.Add(managedCert.Id!);
                        }
                    }
                    else
                    {
                        SetCertificateUnreadable(_logger, managedCert, certFile.FullName);
                        certReadFailures.Add(managedCert.Id!);
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
                            // a successful renewal in the log does not help the user if we still cannot read the
                            // resulting certificate, so leave that problem reported against the item
                            if (certReadFailures.Contains(item.Id!))
                            {
                                continue;
                            }

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
        public override Task<bool> IsPresent()
        {
            ResolveDefaultPaths();

            return Task.FromResult(!string.IsNullOrWhiteSpace(_settingsPath) && Directory.Exists(_settingsPath));
        }

        /// <inheritdoc />
        public override async Task<string> ResolveLogPath()
        {
            if (string.IsNullOrWhiteSpace(_logPath))
            {
                // the log path is not configured, so use the default certbot log location for this machine
                await IsPresent();
            }

            return _logPath;
        }

        /// <summary>
        /// Populate the config and log paths from the default certbot locations for this machine, for whichever
        /// of them has not been configured. The config and log paths are resolved independently because either
        /// one can be configured on its own
        /// </summary>
        private void ResolveDefaultPaths()
        {
            var settingsPathIsUsable = !string.IsNullOrWhiteSpace(_settingsPath) && Directory.Exists(_settingsPath);

            if (settingsPathIsUsable && !string.IsNullOrWhiteSpace(_logPath))
            {
                return;
            }

            var candidates = new List<(string SettingsPath, string LogPath)>();

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                candidates.Add((WinSettingsPath, WinLogPath));

                var appDataSettingsPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "certbot");
                candidates.Add((appDataSettingsPath, Path.Combine(appDataSettingsPath, "log")));
            }
            else
            {
                candidates.Add((NixSettingsPath, NixLogPath));
            }

            foreach (var candidate in candidates)
            {
                if (!Directory.Exists(candidate.SettingsPath))
                {
                    continue;
                }

                if (!settingsPathIsUsable)
                {
                    _settingsPath = candidate.SettingsPath;
                }

                if (string.IsNullOrWhiteSpace(_logPath))
                {
                    _logPath = candidate.LogPath;
                }

                return;
            }
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
                // includes the current letsencrypt.log as well as the rotated letsencrypt.log.N files, and only
                // the most recent files are read as certbot retains up to 1000 of them by default
                var logFiles = logDirectory.GetFiles("*.log*", SearchOption.AllDirectories)
                    .OrderByDescending(f => f.LastWriteTime)
                    .Take(MaxLogFilesScanned);

                foreach (var log in logFiles)
                {
                    var logContent = File.ReadAllText(log.FullName);

                    var logLines = logContent.Split('\n');

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
