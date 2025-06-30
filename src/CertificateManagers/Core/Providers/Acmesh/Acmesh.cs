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

namespace Certify.Plugin.CertificateManagers.Providers.AcmeSh
{
    /// <summary>
    /// Certificate manager for acme.sh local config.
    /// </summary>
    public class AcmeSh : CertificateManagerBase, ICertificateManager
    {
        private string _settingsPath = string.Empty;
        private string _logPath = string.Empty;
        private ILogger _logger = default!;

        private const string NixLogPath = "~/.acme.sh";
        private const string NixSettingsPath = "~/.acme.sh";
        private const string WinLogPath = "C:\\acme.sh";
        private const string WinSettingsPath = "C:\\acme.sh";
        private const string ScriptFileName = "acme.sh";
        private const string ConfigFilePattern = "*.conf";

        /// <summary>
        /// Provider definition for acme.sh.
        /// </summary>
        public static ProviderDefinition Definition => new ProviderDefinition
        {
            Id = "acme.sh",
            Title = "acme.sh",
            Description = "Queries local config for certificates managed by acme.sh",
            HelpUrl = "https://acme.sh",
            IsEnabled = true
        };

        /// <inheritdoc />
        public override void Init(ILogger logger, string settingsPath = "", string logPath = "")
        {
            _logger = logger;
            _settingsPath = settingsPath;
            _logPath = logPath;
        }

        /// <inheritdoc />
        public override ProviderDefinition GetProviderDefinition() => Definition;

        /// <inheritdoc />
        public override async Task<List<ManagedCertificate>> GetManagedCertificates(ManagedCertificateFilter? filter = null)
        {
            var managedCertificates = new List<ManagedCertificate>();

            if (!await IsPresent())
            {
                return managedCertificates;
            }

            var directorySearch = new DirectoryInfo(_settingsPath);

            if (!directorySearch.Exists)
            {
                return managedCertificates;
            }

            // Get acme.sh script version if available
            var scriptVersion = "unknown";
            var scriptPath = Path.Combine(_settingsPath, ScriptFileName);

            if (File.Exists(scriptPath))
            {
                var acmeScript = File.ReadAllLines(scriptPath);

                if (acmeScript.Length > 2 && acmeScript[2].StartsWith("VER="))
                {
                    scriptVersion = acmeScript[2].Replace("VER=", string.Empty).Trim();
                }
            }

            var configFiles = directorySearch.GetFiles(ConfigFilePattern, SearchOption.AllDirectories);

            foreach (var config in configFiles)
            {
                try
                {
                    var settings = IniFileParser.Parse(File.ReadAllText(config.FullName), _logger);

                    if (!settings.ContainsKey("_global") || !settings["_global"].ContainsKey("Le_Domain"))
                    {
                        _logger.LogDebug("Skipping conf file {name}", config.FullName);
                        continue;
                    }

                    var id = settings["_global"]["Le_Domain"].Trim("' ".ToCharArray());
                    var renewalPath = Path.GetDirectoryName(config.FullName);

                    if (renewalPath == null)
                    {
                        continue;
                    }

                    var managedCert = new ManagedCertificate
                    {
                        Id = $"ext-acme.sh-{Certify.Management.Util.ToUrlSafeBase64String(id)}",
                        Name = id,
                        ItemType = ManagedCertificateType.SSL_ExternallyManaged,
                        SourceId = Definition.Id,
                        SourceName = $"{Definition.Title}-{scriptVersion}",
                        IsChanged = false
                    };

                    var certFile = new FileInfo(Path.Combine(renewalPath, $"{id}.cer"));

                    if (certFile.Exists)
                    {
                        PopulateManagedCertificateFromFile(_logger, managedCert, certFile);
                    }
                    else
                    {
                        _logger.LogWarning("Failed to access cert file {file}", certFile);
                    }

                    managedCertificates.Add(managedCert);
                }
                catch (Exception exp)
                {
                    _logger.LogError($"Failed to parse config: [{config.FullName}] {exp}");
                }
            }

            // Get latest log entries for each item
            var lastLogResults = ParseLatestLogs(DateTimeOffset.UtcNow.AddDays(-1), managedCertificates.Select(l => l.Name ?? "<none>").ToList())
                .OrderByDescending(l => l.StatusDate)
                .ToList();

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
                        item.RenewalFailureCount = lastLogResults.Count(l => l.ItemId == item.Name && l.Status == "Error");
                    }
                }
            }

            return managedCertificates;
        }

        /// <inheritdoc />
        public override async Task<bool> IsPresent()
        {
            if (!string.IsNullOrEmpty(_settingsPath) && Directory.Exists(_settingsPath))
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
                    return true;
                }

                var appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
                settingsPath = Path.Combine(appDataPath, "acme.sh");

                if (Directory.Exists(settingsPath))
                {
                    _settingsPath = settingsPath;
                    return true;
                }
            }
            else
            {
                settingsPath = NixSettingsPath;

                if (Directory.Exists(settingsPath))
                {
                    _settingsPath = settingsPath;
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
            var logPath = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? WinLogPath : NixLogPath;
            var results = new List<StatusLogResult>();

            var logDirectory = new DirectoryInfo(logPath);

            if (!logDirectory.Exists)
            {
                return results;
            }

            try
            {
                var logFiles = logDirectory.GetFiles("*.log.*", SearchOption.AllDirectories)
                    .OrderByDescending(f => f.LastWriteTime);

                foreach (var log in logFiles)
                {
                    var logContent = File.ReadAllText(log.FullName);
                    var logLines = logContent.Split('\n').Reverse();
                    var logResult = new StatusLogResult();

                    foreach (var line in logLines)
                    {
                        try
                        {
                            var dateToParse = line.Split(']')[0].Replace("[", "");
                            var compositeDate = string.Empty;

                            try
                            {
                                var year = dateToParse.Substring(dateToParse.Length - 4);
                                compositeDate = $"{dateToParse.Substring(0, 10)} {year} {dateToParse.Substring(11, 8)}";
                            }
                            catch
                            {
                                // Log line item doesn't start with a date
                            }

                            if (DateTimeOffset.TryParse(compositeDate, out var logDate))
                            {
                                logResult.StatusDate = logDate;

                                if (line.Contains("Your cert is in:"))
                                {
                                    logResult.Status = "Success";
                                }
                                else if (line.Contains("stopped retrying"))
                                {
                                    logResult.Status = "Error";
                                    logResult.Message = line.Split(']')[1].Trim();
                                }

                                if (logResult.ItemId == null)
                                {
                                    foreach (var id in searchIds)
                                    {
                                        if (line.Contains($"Renewing: '{id}'"))
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
                            _logger.LogError($"acme.sh: Error parsing log line: {line} {exp}");
                        }
                    }
                }
            }
            catch (Exception exp)
            {
                _logger.LogError($"acme.sh: Error reading log files: {exp}");
            }

            return results;
        }
    }
}
