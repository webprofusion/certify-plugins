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
    public class AcmeSh : CertificateManagerBase, ICertificateManager
    {
        private string _settingsPath = "";
        private string _logPath = "";
        private ILogger _logger = default!;

        private string _nixLogPath = "~/.acme.sh";
        private string _nixSettingsPath = "~/.acme.sh";

        private string _winLogPath = "C:\\acme.sh";
        private string _winSettingsPath = "C:\\acme.sh";

        public static ProviderDefinition Definition
        {
            get
            {
                return new ProviderDefinition
                {
                    Id = "acme.sh",
                    Title = "acme.sh",
                    Description = "Queries local config for certificates managed by acme.sh",
                    HelpUrl = "https://acme.sh",
                    IsEnabled = true
                };
            }
        }

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

        public override async Task<List<ManagedCertificate>> GetManagedCertificates(ManagedCertificateFilter? filter = null)
        {
            var list = new List<ManagedCertificate>();

            if (await IsPresent())
            {
                var directorySearch = new DirectoryInfo(Path.Combine(_settingsPath));

                if (directorySearch.Exists)
                {
                    var scriptPath = Path.Combine(_settingsPath, "acme.sh");
                    var scriptVersion = "unknown";
                    if (File.Exists(scriptPath))
                    {
                        var acmeScript = File.ReadAllText(scriptPath);
                        scriptVersion = acmeScript.Split('\n')[2].Replace("VER=", "").Trim();
                    }

                    var configFiles = directorySearch.GetFiles("*.conf", SearchOption.AllDirectories);

                    foreach (var config in configFiles)
                    {
                        try
                        {
                            var settings = IniFileParser.Parse(File.ReadAllText(config.FullName), _logger);

                            if (!settings.ContainsKey("_global") || !settings["_global"].ContainsKey("Le_Domain"))
                            {
                                // not a renewal config
                                _logger.LogDebug("Skipping conf file {name}", config.FullName);

                            }
                            else
                            {

                                var id = settings["_global"]["Le_Domain"].Trim("' ".ToCharArray());
                                var renewalPath = Path.GetDirectoryName(config.FullName);

                                if (renewalPath != null)
                                {
                                    var managedCert = new ManagedCertificate
                                    {
                                        Id = $"ext-acme.sh-{Certify.Management.Util.ToUrlSafeBase64String(id)}",
                                        Name = id,
                                        ItemType = ManagedCertificateType.SSL_ExternallyManaged,
                                        SourceId = Definition.Id,
                                        SourceName = $"{Definition.Title}-{scriptVersion}",
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

                                    managedCert.IsChanged = false;
                                    list.Add(managedCert);
                                }
                            }
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

        public override async Task<bool> IsPresent()
        {
            if (!string.IsNullOrEmpty(_settingsPath) && Directory.Exists(_settingsPath))
            {
                return true;
            }

            // certbot may use C:\Certbot or may have moved to appdata
            // https://github.com/certbot/certbot/issues/7872
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                var settingsPath = _winSettingsPath;

                if (Directory.Exists(settingsPath))
                {
                    _settingsPath = settingsPath;
                    return true;
                }

                // try app data
                var appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
                settingsPath = Path.Combine(appDataPath, "acme.sh");

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

        private List<StatusLogResult> ParseLatestLogs(DateTimeOffset searchStart, List<string> searchIds)
        {
            var logPath = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? _winLogPath : _nixLogPath;

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
                            var dateToParse = line.Split(']')[0].Replace("[", "");
                            var compositeDate = "";
                            try
                            {
                                // create new date string with date in right place
                                var year = dateToParse.Substring(dateToParse.Length - 4);
                                compositeDate = $"{dateToParse.Substring(0, 10)} {year} {dateToParse.Substring(11, 8)}";
                            }
                            catch
                            {
                                // log line item doesn't start with a date
                            }

                            if (DateTimeOffset.TryParse(compositeDate, out var logDate))  //"ddd MMM dd HH:mm:ss yyyy"
                            {
                                logResult.StatusDate = logDate;

                                // look for status indicators, these vary between automated renewals and interactive cli usage
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
                                    // add to results

                                    results.Add(logResult);

                                    logResult = new StatusLogResult();
                                }
                            }
                        }
                        catch (Exception exp)
                        {
                            _logger.LogError("acme.sh: Error parsing log line: {line} {exp}", line, exp);
                        }
                    }
                }
            }
            catch (Exception exp)
            {
                _logger.LogError("acme.sh: Error reading log files: {exp}", exp);
            }

            return results;
        }
    }
}
