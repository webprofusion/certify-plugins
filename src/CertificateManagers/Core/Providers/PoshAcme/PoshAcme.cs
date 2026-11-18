using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Certify.Models;
using Certify.Models.Config;
using Certify.Plugin.CertificateManagers.Utils;
using Certify.Providers.CertificateManagers;
using Microsoft.Extensions.Logging;

namespace Certify.Plugin.CertificateManagers.Providers.PoshAcme
{
    /// <summary>
    /// Certificate manager for Posh-ACME (PowerShell) local config.
    /// </summary>
    public partial class PoshAcme : CertificateManagerBase, ICertificateManager
    {
        private string _settingsPath = string.Empty;
        private string _logPath = string.Empty;
        private ILogger _logger = default!;

        private const string ProviderId = "posh-acme";
        private const string ProviderTitle = "Posh-ACME";
        private const string OrderFileName = "order.json";
        private const string ConfigFolderName = "Posh-ACME";

        /// <summary>
        /// Provider definition for Posh-ACME.
        /// </summary>
        public static ProviderDefinition Definition => new ProviderDefinition
        {
            Id = ProviderId,
            Title = ProviderTitle,
            Description = "Queries local config for certificates managed by Posh-ACME (PowerShell)",
            HelpUrl = "https://github.com/rmbolger/Posh-ACME"
        };

        /// <inheritdoc />
        public override void Init(ILogger logger, CertificateManagerPreference prefs)
        {
            _logger = logger;
            _settingsPath = prefs?.ConfigPath ?? "";
            _logPath = prefs?.LogPath ?? "";
        }

        /// <inheritdoc />
        public override ProviderDefinition GetProviderDefinition() => Definition;

        /// <summary>
        /// Posh-ACME is a PowerShell module which reports to the host rather than to a log file of its own, so
        /// entries are only available if the user has configured a path where their scripts write output
        /// </summary>
        public override Task<string> ResolveLogPath() => Task.FromResult(_logPath);

        /// <inheritdoc />
        public override async Task<List<ManagedCertificate>> GetManagedCertificates(ManagedCertificateFilter? filter = null)
        {
            var managedCertificates = new List<ManagedCertificate>();

            if (!await IsPresent())
            {
                return managedCertificates;
            }

            var directorySearch = new DirectoryInfo(_settingsPath);
            var configFiles = directorySearch.GetFiles(OrderFileName, SearchOption.AllDirectories);
            var serverUrls = new Dictionary<string, string?>();

            foreach (var config in configFiles)
            {
                try
                {
                    var fileContent = File.ReadAllText(config.FullName);
                    var cfg = JsonUtils.Deserialize<ConfigSettings>(fileContent);

                    if (cfg is null)
                    {
                        continue;
                    }

                    var managedCert = new ManagedCertificate
                    {
                        Id = ItemIdFor(cfg.Id),
                        Name = cfg.FriendlyName,
                        ItemType = ManagedCertificateType.SSL_ExternallyManaged,
                        SourceId = Definition.Id,
                        SourceName = Definition.Title,
                        DateRenewed = cfg.RenewAfter,
                        DateExpiry = cfg.CertExpires,
                        LastRenewalStatus = cfg.Status == "valid" ? RequestState.Success : cfg.Status != null ? RequestState.Error : null,
                        DateLastRenewalAttempt = config.LastWriteTime,
                        IsChanged = false
                    };

                    SetDomains(managedCert, new[] { cfg.MainDomain }.Concat(cfg.SANs ?? []));

                    // orders are kept in {server}\{account}\{order}
                    SetCertificateAuthority(managedCert, GetServerDirectoryUrl(config.Directory?.Parent?.Parent, serverUrls), config.Directory?.Parent?.Parent?.Name);

                    var certFile = new FileInfo(Path.Combine(config.DirectoryName!, "cert.cer"));

                    if (certFile.Exists)
                    {
                        PopulateManagedCertificateFromFile(_logger, managedCert, certFile);
                    }
                    else
                    {
                        SetCertificateUnreadable(_logger, managedCert, certFile.FullName);
                    }

                    managedCertificates.Add(managedCert);
                }
                catch (Exception exp)
                {
                    _logger?.LogWarning($"Failed to parse config: [{config.FullName}] {exp}");
                }
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

            var customHome = Environment.GetEnvironmentVariable("POSHACME_HOME");

            // Posh-ACME keeps its config in the profile of the user who runs it, which is usually not the account
            // this service runs as, so other users' profiles are searched too
            var settingsPath = OperatingSystem.IsWindows()
                ? ConfigLocator.FirstExisting([
                        string.IsNullOrWhiteSpace(customHome) ? null : Environment.ExpandEnvironmentVariables(customHome),
                        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), ConfigFolderName)
                    ]) ?? ConfigLocator.FindSingleInUserHomes(_logger, ProviderTitle, Path.Combine("AppData", "Local", ConfigFolderName))
                : ConfigLocator.FirstExisting([
                        customHome,
                        ConfigLocator.ExpandHome($"~/.config/{ConfigFolderName}")
                    ]) ?? ConfigLocator.FindSingleInUserHomes(_logger, ProviderTitle, Path.Combine(".config", ConfigFolderName));

            if (settingsPath != null)
            {
                _settingsPath = settingsPath;
                return true;
            }

            return false;
        }

        /// <summary>
        /// The ACME directory URL of a Posh-ACME server folder, recorded in its dir.json
        /// </summary>
        private string? GetServerDirectoryUrl(DirectoryInfo? serverFolder, Dictionary<string, string?> cache)
        {
            if (serverFolder == null)
            {
                return null;
            }

            if (!cache.TryGetValue(serverFolder.FullName, out var url))
            {
                try
                {
                    var dirFile = Path.Combine(serverFolder.FullName, "dir.json");

                    if (File.Exists(dirFile))
                    {
                        using var dir = System.Text.Json.JsonDocument.Parse(File.ReadAllText(dirFile));

                        if (dir.RootElement.TryGetProperty("location", out var location))
                        {
                            url = location.GetString();
                        }
                    }
                }
                catch (Exception exp)
                {
                    _logger?.LogDebug($"{ProviderTitle}: Could not read the server details in {serverFolder.FullName}: {exp.Message}");
                }

                cache[serverFolder.FullName] = url;
            }

            return url;
        }
    }
}
