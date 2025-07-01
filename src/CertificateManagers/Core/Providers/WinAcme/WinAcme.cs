using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Certify.Models;
using Certify.Models.Config;
using Certify.Plugin.CertificateManagers.Utils;
using Certify.Plugin.CertificateManagers.WinAcme;
using Certify.Providers.CertificateManagers;
using Microsoft.Extensions.Logging;

namespace Certify.Plugin.CertificateManagers.Providers.WinAcme
{
    /// <summary>
    /// Certificate manager for win-acme local config.
    /// </summary>
    public class WinAcme : CertificateManagerBase, ICertificateManager
    {
        private string _settingsPath = string.Empty;
        private string _logPath = string.Empty;
        private ILogger _logger = default!;

        private const string RenewalFilePattern = "*.renewal.json";

        public static ProviderDefinition Definition => new()
        {
            Id = "win-acme",
            Title = "win-acme",
            Description = "Queries local config for certificates managed by win-acme",
            HelpUrl = "https://win-acme.com"
        };

        internal virtual string AppDataFolder => "win-acme";
        internal virtual string ProviderId => Definition.Id;
        internal virtual string ProviderTitle => Definition.Title;
        internal virtual string IdPrefix => Definition.Id;

        /// <inheritdoc />
        public override void Init(ILogger logger, CertificateManagerPreference prefs)
        {
            _logger = logger;
            _settingsPath = prefs?.ConfigPath ?? "";
            _logPath = prefs?.LogPath ?? "";
        }

        /// <inheritdoc />
        public override ProviderDefinition GetProviderDefinition() => Definition;

        private async Task<string> ReadAllTextAsync(string path)
        {
            using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, true))
            using (var reader = new StreamReader(stream))
            {
                return await reader.ReadToEndAsync().ConfigureAwait(false);
            }
        }

        /// <inheritdoc />
        public override async Task<List<ManagedCertificate>> GetManagedCertificates(ManagedCertificateFilter? filter = null)
        {
            var managedCertificates = new List<ManagedCertificate>();

            if (!await IsPresent())
            {
                return managedCertificates;
            }

            var directorySearch = new DirectoryInfo(_settingsPath);
            var configFiles = directorySearch.GetFiles(RenewalFilePattern, SearchOption.AllDirectories);

            foreach (var config in configFiles)
            {
                try
                {
                    var fileContent = await ReadAllTextAsync(config.FullName);
                    var cfg = JsonUtils.Deserialize<ConfigSettings>(fileContent);

                    if (cfg == null)
                    {
                        continue;
                    }

                    var lastStatus = cfg.History?.LastOrDefault();
                    var lastSuccess = cfg.History?.LastOrDefault(x => x.Success && x.OrderResults?.Any() == true);
                    var lastSuccessResult = lastSuccess?.OrderResults?.LastOrDefault(x => x.Success);

                    var managedCert = new ManagedCertificate
                    {
                        Id = $"ext-{IdPrefix}-{cfg.Id}",
                        Name = cfg.LastFriendlyName,
                        ItemType = ManagedCertificateType.SSL_ExternallyManaged,
                        SourceId = ProviderId,
                        SourceName = ProviderTitle,
                        CertificateThumbprintHash = lastSuccessResult?.Thumbprint,
                        DateRenewed = lastSuccess?.Date,
                        DateStart = lastSuccess?.Date,
                        DateExpiry = lastSuccessResult?.ExpireDate,
                        LastRenewalStatus = lastStatus?.Success == true ? RequestState.Success : (lastStatus != null ? RequestState.Error : (RequestState?)null),
                        RenewalFailureMessage = lastStatus?.Success == false ? string.Join("\n", lastStatus.OrderResults?.Select(r => r.ErrorMessages).Where(m => m != null).SelectMany(m => m)) : null,
                        DateLastRenewalAttempt = lastStatus?.Date,
                        RequestConfig = new CertRequestConfig
                        {
                            PrimaryDomain = cfg.TargetPluginOptions?.CommonName,
                            SubjectAlternativeNames = cfg.TargetPluginOptions?.AlternativeNames?.ToArray()
                        },
                        DomainOptions =
                        [
                            new() {
                                Domain = cfg.TargetPluginOptions?.CommonName,
                                IsPrimaryDomain = true,
                                IsManualEntry = true,
                                IsSelected = true
                            }
                        ],
                        IsChanged = false
                    };

                    // Add additional SANs as domain options
                    if (managedCert.RequestConfig.SubjectAlternativeNames != null)
                    {
                        var domains = managedCert.RequestConfig.SubjectAlternativeNames
                            .Where(d => d != managedCert.RequestConfig.PrimaryDomain)
                            .Distinct();

                        foreach (var d in domains)
                        {
                            managedCert.DomainOptions.Add(new DomainOption
                            {
                                Domain = d,
                                IsManualEntry = true,
                                IsPrimaryDomain = false
                            });
                        }
                    }

                    managedCertificates.Add(managedCert);
                }
                catch (Exception exp)
                {
                    _logger.LogError($"Failed to parse config: [{config.FullName}] {exp}");
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

            var appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            var settingsPath = Path.Combine(appDataPath, AppDataFolder);

            if (Directory.Exists(settingsPath))
            {
                _settingsPath = settingsPath;
                return true;
            }

            return false;
        }
    }
}
