using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Xml.Linq;
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
    public partial class WinAcme : CertificateManagerBase, ICertificateManager
    {
        private string _settingsPath = string.Empty;
        private string _logPath = string.Empty;
        private ILogger _logger = default!;

        private const string RenewalFilePattern = "*.renewal.json";
        private const string CertificateCacheFolder = "Certificates";
        private const string CsrFileSuffix = "-csr.pem";

        /// <summary>
        /// Certificate stores the default certificate store plugin writes to
        /// </summary>
        private static readonly string[] CertificateStoreNames = ["WebHosting", "My"];

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

        /// <summary>
        /// The client name, which names the config folder and the scheduled task
        /// </summary>
        internal virtual string ClientName => "win-acme";

        /// <inheritdoc />
        public override void Init(ILogger logger, CertificateManagerPreference prefs)
        {
            _logger = logger;
            _settingsPath = prefs?.ConfigPath ?? "";
            _logPath = prefs?.LogPath ?? "";
        }

        /// <inheritdoc />
        public override ProviderDefinition GetProviderDefinition() => Definition;

        private static async Task<string> ReadAllTextAsync(string path)
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
                    var renewal = JsonUtils.Deserialize<WinAcmeRenewal>(fileContent);

                    if (renewal?.Id == null)
                    {
                        continue;
                    }

                    managedCertificates.AddRange(GetRenewalItems(renewal, config.Directory!));
                }
                catch (Exception exp)
                {
                    _logger.LogError($"Failed to parse config: [{config.FullName}] {exp}");
                }
            }

            return managedCertificates;
        }

        /// <summary>
        /// The items for a renewal. A renewal holds one certificate unless its order plugin splits it into several
        /// orders (by host, domain or site), in which case each order is its own item
        /// </summary>
        private IEnumerable<ManagedCertificate> GetRenewalItems(WinAcmeRenewal renewal, DirectoryInfo renewalFolder)
        {
            var history = renewal.History ?? [];

            var orderNames = GetOrderNames(history);

            foreach (var orderName in orderNames)
            {
                var isMain = IsMainOrder(orderName);

                var results = history
                    .Select(h => (Run: h, Result: GetOrderResult(h, orderName)))
                    .Where(x => x.Result != null)
                    .ToList();

                var last = results.LastOrDefault();
                var lastSuccess = results.LastOrDefault(x => x.Result!.Success == true && (x.Result.Thumbprint != null || x.Result.ExpireDate != null));
                var failuresSinceSuccess = results.AsEnumerable().Reverse().TakeWhile(x => x.Result!.Success == false).Count();

                var name = renewal.LastFriendlyName ?? renewal.FriendlyName ?? renewal.TargetPluginOptions?.CommonName;

                var managedCert = new ManagedCertificate
                {
                    Id = $"{ManagedCertificate.ExternalItemIdPrefix}{IdPrefix}-{renewal.Id}" + (isMain ? string.Empty : $"-{Certify.Management.Util.ToUrlSafeBase64String(orderName)}"),
                    Name = isMain ? name : $"{name} [{orderName}]",
                    ItemType = ManagedCertificateType.SSL_ExternallyManaged,
                    SourceId = ProviderId,
                    SourceName = ProviderTitle,
                    CertificateThumbprintHash = lastSuccess.Result?.Thumbprint,
                    DateRenewed = lastSuccess.Run?.Date,
                    DateStart = lastSuccess.Run?.Date,
                    DateExpiry = lastSuccess.Result?.ExpireDate,
                    LastRenewalStatus = last.Result?.Success switch
                    {
                        true => RequestState.Success,
                        false => RequestState.Error,
                        _ => null
                    },
                    RenewalFailureMessage = last.Result?.Success == false && last.Result.ErrorMessages?.Count > 0 ? string.Join("\n", last.Result.ErrorMessages) : null,
                    RenewalFailureCount = failuresSinceSuccess,
                    DateLastRenewalAttempt = last.Run?.Date,
                    IsChanged = false
                };

                SetCertificateAuthority(managedCert, renewal.EndPoint, renewalFolder.Name);

                // a renewal which names its domains (manual and CSR targets) is used as is. Other targets, such as
                // IIS, are resolved again at each run, so the domains are read from the issued certificate or the
                // last request instead. The renewal's common name is only a fallback for an unsplit renewal, as an
                // order of a split renewal may not include it
                var domains = isMain && renewal.TargetPluginOptions?.AlternativeNames?.Count > 0
                    ? new List<string?> { renewal.TargetPluginOptions.CommonName }.Concat(renewal.TargetPluginOptions.AlternativeNames)
                    : FindIssuedCertificateDomains(managedCert.CertificateThumbprintHash, managedCert)
                        ?? FindRequestedDomains(renewalFolder, renewal.Id!, orderName)
                        ?? (isMain ? [renewal.TargetPluginOptions?.CommonName] : []);

                SetDomains(managedCert, domains);

                yield return managedCert;
            }
        }

        private static bool IsMainOrder(string? name) =>
            name == null || string.Equals(name, WinAcmeRenewal.MainOrderName, StringComparison.OrdinalIgnoreCase);

        private static List<string> GetCurrentOrderNames(HistoryItem? run) =>
            run?.GetOrderResults()
                .Where(r => r.Missing != true)
                .Select(r => r.Name ?? WinAcmeRenewal.MainOrderName)
                .ToList() ?? [];

        /// <summary>
        /// The orders of a renewal: those of its latest successful run and of its latest run, less any the latest
        /// run reported as no longer present
        /// </summary>
        private static List<string> GetOrderNames(List<HistoryItem> history)
        {
            var latestRun = history.LastOrDefault();
            var successNames = GetCurrentOrderNames(history.LastOrDefault(h => h.Success == true));
            var missing = latestRun?.GetOrderResults().Where(r => r.Missing == true).Select(r => r.Name).ToList() ?? [];

            var names = successNames
                .Concat(GetCurrentOrderNames(latestRun))
                .Where(n => !missing.Contains(n, StringComparer.OrdinalIgnoreCase))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            // a run which fails before splitting the renewal into its orders records a single main result, which
            // belongs to each of the orders rather than being an order of its own
            if (names.Count > 1 && !successNames.Any(IsMainOrder))
            {
                names.RemoveAll(n => IsMainOrder(n));
            }

            return names.Count > 0 ? names : [WinAcmeRenewal.MainOrderName];
        }

        /// <summary>
        /// The result of a run for an order. A run which failed before splitting the renewal into its orders only has
        /// a main result, which applies to every order
        /// </summary>
        private static HistoryResult? GetOrderResult(HistoryItem run, string orderName)
        {
            var results = run.GetOrderResults();
            var result = results.FirstOrDefault(r => string.Equals(r.Name ?? WinAcmeRenewal.MainOrderName, orderName, StringComparison.OrdinalIgnoreCase));

            if (result == null && run.Success == false && results.Count == 1 && IsMainOrder(results[0].Name))
            {
                result = results[0];
            }

            return result;
        }

        /// <summary>
        /// The domains of the issued certificate, if it is in the local machine certificate store. Also takes the
        /// validity dates from the certificate
        /// </summary>
        private List<string?>? FindIssuedCertificateDomains(string? thumbprint, ManagedCertificate managedCert)
        {
            if (string.IsNullOrWhiteSpace(thumbprint) || !OperatingSystem.IsWindows())
            {
                return null;
            }

            foreach (var storeName in CertificateStoreNames)
            {
                try
                {
                    using var store = new X509Store(storeName, StoreLocation.LocalMachine);
                    store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

                    var match = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false).FirstOrDefault();

                    if (match != null)
                    {
                        managedCert.DateStart = match.NotBefore;
                        managedCert.DateExpiry = match.NotAfter;
                        return GetCertificateDomains(match).Cast<string?>().ToList();
                    }
                }
                catch (CryptographicException)
                {
                    // the store does not exist on this machine
                }
            }

            return null;
        }

        /// <summary>
        /// The domains of the most recent certificate request for an order, which win-acme caches as
        /// {renewal id}-{order name}-{hash}-csr.pem in its certificate cache folder
        /// </summary>
        private List<string?>? FindRequestedDomains(DirectoryInfo renewalFolder, string renewalId, string orderName)
        {
            var cacheFolder = new DirectoryInfo(Path.Combine(renewalFolder.FullName, CertificateCacheFolder));

            if (!cacheFolder.Exists)
            {
                return null;
            }

            var prefix = $"{renewalId}-{orderName}-";
            var csrFile = cacheFolder.GetFiles($"{renewalId}-*{CsrFileSuffix}")
                .Where(f => f.Name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)
                    && Regex.IsMatch(f.Name[prefix.Length..], $"^[a-f0-9]+{Regex.Escape(CsrFileSuffix)}$", RegexOptions.IgnoreCase))
                .OrderByDescending(f => f.LastWriteTimeUtc)
                .FirstOrDefault();

            if (csrFile == null)
            {
                return null;
            }

            try
            {
                var request = CertificateRequest.LoadSigningRequestPem(File.ReadAllText(csrFile.FullName), HashAlgorithmName.SHA256,
                    CertificateRequestLoadOptions.SkipSignatureValidation | CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions);

                var domains = new List<string?>();

                var commonName = request.SubjectName.EnumerateRelativeDistinguishedNames()
                    .FirstOrDefault(n => !n.HasMultipleElements && n.GetSingleElementType().Value == "2.5.4.3")?
                    .GetSingleElementValue();

                domains.Add(commonName);

                foreach (var ext in request.CertificateExtensions.OfType<X509Extension>().Where(e => e.Oid?.Value == "2.5.29.17"))
                {
                    var san = new X509SubjectAlternativeNameExtension(ext.RawData, ext.Critical);
                    domains.AddRange(san.EnumerateDnsNames());
                    domains.AddRange(san.EnumerateIPAddresses().Select(ip => ip.ToString()));
                }

                return domains.Any(d => !string.IsNullOrWhiteSpace(d)) ? domains : null;
            }
            catch (Exception exp)
            {
                _logger?.LogWarning($"{ProviderTitle}: Failed to read cached certificate request {csrFile.FullName}: {exp.Message}");
                return null;
            }
        }

        /// <inheritdoc />
        public override Task<bool> IsPresent()
        {
            if (!string.IsNullOrWhiteSpace(_settingsPath) && Directory.Exists(_settingsPath))
            {
                return Task.FromResult(true);
            }

            var settingsPath = ConfigLocator.FirstExisting(
                [
                    FindScheduledConfigurationPath(),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), AppDataFolder),
                    OperatingSystem.IsWindows() ? null : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), AppDataFolder)
                ]);

            // simple-acme run without elevation on Linux keeps its config in the user's own profile
            if (settingsPath == null && !OperatingSystem.IsWindows())
            {
                settingsPath = ConfigLocator.FindSingleInUserHomes(_logger, ProviderTitle, Path.Combine(".local", "share", AppDataFolder));
            }

            if (settingsPath != null)
            {
                _settingsPath = settingsPath;
                return Task.FromResult(true);
            }

            return Task.FromResult(false);
        }

        /// <summary>
        /// The config folder set by Client.ConfigurationPath in the settings.json beside the program, found from the
        /// "{client} renew ({server})" scheduled task the program creates. The program location is not recorded
        /// anywhere else
        /// </summary>
        private string? FindScheduledConfigurationPath()
        {
            try
            {
                foreach (var programFolder in FindScheduledProgramFolders())
                {
                    var settingsFile = Path.Combine(programFolder, "settings.json");

                    if (!File.Exists(settingsFile))
                    {
                        continue;
                    }

                    using var settings = JsonDocument.Parse(File.ReadAllText(settingsFile), new JsonDocumentOptions { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true });

                    if (settings.RootElement.TryGetProperty("Client", out var client)
                        && client.TryGetProperty("ConfigurationPath", out var configPath)
                        && configPath.ValueKind == JsonValueKind.String
                        && !string.IsNullOrWhiteSpace(configPath.GetString()))
                    {
                        var root = Environment.ExpandEnvironmentVariables(configPath.GetString()!);

                        // older releases created a client name folder inside the chosen path
                        var rootWithClient = Path.Combine(root, ClientName);
                        return Directory.Exists(rootWithClient) ? rootWithClient : root;
                    }
                }
            }
            catch (Exception exp)
            {
                _logger?.LogDebug($"{ProviderTitle}: Could not read the scheduled task to find a custom config path: {exp.Message}");
            }

            return null;
        }

        /// <summary>
        /// The program folders of the "{client} renew ({server})" scheduled tasks the program creates, which is the only
        /// record of where the program is
        /// </summary>
        private IEnumerable<string> FindScheduledProgramFolders()
        {
            if (!OperatingSystem.IsWindows())
            {
                yield break;
            }

            var tasksFolder = new DirectoryInfo(Path.Combine(Environment.SystemDirectory, "Tasks"));

            if (!tasksFolder.Exists)
            {
                yield break;
            }

            // only administrators can list the tasks folder, so when not elevated the program is not found this way
            FileInfo[] taskFiles;

            try
            {
                taskFiles = tasksFolder.GetFiles($"{ClientName} renew (*)");
            }
            catch (Exception exp) when (exp is UnauthorizedAccessException || exp is IOException)
            {
                _logger?.LogDebug($"{ProviderTitle}: Could not list scheduled tasks: {exp.Message}");
                yield break;
            }

            foreach (var taskFile in taskFiles)
            {
                string? programFolder = null;

                try
                {
                    var task = XDocument.Load(taskFile.FullName);
                    var ns = task.Root?.Name.Namespace ?? XNamespace.None;
                    var exec = task.Descendants(ns + "Exec").FirstOrDefault();
                    var command = exec?.Element(ns + "Command")?.Value?.Trim().Trim('"');
                    programFolder = exec?.Element(ns + "WorkingDirectory")?.Value?.Trim().Trim('"');

                    if (string.IsNullOrWhiteSpace(programFolder) && !string.IsNullOrWhiteSpace(command))
                    {
                        programFolder = Path.GetDirectoryName(command);
                    }
                }
                catch (Exception exp)
                {
                    _logger?.LogDebug($"{ProviderTitle}: Could not read scheduled task {taskFile.Name}: {exp.Message}");
                }

                if (!string.IsNullOrWhiteSpace(programFolder) && Directory.Exists(programFolder))
                {
                    yield return programFolder;
                }
            }
        }

        /// <summary>
        /// Log files are written using a rolling date suffix, e.g. log-20250626.txt
        /// </summary>
        protected override string[] LogFilePatterns => new[] { "log-*.txt", "*.log", "*.log.*" };

        /// <inheritdoc />
        public override async Task<string> ResolveLogPath()
        {
            if (string.IsNullOrWhiteSpace(_logPath) && await IsPresent())
            {
                // logs are kept in a Log folder below the config path, which is per base uri (e.g. %programdata%\win-acme\acme-v02.api.letsencrypt.org\Log)
                try
                {
                    var logDirectory = new DirectoryInfo(_settingsPath)
                        .GetDirectories("Log", SearchOption.AllDirectories)
                        .OrderByDescending(d => d.LastWriteTimeUtc)
                        .FirstOrDefault();

                    _logPath = logDirectory?.FullName ?? _settingsPath;
                }
                catch (Exception exp)
                {
                    _logger?.LogWarning($"{ProviderTitle}: Failed to locate log folder under {_settingsPath}: {exp.Message}");
                    _logPath = _settingsPath;
                }
            }

            return _logPath;
        }
    }
}
