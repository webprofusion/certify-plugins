using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Certify.Models;
using Certify.Models.Config;
using Certify.Models.Hub;
using Certify.Models.Providers;
using Certify.Shared.Core.Utils;
using Microsoft.Extensions.Logging;

namespace Certify.Plugin.CertificateManagers.Utils
{
    /// <summary>
    /// Base class for certificate manager providers. Provides default implementations and helpers.
    /// </summary>
    public class CertificateManagerBase
    {
        /// <summary>
        /// Maximum number of log files to inspect when gathering log entries for an item. External tools can
        /// retain a large number of rotated log files (certbot keeps 1000 by default), so only the most
        /// recently written files are scanned
        /// </summary>
        protected const int MaxLogFilesScanned = 10;

        /// <summary>
        /// Maximum number of log lines returned for a single item, regardless of the requested limit
        /// </summary>
        protected const int MaxLogLines = 1000;

        /// <summary>
        /// File patterns used to identify the log files belonging to this tool, within the resolved log path
        /// </summary>
        protected virtual string[] LogFilePatterns => new[] { "*.log", "*.log.*" };

        private static readonly Regex _logLineDatePattern = new Regex(
            @"^\s*\[?(?<date>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:\s*(?:Z|[+-]\d{2}:?\d{2}))?)",
            RegexOptions.Compiled);

        private static readonly Regex _logLineLevelPattern = new Regex(
            @"\b(?<level>TRACE|VERBOSE|DEBUG|DBG|INFORMATION|INFO|INF|WARNING|WARN|WRN|ERROR|ERR|FATAL|CRITICAL|CRIT)\b",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        /// <summary>
        /// Delete a managed certificate by ID.
        /// </summary>
        public virtual Task DeleteManagedCertificate(string id) => throw new NotImplementedException();

        /// <summary>
        /// Get all account registrations.
        /// </summary>
        public virtual Task<List<AccountDetails>> GetAccountRegistrations() => throw new NotImplementedException();

        /// <summary>
        /// Get a managed certificate by ID.
        /// </summary>
        public virtual Task<ManagedCertificate> GetManagedCertificate(string id) => throw new NotImplementedException();

        /// <summary>
        /// Get all managed certificates, optionally filtered.
        /// </summary>
        public virtual Task<List<ManagedCertificate>> GetManagedCertificates(ManagedCertificateFilter? filter = null) => throw new NotImplementedException();

        /// <summary>
        /// Get the provider definition.
        /// </summary>
        public virtual ProviderDefinition GetProviderDefinition() => throw new NotImplementedException();

        /// <summary>
        /// Initialize the provider with logger and paths.
        /// </summary>
        public virtual void Init(ILogger logger, CertificateManagerPreference prefs) => throw new NotImplementedException();

        /// <summary>
        /// Check if the provider/config is present.
        /// </summary>
        public virtual Task<bool> IsPresent() => throw new NotImplementedException();

        /// <summary>
        /// Get the log path this provider will read from. Providers which can detect the default log location
        /// for their tool override this so that a blank configured log path still resolves to the usual location
        /// </summary>
        public virtual Task<string> ResolveLogPath() => Task.FromResult(string.Empty);

        /// <summary>
        /// Get recent log entries relating to the given item from this tool's own log files. Each tool has its
        /// own log format, so entries are attributed to an item by looking for the item name within each line and
        /// the log level and event date are inferred from common log line formats
        /// </summary>
        public virtual async Task<LogItem[]> GetItemLog(ManagedCertificate item, int limit)
        {
            var title = ProviderTitleOrDefault();
            var maxLines = limit <= 0 ? MaxLogLines : Math.Min(limit, MaxLogLines);
            var logPath = await ResolveLogPath();

            if (string.IsNullOrWhiteSpace(logPath))
            {
                return LogFetchMessage($"No log path is configured for {title} and no default log location was found on this machine. Set the log path for {title} in the External Certificate Managers section of instance settings.");
            }

            if (!Directory.Exists(logPath))
            {
                return LogFetchMessage($"The {title} log path does not exist or cannot be accessed by this service: {logPath}");
            }

            List<FileInfo> logFiles;

            try
            {
                var logDirectory = new DirectoryInfo(logPath);

                logFiles = LogFilePatterns
                    .SelectMany(pattern => logDirectory.GetFiles(pattern, SearchOption.AllDirectories))
                    .DistinctBy(f => f.FullName)
                    .OrderByDescending(f => f.LastWriteTimeUtc)
                    .Take(MaxLogFilesScanned)
                    .ToList();
            }
            catch (Exception exp)
            {
                return LogFetchMessage($"Failed to read the {title} log path {logPath}. This service may not have permission to read this folder. {exp.Message}", "ERR");
            }

            if (logFiles.Count == 0)
            {
                return LogFetchMessage($"No {title} log files were found under {logPath}");
            }

            var itemName = item?.Name?.Trim();
            var matchesByFile = new List<List<LogItem>>();
            var matchedCount = 0;

            // scan the most recently written files first so we can stop early, results are then presented oldest first
            foreach (var file in logFiles)
            {
                var fileMatches = ReadItemLogEntries(file, itemName, maxLines, maxLines - matchedCount);

                matchedCount += fileMatches.Count;
                matchesByFile.Add(fileMatches);

                if (matchedCount >= maxLines)
                {
                    break;
                }
            }

            matchesByFile.Reverse();

            var results = matchesByFile.SelectMany(f => f).ToList();

            if (results.Count == 0)
            {
                // no lines could be attributed to this item, so show the most recent activity from this tool instead
                results.Add(new LogItem
                {
                    LogLevel = "INF",
                    EventDate = DateTime.UtcNow,
                    Message = $"No {title} log entries could be matched to {(string.IsNullOrWhiteSpace(itemName) ? "this item" : itemName)}. Showing the most recent {title} log activity from {logFiles[0].Name}:"
                });

                results.AddRange(ReadItemLogEntries(logFiles[0], null, maxLines, maxLines));
            }

            return results.ToArray();
        }

        /// <summary>
        /// Read the tail of a single log file, returning the entries which mention the given item name (or all
        /// entries if no item name is given)
        /// </summary>
        /// <param name="file">log file to read</param>
        /// <param name="itemName">item name to attribute lines to, or null for all lines</param>
        /// <param name="maxLines">number of lines to read from the end of the file</param>
        /// <param name="maxMatches">number of matching entries to return</param>
        private List<LogItem> ReadItemLogEntries(FileInfo file, string? itemName, int maxLines, int maxMatches)
        {
            var results = new List<LogItem>();

            IEnumerable<string> lines;

            try
            {
                lines = LogParsing.ReadLogTail(file.FullName, maxLines);
            }
            catch (Exception exp)
            {
                return new List<LogItem>
                {
                    new LogItem { LogLevel = "ERR", EventDate = DateTime.UtcNow, Message = $"Could not read log file {file.FullName}: {exp.Message}" }
                };
            }

            DateTime? lastKnownDate = null;

            foreach (var line in lines)
            {
                var entry = ParseProviderLogLine(line, lastKnownDate);

                if (entry.EventDate != null)
                {
                    lastKnownDate = entry.EventDate;
                }

                if (string.IsNullOrWhiteSpace(itemName) || line.Contains(itemName, StringComparison.OrdinalIgnoreCase))
                {
                    results.Add(entry);

                    if (results.Count >= maxMatches)
                    {
                        break;
                    }
                }
            }

            return results;
        }

        /// <summary>
        /// Present a line from this tool's log file as a log item, inferring the event date and log level where
        /// the line uses a recognisable format. Lines which continue a previous entry (a stack trace, for example)
        /// have no date of their own so they inherit the date of the entry they follow
        /// </summary>
        protected virtual LogItem ParseProviderLogLine(string line, DateTime? lastKnownDate)
        {
            var message = line?.Trim() ?? string.Empty;
            var eventDate = lastKnownDate;

            var dateMatch = _logLineDatePattern.Match(message);

            if (dateMatch.Success
                && DateTimeOffset.TryParse(dateMatch.Groups["date"].Value.Replace(',', '.'), CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out var parsedDate))
            {
                eventDate = parsedDate.UtcDateTime;
            }

            var levelMatch = _logLineLevelPattern.Match(message);

            return new LogItem
            {
                LogLevel = levelMatch.Success ? MapLogLevel(levelMatch.Groups["level"].Value) : "INF",
                EventDate = eventDate,
                Message = message
            };
        }

        private static string MapLogLevel(string level)
        {
            switch (level.ToUpperInvariant())
            {
                case "WARNING":
                case "WARN":
                case "WRN":
                    return "WRN";
                case "ERROR":
                case "ERR":
                case "FATAL":
                case "CRITICAL":
                case "CRIT":
                    return "ERR";
                default:
                    return "INF";
            }
        }

        /// <summary>
        /// Report why log entries could not be fetched, so the reason is visible to the user rather than
        /// appearing as an item with no log history
        /// </summary>
        protected static LogItem[] LogFetchMessage(string message, string logLevel = "WRN") =>
            new[] { new LogItem { LogLevel = logLevel, EventDate = DateTime.UtcNow, Message = message } };

        /// <summary>
        /// Perform certificate cleanup.
        /// </summary>
        public virtual Task PerformCertificateCleanup() => throw new NotImplementedException();

        /// <summary>
        /// Perform a certificate request.
        /// </summary>
        public virtual Task<CertificateRequestResult> PerformCertificateRequest(
            ILog log,
            ManagedCertificate managedCertificate,
            IProgress<RequestProgressState> progress = null,
            bool resumePaused = false,
            bool skipRequest = false,
            bool failOnSkip = false) => throw new NotImplementedException();

        /// <summary>
        /// Perform renewal for all managed certificates.
        /// </summary>
        public virtual Task<List<CertificateRequestResult>> PerformRenewalAllManagedCertificates(
            RenewalSettings settings,
            Dictionary<string, Progress<RequestProgressState>>? progressTrackers = null) => throw new NotImplementedException();

        /// <summary>
        /// Update a managed certificate.
        /// </summary>
        public virtual Task<ManagedCertificate> UpdateManagedCertificate(ManagedCertificate site) => throw new NotImplementedException();

        /// <summary>
        /// Populate a ManagedCertificate object with details from a PEM certificate file.
        /// </summary>
        /// <param name="log">Logger instance</param>
        /// <param name="managedCert">The managed certificate to populate</param>
        /// <param name="certFile">The certificate file</param>
        public void PopulateManagedCertificateFromFile(ILogger log, ManagedCertificate managedCert, FileInfo certFile)
        {
            try
            {
                var cert = Certify.Management.CertificateManager.ReadCertificateFromPem(certFile.FullName);

                if (cert == null)
                {
                    SetCertificateUnreadable(log, managedCert, certFile.FullName);
                    return;
                }

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
                    // Assume certs with less than 30 days left have failed to renew
                    managedCert.LastRenewalStatus = RequestState.Error;
                    managedCert.RenewalFailureMessage = $"Check {ProviderTitleOrDefault()} configuration. This certificate will expire in less than 30 days and has not yet automatically renewed.";
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
                    new DomainOption
                    {
                        Domain = managedCert.RequestConfig.PrimaryDomain,
                        IsPrimaryDomain = true,
                        IsManualEntry = true,
                        IsSelected = true
                    }
                };
            }
            catch (Exception exp)
            {
                SetCertificateUnreadable(log, managedCert, certFile.FullName, exp);
            }
        }

        /// <summary>
        /// Record that the certificate file for a discovered renewal config could not be read or parsed. The
        /// problem is reported against the item itself as well as being logged, because otherwise the item just
        /// appears in the list with no certificate details and no indication of why
        /// </summary>
        /// <param name="log">Logger instance</param>
        /// <param name="managedCert">The managed certificate the file belongs to</param>
        /// <param name="certFilePath">Path of the certificate file which could not be read</param>
        /// <param name="exp">The failure encountered while reading the file, if the read was attempted</param>
        protected void SetCertificateUnreadable(ILogger? log, ManagedCertificate managedCert, string certFilePath, Exception? exp = null)
        {
            string reason;

            // the permission hint only applies where access is a possible cause, a file we could read but not
            // make sense of is a different problem
            var mayBeAccessProblem = true;

            if (exp is UnauthorizedAccessException || exp is System.Security.SecurityException)
            {
                reason = $"this service does not have permission to read it: {exp.Message}";
            }
            else if (exp != null)
            {
                reason = $"it could not be parsed: {exp.Message}";
                mayBeAccessProblem = false;
            }
            else
            {
                // ReadCertificateFromPem returns nothing for a file it cannot open or make sense of, and a file in
                // a folder this service cannot access is reported as missing rather than as an access error
                reason = "it is missing, unreadable, or this service does not have permission to read it";
            }

            var message = $"The certificate for this item is managed by {ProviderTitleOrDefault()} but {reason} ({certFilePath})."
                + (mayBeAccessProblem ? " Certificate files are often readable only by an administrator or root, so this service may need to be granted read access." : string.Empty);

            log?.LogWarning("{message}", message);

            managedCert.LastRenewalStatus = RequestState.Error;
            managedCert.RenewalFailureMessage = message;

            if (managedCert.RenewalFailureCount == 0)
            {
                managedCert.RenewalFailureCount = 1;
            }
        }

        /// <summary>
        /// The display title of this provider, for use in messages shown to the user
        /// </summary>
        protected string ProviderTitleOrDefault()
        {
            try
            {
                return GetProviderDefinition()?.Title ?? "an external certificate manager";
            }
            catch (NotImplementedException)
            {
                return "an external certificate manager";
            }
        }
    }
}

