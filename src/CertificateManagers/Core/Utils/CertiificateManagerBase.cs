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

        /// <summary>
        /// A sortable timestamp at the start of a line, optionally with fractional seconds and a time zone offset,
        /// e.g. certbot "2025-06-26 09:00:38,880:DEBUG:" or win-acme "2025-06-26 17:07:25.840 +08:00 [DBG]"
        /// </summary>
        private static readonly Regex _logLineDatePattern = new Regex(
            @"^\s*\[?(?<date>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:\s*(?:Z|[+-]\d{2}:?\d{2}))?)",
            RegexOptions.Compiled);

        /// <summary>
        /// The output of the unix date command in brackets at the start of a line, as used by acme.sh,
        /// e.g. "[Mon Sep  9 04:50:59 AWST 2024]". The day and month names are whatever the locale of the machine
        /// running the tool produced, so they are matched loosely and resolved when the date is parsed
        /// </summary>
        private static readonly Regex _logLineUnixDatePattern = new Regex(
            @"^\s*\[[^\s\]]{2,12}\s+(?<month>[^\s\]]{3,12})\s+(?<day>\d{1,2})\s+(?<time>\d{1,2}:\d{2}:\d{2})(?:\s+(?<zone>[A-Za-z]{2,5}))?\s+(?<year>\d{4})\]",
            RegexOptions.Compiled);

        /// <summary>
        /// Month name formats accepted in a unix date stamp, abbreviated or in full
        /// </summary>
        private static readonly string[] _unixDateFormats = { "MMM d yyyy H:mm:ss", "MMMM d yyyy H:mm:ss" };

        /// <summary>
        /// Time zone abbreviations which can be resolved without knowing where the log was written
        /// </summary>
        private static readonly HashSet<string> _universalZoneNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "UTC", "GMT", "UT", "Z" };

        private static readonly Regex _logLineLevelPattern = new Regex(
            @"\b(?<level>TRACE|VERBOSE|VRB|DEBUG|DBG|INFORMATION|INFO|INF|WARNING|WARN|WRN|ERROR|ERR|FATAL|FTL|CRITICAL|CRIT)\b",
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

            var lineList = lines as IList<string> ?? lines.ToList();
            var entries = lineList.Select(ParseProviderLogLine).ToList();

            PopulateMissingEventDates(entries, file.LastWriteTimeUtc);

            for (var i = 0; i < entries.Count; i++)
            {
                if (string.IsNullOrWhiteSpace(itemName) || lineList[i].Contains(itemName, StringComparison.OrdinalIgnoreCase))
                {
                    results.Add(entries[i]);

                    if (results.Count >= maxMatches)
                    {
                        break;
                    }
                }
            }

            return results;
        }

        /// <summary>
        /// Give an event date to the entries which did not carry one of their own, so that log output does not
        /// show a run of undated entries.
        /// A line which continues the entry above it (a stack trace, or a tool which only stamps the first line of
        /// each entry) takes the date of the entry it follows. Lines at the start of the range have nothing above
        /// them, because the read starts partway into the file, so they take the date of the first entry which does
        /// carry one. If no line in the range carries a date at all, the time the log file was last written is used
        /// as an approximation, which is accurate for the end of the file and progressively earlier before that
        /// </summary>
        /// <param name="entries">parsed entries, in the order they appear in the file</param>
        /// <param name="fileLastWriteTimeUtc">when the log file was last written</param>
        protected static void PopulateMissingEventDates(IList<LogItem> entries, DateTime fileLastWriteTimeUtc)
        {
            var anyDated = false;
            DateTime? lastKnownDate = null;

            foreach (var entry in entries)
            {
                if (entry.EventDate != null)
                {
                    lastKnownDate = entry.EventDate;
                    anyDated = true;
                }
                else
                {
                    entry.EventDate = lastKnownDate;
                }
            }

            if (!anyDated)
            {
                foreach (var entry in entries)
                {
                    entry.EventDate = fileLastWriteTimeUtc;
                }

                return;
            }

            DateTime? nextKnownDate = null;

            for (var i = entries.Count - 1; i >= 0; i--)
            {
                if (entries[i].EventDate != null)
                {
                    nextKnownDate = entries[i].EventDate;
                }
                else
                {
                    entries[i].EventDate = nextKnownDate;
                }
            }
        }

        /// <summary>
        /// Present a line from this tool's log file as a log item, reading the event date and log level from the
        /// line where it uses a recognisable format. A line which carries neither is returned without a date, for
        /// <see cref="PopulateMissingEventDates"/> to resolve from the lines around it
        /// </summary>
        protected virtual LogItem ParseProviderLogLine(string line)
        {
            var message = line?.Trim() ?? string.Empty;
            var levelMatch = _logLineLevelPattern.Match(message);

            return new LogItem
            {
                LogLevel = levelMatch.Success ? MapLogLevel(levelMatch.Groups["level"].Value) : "INF",
                EventDate = ParseLogLineDate(message),
                Message = message
            };
        }

        /// <summary>
        /// Read the timestamp from the start of a log line, in the formats used by the tools we read logs from:
        /// a sortable date optionally carrying a time zone offset (certbot, win-acme, simple-acme), or the output
        /// of the unix date command in brackets (acme.sh)
        /// </summary>
        /// <param name="message">the log line</param>
        /// <returns>the event date in UTC, or null if the line does not start with a timestamp</returns>
        protected static DateTime? ParseLogLineDate(string message)
        {
            var dateMatch = _logLineDatePattern.Match(message);

            if (dateMatch.Success)
            {
                // certbot separates the fractional seconds with a comma, which is not a recognised date separator
                var value = dateMatch.Groups["date"].Value.Replace(',', '.');

                // a line which carries no offset is assumed to be local time, as these tools log in the time zone
                // of the machine they run on
                if (DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out var parsedDate))
                {
                    return parsedDate.UtcDateTime;
                }
            }

            var unixDateMatch = _logLineUnixDatePattern.Match(message);

            if (unixDateMatch.Success)
            {
                // the month name comes from the locale of the machine which wrote the log, so try this machine's
                // culture as well as the invariant one, and allow the trailing period some locales use
                var month = unixDateMatch.Groups["month"].Value.TrimEnd('.');
                var composedDate = $"{month} {unixDateMatch.Groups["day"].Value} {unixDateMatch.Groups["year"].Value} {unixDateMatch.Groups["time"].Value}";

                foreach (var culture in new[] { CultureInfo.InvariantCulture, CultureInfo.CurrentCulture })
                {
                    if (DateTime.TryParseExact(composedDate, _unixDateFormats, culture, DateTimeStyles.None, out var parsedUnixDate))
                    {
                        // the zone is an abbreviation such as AWST which cannot be resolved, so only an explicitly
                        // universal zone is treated as such and anything else is taken as local time
                        return _universalZoneNames.Contains(unixDateMatch.Groups["zone"].Value)
                            ? DateTime.SpecifyKind(parsedUnixDate, DateTimeKind.Utc)
                            : DateTime.SpecifyKind(parsedUnixDate, DateTimeKind.Local).ToUniversalTime();
                    }
                }
            }

            // the line carries no timestamp we can read, so its date is resolved from the lines around it
            return null;
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
                case "FTL":
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

