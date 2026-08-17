using System;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Certify.Models;
using Certify.Models.Config;
using Certify.Plugin.CertificateManagers.Providers.AcmeSh;
using Certify.Plugin.CertificateManagers.Providers.Certbot;
using Certify.Plugin.CertificateManagers.Providers.PoshAcme;
using Certify.Plugin.CertificateManagers.Providers.SimpleAcme;
using Certify.Plugin.CertificateManagers.Providers.WinAcme;
using Certify.Providers.CertificateManagers;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests.Plugin.CertificateManagers
{
    [TestClass]
    public class CertificateManagerTests
    {
        private async Task AssertManagerConfigAndRenewals(ICertificateManager manager, string configName)
        {
            var isPresent = await manager.IsPresent();
            Assert.IsTrue(isPresent, $"{configName} config should be present");

            var certs = await manager.GetManagedCertificates();
            Assert.IsTrue(certs.Count > 0, $"{configName} renewals should be present");

            var hasStartDates = certs.Exists(c => c.DateStart != null);
            Assert.IsTrue(hasStartDates, $"{configName} renewals should have start dates");

            var hasEndDates = certs.Exists(c => c.DateExpiry != null);
            Assert.IsTrue(hasEndDates, $"{configName} renewals should have expiry dates");
        }

        [TestMethod]
        public async Task WinAcme()
        {
            var logger = new NullLogger<WinAcme>();
            var currentDirectory = Directory.GetCurrentDirectory();
            var configDirectory = Path.Combine(currentDirectory, "Assets", "win-acme");
            var prefs = new CertificateManagerPreference
            {
                ConfigPath = configDirectory,
                LogPath = configDirectory
            };
            var manager = new WinAcme();
            manager.Init(logger, prefs);
            await AssertManagerConfigAndRenewals(manager, "win-acme");
        }

        [TestMethod]
        public async Task PoshACME()
        {
            var logger = new NullLogger<PoshAcme>();
            var currentDirectory = Directory.GetCurrentDirectory();
            var configDirectory = Path.Combine(currentDirectory, "Assets", "posh-acme");
            var prefs = new CertificateManagerPreference
            {
                ConfigPath = configDirectory,
                LogPath = configDirectory
            };
            var manager = new PoshAcme();
            manager.Init(logger, prefs);
            await AssertManagerConfigAndRenewals(manager, "Posh-ACME");
        }

        [TestMethod]
        public async Task SimpleAcme()
        {
            var logger = new NullLogger<SimpleAcme>();
            var currentDirectory = Directory.GetCurrentDirectory();
            var configDirectory = Path.Combine(currentDirectory, "Assets", "simple-acme");
            var prefs = new CertificateManagerPreference
            {
                ConfigPath = configDirectory,
                LogPath = configDirectory
            };
            var manager = new SimpleAcme();
            manager.Init(logger, prefs);
            await AssertManagerConfigAndRenewals(manager, "simple-acme");
        }

        [TestMethod]
        public async Task Certbot()
        {
            var logger = new NullLogger<Certbot>();
            var currentDirectory = Directory.GetCurrentDirectory();
            var assetsDirectory = Path.Combine(currentDirectory, "Assets", "certbot");
            var settingsDirectory = Path.Combine(assetsDirectory, "test-config");
            var logDirectory = Path.Combine(assetsDirectory, "test-logs");
            var prefs = new CertificateManagerPreference
            {
                ConfigPath = settingsDirectory,
                LogPath = logDirectory
            };
            var manager = new Certbot();
            manager.Init(logger, prefs);
            await AssertManagerConfigAndRenewals(manager, "Certbot");
        }

        [TestMethod]
        public async Task CertbotUsesRenewalConfigCertPath()
        {
            var logger = new NullLogger<Certbot>();
            var currentDirectory = Directory.GetCurrentDirectory();
            var assetsDirectory = Path.Combine(currentDirectory, "Assets", "certbot");
            var sourceSettingsDirectory = Path.Combine(assetsDirectory, "test-config");
            var sourceLogDirectory = Path.Combine(assetsDirectory, "test-logs");
            var tempRoot = Path.Combine(Path.GetTempPath(), $"certbot-test-{System.Guid.NewGuid():N}");
            var settingsDirectory = Path.Combine(tempRoot, "test-config");
            var logDirectory = Path.Combine(tempRoot, "test-logs");

            try
            {
                foreach (var sourceFile in Directory.GetFiles(sourceSettingsDirectory, "*", SearchOption.AllDirectories))
                {
                    var relativePath = Path.GetRelativePath(sourceSettingsDirectory, sourceFile);
                    var destinationFile = Path.Combine(settingsDirectory, relativePath);
                    var destinationDirectory = Path.GetDirectoryName(destinationFile)!;
                    Directory.CreateDirectory(destinationDirectory);

                    File.Copy(sourceFile, destinationFile, true);
                }

                foreach (var sourceFile in Directory.GetFiles(sourceLogDirectory, "*", SearchOption.AllDirectories))
                {
                    var relativePath = Path.GetRelativePath(sourceLogDirectory, sourceFile);
                    var destinationFile = Path.Combine(logDirectory, relativePath);
                    var destinationDirectory = Path.GetDirectoryName(destinationFile)!;
                    Directory.CreateDirectory(destinationDirectory);

                    File.Copy(sourceFile, destinationFile, true);
                }

                var renewalFile = Path.Combine(settingsDirectory, "renewal", "wsl.projectbids.co.uk.conf");
                var renamedRenewalFile = Path.Combine(settingsDirectory, "renewal", "custom-cert-name.conf");
                File.Move(renewalFile, renamedRenewalFile);

                var localCertPath = Path.Combine(settingsDirectory, "live", "wsl.projectbids.co.uk", "cert.pem");
                var localFullChainPath = Path.Combine(settingsDirectory, "live", "wsl.projectbids.co.uk", "fullchain.pem");
                var renewalFileContent = File.ReadAllText(renamedRenewalFile)
                    .Replace("cert = /etc/letsencrypt/live/wsl.projectbids.co.uk/cert.pem", $"cert = {localCertPath}")
                    .Replace("fullchain = /etc/letsencrypt/live/wsl.projectbids.co.uk/fullchain.pem", $"fullchain = {localFullChainPath}");
                File.WriteAllText(renamedRenewalFile, renewalFileContent);

                var prefs = new CertificateManagerPreference
                {
                    ConfigPath = settingsDirectory,
                    LogPath = logDirectory
                };

                var manager = new Certbot();
                manager.Init(logger, prefs);

                var certs = await manager.GetManagedCertificates();
                var cert = certs.Find(c => c.Name == "custom-cert-name");

                Assert.IsNotNull(cert, "Expected cert from renamed renewal file");
                Assert.IsNotNull(cert.DateExpiry, "Expected cert metadata using renewal config cert path");
                Assert.IsFalse(string.IsNullOrWhiteSpace(cert.CertificateThumbprintHash), "Expected certificate thumbprint");
            }
            finally
            {
                if (Directory.Exists(tempRoot))
                {
                    Directory.Delete(tempRoot, true);
                }
            }
        }

        /// <summary>
        /// Copy the certbot config assets to a temporary folder so a test can modify them, along with an empty log
        /// folder so that log parsing cannot affect the item status
        /// </summary>
        private static (string SettingsPath, string LogPath) CopyCertbotConfigToTemp()
        {
            var sourceSettingsDirectory = Path.Combine(Directory.GetCurrentDirectory(), "Assets", "certbot", "test-config");
            var tempRoot = Path.Combine(Path.GetTempPath(), $"certbot-config-{Guid.NewGuid():N}");
            var settingsDirectory = Path.Combine(tempRoot, "config");
            var logDirectory = Path.Combine(tempRoot, "logs");

            foreach (var sourceFile in Directory.GetFiles(sourceSettingsDirectory, "*", SearchOption.AllDirectories))
            {
                var destinationFile = Path.Combine(settingsDirectory, Path.GetRelativePath(sourceSettingsDirectory, sourceFile));

                Directory.CreateDirectory(Path.GetDirectoryName(destinationFile)!);
                File.Copy(sourceFile, destinationFile, true);
            }

            Directory.CreateDirectory(logDirectory);

            return (settingsDirectory, logDirectory);
        }

        [TestMethod]
        public async Task CertbotReportsMissingCertificateAsRenewalFailure()
        {
            // a renewal config we can read but a certificate we cannot is the usual symptom of the certificate
            // folder being readable only by root, so the item must say so rather than just appearing empty
            var (settingsPath, logPath) = CopyCertbotConfigToTemp();

            try
            {
                var certPath = Path.Combine(settingsPath, "live", "wsl.projectbids.co.uk", "cert.pem");
                File.Delete(certPath);

                var manager = new Certbot();
                manager.Init(new NullLogger<Certbot>(), new CertificateManagerPreference { ConfigPath = settingsPath, LogPath = logPath });

                var certs = await manager.GetManagedCertificates();
                var item = certs.Find(c => c.Name == "wsl.projectbids.co.uk");

                Assert.IsNotNull(item, "The item should still be listed from its renewal config");
                Assert.AreEqual(RequestState.Error, item.LastRenewalStatus, "An unreadable certificate should be reported as a failure");
                Assert.IsFalse(string.IsNullOrWhiteSpace(item.RenewalFailureMessage), "The reason should be reported against the item");
                Assert.IsTrue(item.RenewalFailureMessage.Contains(certPath), "The reported reason should identify the certificate file");
            }
            finally
            {
                DeleteTempTree(settingsPath);
            }
        }

        [TestMethod]
        public async Task CertbotReportsUnparseableCertificateAsRenewalFailure()
        {
            var (settingsPath, logPath) = CopyCertbotConfigToTemp();

            try
            {
                var certPath = Path.Combine(settingsPath, "live", "wsl.projectbids.co.uk", "cert.pem");
                File.WriteAllText(certPath, "this is not a certificate");

                var manager = new Certbot();
                manager.Init(new NullLogger<Certbot>(), new CertificateManagerPreference { ConfigPath = settingsPath, LogPath = logPath });

                var certs = await manager.GetManagedCertificates();
                var item = certs.Find(c => c.Name == "wsl.projectbids.co.uk");

                Assert.IsNotNull(item, "The item should still be listed from its renewal config");
                Assert.AreEqual(RequestState.Error, item.LastRenewalStatus, "An unparseable certificate should be reported as a failure");
                Assert.IsTrue(item.RenewalFailureMessage?.Contains(certPath) == true, "The reported reason should identify the certificate file");
                Assert.IsNull(item.CertificateThumbprintHash, "No certificate details should be reported for a certificate which could not be read");
            }
            finally
            {
                DeleteTempTree(settingsPath);
            }
        }

        private static void DeleteTempTree(string settingsPath)
        {
            var tempRoot = Path.GetDirectoryName(settingsPath);

            if (tempRoot != null && Directory.Exists(tempRoot))
            {
                Directory.Delete(tempRoot, true);
            }
        }

        [TestMethod]
        public async Task CertbotItemLogReturnsEntriesForItem()
        {
            var logger = new NullLogger<Certbot>();
            var assetsDirectory = Path.Combine(Directory.GetCurrentDirectory(), "Assets", "certbot");
            var prefs = new CertificateManagerPreference
            {
                ConfigPath = Path.Combine(assetsDirectory, "test-config"),
                LogPath = Path.Combine(assetsDirectory, "test-logs")
            };

            var manager = new Certbot();
            manager.Init(logger, prefs);

            var certs = await manager.GetManagedCertificates();
            var item = certs.Find(c => c.Name == "wsl.projectbids.co.uk");

            Assert.IsNotNull(item, "Expected test item from certbot renewal config");

            var log = await manager.GetItemLog(item, 200);

            Assert.IsTrue(log.Length > 0, "Log entries should be returned for the item");
            Assert.IsTrue(
                log.All(l => l.Message.Contains(item.Name, StringComparison.OrdinalIgnoreCase)),
                "Returned entries should be the ones which mention this item");
            Assert.IsTrue(log.Any(l => l.EventDate != null), "Entries should have an event date read from the log line");
        }

        [TestMethod]
        public async Task CertbotItemLogReportsReasonWhenLogPathIsUnavailable()
        {
            // a log fetch which cannot be performed must report why, otherwise the item just appears to have no log history
            var logger = new NullLogger<Certbot>();
            var assetsDirectory = Path.Combine(Directory.GetCurrentDirectory(), "Assets", "certbot");
            var missingLogPath = Path.Combine(Path.GetTempPath(), $"certbot-missing-logs-{Guid.NewGuid():N}");

            var prefs = new CertificateManagerPreference
            {
                ConfigPath = Path.Combine(assetsDirectory, "test-config"),
                LogPath = missingLogPath
            };

            var manager = new Certbot();
            manager.Init(logger, prefs);

            var log = await manager.GetItemLog(new ManagedCertificate { Name = "wsl.projectbids.co.uk" }, 100);

            Assert.AreEqual(1, log.Length, "A single explanation should be returned");
            Assert.IsTrue(log[0].Message.Contains(missingLogPath), "The explanation should identify the path which was tried");
        }

        [TestMethod]
        public async Task CertbotItemLogWithBlankLogPathStillReportsAnOutcome()
        {
            // a blank log path means 'use the default location for this machine', which either resolves to real log
            // entries or to an explanation, but never to a silently empty log
            var logger = new NullLogger<Certbot>();
            var assetsDirectory = Path.Combine(Directory.GetCurrentDirectory(), "Assets", "certbot");

            var prefs = new CertificateManagerPreference
            {
                ConfigPath = Path.Combine(assetsDirectory, "test-config"),
                LogPath = string.Empty
            };

            var manager = new Certbot();
            manager.Init(logger, prefs);

            var log = await manager.GetItemLog(new ManagedCertificate { Name = "wsl.projectbids.co.uk" }, 100);

            Assert.IsTrue(log.Length > 0, "A log request should always return either log entries or the reason there are none");
        }

        [TestMethod]
        public async Task AcmeShItemLogReadsUnixStyleEntryDates()
        {
            // acme.sh stamps each line with the output of the unix date command, e.g. [Mon Sep  9 04:50:59 AWST 2024]
            var configDirectory = Path.Combine(Directory.GetCurrentDirectory(), "Assets", "acme.sh");

            var manager = new AcmeSh();
            manager.Init(new NullLogger<AcmeSh>(), new CertificateManagerPreference { ConfigPath = configDirectory, LogPath = configDirectory });

            var log = await manager.GetItemLog(new ManagedCertificate { Name = "wsl5.projectbids.co.uk" }, 500);

            Assert.IsTrue(log.Length > 0, "Log entries should be returned for the item");
            Assert.IsTrue(log.All(l => l.EventDate != null), "Every entry should have an event date");

            // every acme.sh line carries its own stamp, so each entry date should be the time on its own line. The
            // zone is an abbreviation which cannot be resolved, so the time is read as local
            var stampedEntries = log.Where(l => l.Message.StartsWith("[")).ToList();

            Assert.IsTrue(stampedEntries.Count > 0, "Expected stamped entries from the test log");

            foreach (var entry in stampedEntries)
            {
                var stamp = entry.Message.Substring(1, entry.Message.IndexOf(']') - 1);
                var parts = stamp.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                var eventDate = entry.EventDate!.Value.ToLocalTime();

                Assert.AreEqual(parts[3], eventDate.ToString("HH:mm:ss"), $"Time of day should match the log line: {entry.Message}");
                Assert.AreEqual(parts[5], eventDate.Year.ToString(), $"Year should match the log line: {entry.Message}");
            }
        }

        [TestMethod]
        public async Task AcmeShItemLogReadsUniversalUnixEntryDateExactly()
        {
            var logDirectory = Path.Combine(Path.GetTempPath(), $"acme-sh-log-{Guid.NewGuid():N}");

            Directory.CreateDirectory(logDirectory);

            try
            {
                File.WriteAllLines(Path.Combine(logDirectory, "acme.sh.log"),
                [
                    "[Mon Sep  9 04:50:59 UTC 2024] Renewing: 'test.example.com'",
                    "[Mon Sep  9 04:51:07 UTC 2024] Your cert is in: /home/chris/.acme.sh/test.example.com/test.example.com.cer"
                ]);

                var manager = new AcmeSh();
                manager.Init(new NullLogger<AcmeSh>(), new CertificateManagerPreference { ConfigPath = logDirectory, LogPath = logDirectory });

                var log = await manager.GetItemLog(new ManagedCertificate { Name = "test.example.com" }, 100);

                Assert.AreEqual(2, log.Length, "Both lines mentioning the item should be returned");
                Assert.AreEqual(new DateTime(2024, 9, 9, 4, 50, 59, DateTimeKind.Utc), log[0].EventDate, "A line stamped in UTC should be read as that exact time");
                Assert.AreEqual(new DateTime(2024, 9, 9, 4, 51, 7, DateTimeKind.Utc), log[1].EventDate);
            }
            finally
            {
                Directory.Delete(logDirectory, true);
            }
        }

        [TestMethod]
        public async Task WinAcmeItemLogReadsEntryDatesFromDefaultLogFolder()
        {
            // no log path is configured, so the Log folder below the config path should be found, and win-acme
            // stamps each line with an offset which fixes the entry date regardless of this machine's time zone
            var configDirectory = Path.Combine(Directory.GetCurrentDirectory(), "Assets", "win-acme");

            var manager = new WinAcme();
            manager.Init(new NullLogger<WinAcme>(), new CertificateManagerPreference { ConfigPath = configDirectory, LogPath = string.Empty });

            var resolvedLogPath = await manager.ResolveLogPath();

            Assert.IsTrue(resolvedLogPath.EndsWith("Log"), $"The default win-acme log folder should be found, got '{resolvedLogPath}'");

            var log = await manager.GetItemLog(new ManagedCertificate { Name = "[IIS] test.projectbids.co.uk" }, 500);

            Assert.IsTrue(log.Length > 0, "Log entries should be returned");
            Assert.IsTrue(log.All(l => l.EventDate != null), "Every entry should have an event date");

            // win-acme stamps an offset on every line, so each entry date should be that instant regardless of the
            // time zone of the machine reading the log
            var verified = 0;

            foreach (var entry in log.Where(l => l.Message.Contains('[')))
            {
                var stamp = entry.Message.Substring(0, entry.Message.IndexOf('['));

                if (DateTimeOffset.TryParse(stamp, CultureInfo.InvariantCulture, DateTimeStyles.None, out var expectedDate))
                {
                    Assert.AreEqual(expectedDate.UtcDateTime, entry.EventDate, $"Entry date should be the offset time on its own line: {entry.Message}");
                    verified++;
                }
            }

            Assert.IsTrue(verified > 0, "Expected stamped entries from the test log");
            Assert.IsTrue(
                log.Where(l => l.Message.Contains("[DBG]") || l.Message.Contains("[VRB]")).All(l => l.LogLevel == "INF"),
                "Debug and verbose lines should not be reported as warnings or errors");
        }

        [TestMethod]
        public async Task LogEntriesWithNoDateOfTheirOwnTakeTheDateAroundThem()
        {
            var logDirectory = Path.Combine(Path.GetTempPath(), $"certbot-log-dates-{Guid.NewGuid():N}");

            Directory.CreateDirectory(logDirectory);

            try
            {
                // the read starts partway into a file, so the leading lines have no dated line above them
                File.WriteAllLines(Path.Combine(logDirectory, "letsencrypt.log"),
                [
                    "  continuation of an entry from earlier in the file, for test.example.com",
                    "2025-06-26 09:00:39,100:ERROR:certbot._internal.renewal:Failed to renew certificate test.example.com",
                    "  detail continues on this line for test.example.com"
                ]);

                var manager = new Certbot();
                manager.Init(new NullLogger<Certbot>(), new CertificateManagerPreference { ConfigPath = logDirectory, LogPath = logDirectory });

                var log = await manager.GetItemLog(new ManagedCertificate { Name = "test.example.com" }, 100);

                Assert.AreEqual(3, log.Length);
                Assert.AreEqual(log[1].EventDate, log[0].EventDate, "A leading line should take the date of the first dated entry which follows it");
                Assert.AreEqual(log[1].EventDate, log[2].EventDate, "A continuation line should take the date of the entry it follows");
            }
            finally
            {
                Directory.Delete(logDirectory, true);
            }
        }

        [TestMethod]
        public async Task LogEntriesInAnUndatedFileUseTheFileWriteTime()
        {
            var logDirectory = Path.Combine(Path.GetTempPath(), $"certbot-log-undated-{Guid.NewGuid():N}");

            Directory.CreateDirectory(logDirectory);

            try
            {
                var logFile = Path.Combine(logDirectory, "letsencrypt.log");

                File.WriteAllLines(logFile,
                [
                    "starting renewal for test.example.com",
                    "finished renewal for test.example.com"
                ]);

                var manager = new Certbot();
                manager.Init(new NullLogger<Certbot>(), new CertificateManagerPreference { ConfigPath = logDirectory, LogPath = logDirectory });

                var log = await manager.GetItemLog(new ManagedCertificate { Name = "test.example.com" }, 100);
                var fileWriteTime = new FileInfo(logFile).LastWriteTimeUtc;

                Assert.AreEqual(2, log.Length);
                Assert.IsTrue(log.All(l => l.EventDate == fileWriteTime), "Entries in a file with no timestamps should fall back to the time the file was last written");
            }
            finally
            {
                Directory.Delete(logDirectory, true);
            }
        }

        [TestMethod]
        public async Task CertbotItemLogInfersLevelAndDateFromLogLines()
        {
            var logger = new NullLogger<Certbot>();
            var assetsDirectory = Path.Combine(Directory.GetCurrentDirectory(), "Assets", "certbot");
            var logDirectory = Path.Combine(Path.GetTempPath(), $"certbot-log-parse-{Guid.NewGuid():N}");

            Directory.CreateDirectory(logDirectory);

            try
            {
                File.WriteAllLines(Path.Combine(logDirectory, "letsencrypt.log"),
                [
                    "2025-06-26 09:00:38,880:DEBUG:certbot._internal.main:Attempting renewal of test.example.com, no error yet",
                    "2025-06-26 09:00:39,100:ERROR:certbot._internal.renewal:Failed to renew certificate test.example.com with error: some detail",
                    "  detail continues on this line while renewing test.example.com"
                ]);

                var prefs = new CertificateManagerPreference
                {
                    ConfigPath = Path.Combine(assetsDirectory, "test-config"),
                    LogPath = logDirectory
                };

                var manager = new Certbot();
                manager.Init(logger, prefs);

                var log = await manager.GetItemLog(new ManagedCertificate { Name = "test.example.com" }, 100);

                Assert.AreEqual(3, log.Length, "All lines mentioning the item should be returned, oldest first");
                Assert.AreEqual("INF", log[0].LogLevel, "A debug line which happens to mention the word error is not an error");
                Assert.AreEqual("ERR", log[1].LogLevel, "A line logged at ERROR level should be reported as an error");
                Assert.IsNotNull(log[0].EventDate, "The event date should be read from the log line");
                Assert.IsTrue(log[1].EventDate > log[0].EventDate, "Entries should carry their own event date");
                Assert.AreEqual(log[1].EventDate, log[2].EventDate, "A continuation line should inherit the date of the entry it follows");
            }
            finally
            {
                if (Directory.Exists(logDirectory))
                {
                    Directory.Delete(logDirectory, true);
                }
            }
        }

        [TestMethod]
        public async Task AcmeSh()
        {
            var logger = new NullLogger<AcmeSh>();
            var currentDirectory = Directory.GetCurrentDirectory();
            var configDirectory = Path.Combine(currentDirectory, "Assets", "acme.sh");
            var prefs = new CertificateManagerPreference
            {
                ConfigPath = configDirectory,
                LogPath = configDirectory
            };
            var manager = new AcmeSh();
            manager.Init(logger, prefs);
            await AssertManagerConfigAndRenewals(manager, "Acme.sh");
        }
    }
}
