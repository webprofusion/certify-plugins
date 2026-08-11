using System.IO;
using System.Threading.Tasks;
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
