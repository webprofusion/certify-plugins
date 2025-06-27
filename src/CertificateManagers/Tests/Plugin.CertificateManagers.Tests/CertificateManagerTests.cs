using System.IO;
using System.Threading.Tasks;
using Certify.Plugin.CertificateManagers.Providers.AcmeSh;
using Certify.Plugin.CertificateManagers.Providers.Certbot;
using Certify.Plugin.CertificateManagers.Providers.PoshAcme;
using Certify.Plugin.CertificateManagers.Providers.SimpleAcme;
using Certify.Plugin.CertificateManagers.Providers.WinAcme;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Plugin.Tests
{
    [TestClass]
    public class CertificateManagerTests
    {
        [TestMethod]
        public async Task WinAcme()
        {
            var logger = new NullLogger<WinAcme>();

            var currentDirectory = Directory.GetCurrentDirectory();
            var configDirectory = Path.Combine(currentDirectory, "Assets", "win-acme");

            var manager = new WinAcme();
            manager.Init(logger, configDirectory, configDirectory);

            var isPresent = await manager.IsPresent();

            Assert.IsTrue(isPresent, "win-acme config should be present");

            var certs = await manager.GetManagedCertificates();

            Assert.IsTrue(certs.Count > 0, "win-acme renewals should be present");
        }

        [TestMethod]
        public async Task PoshACME()
        {
            var logger = new NullLogger<PoshAcme>();

            var currentDirectory = Directory.GetCurrentDirectory();
            var configDirectory = Path.Combine(currentDirectory, "Assets", "posh-acme");

            var manager = new PoshAcme();
            manager.Init(logger, configDirectory, configDirectory);

            var isPresent = await manager.IsPresent();

            Assert.IsTrue(isPresent, "Posh-ACME config should be present");

            var certs = await manager.GetManagedCertificates();

            Assert.IsTrue(certs.Count > 0, "Posh-ACME renewals should be present");
        }

        [TestMethod]
        public async Task SimpleAcme()
        {
            var logger = new NullLogger<SimpleAcme>();

            var currentDirectory = Directory.GetCurrentDirectory();
            var configDirectory = Path.Combine(currentDirectory, "Assets", "simple-acme");

            var manager = new SimpleAcme();
            manager.Init(logger, configDirectory, configDirectory);

            var isPresent = await manager.IsPresent();

            Assert.IsTrue(isPresent, "simple-acme config should be present");

            var certs = await manager.GetManagedCertificates();

            Assert.IsTrue(certs.Count > 0, "simple-acme renewals should be present");
        }

        [TestMethod]
        public async Task Certbot()
        {
            var logger = new NullLogger<Certbot>();

            var currentDirectory = Directory.GetCurrentDirectory();
            var assetsDirectory = Path.Combine(currentDirectory, "Assets", "certbot");
            var settingsDirectory = Path.Combine(assetsDirectory, "test-config");
            var logDirectory = Path.Combine(assetsDirectory, "test-logs");

            var manager = new Certbot();
            manager.Init(logger, settingsDirectory, logDirectory);

            var isPresent = await manager.IsPresent();

            Assert.IsTrue(isPresent, "Certbot config should be present");

            var certs = await manager.GetManagedCertificates();

            Assert.IsTrue(certs.Count > 0, "Certbot renewals should be present");

        }

        [TestMethod]
        public async Task AcmeSh()
        {
            var logger = new NullLogger<AcmeSh>();

            // use current working directory for Acme.sh

            var currentDirectory = Directory.GetCurrentDirectory();
            var configDirectory = Path.Combine(currentDirectory, "Assets", "acme.sh");

            var manager = new AcmeSh();
            manager.Init(logger, configDirectory, configDirectory);

            var isPresent = await manager.IsPresent();

            Assert.IsTrue(isPresent, "Acme.sh config should be present");

            var certs = await manager.GetManagedCertificates();

            Assert.IsTrue(certs.Count > 0, "Acme.sh renewals should be present");

        }
    }
}
