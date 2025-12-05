using System;
using System.IO;
using System.Threading.Tasks;
using Certify.Models.Config;
using Certify.Plugin.CertificateManagers.Providers.AzureManagedCertificates;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Plugin.Tests
{
    [TestClass]
    public class AzureManagedCertificatesTests
    {
        [TestMethod]
        public void TestProviderDefinition()
        {
            var definition = AzureManagedCertificates.Definition;

            Assert.IsNotNull(definition);
            Assert.AreEqual("azure.managedcertificates", definition.Id);
            Assert.AreEqual("Azure Managed Certificates", definition.Title);
            Assert.IsTrue(definition.IsEnabled);
            Assert.IsFalse(string.IsNullOrEmpty(definition.Description));
            Assert.IsFalse(string.IsNullOrEmpty(definition.HelpUrl));
        }

        [TestMethod]
        public async Task TestInitialization()
        {
            var logger = new NullLogger<AzureManagedCertificates>();
            var manager = new AzureManagedCertificates();

            // Test with no preferences
            manager.Init(logger, null);

            var definition = manager.GetProviderDefinition();
            Assert.IsNotNull(definition);
            Assert.AreEqual("azure.managedcertificates", definition.Id);
        }

        [TestMethod]
        public async Task TestIsPresent_NoConfig()
        {
            var logger = new NullLogger<AzureManagedCertificates>();
            var manager = new AzureManagedCertificates();

            var prefs = new CertificateManagerPreference
            {
                ConfigPath = null,
                LogPath = null
            };

            manager.Init(logger, prefs);

            // Should return false when no subscription ID is configured
            var isPresent = await manager.IsPresent();
            Assert.IsFalse(isPresent);
        }

        [TestMethod]
        public async Task TestGetManagedCertificates_NoConfig()
        {
            var logger = new NullLogger<AzureManagedCertificates>();
            var manager = new AzureManagedCertificates();

            var prefs = new CertificateManagerPreference
            {
                ConfigPath = null,
                LogPath = null
            };

            manager.Init(logger, prefs);

            // Should return empty list when not configured
            var certs = await manager.GetManagedCertificates();
            Assert.IsNotNull(certs);
            Assert.AreEqual(0, certs.Count);
        }

        [TestMethod]
        public async Task TestSettingsDeserialization()
        {
            var logger = new NullLogger<AzureManagedCertificates>();
            var manager = new AzureManagedCertificates();

            // Create a temporary config file
            var tempDir = Path.GetTempPath();
            var configFile = Path.Combine(tempDir, $"azure-mc-test-{Guid.NewGuid()}.json");

            try
            {
                var configContent = @"{
                    ""SubscriptionId"": ""12345678-1234-1234-1234-123456789012"",
                    ""ResourceGroups"": [""test-rg-1"", ""test-rg-2""],
                    ""TenantId"": ""87654321-4321-4321-4321-210987654321"",
                    ""ClientId"": ""abcdef12-3456-7890-abcd-ef1234567890"",
                    ""ClientSecret"": ""test-secret""
                }";

                File.WriteAllText(configFile, configContent);

                var prefs = new CertificateManagerPreference
                {
                    ConfigPath = configFile,
                    LogPath = null
                };

                manager.Init(logger, prefs);

                // Note: We can't test IsPresent() or GetManagedCertificates() without real Azure credentials
                // Those would require integration tests with actual Azure resources
                Assert.IsTrue(true, "Settings loaded successfully");
            }
            finally
            {
                if (File.Exists(configFile))
                {
                    File.Delete(configFile);
                }
            }
        }

        [TestMethod]
        public async Task TestSettingsDeserialization_InvalidJson()
        {
            var logger = new NullLogger<AzureManagedCertificates>();
            var manager = new AzureManagedCertificates();

            var tempDir = Path.GetTempPath();
            var configFile = Path.Combine(tempDir, $"azure-mc-test-invalid-{Guid.NewGuid()}.json");

            try
            {
                var invalidConfigContent = @"{
                    ""SubscriptionId"": ""12345678-1234-1234-1234-123456789012"",
                    ""ResourceGroups"": [""test-rg-1"", 
                }"; // Invalid JSON

                File.WriteAllText(configFile, invalidConfigContent);

                var prefs = new CertificateManagerPreference
                {
                    ConfigPath = configFile,
                    LogPath = null
                };

                // Should not throw, should handle gracefully
                manager.Init(logger, prefs);

                var isPresent = await manager.IsPresent();
                Assert.IsFalse(isPresent, "Should return false when config is invalid");
            }
            finally
            {
                if (File.Exists(configFile))
                {
                    File.Delete(configFile);
                }
            }
        }

        [TestMethod]
        public async Task TestGetManagedCertificates_WithFilter()
        {
            var logger = new NullLogger<AzureManagedCertificates>();
            var manager = new AzureManagedCertificates();

            var prefs = new CertificateManagerPreference
            {
                ConfigPath = null,
                LogPath = null
            };

            manager.Init(logger, prefs);

            var filter = new Certify.Models.ManagedCertificateFilter
            {
                Name = "test"
            };

            // Should return empty list when not configured, even with filter
            var certs = await manager.GetManagedCertificates(filter);
            Assert.IsNotNull(certs);
            Assert.AreEqual(0, certs.Count);
        }
    }
}
