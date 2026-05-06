using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Certify.Core.Management;
using Certify.Management;
using Certify.Management.Servers;
using Certify.Models;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Certify.Plugins.Server.Nginx.Tests
{
    [TestClass]
    /// <summary>
    /// Integration tests for Nginx Manager
    /// </summary>
    public class NginxServerProviderTests : IDisposable
    {
        private ServerProviderNginx _nginxProvider;

        private readonly string _testSiteDomain = "projectbids.co.uk";
        private readonly List<List<string>> _testSiteDomains = new();
        private readonly int _testSiteHttpPort = 81;

        private string _testSitePath = "D:\\Temp\\Support\\5957\\nginx";
        private string _serverConfigRoot;

        public NginxServerProviderTests()
        {

            // see integration test base for env variable
            /*   _testSiteDomains.Add(new List<string> { "integration1." + _testSiteDomain, "integration2." + _testSiteDomain, "integration3." + _testSiteDomain });
               _testSiteDomains.Add(new List<string> { "www.example.com", "example.com" });
               _testSiteDomains.Add(new List<string> { "www.domain.com", "domain.com" });
            */
            _serverConfigRoot = Path.Combine(_testSitePath);

            _nginxProvider = new ServerProviderNginx(_serverConfigRoot);

            //perform setup for IIS
            Setup().Wait();
        }

        /// <summary>
        /// Perform teardown for IIS
        /// </summary>
        public void Dispose() => Teardown().Wait();

        public async Task Setup()
        {
            foreach (var siteDomains in _testSiteDomains)
            {
                _ = await _nginxProvider.CreateSite(siteDomains, _testSitePath, "http");
            }
        }

        public async Task Teardown()
        {
            foreach (var siteDomains in _testSiteDomains)
            {
                _ = await _nginxProvider.DeleteSite(siteDomains[0]);

                Assert.IsFalse(await _nginxProvider.SiteExists(siteDomains[0]));
            }
        }

        [TestMethod]
        public async Task TestGetBinding()
        {
            var primarySiteDomain = _testSiteDomain;
            var configRoot = CreateTempConfig($@"
events {{}}
http {{
    server {{
        listen 80;
        server_name {primarySiteDomain} www.{primarySiteDomain};
        root /var/www/{primarySiteDomain};
    }}
}}");

            try
            {
                var provider = new ServerProviderNginx(configRoot);
                var allSiteBindings = await provider.GetSiteBindingList(true, primarySiteDomain);

                var targetBinding = allSiteBindings.FirstOrDefault(b => b.Host == primarySiteDomain);

                Assert.IsNotNull(targetBinding, "Binding should not be null");

                Assert.AreEqual(primarySiteDomain, targetBinding.Host, "Binding hostname should equal test");
            }
            finally
            {
                Directory.Delete(configRoot, true);
            }
        }

        [TestMethod]
        public async Task TestGetSiteInfos()
        {
            var targetSiteId = _testSiteDomain;
            var configRoot = CreateTempConfig($@"
events {{}}
http {{
    server {{
        listen 80;
        server_name {targetSiteId} www.{targetSiteId};
        root /var/www/{targetSiteId};
    }}
}}");

            try
            {
                var provider = new ServerProviderNginx(configRoot);
                var allSites = await provider.GetPrimarySites(false);

                Assert.IsNotNull(allSites, "Sites should not be null");

                var targetSite = allSites.FirstOrDefault(s => s.Id == targetSiteId);

                Assert.IsNotNull(targetSite, "Target site should not be null");
            }
            finally
            {
                Directory.Delete(configRoot, true);
            }
        }

        [TestMethod]
        public void TestGetServerVersion()
        {

            var versionResult = _nginxProvider.GetServerVersion("nginx version: nginx/1.18.0 (Ubuntu)");

            Assert.IsNotNull(versionResult, "Version should not be null");

            Assert.IsTrue(versionResult.Major >= 1, "Version should be 1 or higher");
        }

        [TestMethod]
        public async Task TestIsAvailable()
        {
            var provider = new ServerProviderNginx(Path.Combine(Environment.CurrentDirectory, "Assets", "test_config"));

            Assert.IsTrue(await provider.IsAvailable(), "Provider should be available when config is parseable");
        }

        [TestMethod]
        public async Task TestMultipleServerBlocksAreParsed()
        {
            var configRoot = CreateTempConfig(@"
events {}
http {
    server {
        listen 80;
        server_name example.com www.example.com;
        root /var/www/example;
    }
    server {
        listen 443 ssl;
        server_name example.net;
        root /var/www/example-net;
        ssl_certificate /etc/ssl/example.net.crt;
        ssl_certificate_key /etc/ssl/example.net.key;
    }
}");

            try
            {
                var manager = new NginxManager(configRoot);
                var sites = await manager.GetPrimarySites();

                Assert.IsTrue(sites.Any(s => s.Id == "example.com"), "First server block should be parsed");
                Assert.IsTrue(sites.Any(s => s.Id == "example.net"), "Second server block should be parsed");
            }
            finally
            {
                Directory.Delete(configRoot, true);
            }
        }

        [TestMethod]
        public async Task TestInvalidServerNamesAreFiltered()
        {
            var configRoot = CreateTempConfig(@"
events {}
http {
    server {
        listen 80;
        server_name _ ~^(?<subdomain>.+)\.example\.com$ $hostname *.example.org valid.example.com;
        root /var/www/example;
    }
}");

            try
            {
                var manager = new NginxManager(configRoot);
                var bindings = await manager.GetBindings();

                Assert.IsFalse(bindings.Any(b => b.Host == "_"), "Placeholder server names should be excluded");
                Assert.IsFalse(bindings.Any(b => b.Host.Contains("$")), "Variable server names should be excluded");
                Assert.IsFalse(bindings.Any(b => b.Host.StartsWith("~")), "Regex server names should be excluded");
                Assert.IsTrue(bindings.Any(b => b.Host == "example.org"), "Wildcard server names should be normalized");
                Assert.IsTrue(bindings.Any(b => b.Host == "valid.example.com"), "Valid server names should be retained");
            }
            finally
            {
                Directory.Delete(configRoot, true);
            }
        }

        private static string CreateTempConfig(string config)
        {
            var configRoot = Path.Combine(Path.GetTempPath(), "certify-nginx-tests", Guid.NewGuid().ToString());
            Directory.CreateDirectory(configRoot);
            File.WriteAllText(Path.Combine(configRoot, "nginx.conf"), config);
            return configRoot;
        }

        [TestMethod, TestCategory("MegaTest")]
        public async Task TestBindingMatch()
        {
            // create test site with mix of hostname and IP only bindings
            var testStr = "abc123";
            var testSiteDomain = $"test-{testStr}." + _testSiteDomain;

            if (await _nginxProvider.SiteExists(testSiteDomain))
            {
                await _nginxProvider.DeleteSite(testSiteDomain);
            }

            // create site with IP all unassigned, no hostname
            var site = await _nginxProvider.CreateSite(new List<string> { testSiteDomain }, _testSitePath, port: _testSiteHttpPort);

            // add another hostname binding (matching cert and not matching cert)
            //var testDomains = new List<string> { testSiteDomain, "label1." + testSiteDomain, "nested.label." + testSiteDomain };


            // get fresh instance of site since updates
            var bindingsBeforeApply = await _nginxProvider.GetSiteBindingList(false, testSiteDomain);

            var dummyCertPath = Path.GetFullPath(Path.Combine(Environment.CurrentDirectory, "..", "..", "..", "..", "..", "..", "..", "DeploymentTasks", "Tests", "Assets", "dummycert.pfx"));
            var managedCertificate = new ManagedCertificate
            {
                Id = Guid.NewGuid().ToString(),
                Name = testSiteDomain,
                ServerSiteId = site.Id.ToString(),
                UseStagingMode = true,
                RequestConfig = new CertRequestConfig
                {
                    PrimaryDomain = testSiteDomain,
                    Challenges = new ObservableCollection<CertRequestChallengeConfig>(
                        [
                            new CertRequestChallengeConfig{
                                ChallengeType="http-01"
                            }
                        ]),
                    PerformAutoConfig = true,
                    PerformAutomatedCertBinding = true,
                    PerformChallengeFileCopy = true,
                    PerformExtensionlessConfigChecks = true,
                    WebsiteRootPath = _testSitePath,
                    DeploymentSiteOption = DeploymentOption.SingleSite,
                    DeploymentBindingMatchHostname = true,
                    DeploymentBindingBlankHostname = true,
                    DeploymentBindingReplacePrevious = true,
                    SubjectAlternativeNames = [testSiteDomain, "label1." + testSiteDomain]
                },
                ItemType = ManagedCertificateType.SSL_ACME,
                CertificatePath = dummyCertPath
            };

            var actions = await new BindingDeploymentManager().StoreAndDeploy(
                _nginxProvider.GetDeploymentTarget(),
                managedCertificate, dummyCertPath, "",
                true, CertificateManager.DEFAULT_STORE_NAME);

            foreach (var a in actions)
            {
                System.Console.WriteLine(a.Description);
            }

            // get cert info to compare hash
            //var certInfo = CertificateManager.LoadCertificate(managedCertificate.CertificatePath);

            // check  site bindings
            var finalBindings = await _nginxProvider.GetSiteBindingList(false, testSiteDomain);

            Assert.IsTrue(bindingsBeforeApply.Count < finalBindings.Count, "Should have new bindings");

            try
            {
                // check we have the new bindings we expected

                // blank hostname binding
                var testBinding = finalBindings.FirstOrDefault(b => b.Host == "" && b.Protocol == "https");
                // Assert.IsTrue(IsCertHashEqual(testBinding.CertificateHash, certInfo.GetCertHash()), "Blank hostname binding should be added and have certificate set");

            }
            finally
            {
                // clean up either way
                await _nginxProvider.DeleteSite(testSiteDomain);

            }
        }
    }
}
