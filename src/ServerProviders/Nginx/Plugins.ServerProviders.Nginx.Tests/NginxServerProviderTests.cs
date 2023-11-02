using Certify.Management.Servers;
using Certify.Models;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

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

        private string _testSitePath = "c://nginx//sites";
        private string _serverConfigRoot;

        public NginxServerProviderTests()
        {

            // see integration test base for env variable
            _testSiteDomains.Add(new List<string> { "integration1." + _testSiteDomain, "integration2." + _testSiteDomain, "integration3." + _testSiteDomain });
            _testSiteDomains.Add(new List<string> { "www.example.com", "example.com" });
            _testSiteDomains.Add(new List<string> { "www.domain.com", "domain.com" });

            _serverConfigRoot = Path.Combine(AppContext.BaseDirectory, "Assets", "test_config");

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
            var primarySiteDomain = _testSiteDomains[0][0];
            var allSiteBindings = await _nginxProvider.GetSiteBindingList(true, primarySiteDomain);

            var targetBinding = allSiteBindings.FirstOrDefault(b => b.Host == primarySiteDomain);

            Assert.IsNotNull(targetBinding, "Binding should not be null");

            Assert.AreEqual(targetBinding.Host, primarySiteDomain, "Binding hostname should equal test");

        }



        [TestMethod]
        public async Task TestGetSiteInfos()
        {

            var allSites = await _nginxProvider.GetPrimarySites(false);

            Assert.IsNotNull(allSites, "Sites should not be null");

            var targetSiteId = _testSiteDomains[0].First();
            var targetSite = allSites.FirstOrDefault(s => s.Id == targetSiteId);

            Assert.IsNotNull(targetSite, "Target site should not be null");
        }

        [TestMethod]
        public async Task TestGetServerVersion()
        {

            var versionResult = _nginxProvider.GetServerVersion("nginx version: nginx/1.18.0 (Ubuntu)");

            Assert.IsNotNull(versionResult, "Version should not be null");

            Assert.IsTrue(versionResult.Major >= 1, "Version should be 1 or higher");
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
            //await _nginxManager.AddSiteBindings(site.Id.ToString(), testDomains, _testSiteHttpPort);

            // get fresh instance of site since updates
            var bindingsBeforeApply = await _nginxProvider.GetSiteBindingList(false, testSiteDomain);


            var dummyCertPath = Environment.CurrentDirectory + "\\Assets\\dummycert.pem";
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
                        new List<CertRequestChallengeConfig>
                        {
                            new CertRequestChallengeConfig{
                                ChallengeType="http-01"
                            }
                        }),
                    PerformAutoConfig = true,
                    PerformAutomatedCertBinding = true,
                    PerformChallengeFileCopy = true,
                    PerformExtensionlessConfigChecks = true,
                    WebsiteRootPath = _testSitePath,
                    DeploymentSiteOption = DeploymentOption.SingleSite,
                    DeploymentBindingMatchHostname = true,
                    DeploymentBindingBlankHostname = true,
                    DeploymentBindingReplacePrevious = true,
                    SubjectAlternativeNames = new string[] { testSiteDomain, "label1." + testSiteDomain }
                },
                ItemType = ManagedCertificateType.SSL_ACME,
                CertificatePath = dummyCertPath
            };

            /*var actions = await new BindingDeploymentManager().StoreAndDeploy(
                _nginxManager.GetDeploymentTarget(),
                managedCertificate, dummyCertPath, "",
                false, CertificateManager.DEFAULT_STORE_NAME);

            foreach (var a in actions)
            {
                System.Console.WriteLine(a.Description);
            }

            // get cert info to compare hash
            var certInfo = CertificateManager.LoadCertificate(managedCertificate.CertificatePath);
            */

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
