using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using Certify.Management;
using Certify.Models;
using Certify.Models.Providers;
using Microsoft.Extensions.Logging;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Newtonsoft.Json;

namespace DeploymentTaskTests
{
    public class IntegrationTestBase
    {
        /// <summary>
        /// Example test domain, real tests will set CERTIFY_TESTDOMAIN env variable
        /// </summary>
        public string PrimaryTestDomain = "test.certifytheweb.com";
        public string PrimaryIISRoot = @"c:\inetpub\wwwroot\";
        public Dictionary<string, string> ConfigSettings = new Dictionary<string, string>();
        internal ILog _log;
        internal PluginManager _pluginManager;

        public IntegrationTestBase()
        {
            if (Environment.GetEnvironmentVariable("CERTIFY_TESTDOMAIN") != null)
            {
                PrimaryTestDomain = Environment.GetEnvironmentVariable("CERTIFY_TESTDOMAIN");
            }

            /* ConfigSettings.Add("AWS_ZoneId", "example");
             ConfigSettings.Add("Azure_ZoneId", "example");
             ConfigSettings.Add("Cloudflare_ZoneId", "example");
             System.IO.File.WriteAllText("C:\\temp\\TestConfigSettings.json", JsonConvert.SerializeObject(ConfigSettings));
             */

            ConfigSettings = JsonConvert.DeserializeObject<Dictionary<string, string>>(System.IO.File.ReadAllText("C:\\temp\\Certify\\TestConfigSettings.json"));

            _log = new Loggy(LoggerFactory.Create(builder => builder.AddDebug()).CreateLogger<IntegrationTestBase>());
        }

        [TestInitialize]
        public void Setup()
        {
            _pluginManager = new PluginManager();
        }

        public ManagedCertificate GetMockManagedCertificate(string siteName, string siteId, string testDomain, string testPath)
        {
            var dummyManagedCertificate = new ManagedCertificate
            {
                Id = Guid.NewGuid().ToString(),
                Name = siteName,
                GroupId = siteId,
                RequestConfig = new CertRequestConfig
                {
                    PrimaryDomain = testDomain,
                    PerformAutoConfig = true,
                    PerformAutomatedCertBinding = true,
                    PerformChallengeFileCopy = true,
                    PerformExtensionlessConfigChecks = true,
                    WebsiteRootPath = testPath,
                    Challenges = new ObservableCollection<CertRequestChallengeConfig>
                    {

                    },
                    DeploymentSiteOption = DeploymentOption.SingleSite
                },
                ItemType = ManagedCertificateType.SSL_ACME,
                CertificatePath = Path.Combine(AppContext.BaseDirectory, "Assets\\dummycert.pfx")
            };

            return dummyManagedCertificate;

        }
    }
}
