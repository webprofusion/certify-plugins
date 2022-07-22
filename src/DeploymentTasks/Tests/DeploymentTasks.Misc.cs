using Certify.Core.Management.DeploymentTasks;
using Certify.Management;
using Certify.Models.Config;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace DeploymentTaskTests
{
    [TestClass]
    public class DeploymentTaskMisc : IntegrationTestBase
    {

        [TestInitialize]
        public new void Setup()
        {
            base.Setup();

            _pluginManager.LoadPlugins(new List<string> { "DeploymentTasks" });
        }

        [Ignore]
        [TestMethod, TestCategory("TestCredentials")]
        public async Task CreateTestCredentials()
        {
            var credentialsManager = new SQLiteCredentialsManager
            {
                StorageSubfolder = "credentials\\test"
            };

            var secrets = new Dictionary<string, string>
            {
                { "username", "ubuntu" },
                { "password", "testuser" }
            };

            var storedCred = await credentialsManager.Update(new StoredCredential
            {
                StorageKey = "atestsshuser",
                Title = "Test: SSH",
                DateCreated = DateTime.Now,
                ProviderType = "SSH",
                Secret = JsonConvert.SerializeObject(secrets)
            });

            secrets = new Dictionary<string, string>
            {
                { "username", "testuser" },
                { "password", "testuser" }
            };

            storedCred = await credentialsManager.Update(new StoredCredential
            {
                StorageKey = ConfigSettings["TestCredentialsKey_UNC"],
                Title = "Test: UNC testuser",
                DateCreated = DateTime.Now,
                ProviderType = "Windows",
                Secret = JsonConvert.SerializeObject(secrets)
            });

        }

        [TestMethod, TestCategory("Misc")]
        public async Task TestGetAllDeploymentTaskProviders()
        {

            var allProviders = await DeploymentTaskProviderFactory.GetDeploymentTaskProviders(_pluginManager.DeploymentTaskProviders);

            // all providers have a unique title
            Assert.IsTrue(allProviders.Select(p => p.Title).Distinct().Count() == allProviders.Count);

            // all providers have a unique id
            Assert.IsTrue(allProviders.Select(p => p.Id).Distinct().Count() == allProviders.Count);

            // all providers have a unique description
            Assert.IsTrue(allProviders.Select(p => p.Description).Distinct().Count() == allProviders.Count);
        }

    }
}
