using Certify.Config;
using Certify.Core.Management.DeploymentTasks;
using Certify.Models;
using Certify.Models.Config;
using Certify.Providers.DeploymentTasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace DeploymentTaskTests
{
    [TestClass]
    public class DeploymentTasksAzure : IntegrationTestBase
    {

        [TestInitialize]
        public new void Setup()
        {
            base.Setup();

            _pluginManager.LoadPlugins(new List<string> { "DeploymentTasks" });
        }

        [TestMethod, TestCategory("Export")]
        public async Task TestDeployToKeyVault()
        {
            var deploymentTasks = new List<DeploymentTask>();

            var azureKeyVaultUri = ConfigSettings["Azure_TestKeyVaultUri"];
            var inputFile = ConfigSettings["TestLocalPath"] + "\\testcert.pfx";

            var tasktypeId = Plugin.DeploymentTasks.Azure.AzureKeyVault.Definition.Id.ToLower();

            var config = new DeploymentTaskConfig
            {
                TaskTypeId = tasktypeId,
                TaskName = "A test pfx export task",
                ChallengeProvider = StandardAuthTypes.STANDARD_AUTH_LOCAL,

                Parameters = new List<ProviderParameterSetting>
                {
                    new ProviderParameterSetting("vault_uri", azureKeyVaultUri)
                }
            };

            var provider = DeploymentTaskProviderFactory.Create(tasktypeId, _pluginManager.DeploymentTaskProviders);
            var t = new DeploymentTask(provider, config, null);

            deploymentTasks.Add(t);

            // perform preview deployments
            var managedCert = GetMockManagedCertificate("DeploymentTest", "123", PrimaryTestDomain, PrimaryIISRoot);
            managedCert.CertificatePath = inputFile;

            foreach (var task in deploymentTasks)
            {
                var results = await task.Execute(_log, null, managedCert, CancellationToken.None, new DeploymentContext { }, isPreviewOnly: false);

                // assert new valid pfx exists in destination
                Assert.IsTrue(results.All(r => r.IsSuccess));
            }
        }
    }
}
