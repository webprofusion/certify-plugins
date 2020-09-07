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
    public class DeploymentTasksServiceManager : IntegrationTestBase
    {

        [TestInitialize]
        public new void Setup()
        {
            base.Setup();

            _pluginManager.LoadPlugins(new List<string> { "DeploymentTasks" });
        }

        [TestMethod, TestCategory("ServiceManager")]
        public async Task TestServiceManager()
        {

            var deploymentTasks = new List<DeploymentTask>();
            var taskTypeId = Certify.Providers.DeploymentTasks.ServiceManager.Definition.Id.ToLower();
            var provider = DeploymentTaskProviderFactory.Create(taskTypeId, _pluginManager.DeploymentTaskProviders);

            var svcName = "hMailServer";

            var restartTaskConfig = new DeploymentTaskConfig
            {
                TaskTypeId = taskTypeId,
                TaskName = "A test service manager task restart",
                ChallengeProvider = StandardAuthTypes.STANDARD_AUTH_LOCAL,

                Parameters = new List<ProviderParameterSetting>
                {
                    new ProviderParameterSetting("servicename", svcName),
                    new ProviderParameterSetting("action", "restart"),
                    new ProviderParameterSetting("maxwait", "20")
                }
            };
            deploymentTasks.Add(new DeploymentTask(provider, restartTaskConfig, null));

            var stopTaskConfig = new DeploymentTaskConfig
            {
                TaskTypeId = taskTypeId,
                TaskName = "A test service manager task stop",
                ChallengeProvider = StandardAuthTypes.STANDARD_AUTH_LOCAL,

                Parameters = new List<ProviderParameterSetting>
                {
                    new ProviderParameterSetting("servicename", svcName),
                    new ProviderParameterSetting("action", "stop"),
                    new ProviderParameterSetting("maxwait", "20")
                }
            };
            deploymentTasks.Add(new DeploymentTask(provider, stopTaskConfig, null));

            var startTaskConfig = new DeploymentTaskConfig
            {
                TaskTypeId = taskTypeId,
                TaskName = "A test service manager task start",
                ChallengeProvider = StandardAuthTypes.STANDARD_AUTH_LOCAL,

                Parameters = new List<ProviderParameterSetting>
                {
                    new ProviderParameterSetting("servicename", svcName),
                    new ProviderParameterSetting("action", "start"),
                    new ProviderParameterSetting("maxwait", "20")
                }
            };

            deploymentTasks.Add(new DeploymentTask(provider, startTaskConfig, null));

            // perform preview deployments
            var managedCert = GetMockManagedCertificate("Test", "123", PrimaryTestDomain, PrimaryIISRoot);

            List<ActionResult> results = new List<ActionResult>();
            foreach (var task in deploymentTasks)
            {
                results.AddRange(await task.Execute(_log, null, managedCert, CancellationToken.None, new DeploymentContext { }, isPreviewOnly: false));
            }

            // assert output exists in destination
            Assert.IsTrue(results.All(r => r.IsSuccess == true));

        }
    }
}
