using Certify.Config;
using Certify.Core.Management.DeploymentTasks;
using Certify.Models;
using Certify.Models.Config;
using Certify.Providers.DeploymentTasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace DeploymentTaskTests
{
    [TestClass]
    public class DeploymentTasksExport : IntegrationTestBase
    {

        [TestInitialize]
        public new void Setup()
        {
            base.Setup();

            _pluginManager.LoadPlugins(new List<string> { "DeploymentTasks" });
        }

        [TestMethod, TestCategory("Export")]
        public async Task TestPFxExport()
        {
            var deploymentTasks = new List<DeploymentTask>();

            var outputFile = ConfigSettings["TestLocalPath"] + "\\test_pfx_export_apache.pfx";

            var config = new DeploymentTaskConfig
            {
                TaskTypeId = Certify.Providers.DeploymentTasks.CertificateExport.Definition.Id.ToLower(),
                TaskName = "A test pfx export task",
                ChallengeProvider = StandardAuthTypes.STANDARD_AUTH_LOCAL,

                Parameters = new List<ProviderParameterSetting>
                {
                    new ProviderParameterSetting("path", outputFile),
                    new ProviderParameterSetting("type", "pfxfull")
                }
            };

            var provider = DeploymentTaskProviderFactory.Create(Certify.Providers.DeploymentTasks.CertificateExport.Definition.Id.ToLower(), _pluginManager.DeploymentTaskProviders);
            var t = new DeploymentTask(provider, config, null);

            deploymentTasks.Add(t);

            // perform preview deployments
            var managedCert = GetMockManagedCertificate("DeploymentTest", "123", PrimaryTestDomain, PrimaryIISRoot);

            foreach (var task in deploymentTasks)
            {
                var result = await task.Execute(_log, managedCert, CancellationToken.None, isPreviewOnly: false);
            }

            // assert new valid pfx exists in destination
            Assert.IsTrue(File.Exists(outputFile));
            File.Delete(outputFile);
        }

        [TestMethod, TestCategory("Export")]
        public async Task TestPemApacheExport()
        {

            var deploymentTasks = new List<DeploymentTask>();

            var outputPath = ConfigSettings["TestLocalPath"] + "\\test_pfx_export";

            var config = new DeploymentTaskConfig
            {
                TaskTypeId = Certify.Providers.DeploymentTasks.Apache.Definition.Id.ToLower(),
                TaskName = "A test Apache export task",
                ChallengeProvider = StandardAuthTypes.STANDARD_AUTH_LOCAL,

                Parameters = new List<ProviderParameterSetting>
                {
                    new ProviderParameterSetting("path_cert", outputPath+".crt"),
                    new ProviderParameterSetting("path_key", outputPath+".key"),
                    new ProviderParameterSetting("path_chain", outputPath+".chain")
                }
            };

            var provider = DeploymentTaskProviderFactory.Create(Certify.Providers.DeploymentTasks.Apache.Definition.Id.ToLower(), _pluginManager.DeploymentTaskProviders);
            var t = new DeploymentTask(provider, config, null);

            deploymentTasks.Add(t);

            // perform preview deployments
            var managedCert = GetMockManagedCertificate("LocalApacheDeploymentTest", "123", PrimaryTestDomain, PrimaryIISRoot);

            foreach (var task in deploymentTasks)
            {
                var result = await task.Execute(_log, managedCert, CancellationToken.None, isPreviewOnly: false);
            }

            // assert output exists in destination
            Assert.IsTrue(File.Exists(outputPath + ".crt"));
            Assert.IsTrue(File.Exists(outputPath + ".key"));
            Assert.IsTrue(File.Exists(outputPath + ".chain"));

            File.Delete(outputPath + ".crt");
            File.Delete(outputPath + ".key");
            File.Delete(outputPath + ".chain");
        }

        [TestMethod, TestCategory("Export")]
        public async Task TestPemNginxExport()
        {

            var deploymentTasks = new List<DeploymentTask>();

            var outputPath = ConfigSettings["TestLocalPath"] + "\\test_pfx_export_nginx";

            var config = new DeploymentTaskConfig
            {
                TaskTypeId = Nginx.Definition.Id.ToLower(),
                TaskName = "A test Nginx export task",
                ChallengeProvider = StandardAuthTypes.STANDARD_AUTH_LOCAL,

                Parameters = new List<ProviderParameterSetting>
                {
                    new ProviderParameterSetting("path_cert", outputPath+".crt"),
                    new ProviderParameterSetting("path_key", outputPath+".key")
                }
            };

            var provider = DeploymentTaskProviderFactory.Create(Nginx.Definition.Id.ToLower(), _pluginManager.DeploymentTaskProviders);
            var t = new DeploymentTask(provider, config, null);

            deploymentTasks.Add(t);

            // perform preview deployments
            var managedCert = GetMockManagedCertificate("LocalNginxDeploymentTest", "123", PrimaryTestDomain, PrimaryIISRoot);

            foreach (var task in deploymentTasks)
            {
                var result = await task.Execute(_log, managedCert, CancellationToken.None, isPreviewOnly: false);
            }

            // assert output exists in destination
            Assert.IsTrue(File.Exists(outputPath + ".crt"));
            Assert.IsTrue(File.Exists(outputPath + ".key"));

            File.Delete(outputPath + ".crt");
            File.Delete(outputPath + ".key");
        }

    }
}
