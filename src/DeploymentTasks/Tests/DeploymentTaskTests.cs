using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Certify;
using Certify.Config;
using Certify.Core.Management.DeploymentTasks;
using Certify.Management;
using Certify.Models;
using Certify.Models.Config;
using Certify.Providers.Deployment.Core.Shared;
using Certify.Providers.DeploymentTasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Newtonsoft.Json;
using SimpleImpersonation;

namespace DeploymentTaskTests
{
    [TestClass]
    public class DeploymentTaskTests : IntegrationTestBase
    {
        PluginManager _pluginManager;

        [TestInitialize]
        public void Setup()
        {
            _pluginManager = new PluginManager();
            _pluginManager.LoadPlugins(new List<string> { "DeploymentTasks" });
        }

        [Ignore]
        [TestMethod, TestCategory("TestCredentials")]
        public async Task CreateTestCredentials()
        {
            var credentialsManager = new CredentialsManager
            {
                StorageSubfolder = "credentials\\test"
            };

            var secrets = new Dictionary<string, string>
            {
                { "username", "ubuntu" },
                { "password", "testuser" }
            };

            var storedCred = await credentialsManager.UpdateCredential(new StoredCredential
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

            storedCred = await credentialsManager.UpdateCredential(new StoredCredential
            {
                StorageKey = ConfigSettings["TestCredentialsKey_UNC"],
                Title = "Test: UNC testuser",
                DateCreated = DateTime.Now,
                ProviderType = "Windows",
                Secret = JsonConvert.SerializeObject(secrets)
            });

        }

        [TestMethod, TestCategory("NetworkFileCopy")]
        public async Task TestWindowsNetworkFileCopy()
        {
            var destPath = ConfigSettings["TestUNCPath"];

            var credentialsManager = new CredentialsManager
            {
                StorageSubfolder = "credentials\\test"
            };

            var storedCred = await credentialsManager.GetUnlockedCredentialsDictionary(ConfigSettings["TestCredentialsKey_UNC"]);

            // create a test temp file
            var tmpPath = Path.GetTempFileName();
            File.WriteAllText(tmpPath, "This is a test temp file");
            var files = new Dictionary<string, string>
            {
                { tmpPath, destPath+ @"\test-copy.txt" }
            };

            var credentials = new UserCredentials(storedCred["username"], storedCred["password"]);

            var client = new WindowsNetworkFileClient(credentials);

            // test file list
            var fileList = client.ListFiles(destPath);
            Assert.IsTrue(fileList.Count > 0);

            // test file copy
            var results = client.CopyLocalToRemote(_log, files);

            File.Delete(tmpPath);

            Assert.IsTrue(results.All(s => s.IsSuccess == true));

        }

        [TestMethod, TestCategory("NetworkFileCopy")]
        public async Task TestSftpFileCopy()
        {
            var credentialsManager = new CredentialsManager
            {
                StorageSubfolder = "credentials\\test"
            };

            string destPath = ConfigSettings["TestSSHPath"];

            var storedCred = await credentialsManager.GetUnlockedCredentialsDictionary(ConfigSettings["TestCredentialsKey_SSH"]);

            // var credentials = new UserCredentials(storedCred["username"], storedCred["password"]);

            // create a test temp file
            var tmpPath = Path.GetTempFileName();
            File.WriteAllText(tmpPath, "This is a test temp file");

            var files = new Dictionary<string, string>
            {
                { tmpPath, destPath+"/testfilecopy.txt" }
            };

            var client = new SftpClient(new SshConnectionConfig
            {
                Host = ConfigSettings["TestSSHHost"],
                KeyPassphrase = storedCred["password"],
                Port = 22,
                Username = storedCred["username"],
                PrivateKeyPath = ConfigSettings["TestSSHPrivateKeyPath"]
            });

            // test file list
            var fileList = client.ListFiles(destPath, null);
            Assert.IsTrue(fileList.Count > 0);

            // test file copy
            var copiedOK = client.CopyLocalToRemote(files, null);

            Assert.IsTrue(copiedOK);

            File.Delete(tmpPath);

        }

        [TestMethod, TestCategory("Export")]
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
                var result = await task.Execute(_log, managedCert, isPreviewOnly: false);
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
                var result = await task.Execute(_log, managedCert, isPreviewOnly: false);
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
                TaskTypeId = Certify.Providers.DeploymentTasks.Nginx.Definition.Id.ToLower(),
                TaskName = "A test Nginx export task",
                ChallengeProvider = StandardAuthTypes.STANDARD_AUTH_LOCAL,

                Parameters = new List<ProviderParameterSetting>
                {
                    new ProviderParameterSetting("path_cert", outputPath+".crt"),
                    new ProviderParameterSetting("path_key", outputPath+".key")
                }
            };

            var provider = DeploymentTaskProviderFactory.Create(Certify.Providers.DeploymentTasks.Nginx.Definition.Id.ToLower(), _pluginManager.DeploymentTaskProviders);
            var t = new DeploymentTask(provider, config, null);

            deploymentTasks.Add(t);

            // perform preview deployments
            var managedCert = GetMockManagedCertificate("LocalNginxDeploymentTest", "123", PrimaryTestDomain, PrimaryIISRoot);

            foreach (var task in deploymentTasks)
            {
                var result = await task.Execute(_log, managedCert, isPreviewOnly: false);
            }

            // assert output exists in destination
            Assert.IsTrue(File.Exists(outputPath + ".crt"));
            Assert.IsTrue(File.Exists(outputPath + ".key"));

            File.Delete(outputPath + ".crt");
            File.Delete(outputPath + ".key");
        }


        [TestMethod, TestCategory("Misc")]
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
                results.AddRange(await task.Execute(_log, managedCert, isPreviewOnly: false));
            }

            // assert output exists in destination
            Assert.IsTrue(results.All(r => r.IsSuccess == true));

        }
    }
}
