using Certify.Management;
using Certify.Providers.Deployment.Core.Shared;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Plugin.DeploymentTasks.Core.Shared.Model;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace DeploymentTaskTests
{
    [TestClass]
    public class DeploymentTasksFileCopy : IntegrationTestBase
    {

        [TestInitialize]
        public new void Setup()
        {
            base.Setup();

            _pluginManager.LoadPlugins(new List<string> { "DeploymentTasks" }, false);
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
            var files = new List<FileCopy>
            {
               new FileCopy { SourcePath= tmpPath, DestinationPath= destPath+ @"\test-copy.txt" }
            };

            var credentials = Plugin.DeploymentTasks.Shared.Helpers.GetWindowsCredentials(storedCred);

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

            var files = new List<FileCopy>
            {
                new FileCopy{ SourcePath= tmpPath, DestinationPath=  destPath+"/testfilecopy.txt" }
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

    }
}
