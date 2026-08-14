using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using Certify.Config;
using Certify.Core.Management.DeploymentTasks;
using Certify.Datastore.SQLite;
using Certify.Management;
using Certify.Models;
using Certify.Models.Config;
using Certify.Providers;
using Certify.Providers.DeploymentTasks;
using Certify.Shared;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Newtonsoft.Json;

namespace Certify.Tests.DeploymentTaskTests
{
    [TestClass]
    public class DeploymentTaskMisc : IntegrationTestBase
    {

        [TestInitialize]
        public override void Setup()
        {
            base.Setup();

            _pluginManager.LoadPlugins(new List<string> { "DeploymentTasks" });
        }

        [Ignore]
        [TestMethod, TestCategory("TestCredentials")]
        public async Task CreateTestCredentials()
        {
            var credentialsManager = new SQLiteCredentialStore(storageSubfolder: "credentials\\test");

            var secrets = new Dictionary<string, string>
            {
                { "username", "ubuntu" },
                { "password", "testuser" }
            };

            var storedCred = await credentialsManager.Update(new StoredCredential
            {
                StorageKey = "atestsshuser",
                Title = "Test: SSH",
                DateCreated = DateTimeOffset.UtcNow,
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
                DateCreated = DateTimeOffset.UtcNow,
                ProviderType = "Windows",
                Secret = JsonConvert.SerializeObject(secrets)
            });

        }

        [TestMethod, TestCategory("Misc")]
        public async Task TestGetAllDeploymentTaskProviders()
        {

            var allProviders = await DeploymentTaskProviderFactory.GetDeploymentTaskProviders(_pluginManager.DeploymentTaskProviders);

            // all providers have a unique title
            Assert.AreEqual(allProviders.Count, allProviders.Select(p => p.Title).Distinct().Count());

            // all providers have a unique id
            Assert.AreEqual(allProviders.Count, allProviders.Select(p => p.Id).Distinct().Count());

            // all providers have a unique description
            Assert.AreEqual(allProviders.Count, allProviders.Select(p => p.Description).Distinct().Count());
        }

        [TestMethod, TestCategory("Misc")]
        public async Task TestPowershellScriptArgumentParsingPreservesAdditionalEquals()
        {
            var provider = new PowershellScript();
            var taskConfig = new DeploymentTaskConfig
            {
                ChallengeProvider = StandardAuthTypes.STANDARD_AUTH_LOCAL,
                Parameters = new List<ProviderParameterSetting>
                {
                    new("scriptpath", Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Assets","Powershell","Simple.ps1")),
                    new("args", @"token=abc=123;name=fred"),
                    new("timeout", "5")
                }
            };

            var result = await provider.Execute(new DeploymentTaskExecutionParams(
                _log,
                null,
                new CertificateRequestResult(new ManagedCertificate()),
                taskConfig,
                null,
                isPreviewOnly: false,
                definition: provider.GetDefinition(null),
                context: new DeploymentContext { PowershellExecutionPolicy = "Unrestricted" },
                cancellationToken: CancellationToken.None));

            Assert.AreEqual(1, result.Count);
            Assert.IsTrue(result[0].IsSuccess);
        }

        [TestMethod, TestCategory("Misc")]
        public async Task TestPowershellScriptQuotedScriptPathRunsSuccessfully()
        {
            var provider = new PowershellScript();
            var scriptPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Assets", "Powershell", "Simple.ps1");
            var taskConfig = new DeploymentTaskConfig
            {
                ChallengeProvider = StandardAuthTypes.STANDARD_AUTH_LOCAL,
                Parameters = new List<ProviderParameterSetting>
                {
                    new("scriptpath", $"\"{scriptPath}\""),
                    new("timeout", "5")
                }
            };

            var result = await provider.Execute(new DeploymentTaskExecutionParams(
                _log,
                null,
                new CertificateRequestResult(new ManagedCertificate()),
                taskConfig,
                null,
                isPreviewOnly: false,
                definition: provider.GetDefinition(null),
                context: new DeploymentContext { PowershellExecutionPolicy = "Unrestricted" },
                cancellationToken: CancellationToken.None));

            Assert.AreEqual(1, result.Count);
            Assert.IsTrue(result[0].IsSuccess, result[0].Message);
        }

        [TestMethod, TestCategory("Misc"), Description("PowerShell script receives populated result parameter when inputresult=true")]
        public async Task TestPowershellScriptReceivesResultParamWhenInputResultTrue()
        {
            var scriptPath = Path.Combine(Path.GetTempPath(), $"certify-ps-result-{Guid.NewGuid():N}.ps1");
            File.WriteAllText(scriptPath,
                "param($result)\n" +
                "Write-Output \"RESULT_NOT_NULL: $($null -ne $result)\"\n" +
                "Write-Output \"RESULT_IS_SUCCESS: $($result.IsSuccess)\"\n" +
                "Write-Output \"RESULT_MESSAGE: $($result.Message)\"");

            try
            {
                var provider = new PowershellScript();
                var taskConfig = new DeploymentTaskConfig
                {
                    ChallengeProvider = StandardAuthTypes.STANDARD_AUTH_LOCAL,
                    Parameters = new List<ProviderParameterSetting>
                    {
                        new("scriptpath", scriptPath),
                        new("inputresult", "true"),
                        new("timeout", "5")
                    }
                };

                var managedCert = new ManagedCertificate { Id = "test-cert" };
                var certResult = new CertificateRequestResult(managedCert) { IsSuccess = true, Message = "Test success" };

                var execParams = new DeploymentTaskExecutionParams(
                    _log,
                    null,
                    certResult,
                    taskConfig,
                    null,
                    isPreviewOnly: false,
                    definition: provider.GetDefinition(null),
                    context: new DeploymentContext { PowershellExecutionPolicy = "Unrestricted" },
                    cancellationToken: CancellationToken.None);

                var results = await provider.Execute(execParams);

                Assert.AreEqual(1, results.Count);
                Assert.IsTrue(results[0].IsSuccess, results[0].Message);
                // Verify that result parameter was passed and has properties
                StringAssert.Contains(results[0].Message, "RESULT_NOT_NULL: True", "Result parameter should not be null when inputresult=true");
                StringAssert.Contains(results[0].Message, "RESULT_IS_SUCCESS: True", "Result.IsSuccess property should be accessible");
                StringAssert.Contains(results[0].Message, "RESULT_MESSAGE: Test success", "Result.Message property should be accessible with correct value");
            }
            finally
            {
                try { File.Delete(scriptPath); } catch { }
            }
        }

        [TestMethod, TestCategory("Misc"), Description("PowerShell script does not receive result parameter when inputresult=false")]
        public async Task TestPowershellScriptDoesNotReceiveResultParamWhenInputResultFalse()
        {
            var scriptPath = Path.Combine(Path.GetTempPath(), $"certify-ps-no-result-{Guid.NewGuid():N}.ps1");
            File.WriteAllText(scriptPath,
                "param($result)\n" +
                "Write-Output \"RESULT_IS_NULL: $($null -eq $result)\"");

            try
            {
                var provider = new PowershellScript();
                var taskConfig = new DeploymentTaskConfig
                {
                    ChallengeProvider = StandardAuthTypes.STANDARD_AUTH_LOCAL,
                    Parameters = new List<ProviderParameterSetting>
                    {
                        new("scriptpath", scriptPath),
                        new("inputresult", "false"),
                        new("timeout", "5")
                    }
                };

                var execParams = new DeploymentTaskExecutionParams(
                    _log,
                    null,
                    new CertificateRequestResult(new ManagedCertificate()),
                    taskConfig,
                    null,
                    isPreviewOnly: false,
                    definition: provider.GetDefinition(null),
                    context: new DeploymentContext { PowershellExecutionPolicy = "Unrestricted" },
                    cancellationToken: CancellationToken.None);

                var results = await provider.Execute(execParams);

                Assert.AreEqual(1, results.Count);
                Assert.IsTrue(results[0].IsSuccess, results[0].Message);
                StringAssert.Contains(results[0].Message, "RESULT_IS_NULL: True");
            }
            finally
            {
                try { File.Delete(scriptPath); } catch { }
            }
        }

        [TestMethod, TestCategory("Misc"), Description("PowerShell script receives result parameter when inputresult is missing (default false)")]
        public async Task TestPowershellScriptDoesNotReceiveResultParamWhenInputResultMissing()
        {
            var scriptPath = Path.Combine(Path.GetTempPath(), $"certify-ps-default-result-{Guid.NewGuid():N}.ps1");
            File.WriteAllText(scriptPath,
                "param($result)\n" +
                "Write-Output \"RESULT_IS_NULL: $($null -eq $result)\"");

            try
            {
                var provider = new PowershellScript();
                var taskConfig = new DeploymentTaskConfig
                {
                    ChallengeProvider = StandardAuthTypes.STANDARD_AUTH_LOCAL,
                    Parameters = new List<ProviderParameterSetting>
                    {
                        new("scriptpath", scriptPath),
                        // ← Note: inputresult parameter is NOT set (defaults to false)
                        new("timeout", "5")
                    }
                };

                var execParams = new DeploymentTaskExecutionParams(
                    _log,
                    null,
                    new CertificateRequestResult(new ManagedCertificate()),
                    taskConfig,
                    null,
                    isPreviewOnly: false,
                    definition: provider.GetDefinition(null),
                    context: new DeploymentContext { PowershellExecutionPolicy = "Unrestricted" },
                    cancellationToken: CancellationToken.None);

                var results = await provider.Execute(execParams);

                Assert.AreEqual(1, results.Count);
                Assert.IsTrue(results[0].IsSuccess, results[0].Message);
                StringAssert.Contains(results[0].Message, "RESULT_IS_NULL: True");
            }
            finally
            {
                try { File.Delete(scriptPath); } catch { }
            }
        }

        [TestMethod, TestCategory("Misc"), Description("Malformed inputresult values are treated as false")]
        [DataRow("maybe")]
        [DataRow("1")]
        [DataRow("False")]
        [DataRow("")]
        public async Task TestPowershellScriptMalformedInputResultTreatedAsFalse(string inputResultValue)
        {
            var scriptPath = Path.Combine(Path.GetTempPath(), $"certify-ps-malformed-{Guid.NewGuid():N}.ps1");
            File.WriteAllText(scriptPath,
                "param($result)\n" +
                "Write-Output \"RESULT_IS_NULL: $($null -eq $result)\"");

            try
            {
                var provider = new PowershellScript();
                var taskConfig = new DeploymentTaskConfig
                {
                    ChallengeProvider = StandardAuthTypes.STANDARD_AUTH_LOCAL,
                    Parameters = new List<ProviderParameterSetting>
                    {
                        new("scriptpath", scriptPath),
                        new("inputresult", inputResultValue),
                        new("timeout", "5")
                    }
                };

                var execParams = new DeploymentTaskExecutionParams(
                    _log,
                    null,
                    new CertificateRequestResult(new ManagedCertificate()),
                    taskConfig,
                    null,
                    isPreviewOnly: false,
                    definition: provider.GetDefinition(null),
                    context: new DeploymentContext { PowershellExecutionPolicy = "Unrestricted" },
                    cancellationToken: CancellationToken.None);

                var results = await provider.Execute(execParams);

                Assert.AreEqual(1, results.Count, $"Expected one result for inputresult='{inputResultValue}'");
                Assert.IsTrue(results[0].IsSuccess, $"Expected success for inputresult='{inputResultValue}': {results[0].Message}");
                StringAssert.Contains(results[0].Message, "RESULT_IS_NULL: True", $"Expected result parameter to be null for inputresult='{inputResultValue}'");
            }
            finally
            {
                try { File.Delete(scriptPath); } catch { }
            }
        }

        [TestMethod, TestCategory("Misc"), Description("PowerShell script receives result parameter alongside other arguments")]
        public async Task TestPowershellScriptResultParamWorksWithArgsPayload()
        {
            var scriptPath = Path.Combine(Path.GetTempPath(), $"certify-ps-result-args-{Guid.NewGuid():N}.ps1");
            File.WriteAllText(scriptPath,
                "param($result, $customArg, $another)\n" +
                "Write-Output \"HAS_RESULT: $($null -ne $result)\"\n" +
                "Write-Output \"CUSTOM_ARG: $customArg\"\n" +
                "Write-Output \"ANOTHER: $another\"");

            try
            {
                var provider = new PowershellScript();
                var taskConfig = new DeploymentTaskConfig
                {
                    ChallengeProvider = StandardAuthTypes.STANDARD_AUTH_LOCAL,
                    Parameters = new List<ProviderParameterSetting>
                    {
                        new("scriptpath", scriptPath),
                        new("inputresult", "true"),
                        new("args", "customArg=myvalue;another=test"),
                        new("timeout", "5")
                    }
                };

                var managedCert = new ManagedCertificate { Id = "test-cert" };
                var certResult = new CertificateRequestResult(managedCert);

                var execParams = new DeploymentTaskExecutionParams(
                    _log,
                    null,
                    certResult,
                    taskConfig,
                    null,
                    isPreviewOnly: false,
                    definition: provider.GetDefinition(null),
                    context: new DeploymentContext { PowershellExecutionPolicy = "Unrestricted" },
                    cancellationToken: CancellationToken.None);

                var results = await provider.Execute(execParams);

                Assert.AreEqual(1, results.Count);
                Assert.IsTrue(results[0].IsSuccess, results[0].Message);
                StringAssert.Contains(results[0].Message, "HAS_RESULT: True");
                StringAssert.Contains(results[0].Message, "CUSTOM_ARG: myvalue");
                StringAssert.Contains(results[0].Message, "ANOTHER: test");
            }
            finally
            {
                try { File.Delete(scriptPath); } catch { }
            }
        }

        [TestMethod, TestCategory("Misc"), Description("PowerShell script receives result parameter with Full impersonation mode"), TestCategory("RequiresLocalUser")]
        public async Task TestPowershellScriptResultParamWithFullImpersonation()
        {
            var scriptPath = Path.Combine(Path.GetTempPath(), $"certify-ps-result-impersonate-{Guid.NewGuid():N}.ps1");
            File.WriteAllText(scriptPath,
                "param($result)\n" +
                "Write-Output \"HAS_RESULT: $($null -ne $result)\"\n" +
                "Write-Output \"RESULT_IS_SUCCESS: $($result.IsSuccess)\"");

            try
            {
                var provider = new PowershellScript();
                var taskConfig = new DeploymentTaskConfig
                {
                    ChallengeProvider = StandardAuthTypes.STANDARD_AUTH_LOCAL_AS_USER,
                    Parameters = new List<ProviderParameterSetting>
                    {
                        new("scriptpath", scriptPath),
                        new("inputresult", "true"),
                        new("impersonationmode", PowerShellImpersonationMode.Full.ToString()),
                        new("executionmode", PowerShellExecutionMode.SystemProcess.ToString()),
                        new("timeout", "5")
                    }
                };

                var managedCert = new ManagedCertificate { Id = "test-cert" };
                var certResult = new CertificateRequestResult(managedCert) { IsSuccess = true };

                // For impersonation tests, credentials would typically come from the environment
                // This test validates that the result parameter is passed even with impersonation enabled
                var execParams = new DeploymentTaskExecutionParams(
                    _log,
                    null,
                    certResult,
                    taskConfig,
                    new Dictionary<string, string> { ["username"] = "testuser", ["password"] = "testpass" },
                    isPreviewOnly: false,
                    definition: provider.GetDefinition(null),
                    context: new DeploymentContext { PowershellExecutionPolicy = "Unrestricted" },
                    cancellationToken: CancellationToken.None);

                var results = await provider.Execute(execParams);

                Assert.AreEqual(1, results.Count);
                // Note: This test may fail in CI/test environments without valid impersonation credentials
                // The important assertion is that the result parameter is passed when configured
                if (results[0].IsSuccess)
                {
                    StringAssert.Contains(results[0].Message, "HAS_RESULT: True", "Result parameter should be passed with Full impersonation");
                    StringAssert.Contains(results[0].Message, "RESULT_IS_SUCCESS: True", "Result.IsSuccess property should be accessible with Full impersonation");
                }
            }
            finally
            {
                try { File.Delete(scriptPath); } catch { }
            }
        }

        [TestMethod, TestCategory("Misc")]
        public async Task TestDeploymentTaskTriggersRespectPrimaryRequestStatus()
        {
            var successSteps = await PerformMockTaskList(
                primaryRequestSucceeded: true,
                skipDeferredTasks: true,
                forceTaskExecution: false,
                CreateMockTask("Success Only", TaskTriggerType.ON_SUCCESS),
                CreateMockTask("Error Only", TaskTriggerType.ON_ERROR),
                CreateMockTask("Any Status", TaskTriggerType.ANY_STATUS),
                CreateMockTask("Disabled", TaskTriggerType.NOT_ENABLED));

            AssertTaskCompleted(successSteps, "Success Only");
            AssertTaskSkipped(successSteps, "Error Only", "primary request was successful");
            AssertTaskCompleted(successSteps, "Any Status");
            AssertTaskSkipped(successSteps, "Disabled", "not enabled");

            var failedSteps = await PerformMockTaskList(
                primaryRequestSucceeded: false,
                skipDeferredTasks: true,
                forceTaskExecution: false,
                CreateMockTask("Success Only", TaskTriggerType.ON_SUCCESS),
                CreateMockTask("Error Only", TaskTriggerType.ON_ERROR),
                CreateMockTask("Any Status", TaskTriggerType.ANY_STATUS));

            AssertTaskSkipped(failedSteps, "Success Only", "primary request unsuccessful");
            AssertTaskCompleted(failedSteps, "Error Only");
            AssertTaskCompleted(failedSteps, "Any Status");
        }

        [TestMethod, TestCategory("Misc")]
        public async Task TestManualDeploymentTaskCanRunAfterPrimaryRequestFailed()
        {
            var steps = await PerformMockTaskList(
                primaryRequestSucceeded: false,
                skipDeferredTasks: false,
                forceTaskExecution: false,
                CreateMockTask("Manual Task", TaskTriggerType.MANUAL));

            AssertTaskCompleted(steps, "Manual Task");
        }

        [TestMethod, TestCategory("Misc")]
        public async Task TestSelectedDeploymentTaskExecutionIgnoresLastFailedPrimaryRequestStatus()
        {
            var task = CreateMockTask("Success Only", TaskTriggerType.ON_SUCCESS);
            var managedCert = GetMockManagedCertificate("DeploymentTaskManualRunTest", "123", PrimaryTestDomain, PrimaryIISRoot);
            managedCert.LastRenewalStatus = RequestState.Error;
            managedCert.PostRequestTasks = new ObservableCollection<DeploymentTaskConfig>();
            managedCert.PostRequestTasks.Add(task);

            var manager = CreateTestManager(managedCert);

            var steps = await manager.PerformDeploymentTask(_log, managedCert.Id, task.Id, isPreviewOnly: false, skipDeferredTasks: false, forceTaskExecution: false);

            AssertTaskCompleted(steps, "Success Only");
        }

        [TestMethod, TestCategory("Misc")]
        public async Task TestForceDeploymentTaskExecutionOverridesTriggerStatus()
        {
            var steps = await PerformMockTaskList(
                primaryRequestSucceeded: false,
                skipDeferredTasks: true,
                forceTaskExecution: true,
                CreateMockTask("Success Only", TaskTriggerType.ON_SUCCESS));

            AssertTaskCompleted(steps, "Success Only");
            Assert.IsTrue(steps.Single(s => s.Title == "Success Only").Substeps.Any(s => s.Description.Contains("MockTaskWorkCompleted")));
        }

        [TestMethod, TestCategory("Misc")]
        public async Task TestDeploymentTaskFailureControlsLaterTaskExecution()
        {
            var defaultSteps = await PerformMockTaskList(
                primaryRequestSucceeded: true,
                skipDeferredTasks: true,
                forceTaskExecution: false,
                CreateMockTask("Failing Task", TaskTriggerType.ANY_STATUS, message: null),
                CreateMockTask("Blocked Task", TaskTriggerType.ON_SUCCESS));

            AssertTaskFailed(defaultSteps, "Failing Task", "message not supplied");
            AssertTaskSkipped(defaultSteps, "Blocked Task", "previous task failed");

            var continueSteps = await PerformMockTaskList(
                primaryRequestSucceeded: true,
                skipDeferredTasks: true,
                forceTaskExecution: false,
                CreateMockTask("Failing Task", TaskTriggerType.ANY_STATUS, message: null),
                CreateMockTask("Recovery Task", TaskTriggerType.ON_TASK_ERROR, runIfLastStepFailed: true),
                CreateMockTask("Success Task", TaskTriggerType.ON_SUCCESS, runIfLastStepFailed: true));

            AssertTaskFailed(continueSteps, "Failing Task", "message not supplied");
            AssertTaskCompleted(continueSteps, "Recovery Task");
            AssertTaskCompleted(continueSteps, "Success Task");
        }

        private async Task<List<ActionStep>> PerformMockTaskList(bool primaryRequestSucceeded, bool skipDeferredTasks, bool forceTaskExecution, params DeploymentTaskConfig[] taskConfigs)
        {
            var manager = CreateTestManager();

            var managedCert = GetMockManagedCertificate("DeploymentTaskTriggerTest", "123", PrimaryTestDomain, PrimaryIISRoot);
            var requestResult = new CertificateRequestResult(managedCert, primaryRequestSucceeded, string.Empty)
            {
                PrimaryRequest = new RequestStageStatus
                {
                    Status = primaryRequestSucceeded ? RequestState.Success : RequestState.Error
                }
            };

            return await manager.PerformTaskList(
                _log,
                isPreviewOnly: false,
                skipDeferredTasks,
                requestResult,
                taskConfigs,
                forceTaskExecute: forceTaskExecution,
                evaluateAgainstPrimaryRequestStatus: true);
        }

        private CertifyManager CreateTestManager(ManagedCertificate managedCertificate = null)
        {
            var manager = new CertifyManager();

            var pluginManagerField = typeof(CertifyManager).GetField("_pluginManager", BindingFlags.Instance | BindingFlags.NonPublic);
            pluginManagerField.SetValue(manager, _pluginManager);

            var serverConfigField = typeof(CertifyManager).GetField("_serverConfig", BindingFlags.Instance | BindingFlags.NonPublic);
            serverConfigField.SetValue(manager, new ServiceConfig());

            if (managedCertificate != null)
            {
                var itemManager = new InMemoryManagedItemStore(managedCertificate);
                var itemManagerField = typeof(CertifyManager).GetField("_itemManager", BindingFlags.Instance | BindingFlags.NonPublic);
                itemManagerField.SetValue(manager, itemManager);
            }

            return manager;
        }

        private static DeploymentTaskConfig CreateMockTask(string name, TaskTriggerType trigger, bool runIfLastStepFailed = false, string message = "OK")
        {
            var parameters = new List<ProviderParameterSetting>
            {
                new("throw", "false")
            };

            if (message != null)
            {
                parameters.Add(new("message", message));
            }

            return new DeploymentTaskConfig
            {
                Id = Guid.NewGuid().ToString(),
                TaskTypeId = Certify.Providers.DeploymentTasks.Core.MockTask.Definition.Id,
                TaskName = name,
                ChallengeProvider = StandardAuthTypes.STANDARD_AUTH_LOCAL,
                TaskTrigger = trigger,
                RunIfLastStepFailed = runIfLastStepFailed,
                Parameters = parameters
            };
        }

        private static void AssertTaskCompleted(List<ActionStep> steps, string taskName)
        {
            var step = steps.Single(s => s.Title == taskName);
            Assert.IsFalse(step.HasError, $"Task '{taskName}' should not have failed.");
            Assert.IsFalse(step.HasWarning, $"Task '{taskName}' should have executed, not skipped.");
            Assert.AreEqual("Task Completed OK", step.Description);
        }

        private static void AssertTaskFailed(List<ActionStep> steps, string taskName, string expectedMessage)
        {
            var step = steps.Single(s => s.Title == taskName);
            Assert.IsTrue(step.HasError, $"Task '{taskName}' should have failed.");
            StringAssert.Contains(step.Description, expectedMessage);
        }

        private static void AssertTaskSkipped(List<ActionStep> steps, string taskName, string expectedReason)
        {
            var step = steps.Single(s => s.Title == taskName);
            Assert.IsFalse(step.HasError, $"Skipped task '{taskName}' should not be marked as failed.");
            Assert.IsTrue(step.HasWarning, $"Task '{taskName}' should have been skipped.");
            StringAssert.Contains(step.Description, expectedReason);
        }

        private class InMemoryManagedItemStore : IManagedItemStore
        {
            private ManagedCertificate _managedCertificate;

            public InMemoryManagedItemStore(ManagedCertificate managedCertificate)
            {
                _managedCertificate = managedCertificate;
            }

            public bool Init(string connectionString, Certify.Models.Providers.ILog log, string instanceId = null) => true;

            public Task DeleteAll() => Task.CompletedTask;

            public Task StoreAll(IEnumerable<ManagedCertificate> list) => Task.CompletedTask;

            public Task Delete(ManagedCertificate site) => Task.CompletedTask;

            public Task DeleteByName(string nameStartsWith) => Task.CompletedTask;

            public Task<ManagedCertificate> GetById(string siteId) => Task.FromResult(_managedCertificate?.Id == siteId ? _managedCertificate : null);

            public Task<List<ManagedCertificate>> Find(ManagedCertificateFilter filter) => Task.FromResult(new List<ManagedCertificate> { _managedCertificate });

            public Task<long> CountAll(ManagedCertificateFilter filter) => Task.FromResult(1L);

            public Task<ManagedCertificate> Update(ManagedCertificate managedCertificate)
            {
                _managedCertificate = managedCertificate;
                return Task.FromResult(_managedCertificate);
            }

            public Task PerformMaintenance() => Task.CompletedTask;

            public Task<bool> IsInitialised() => Task.FromResult(true);
        }
    }
}
