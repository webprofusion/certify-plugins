using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Certify.Config;
using Certify.Management;
using Certify.Models;
using Certify.Models.Config;
using Certify.Providers.DeploymentTasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests.Plugin.DeploymentTasks
{
    [TestClass]
    public class DeploymentTasksPowershellTaskImpersonation
    {
        [TestMethod, Description("Run PowerShell script task temp script runs as a different local user")]
        [TestCategory("RequiresLocalUser")]
        public async Task TestRunPowershellScriptTaskTempScriptRunsAsDifferentLocalUser()
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                Assert.Inconclusive("PowerShell process impersonation is only supported on Windows.");
            }

            var scriptPath = Path.Combine(Path.GetTempPath(), $"certify-powershell-task-{Guid.NewGuid():N}.ps1");

            File.WriteAllText(scriptPath,
                "param($result); " +
                "$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name; " +
                "Write-Output \"Identity: $identity\"; " +
                "Write-Output \"Task script completed\"");

            try
            {
                var result = await PowerShellManager.RunScript(new PowerShellScriptSettings
                {
                    PowerShellExecutionPolicy = "Unrestricted",
                    ScriptFile = scriptPath,
                    Result = new CertificateRequestResult(new ManagedCertificate()),
                    ExecutionMode = PowerShellExecutionMode.SystemPowerShellProcess,
                    Credentials = new System.Collections.Generic.Dictionary<string, string>
                    {
                        ["username"] = "testuser",
                        ["password"] = "testing123"
                    }
                });

                Assert.IsTrue(result.IsSuccess, result.Message);
                StringAssert.Contains(result.Message.ToLowerInvariant(), "testuser");
                StringAssert.Contains(result.Message, "Task script completed");
            }
            finally
            {
                try
                {
                    File.Delete(scriptPath);
                }
                catch
                {
                }
            }
        }

        [TestMethod, Description("PowerShell script task validation requires Launch New Process for Full Impersonation modes")]
        [DataRow(PowerShellImpersonationMode.Full)]
        [DataRow(PowerShellImpersonationMode.FullWithProfile)]
        public async Task TestPowershellScriptTaskFullImpersonationRequiresLaunchNewProcess(PowerShellImpersonationMode impersonationMode)
        {
            var provider = new PowershellScript();
            var settings = new DeploymentTaskConfig
            {
                ChallengeProvider = StandardAuthTypes.STANDARD_AUTH_LOCAL_AS_USER,
                Parameters = new System.Collections.Generic.List<ProviderParameterSetting>
                {
                    new ProviderParameterSetting("scriptpath", "C:\\Temp\\test.ps1"),
                    new ProviderParameterSetting("impersonationmode", impersonationMode.ToString()),
                    new ProviderParameterSetting("newprocess", "false")
                }
            };

            var execParams = new DeploymentTaskExecutionParams(null, null, null, settings, new Dictionary<string, string>
            {
                ["username"] = "testuser",
                ["password"] = "testing123"
            }, true, null, new DeploymentContext(), default);

            var results = await provider.Validate(execParams);

            Assert.IsTrue(results.Any(r => r.Message.Contains("Launch New Process", StringComparison.OrdinalIgnoreCase)), string.Join("\n", results.Select(r => r.Message)));
        }

        [TestMethod, Description("PowerShell script task definition exposes full impersonation with profile and no standalone load profile option")]
        public void TestPowershellScriptTaskDefinitionUsesFullImpersonationWithProfileMode()
        {
            var provider = new PowershellScript();
            var definition = provider.GetDefinition(null);

            var impersonationModeParameter = definition.ProviderParameters.Single(p => p.Key == "impersonationmode");

            StringAssert.Contains(impersonationModeParameter.OptionsList, "FullWithProfile=Full Impersonation With Profile");
            Assert.IsFalse(definition.ProviderParameters.Any(p => p.Key == "loaduserprofile"));
        }
    }
}
