using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Certify.Management;
using Certify.Models;
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
    }
}
