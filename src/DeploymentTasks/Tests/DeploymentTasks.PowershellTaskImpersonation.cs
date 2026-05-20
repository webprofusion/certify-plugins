using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;
using System.Text.Json;
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
        private const string TestLocalUsername = "testuser";
        private const string TestLocalPassword = "testing123";
        private const string MatrixReportPathEnvVar = "CERTIFY_POWERSHELL_TASK_MATRIX_REPORT_PATH";
        private const string MatrixRunLabelEnvVar = "CERTIFY_POWERSHELL_TASK_MATRIX_RUN_LABEL";

        public TestContext TestContext { get; set; }

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
                    ExecutionMode = PowerShellExecutionMode.SystemProcess,
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

        [TestMethod, Description("PowerShell script task validation no longer depends on a Launch New Process option for Full Impersonation modes")]
        [DataRow(PowerShellImpersonationMode.Full)]
        [DataRow(PowerShellImpersonationMode.FullWithProfile)]
        public async Task TestPowershellScriptTaskFullImpersonationValidationDoesNotRequireLaunchNewProcessOption(PowerShellImpersonationMode impersonationMode)
        {
            var provider = new PowershellScript();
            var settings = new DeploymentTaskConfig
            {
                ChallengeProvider = StandardAuthTypes.STANDARD_AUTH_LOCAL_AS_USER,
                Parameters = new System.Collections.Generic.List<ProviderParameterSetting>
                {
                    new ProviderParameterSetting("scriptpath", "C:\\Temp\\test.ps1"),
                    new ProviderParameterSetting("impersonationmode", impersonationMode.ToString())
                }
            };

            var execParams = new DeploymentTaskExecutionParams(null, null, null, settings, new Dictionary<string, string>
            {
                ["username"] = "testuser",
                ["password"] = "testing123"
            }, true, null, new DeploymentContext(), default);

            var results = await provider.Validate(execParams);

            Assert.IsFalse(results.Any(r => r.Message.Contains("Launch New Process", StringComparison.OrdinalIgnoreCase)), string.Join("\n", results.Select(r => r.Message)));
        }

        [TestMethod, Description("PowerShell script task definition exposes simplified execution modes and no standalone launch new process option")]
        public void TestPowershellScriptTaskDefinitionUsesSimplifiedExecutionModes()
        {
            var provider = new PowershellScript();
            var definition = provider.GetDefinition(null);

            var impersonationModeParameter = definition.ProviderParameters.Single(p => p.Key == "impersonationmode");
            var executionModeParameter = definition.ProviderParameters.Single(p => p.Key == "executionmode");

            StringAssert.Contains(impersonationModeParameter.OptionsList, "FullWithProfile=Full Impersonation With Profile");
            StringAssert.Contains(executionModeParameter.OptionsList, "Automatic=Automatic");
            StringAssert.Contains(executionModeParameter.OptionsList, "SystemProcess=System Process");
            Assert.IsFalse(definition.ProviderParameters.Any(p => p.Key == "loaduserprofile"));
            Assert.IsFalse(definition.ProviderParameters.Any(p => p.Key == "newprocess"));
        }

        [TestMethod, Description("Run PowerShell script task exercises execution, impersonation, and payload combinations")]
        [TestCategory("RequiresLocalUser")]
        [SupportedOSPlatform("windows")]
        public async Task TestRunPowershellScriptTaskExecutionMatrixMatchesExpectedOutcomes()
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                Assert.Inconclusive("PowerShell deployment task impersonation matrix requires Windows.");
            }

            var provider = new PowershellScript();
            var hostIdentity = WindowsIdentity.GetCurrent().Name;
            var isRunningAsLocalSystem = IsRunningAsLocalSystem();
            var scriptPath = CreateExecutionMatrixScript();
            var reportPath = Environment.GetEnvironmentVariable(MatrixReportPathEnvVar);
            var runLabel = Environment.GetEnvironmentVariable(MatrixRunLabelEnvVar);

            var summaries = new List<string>();
            var failures = new List<string>();
            var assessments = new List<PowerShellTaskAssessment>();

            try
            {
                foreach (var scenario in GetExecutionMatrixScenarios())
                {
                    var validationAndExecution = await ExecuteScenarioSafely(provider, scenario, scriptPath);
                    var assessment = AssessScenario(validationAndExecution, hostIdentity, isRunningAsLocalSystem);

                    summaries.Add(assessment.Summary);
                    assessments.Add(assessment);
                    TestContext?.WriteLine(assessment.Summary);

                    if (!assessment.IsExpected)
                    {
                        failures.Add(assessment.Summary);
                    }
                }

                WriteExecutionMatrixReportIfRequested(reportPath, runLabel, hostIdentity, isRunningAsLocalSystem, assessments);
            }
            finally
            {
                DeleteTempScript(scriptPath);
            }

            Assert.AreEqual(36, summaries.Count, "The execution matrix should cover every auth, execution, impersonation, and payload combination.");

            if (failures.Any())
            {
                Assert.Fail("Unexpected PowerShell deployment task matrix results:" + Environment.NewLine + string.Join(Environment.NewLine, failures));
            }
        }

        private static IReadOnlyList<PowerShellTaskScenario> GetExecutionMatrixScenarios()
        {
            var scenarios = new List<PowerShellTaskScenario>();
            var authTypes = new[] { StandardAuthTypes.STANDARD_AUTH_LOCAL, StandardAuthTypes.STANDARD_AUTH_LOCAL_AS_USER };
            var executionModes = new[] { PowerShellExecutionMode.Automatic, PowerShellExecutionMode.InProcess, PowerShellExecutionMode.SystemProcess };
            var impersonationModes = new[] { PowerShellImpersonationMode.Default, PowerShellImpersonationMode.Full, PowerShellImpersonationMode.FullWithProfile };

            foreach (var authType in authTypes)
            {
                foreach (var executionMode in executionModes)
                {
                    foreach (var impersonationMode in impersonationModes)
                    {
                        scenarios.Add(new PowerShellTaskScenario(authType, executionMode, impersonationMode, false));
                        scenarios.Add(new PowerShellTaskScenario(authType, executionMode, impersonationMode, true));
                    }
                }
            }

            return scenarios;
        }

        private static string CreateExecutionMatrixScript()
        {
            var scriptPath = Path.Combine(Path.GetTempPath(), $"certify-powershell-task-matrix-{Guid.NewGuid():N}.ps1");
            File.WriteAllText(scriptPath,
                "param($result, $message, [bool]$flag)\n" +
                "$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name\n" +
                "Write-Output \"TASK_IDENTITY: $identity\"\n" +
                "Write-Output \"TASK_HAS_RESULT: $($null -ne $result)\"\n" +
                "Write-Output \"TASK_MESSAGE: $message\"\n" +
                "Write-Output \"TASK_FLAG: $flag\"\n" +
                "Write-Output \"TASK_PROFILE: $env:USERPROFILE\"\n" +
                "Write-Output \"TASK_COMPLETED\"");

            return scriptPath;
        }

        private static async Task<PowerShellTaskScenarioResult> ExecuteScenario(PowershellScript provider, PowerShellTaskScenario scenario, string scriptPath)
        {
            var payloadMessage = scenario.HasArgsPayload ? $"payload-{scenario.ExecutionMode}-{scenario.ImpersonationMode}-{scenario.AuthType.Split('.').Last()}" : null;
            var parameters = new List<ProviderParameterSetting>
            {
                new ProviderParameterSetting("scriptpath", scriptPath),
                new ProviderParameterSetting("executionmode", scenario.ExecutionMode.ToString()),
                new ProviderParameterSetting("impersonationmode", scenario.ImpersonationMode.ToString()),
                new ProviderParameterSetting("timeout", "5")
            };

            if (scenario.HasArgsPayload)
            {
                parameters.Add(new ProviderParameterSetting("args", $"message={payloadMessage};flag=true"));
            }

            var settings = new DeploymentTaskConfig
            {
                ChallengeProvider = scenario.AuthType,
                Parameters = parameters
            };

            var credentials = scenario.AuthType == StandardAuthTypes.STANDARD_AUTH_LOCAL_AS_USER
                ? new Dictionary<string, string>
                {
                    ["username"] = TestLocalUsername,
                    ["password"] = TestLocalPassword
                }
                : null;

            var execParams = new DeploymentTaskExecutionParams(
                null,
                null,
                new CertificateRequestResult(new ManagedCertificate()),
                settings,
                credentials,
                isPreviewOnly: false,
                definition: provider.GetDefinition(null),
                context: new DeploymentContext { PowershellExecutionPolicy = "Unrestricted" },
                cancellationToken: default);

            var validationResults = await provider.Validate(execParams);
            var executionResults = await provider.Execute(execParams);

            return new PowerShellTaskScenarioResult(
                scenario,
                payloadMessage,
                validationResults,
                executionResults.Single(),
                false,
                null,
                true,
                true);
        }

        private static async Task<PowerShellTaskScenarioResult> ExecuteScenarioSafely(PowershellScript provider, PowerShellTaskScenario scenario, string scriptPath)
        {
            try
            {
                return await ExecuteScenario(provider, scenario, scriptPath);
            }
            catch (Exception ex)
            {
                var payloadMessage = scenario.HasArgsPayload ? $"payload-{scenario.ExecutionMode}-{scenario.ImpersonationMode}-{scenario.AuthType.Split('.').Last()}" : null;

                return new PowerShellTaskScenarioResult(
                    scenario,
                    payloadMessage,
                    [],
                    new ActionResult($"Scenario execution threw {ex.GetType().Name}: {ex.Message}", false),
                    true,
                    ex.ToString(),
                    false,
                    false);
            }
        }

        private static PowerShellTaskAssessment AssessScenario(PowerShellTaskScenarioResult scenarioResult, string hostIdentity, bool isRunningAsLocalSystem)
        {
            var scenario = scenarioResult.Scenario;
            var validationMessages = string.Join(" | ", scenarioResult.ValidationResults.Select(r => r.Message));
            var issues = new List<string>();

            if (scenarioResult.ThrownException)
            {
                issues.Add($"scenario threw exception '{scenarioResult.ExceptionDetail}'");
            }

            var expectsValidationFailure = scenario.AuthType == StandardAuthTypes.STANDARD_AUTH_LOCAL
                && scenario.ImpersonationMode != PowerShellImpersonationMode.Default;

            if (!scenarioResult.ValidationAttempted)
            {
                issues.Add("validation was not attempted");
            }
            else if (expectsValidationFailure)
            {
                if (!scenarioResult.ValidationResults.Any(r => r.Message.Contains("stored Windows credentials", StringComparison.OrdinalIgnoreCase)))
                {
                    issues.Add($"expected validation failure for missing stored Windows credentials but got '{validationMessages}'");
                }
            }
            else if (scenarioResult.ValidationResults.Any())
            {
                issues.Add($"expected validation success but got '{validationMessages}'");
            }

            var expectsExecutionSuccess = ExpectsExecutionSuccess(scenario, isRunningAsLocalSystem);
            var expectedResolvedExecutionMode = GetExpectedResolvedExecutionMode(scenario);
            var actualResolvedExecutionMode = GetActualResolvedExecutionMode(scenarioResult.ExecutionResult.Message);

            if (!scenarioResult.ExecutionAttempted)
            {
                issues.Add("execution was not attempted");
            }
            else if (expectsExecutionSuccess)
            {
                if (!scenarioResult.ExecutionResult.IsSuccess)
                {
                    issues.Add($"expected execution success but got failure '{scenarioResult.ExecutionResult.Message}'");
                }
                else
                {
                    ValidateSuccessfulScenario(scenarioResult, hostIdentity, expectedResolvedExecutionMode, issues);
                }
            }
            else
            {
                if (scenarioResult.ExecutionResult.IsSuccess)
                {
                    issues.Add("expected execution failure but the task succeeded");
                }
                else
                {
                    ValidateExpectedFailureScenario(scenarioResult, issues, isRunningAsLocalSystem);
                }
            }

            var expectation = expectsExecutionSuccess ? "ExpectedSuccess" : "ExpectedFailure";
            var actual = scenarioResult.ExecutionResult.IsSuccess ? "Success" : "Failure";
            var validation = scenarioResult.ValidationResults.Any() ? $"Invalid ({validationMessages})" : "Valid";
            var summary = $"[{validation}] {expectation}/{actual} :: {scenario.DisplayName} :: {DescribeResult(scenarioResult.ExecutionResult)}";

            if (issues.Any())
            {
                summary += " :: Issues: " + string.Join("; ", issues);
            }

            return new PowerShellTaskAssessment(
                !issues.Any(),
                summary,
                scenarioResult,
                expectsValidationFailure,
                expectsExecutionSuccess,
                expectedResolvedExecutionMode,
                actualResolvedExecutionMode,
                issues,
                validationMessages);
        }

        private static void WriteExecutionMatrixReportIfRequested(string reportPath, string runLabel, string hostIdentity, bool isRunningAsLocalSystem, IReadOnlyList<PowerShellTaskAssessment> assessments)
        {
            if (string.IsNullOrWhiteSpace(reportPath))
            {
                return;
            }

            var fullReportPath = Path.GetFullPath(reportPath);
            var directory = Path.GetDirectoryName(fullReportPath);

            if (!string.IsNullOrWhiteSpace(directory))
            {
                Directory.CreateDirectory(directory);
            }

            var report = new PowerShellTaskMatrixReport(
                DateTimeOffset.UtcNow,
                string.IsNullOrWhiteSpace(runLabel) ? "Unspecified" : runLabel,
                hostIdentity,
                isRunningAsLocalSystem,
                assessments.Count,
                assessments.Count(a => a.IsExpected),
                assessments.Count(a => !a.IsExpected),
                assessments.Select(a => new PowerShellTaskMatrixReportItem(
                    a.ScenarioResult.Scenario.DisplayName,
                    a.ScenarioResult.Scenario.AuthType,
                    a.ScenarioResult.Scenario.ExecutionMode.ToString(),
                    a.ScenarioResult.Scenario.ImpersonationMode.ToString(),
                    a.ScenarioResult.Scenario.HasArgsPayload,
                    a.ExpectsValidationFailure ? "Failure" : "Success",
                    a.ScenarioResult.ValidationResults.Any() ? "Failure" : "Success",
                    a.ExpectsExecutionSuccess ? "Success" : "Failure",
                    a.ScenarioResult.ExecutionResult.IsSuccess ? "Success" : "Failure",
                    a.ExpectedResolvedExecutionMode.ToString(),
                    a.ActualResolvedExecutionMode,
                    a.IsExpected ? "Pass" : "Fail",
                    a.ScenarioResult.ValidationAttempted,
                    a.ScenarioResult.ExecutionAttempted,
                    a.ScenarioResult.ThrownException,
                    a.Summary,
                    a.Issues,
                    a.ValidationMessages,
                    a.ScenarioResult.PayloadMessage,
                    a.ScenarioResult.ExceptionDetail,
                    a.ScenarioResult.ExecutionResult.Message)).ToList());

            var json = JsonSerializer.Serialize(report, new JsonSerializerOptions
            {
                WriteIndented = true
            });

            File.WriteAllText(fullReportPath, json);
        }

        private static void ValidateSuccessfulScenario(PowerShellTaskScenarioResult scenarioResult, string hostIdentity, PowerShellExecutionMode expectedResolvedExecutionMode, List<string> issues)
        {
            var scenario = scenarioResult.Scenario;
            var message = scenarioResult.ExecutionResult.Message;

            if (!message.Contains($"PowerShell Execution Mode: {expectedResolvedExecutionMode}", StringComparison.OrdinalIgnoreCase))
            {
                issues.Add($"expected resolved execution mode {expectedResolvedExecutionMode}");
            }

            if (scenario.ImpersonationMode != PowerShellImpersonationMode.Default && scenario.ExecutionMode != PowerShellExecutionMode.SystemProcess)
            {
                if (!message.Contains("overridden because Full Impersonation requires a new process", StringComparison.OrdinalIgnoreCase))
                {
                    issues.Add("expected full impersonation execution mode override message");
                }
            }

            if (scenario.ImpersonationMode == PowerShellImpersonationMode.FullWithProfile
                && !message.Contains("loading user profile", StringComparison.OrdinalIgnoreCase))
            {
                issues.Add("expected full impersonation with profile message");
            }

            if (scenario.ImpersonationMode == PowerShellImpersonationMode.Full
                && !message.Contains("user profile loading is disabled", StringComparison.OrdinalIgnoreCase))
            {
                issues.Add("expected full impersonation without profile message");
            }

            if (!message.Contains("TASK_COMPLETED", StringComparison.OrdinalIgnoreCase))
            {
                issues.Add("expected task completion marker");
            }

            if (!message.Contains("TASK_HAS_RESULT: False", StringComparison.OrdinalIgnoreCase))
            {
                issues.Add("expected no result payload to be passed to the script");
            }

            var expectedFlagValue = scenario.HasArgsPayload ? "True" : "False";
            if (!message.Contains($"TASK_FLAG: {expectedFlagValue}", StringComparison.OrdinalIgnoreCase))
            {
                issues.Add($"expected TASK_FLAG: {expectedFlagValue}");
            }

            if (scenario.HasArgsPayload)
            {
                if (!message.Contains($"TASK_MESSAGE: {scenarioResult.PayloadMessage}", StringComparison.Ordinal))
                {
                    issues.Add($"expected payload message '{scenarioResult.PayloadMessage}'");
                }
            }
            else if (!message.Contains("TASK_MESSAGE:", StringComparison.OrdinalIgnoreCase))
            {
                issues.Add("expected blank payload marker");
            }

            var taskIdentity = GetMarkerValue(message, "TASK_IDENTITY:");
            if (string.IsNullOrWhiteSpace(taskIdentity))
            {
                issues.Add("expected task identity marker");
            }
            else
            {
                var expectedIdentity = GetExpectedIdentityFragment(scenario, hostIdentity, expectedResolvedExecutionMode);

                if (expectedIdentity.Equals(hostIdentity, StringComparison.OrdinalIgnoreCase))
                {
                    if (!taskIdentity.Equals(expectedIdentity, StringComparison.OrdinalIgnoreCase))
                    {
                        issues.Add($"expected task identity '{expectedIdentity}' but got '{taskIdentity}'");
                    }
                }
                else if (taskIdentity.IndexOf(expectedIdentity, StringComparison.OrdinalIgnoreCase) < 0)
                {
                    issues.Add($"expected impersonated task identity containing '{expectedIdentity}' but got '{taskIdentity}'");
                }
            }
        }

        private static void ValidateExpectedFailureScenario(PowerShellTaskScenarioResult scenarioResult, List<string> issues, bool isRunningAsLocalSystem)
        {
            var scenario = scenarioResult.Scenario;
            var message = scenarioResult.ExecutionResult.Message;
            var expectedResolvedExecutionMode = GetExpectedResolvedExecutionMode(scenario);

            if (scenario.AuthType == StandardAuthTypes.STANDARD_AUTH_LOCAL)
            {
                if (!message.Contains("requires username and password credentials", StringComparison.OrdinalIgnoreCase))
                {
                    issues.Add("expected missing credential failure for full impersonation without stored Windows credentials");
                }

                return;
            }

            if (scenario.AuthType == StandardAuthTypes.STANDARD_AUTH_LOCAL_AS_USER
                && !scenario.HasArgsPayload
                && expectedResolvedExecutionMode == PowerShellExecutionMode.SystemProcess)
            {
                if (!message.Contains("-File parameter does not exist", StringComparison.OrdinalIgnoreCase)
                    && !LooksLikeProcessLaunchFailure(message)
                    && !message.Contains("Script exited with the following ExitCode", StringComparison.OrdinalIgnoreCase))
                {
                    issues.Add("expected direct script launch failure for alternate-user system-process execution without wrapper payload arguments");
                }

                return;
            }

            if (isRunningAsLocalSystem && scenario.ExecutionMode == PowerShellExecutionMode.SystemProcess && scenario.ImpersonationMode == PowerShellImpersonationMode.Default)
            {
                if (message.Contains("TASK_COMPLETED", StringComparison.OrdinalIgnoreCase))
                {
                    issues.Add("expected process launch failure before the script completed when running as Local System with alternate credentials");
                }

                if (!LooksLikeProcessLaunchFailure(message))
                {
                    issues.Add("expected a process launch failure signal when using alternate credentials from Local System");
                }

                return;
            }

            issues.Add($"unexpected failure message '{message}'");
        }

        private static bool ExpectsExecutionSuccess(PowerShellTaskScenario scenario, bool isRunningAsLocalSystem)
        {
            if (scenario.AuthType == StandardAuthTypes.STANDARD_AUTH_LOCAL)
            {
                return scenario.ImpersonationMode == PowerShellImpersonationMode.Default;
            }

            if (!scenario.HasArgsPayload && GetExpectedResolvedExecutionMode(scenario) == PowerShellExecutionMode.SystemProcess)
            {
                return false;
            }

            if (scenario.ImpersonationMode == PowerShellImpersonationMode.Default
                && scenario.ExecutionMode == PowerShellExecutionMode.SystemProcess
                && isRunningAsLocalSystem)
            {
                return false;
            }

            return true;
        }

        private static PowerShellExecutionMode GetExpectedResolvedExecutionMode(PowerShellTaskScenario scenario)
        {
            if (scenario.ImpersonationMode != PowerShellImpersonationMode.Default)
            {
                return PowerShellExecutionMode.SystemProcess;
            }

            if (scenario.ExecutionMode == PowerShellExecutionMode.Automatic)
            {
                return scenario.AuthType == StandardAuthTypes.STANDARD_AUTH_LOCAL_AS_USER
                    ? PowerShellExecutionMode.InProcess
                    : PowerShellExecutionMode.SystemProcess;
            }

            return scenario.ExecutionMode;
        }

        private static string GetExpectedIdentityFragment(PowerShellTaskScenario scenario, string hostIdentity, PowerShellExecutionMode expectedResolvedExecutionMode)
        {
            if (scenario.AuthType == StandardAuthTypes.STANDARD_AUTH_LOCAL)
            {
                return hostIdentity;
            }

            if (scenario.ImpersonationMode == PowerShellImpersonationMode.Default && expectedResolvedExecutionMode == PowerShellExecutionMode.InProcess)
            {
                return hostIdentity;
            }

            return TestLocalUsername;
        }

        private static string GetMarkerValue(string message, string marker)
        {
            var line = message
                .Split(new[] { "\r\n", "\n" }, StringSplitOptions.None)
                .FirstOrDefault(l => l.StartsWith(marker, StringComparison.OrdinalIgnoreCase));

            return line?.Substring(marker.Length).Trim();
        }

        private static string GetActualResolvedExecutionMode(string message)
        {
            return GetMarkerValue(message, "PowerShell Execution Mode:")?.Split(' ', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
        }

        [SupportedOSPlatform("windows")]
        private static bool IsRunningAsLocalSystem()
        {
            using var identity = WindowsIdentity.GetCurrent();
            return identity.User?.IsWellKnown(WellKnownSidType.LocalSystemSid) == true;
        }

        private static bool LooksLikeProcessLaunchFailure(string message)
        {
            return message.Contains("Error Running Script", StringComparison.OrdinalIgnoreCase)
                || message.Contains("Error:", StringComparison.OrdinalIgnoreCase)
                || message.Contains("Win32Exception", StringComparison.OrdinalIgnoreCase)
                || message.Contains("Logon failure", StringComparison.OrdinalIgnoreCase)
                || message.Contains("The handle is invalid", StringComparison.OrdinalIgnoreCase)
                || message.Contains("The requested operation requires elevation", StringComparison.OrdinalIgnoreCase)
                || message.Contains("Access is denied", StringComparison.OrdinalIgnoreCase)
                || message.Contains("Script exited with the following ExitCode", StringComparison.OrdinalIgnoreCase);
        }

        private static string DescribeResult(ActionResult result)
        {
            var condensedMessage = string.Join(" | ", result.Message
                .Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries)
                .Take(6));

            return result.IsSuccess
                ? condensedMessage
                : $"Failure: {condensedMessage}";
        }

        private static void DeleteTempScript(string scriptPath)
        {
            try
            {
                File.Delete(scriptPath);
            }
            catch
            {
            }
        }

        private sealed record PowerShellTaskScenario(string AuthType, PowerShellExecutionMode ExecutionMode, PowerShellImpersonationMode ImpersonationMode, bool HasArgsPayload)
        {
            public string DisplayName => $"Auth={AuthType.Split('.').Last()}, Execution={ExecutionMode}, Impersonation={ImpersonationMode}, ArgsPayload={HasArgsPayload}";
        }

        private sealed record PowerShellTaskScenarioResult(
            PowerShellTaskScenario Scenario,
            string PayloadMessage,
            IReadOnlyList<ActionResult> ValidationResults,
            ActionResult ExecutionResult,
            bool ThrownException,
            string ExceptionDetail,
            bool ValidationAttempted,
            bool ExecutionAttempted);

        private sealed record PowerShellTaskAssessment(
            bool IsExpected,
            string Summary,
            PowerShellTaskScenarioResult ScenarioResult,
            bool ExpectsValidationFailure,
            bool ExpectsExecutionSuccess,
            PowerShellExecutionMode ExpectedResolvedExecutionMode,
            string ActualResolvedExecutionMode,
            IReadOnlyList<string> Issues,
            string ValidationMessages);

        private sealed record PowerShellTaskMatrixReport(
            DateTimeOffset CreatedOn,
            string RunLabel,
            string HostIdentity,
            bool IsRunningAsLocalSystem,
            int TotalScenarios,
            int PassedScenarios,
            int FailedScenarios,
            IReadOnlyList<PowerShellTaskMatrixReportItem> Scenarios);

        private sealed record PowerShellTaskMatrixReportItem(
            string Scenario,
            string AuthType,
            string RequestedExecutionMode,
            string ImpersonationMode,
            bool HasArgsPayload,
            string ExpectedValidationResult,
            string ActualValidationResult,
            string ExpectedExecutionResult,
            string ActualExecutionResult,
            string ExpectedResolvedExecutionMode,
            string ActualResolvedExecutionMode,
            string Outcome,
            bool ValidationAttempted,
            bool ExecutionAttempted,
            bool ThrownException,
            string Summary,
            IReadOnlyList<string> Issues,
            string ValidationMessages,
            string PayloadMessage,
            string ExceptionDetail,
            string ExecutionMessage);
    }
}
