# Deployment Task Tests

Integration and behavior tests for deployment task providers, including the PowerShell task execution and impersonation coverage.

## Test Project

- Project: `Tests.Plugin.DeploymentTasks.csproj`
- Framework: `.NET 10`
- Test framework: `MSTest`

## Running Tests

Run all deployment task tests:

`dotnet test .\Tests.Plugin.DeploymentTasks.csproj`

Run the PowerShell impersonation test class only:

`dotnet test .\Tests.Plugin.DeploymentTasks.csproj --filter "FullyQualifiedName~DeploymentTasksPowershellTaskImpersonation"`

Run the PowerShell execution matrix test only:

`dotnet test .\Tests.Plugin.DeploymentTasks.csproj --filter "TestRunPowershellScriptTaskExecutionMatrixMatchesExpectedOutcomes"`

## PowerShell Task Coverage

`DeploymentTasks.PowershellTaskImpersonation.cs` includes coverage for:

- execution modes: `Automatic`, `InProcess`, `SystemProcess`
- impersonation modes: `Default`, `Full`, `FullWithProfile`
- auth contexts: local/default user and local-as-user
- with and without argument payloads

The execution matrix test is intended to document which combinations succeed and which fail based on the current host identity and execution path.

## Prerequisites

Some tests are marked with `RequiresLocalUser` and assume a local Windows test account exists:

- username: `testuser`
- password: `testing123`

These tests are Windows-specific.

## Optional JSON Report Output

The PowerShell execution matrix test can optionally write a JSON report containing:

- host identity
- whether the host was running as `Local System`
- each attempted scenario
- expected validation and execution results
- actual validation and execution results
- expected and actual resolved execution modes
- per-scenario `Pass` or `Fail`
- validation attempted / execution attempted flags
- thrown exception flags and exception detail
- issue details and execution output

The report path is controlled by the environment variable:

- `CERTIFY_POWERSHELL_TASK_MATRIX_REPORT_PATH`

An optional run label can also be supplied:

- `CERTIFY_POWERSHELL_TASK_MATRIX_RUN_LABEL`

## Standard User Report Runner

Use `Run-PowerShellTaskImpersonationAsStandardUser.ps1` to run the matrix test as the current user and generate or update the standard-user JSON report.

Default usage:

`pwsh -File .\Run-PowerShellTaskImpersonationAsStandardUser.ps1`

This defaults to:

- filter: `TestRunPowershellScriptTaskExecutionMatrixMatchesExpectedOutcomes`
- report path: `.\reports\powershell-matrix-standard-user.json`
- run label: `StandardUser`

Example with explicit output path:

`pwsh -File .\Run-PowerShellTaskImpersonationAsStandardUser.ps1 -ReportPath .\reports\powershell-matrix-standard-user.json -RunLabel "StandardUser"`

## Local System Report Runner

Use `Run-PowerShellTaskImpersonationAsSystem.ps1` to run the matrix test as `Local System` and generate or update the Local System JSON report.

Default usage:

`pwsh -File .\Run-PowerShellTaskImpersonationAsSystem.ps1`

This defaults to:

- filter: `TestRunPowershellScriptTaskExecutionMatrixMatchesExpectedOutcomes`
- report path: `.\reports\powershell-matrix-local-system.json`
- run label: `LocalSystem`

Example with explicit output path:

`pwsh -File .\Run-PowerShellTaskImpersonationAsSystem.ps1 -ReportPath .\reports\powershell-matrix-local-system.json -RunLabel "LocalSystem"`

Notes:

- the script must be launched from an elevated PowerShell session
- the script uses Sysinternals `PsExec` to start the test host as `SYSTEM`
- `dotnet` and `PsExec` can be provided explicitly using `-DotNetPath` and `-PsExecPath`
- use `-NoExit` to keep the Local System console window open after the test run completes
- even if the test run exits non-zero, the JSON report should still be written with the per-scenario results

## HTML Comparison Report

Use `Compare-PowerShellTaskMatrixReports.ps1` to convert two JSON reports into an HTML comparison document with side-by-side tables.

Example:

```powershell
.\Compare-PowerShellTaskMatrixReports.ps1   -LeftReport .\reports\powershell-matrix-standard-user.json -RightReport .\reports\powershell-matrix-local-system.json -LeftLabel "Standard User" -RightLabel "Local System" -OutputHtml .\reports\powershell-matrix-comparison.html
```

Open the generated HTML report:

`ii .\reports\powershell-matrix-comparison.html`

## Comparing Standard User vs Local System

A simple comparison workflow is:

1. Generate or update the standard-user JSON report.
2. Generate or update the Local System JSON report.
3. Generate an HTML comparison report from those two JSON files.
4. Open the HTML file in a browser and review the side-by-side scenario differences.

Suggested filenames:

- `powershell-matrix-standard-user.json`
- `powershell-matrix-local-system.json`
- `powershell-matrix-comparison.html`

## Notes

- The PowerShell task behavior differs depending on whether the test host is running as a normal user or as `Local System`.
- In-process Windows credential compatibility cases can succeed while still running under the host identity.
- Some out-of-process alternate-user combinations are expected to fail when launching direct script files without wrapper payload arguments; the matrix test captures and validates the currently observed behavior.
- The matrix report is still written even if the overall test fails, so comparison data is preserved for investigation.
