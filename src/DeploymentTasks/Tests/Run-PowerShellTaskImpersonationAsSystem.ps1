[CmdletBinding()]
param(
    [string]$Configuration = "Debug",
    [string]$Filter = "TestRunPowershellScriptTaskExecutionMatrixMatchesExpectedOutcomes",
    [string]$DotNetPath,
    [string]$PsExecPath,
    [string]$ReportPath = ".\reports\powershell-matrix-local-system.json",
    [string]$RunLabel = "LocalSystem",
    [switch]$NoExit,
    [switch]$UseWindowsPowerShell
)

$ErrorActionPreference = "Stop"

function Get-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-IsWindowsPlatform {
    try {
        return [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows)
    }
    catch {
        return $env:OS -eq 'Windows_NT'
    }
}

function Resolve-ExecutablePath {
    param(
        [string[]]$Candidates,
        [switch]$AllowCommandLookup
    )

    foreach ($candidate in $Candidates) {
        if ([string]::IsNullOrWhiteSpace($candidate)) {
            continue
        }

        if (Test-Path -LiteralPath $candidate) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }

        if ($AllowCommandLookup) {
            $command = Get-Command -Name $candidate -ErrorAction SilentlyContinue
            if ($command) {
                return $command.Source
            }
        }
    }

    return $null
}

function New-CandidateList {
    param(
        [string[]]$Values
    )

    return @($Values | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
}

function ConvertTo-SingleQuotedPowerShellString {
    param(
        [string]$Value
    )

    return "'" + ($Value -replace "'", "''") + "'"
}

function ConvertTo-EncodedPowerShellCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Command
    )

    return [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Command))
}

function Resolve-OutputPath {
    param(
        [string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return $null
    }

    $parentPath = Split-Path -Parent $Path
    $leafName = Split-Path -Leaf $Path

    if ([string]::IsNullOrWhiteSpace($parentPath)) {
        return [System.IO.Path]::GetFullPath($Path)
    }

    if (-not (Test-Path -LiteralPath $parentPath)) {
        New-Item -ItemType Directory -Path $parentPath -Force | Out-Null
    }

    return Join-Path (Resolve-Path -LiteralPath $parentPath).Path $leafName
}

if (-not (Get-IsWindowsPlatform)) {
    throw "This helper only supports Windows because it launches the test host as Local System."
}

if (-not (Get-IsAdministrator)) {
    throw "Run this script from an elevated PowerShell session. Launching as Local System requires administrator rights."
}

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectPath = Join-Path $scriptRoot "Tests.Plugin.DeploymentTasks.csproj"

if (-not (Test-Path -LiteralPath $projectPath)) {
    throw "Could not locate the deployment task test project at '$projectPath'."
}

$resolvedDotNetPath = Resolve-ExecutablePath -Candidates (New-CandidateList @(
    $DotNetPath,
    "$env:ProgramFiles\dotnet\dotnet.exe",
    "dotnet.exe",
    "dotnet"
)) -AllowCommandLookup

if (-not $resolvedDotNetPath) {
    throw "Could not locate dotnet.exe. Pass -DotNetPath with the full path to dotnet.exe."
}

$resolvedPsExecPath = Resolve-ExecutablePath -Candidates (New-CandidateList @(
    $PsExecPath,
    "D:\Tools\sysinternals\PsExec64.exe",
    "$env:ProgramFiles\PsExec\PsExec64.exe",
    "$env:ProgramFiles\PsExec\PsExec.exe",
    "$env:SystemRoot\System32\PsExec64.exe",
    "$env:SystemRoot\System32\PsExec.exe",
    "PsExec64.exe",
    "PsExec.exe"
)) -AllowCommandLookup

if (-not $resolvedPsExecPath) {
    throw "Could not locate PsExec. Install Sysinternals PsExec or pass -PsExecPath with the full path to PsExec64.exe."
}

$testArguments = @(
    'test'
    ('"' + $projectPath + '"')
    '--configuration'
    $Configuration
)

$commandParts = @(
    'Set-Location -LiteralPath ' + (ConvertTo-SingleQuotedPowerShellString $scriptRoot)
)

if (-not [string]::IsNullOrWhiteSpace($ReportPath)) {
    $resolvedReportPath = Resolve-OutputPath $ReportPath
    $commandParts += '$env:CERTIFY_POWERSHELL_TASK_MATRIX_REPORT_PATH = ' + (ConvertTo-SingleQuotedPowerShellString $resolvedReportPath)
    $commandParts += '$env:CERTIFY_POWERSHELL_TASK_MATRIX_RUN_LABEL = ' + (ConvertTo-SingleQuotedPowerShellString $RunLabel)
}

if (-not [string]::IsNullOrWhiteSpace($Filter)) {
    $testArguments += @('--filter', ('"' + $Filter + '"'))
}

$commandParts += '& ' + ('"' + $resolvedDotNetPath + '"') + ' ' + ($testArguments -join ' ')

$testCommand = $commandParts -join '; '
$encodedTestCommand = ConvertTo-EncodedPowerShellCommand -Command $testCommand

if ($NoExit) {
    $testCommand += '; Write-Host "`nTest run complete. Press Enter to close this Local System window..." -ForegroundColor Cyan; [void][Console]::ReadLine()'
    $encodedTestCommand = ConvertTo-EncodedPowerShellCommand -Command $testCommand
}

$shellPath = if ($UseWindowsPowerShell) {
    Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
}
else {
    Resolve-ExecutablePath -Candidates (New-CandidateList @(
        "$env:ProgramFiles\PowerShell\7\pwsh.exe",
        "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe",
        "pwsh.exe",
        "pwsh",
        "powershell.exe"
    )) -AllowCommandLookup
}

if (-not $shellPath) {
    throw "Could not locate a PowerShell host to launch under Local System."
}

$systemShellArguments = @(
    '-NoProfile'
    '-ExecutionPolicy', 'Bypass'
    '-EncodedCommand', $encodedTestCommand
)

$psExecArguments = @(
    '-accepteula'
    '-i'
    '-s'
    $shellPath
) + $systemShellArguments

Write-Host "Generating deployment task matrix report as Local System..." -ForegroundColor Cyan
Write-Host "PsExec: $resolvedPsExecPath"
Write-Host "Shell : $shellPath"
Write-Host "dotnet: $resolvedDotNetPath"
Write-Host "Test  : $projectPath"
if ($Filter) {
    Write-Host "Filter: $Filter"
}
if ($ReportPath) {
    Write-Host "Report: $resolvedReportPath"
    Write-Host "Label : $RunLabel"
}

& $resolvedPsExecPath @psExecArguments
if ($LASTEXITCODE -ne 0) {
    Write-Error "The Local System test process exited with code $LASTEXITCODE. This usually means the matrix test reported scenario failures under SYSTEM rather than PsExec itself failing. Re-run with -NoExit to keep the SYSTEM window open; the JSON report at the configured report path should still contain the per-scenario results for comparison."
    exit $LASTEXITCODE
}
