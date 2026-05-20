[CmdletBinding()]
param(
    [string]$Configuration = "Debug",
    [string]$Filter = "TestRunPowershellScriptTaskExecutionMatrixMatchesExpectedOutcomes",
    [string]$DotNetPath,
    [string]$ReportPath = ".\reports\powershell-matrix-standard-user.json",
    [string]$RunLabel = "StandardUser"
)

$ErrorActionPreference = "Stop"

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

function Resolve-OutputPath {
    param(
        [string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return $null
    }

    if ([System.IO.Path]::IsPathRooted($Path)) {
        $fullPath = [System.IO.Path]::GetFullPath($Path)
    }
    else {
        $currentDirectory = (Get-Location).Path
        $fullPath = [System.IO.Path]::GetFullPath((Join-Path $currentDirectory $Path))
    }

    $directory = [System.IO.Path]::GetDirectoryName($fullPath)

    if (-not [string]::IsNullOrWhiteSpace($directory) -and -not (Test-Path -LiteralPath $directory)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }

    return $fullPath
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

$resolvedReportPath = Resolve-OutputPath $ReportPath

$testArguments = @(
    'test'
    ('"' + $projectPath + '"')
    '--configuration'
    $Configuration
)

if (-not [string]::IsNullOrWhiteSpace($Filter)) {
    $testArguments += @('--filter', ('"' + $Filter + '"'))
}

Write-Host "Running deployment task tests as the current standard user..." -ForegroundColor Cyan
Write-Host "dotnet: $resolvedDotNetPath"
Write-Host "Test  : $projectPath"
if ($Filter) {
    Write-Host "Filter: $Filter"
}
if ($resolvedReportPath) {
    Write-Host "Report: $resolvedReportPath"
    Write-Host "Label : $RunLabel"
}

$previousReportPath = [Environment]::GetEnvironmentVariable('CERTIFY_POWERSHELL_TASK_MATRIX_REPORT_PATH')
$previousRunLabel = [Environment]::GetEnvironmentVariable('CERTIFY_POWERSHELL_TASK_MATRIX_RUN_LABEL')

try {
    if ($resolvedReportPath) {
        [Environment]::SetEnvironmentVariable('CERTIFY_POWERSHELL_TASK_MATRIX_REPORT_PATH', $resolvedReportPath)
        [Environment]::SetEnvironmentVariable('CERTIFY_POWERSHELL_TASK_MATRIX_RUN_LABEL', $RunLabel)
    }

    & $resolvedDotNetPath @testArguments
    exit $LASTEXITCODE
}
finally {
    [Environment]::SetEnvironmentVariable('CERTIFY_POWERSHELL_TASK_MATRIX_REPORT_PATH', $previousReportPath)
    [Environment]::SetEnvironmentVariable('CERTIFY_POWERSHELL_TASK_MATRIX_RUN_LABEL', $previousRunLabel)
}
