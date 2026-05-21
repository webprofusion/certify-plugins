[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$LeftReport,

    [Parameter(Mandatory = $true)]
    [string]$RightReport,

    [Parameter(Mandatory = $true)]
    [string]$OutputHtml,

    [string]$LeftLabel = "Left Report",
    [string]$RightLabel = "Right Report",
    [string]$Title = "PowerShell Task Matrix Comparison"
)

$ErrorActionPreference = 'Stop'

function Resolve-ExistingFilePath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "File not found: $Path"
    }

    return (Resolve-Path -LiteralPath $Path).Path
}

function Resolve-OutputFilePath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

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

function HtmlEncode {
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return ''
    }

    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function Get-BadgeClass {
    param(
        [AllowNull()]
        [string]$Value
    )

    switch -Regex ($Value) {
        '^(Pass|Success|true)$' { return 'ok' }
        '^(Fail|Failure|false)$' { return 'fail' }
        default { return 'neutral' }
    }
}

function New-Badge {
    param(
        [AllowNull()]
        [object]$Value
    )

    $text = if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { '-' } else { [string]$Value }
    $class = Get-BadgeClass $text
    return "<span class='badge $class'>$(HtmlEncode $text)</span>"
}

function New-PreBlock {
    param(
        [AllowNull()]
        [string]$Value
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return "<span class='muted'>-</span>"
    }

    return "<pre>$(HtmlEncode $Value)</pre>"
}

function Join-Issues {
    param(
        [AllowNull()]
        [object]$Issues
    )

    if ($null -eq $Issues) {
        return ''
    }

    if ($Issues -is [System.Array] -or $Issues -is [System.Collections.IEnumerable]) {
        $items = @($Issues | ForEach-Object { [string]$_ } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        return ($items -join [Environment]::NewLine)
    }

    return [string]$Issues
}

function Get-ScenarioMap {
    param(
        [Parameter(Mandatory = $true)]
        $Report
    )

    $map = @{}
    foreach ($scenario in @($Report.Scenarios)) {
        $map[[string]$scenario.Scenario] = $scenario
    }

    return $map
}

function Get-CellValue {
    param(
        [AllowNull()]$Scenario,
        [Parameter(Mandatory = $true)][string]$PropertyName
    )

    if ($null -eq $Scenario) {
        return $null
    }

    return $Scenario.$PropertyName
}

function Get-BehaviorDifferences {
    param(
        [AllowNull()]$LeftScenario,
        [AllowNull()]$RightScenario,
        [string]$LeftName,
        [string]$RightName
    )

    $differences = @()

    if ($null -eq $LeftScenario -and $null -eq $RightScenario) {
        return @('Scenario was missing from both reports.')
    }

    if ($null -eq $LeftScenario) {
        return @("Scenario only exists in $RightName.")
    }

    if ($null -eq $RightScenario) {
        return @("Scenario only exists in $LeftName.")
    }

    if ([string]$LeftScenario.Outcome -ne [string]$RightScenario.Outcome) {
        $differences += "$LeftName outcome was $($LeftScenario.Outcome) while $RightName outcome was $($RightScenario.Outcome)."
    }

    if ([string]$LeftScenario.ActualExecutionResult -ne [string]$RightScenario.ActualExecutionResult) {
        $differences += "$LeftName execution result was $($LeftScenario.ActualExecutionResult) while $RightName execution result was $($RightScenario.ActualExecutionResult)."
    }

    if ([string]$LeftScenario.ActualValidationResult -ne [string]$RightScenario.ActualValidationResult) {
        $differences += "$LeftName validation result was $($LeftScenario.ActualValidationResult) while $RightName validation result was $($RightScenario.ActualValidationResult)."
    }

    if ([string]$LeftScenario.ActualResolvedExecutionMode -ne [string]$RightScenario.ActualResolvedExecutionMode) {
        $differences += "$LeftName resolved mode was '$($LeftScenario.ActualResolvedExecutionMode)' while $RightName resolved mode was '$($RightScenario.ActualResolvedExecutionMode)'."
    }

    if ([string]$LeftScenario.ThrownException -ne [string]$RightScenario.ThrownException) {
        $differences += "$LeftName exception flag was $($LeftScenario.ThrownException) while $RightName exception flag was $($RightScenario.ThrownException)."
    }

    if ([string]$LeftScenario.ValidationAttempted -ne [string]$RightScenario.ValidationAttempted) {
        $differences += "$LeftName validation attempted was $($LeftScenario.ValidationAttempted) while $RightName validation attempted was $($RightScenario.ValidationAttempted)."
    }

    if ([string]$LeftScenario.ExecutionAttempted -ne [string]$RightScenario.ExecutionAttempted) {
        $differences += "$LeftName execution attempted was $($LeftScenario.ExecutionAttempted) while $RightName execution attempted was $($RightScenario.ExecutionAttempted)."
    }

    $leftIssues = Join-Issues $LeftScenario.Issues
    $rightIssues = Join-Issues $RightScenario.Issues

    if ($leftIssues -ne $rightIssues) {
        if ([string]::IsNullOrWhiteSpace($leftIssues)) {
            $differences += "$RightName reported issues that $LeftName did not."
        }
        elseif ([string]::IsNullOrWhiteSpace($rightIssues)) {
            $differences += "$LeftName reported issues that $RightName did not."
        }
        else {
            $differences += "$LeftName and $RightName reported different issue details."
        }
    }

    if (-not $differences) {
        $differences += 'No simple behavioral difference detected in the compared summary fields.'
    }

    return $differences
}

$leftPath = Resolve-ExistingFilePath $LeftReport
$rightPath = Resolve-ExistingFilePath $RightReport
$outputPath = Resolve-OutputFilePath $OutputHtml

$left = Get-Content -LiteralPath $leftPath -Raw | ConvertFrom-Json
$right = Get-Content -LiteralPath $rightPath -Raw | ConvertFrom-Json

$leftMap = Get-ScenarioMap $left
$rightMap = Get-ScenarioMap $right
$scenarioNames = @($leftMap.Keys + $rightMap.Keys | Sort-Object -Unique)

$summaryRows = foreach ($item in @(
    @{ Name = 'Run Label'; Left = $left.RunLabel; Right = $right.RunLabel },
    @{ Name = 'Created On'; Left = $left.CreatedOn; Right = $right.CreatedOn },
    @{ Name = 'Host Identity'; Left = $left.HostIdentity; Right = $right.HostIdentity },
    @{ Name = 'Is Local System'; Left = [string]$left.IsRunningAsLocalSystem; Right = [string]$right.IsRunningAsLocalSystem },
    @{ Name = 'Total Scenarios'; Left = [string]$left.TotalScenarios; Right = [string]$right.TotalScenarios },
    @{ Name = 'Passed Scenarios'; Left = [string]$left.PassedScenarios; Right = [string]$right.PassedScenarios },
    @{ Name = 'Failed Scenarios'; Left = [string]$left.FailedScenarios; Right = [string]$right.FailedScenarios }
)) {
    @"
<tr>
    <th>$(HtmlEncode $item.Name)</th>
    <td>$(HtmlEncode $item.Left)</td>
    <td>$(HtmlEncode $item.Right)</td>
</tr>
"@
}

$comparisonRows = foreach ($scenarioName in $scenarioNames) {
    $leftScenario = $leftMap[$scenarioName]
    $rightScenario = $rightMap[$scenarioName]

    $statusClass = if ($null -eq $leftScenario -or $null -eq $rightScenario) {
        'changed'
    }
    elseif ([string]$leftScenario.Outcome -eq [string]$rightScenario.Outcome -and
            [string]$leftScenario.ActualExecutionResult -eq [string]$rightScenario.ActualExecutionResult -and
            [string]$leftScenario.ActualValidationResult -eq [string]$rightScenario.ActualValidationResult) {
        'same'
    }
    else {
        'changed'
    }

    $leftIssues = Join-Issues (Get-CellValue $leftScenario 'Issues')
    $rightIssues = Join-Issues (Get-CellValue $rightScenario 'Issues')

    @"
<tr class='$statusClass'>
    <td class='scenario-name'>$(HtmlEncode $scenarioName)</td>
    <td>$(New-Badge (Get-CellValue $leftScenario 'Outcome'))</td>
    <td>$(New-Badge (Get-CellValue $rightScenario 'Outcome'))</td>
    <td>$(New-Badge (Get-CellValue $leftScenario 'ActualValidationResult'))</td>
    <td>$(New-Badge (Get-CellValue $rightScenario 'ActualValidationResult'))</td>
    <td>$(New-Badge (Get-CellValue $leftScenario 'ActualExecutionResult'))</td>
    <td>$(New-Badge (Get-CellValue $rightScenario 'ActualExecutionResult'))</td>
    <td>$(HtmlEncode (Get-CellValue $leftScenario 'ActualResolvedExecutionMode'))</td>
    <td>$(HtmlEncode (Get-CellValue $rightScenario 'ActualResolvedExecutionMode'))</td>
    <td>$(New-Badge (Get-CellValue $leftScenario 'ThrownException'))</td>
    <td>$(New-Badge (Get-CellValue $rightScenario 'ThrownException'))</td>
</tr>
<tr class='details-row'>
    <td colspan='11'>
        <div class='details-grid'>
            <div class='details-panel'>
                <h4>$(HtmlEncode $LeftLabel)</h4>
                <table>
                    <tr><th>Summary</th><td>$(HtmlEncode (Get-CellValue $leftScenario 'Summary'))</td></tr>
                    <tr><th>Expected Validation</th><td>$(HtmlEncode (Get-CellValue $leftScenario 'ExpectedValidationResult'))</td></tr>
                    <tr><th>Expected Execution</th><td>$(HtmlEncode (Get-CellValue $leftScenario 'ExpectedExecutionResult'))</td></tr>
                    <tr><th>Expected Resolved Mode</th><td>$(HtmlEncode (Get-CellValue $leftScenario 'ExpectedResolvedExecutionMode'))</td></tr>
                    <tr><th>Validation Attempted</th><td>$(HtmlEncode (Get-CellValue $leftScenario 'ValidationAttempted'))</td></tr>
                    <tr><th>Execution Attempted</th><td>$(HtmlEncode (Get-CellValue $leftScenario 'ExecutionAttempted'))</td></tr>
                    <tr><th>Payload Message</th><td>$(HtmlEncode (Get-CellValue $leftScenario 'PayloadMessage'))</td></tr>
                    <tr><th>Validation Messages</th><td>$(New-PreBlock (Get-CellValue $leftScenario 'ValidationMessages'))</td></tr>
                    <tr><th>Issues</th><td>$(New-PreBlock $leftIssues)</td></tr>
                    <tr><th>Exception Detail</th><td>$(New-PreBlock (Get-CellValue $leftScenario 'ExceptionDetail'))</td></tr>
                    <tr><th>Execution Message</th><td>$(New-PreBlock (Get-CellValue $leftScenario 'ExecutionMessage'))</td></tr>
                </table>
            </div>
            <div class='details-panel'>
                <h4>$(HtmlEncode $RightLabel)</h4>
                <table>
                    <tr><th>Summary</th><td>$(HtmlEncode (Get-CellValue $rightScenario 'Summary'))</td></tr>
                    <tr><th>Expected Validation</th><td>$(HtmlEncode (Get-CellValue $rightScenario 'ExpectedValidationResult'))</td></tr>
                    <tr><th>Expected Execution</th><td>$(HtmlEncode (Get-CellValue $rightScenario 'ExpectedExecutionResult'))</td></tr>
                    <tr><th>Expected Resolved Mode</th><td>$(HtmlEncode (Get-CellValue $rightScenario 'ExpectedResolvedExecutionMode'))</td></tr>
                    <tr><th>Validation Attempted</th><td>$(HtmlEncode (Get-CellValue $rightScenario 'ValidationAttempted'))</td></tr>
                    <tr><th>Execution Attempted</th><td>$(HtmlEncode (Get-CellValue $rightScenario 'ExecutionAttempted'))</td></tr>
                    <tr><th>Payload Message</th><td>$(HtmlEncode (Get-CellValue $rightScenario 'PayloadMessage'))</td></tr>
                    <tr><th>Validation Messages</th><td>$(New-PreBlock (Get-CellValue $rightScenario 'ValidationMessages'))</td></tr>
                    <tr><th>Issues</th><td>$(New-PreBlock $rightIssues)</td></tr>
                    <tr><th>Exception Detail</th><td>$(New-PreBlock (Get-CellValue $rightScenario 'ExceptionDetail'))</td></tr>
                    <tr><th>Execution Message</th><td>$(New-PreBlock (Get-CellValue $rightScenario 'ExecutionMessage'))</td></tr>
                </table>
            </div>
        </div>
    </td>
</tr>
"@
}

$differenceRows = foreach ($scenarioName in $scenarioNames) {
    $leftScenario = $leftMap[$scenarioName]
    $rightScenario = $rightMap[$scenarioName]
    $differences = @(Get-BehaviorDifferences -LeftScenario $leftScenario -RightScenario $rightScenario -LeftName $LeftLabel -RightName $RightLabel)

    $isDifferent = $null -eq $leftScenario -or
        $null -eq $rightScenario -or
        [string]$leftScenario.Outcome -ne [string]$rightScenario.Outcome -or
        [string]$leftScenario.ActualExecutionResult -ne [string]$rightScenario.ActualExecutionResult -or
        [string]$leftScenario.ActualValidationResult -ne [string]$rightScenario.ActualValidationResult -or
        [string]$leftScenario.ActualResolvedExecutionMode -ne [string]$rightScenario.ActualResolvedExecutionMode -or
        [string]$leftScenario.ThrownException -ne [string]$rightScenario.ThrownException -or
        [string]$leftScenario.ValidationAttempted -ne [string]$rightScenario.ValidationAttempted -or
        [string]$leftScenario.ExecutionAttempted -ne [string]$rightScenario.ExecutionAttempted -or
        (Join-Issues (Get-CellValue $leftScenario 'Issues')) -ne (Join-Issues (Get-CellValue $rightScenario 'Issues'))

    if (-not $isDifferent) {
        continue
    }

    $differenceList = ($differences | ForEach-Object { "<li>$(HtmlEncode $_)</li>" }) -join [Environment]::NewLine

    @"
<tr>
    <td class='scenario-name'>$(HtmlEncode $scenarioName)</td>
    <td>
        <ul class='difference-list'>
            $differenceList
        </ul>
    </td>
</tr>
"@
}

if (-not $differenceRows) {
    $differenceRows = @"
<tr>
    <td colspan='2'><span class='muted'>No simple behavioral differences were detected between the two reports.</span></td>
</tr>
"@
}

$html = @"
<!DOCTYPE html>
<html lang='en'>
<head>
    <meta charset='utf-8' />
    <title>$(HtmlEncode $Title)</title>
    <style>
        body {
            font-family: Segoe UI, Arial, sans-serif;
            margin: 24px;
            color: #1f2937;
            background: #f8fafc;
        }
        h1, h2, h3, h4 {
            margin-top: 0;
        }
        .meta, .comparison {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 24px;
            background: #ffffff;
            box-shadow: 0 1px 2px rgba(0,0,0,0.08);
        }
        .meta th, .meta td, .comparison th, .comparison td {
            border: 1px solid #dbe2ea;
            padding: 8px 10px;
            vertical-align: top;
        }
        .meta th, .comparison thead th {
            background: #e2e8f0;
            text-align: left;
        }
        .comparison .scenario-name {
            min-width: 360px;
            font-weight: 600;
        }
        .badge {
            display: inline-block;
            border-radius: 999px;
            padding: 2px 10px;
            font-size: 12px;
            font-weight: 600;
        }
        .badge.ok {
            background: #dcfce7;
            color: #166534;
        }
        .badge.fail {
            background: #fee2e2;
            color: #991b1b;
        }
        .badge.neutral {
            background: #e5e7eb;
            color: #374151;
        }
        tr.same > td {
            background: #f8fafc;
        }
        tr.changed > td {
            background: #fff7ed;
        }
        .details-row td {
            background: #f8fafc;
        }
        .details-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 16px;
        }
        .details-panel table {
            width: 100%;
            border-collapse: collapse;
            background: #ffffff;
        }
        .details-panel th, .details-panel td {
            border: 1px solid #dbe2ea;
            padding: 6px 8px;
            vertical-align: top;
            text-align: left;
        }
        .details-panel th {
            width: 180px;
            background: #f1f5f9;
        }
        pre {
            margin: 0;
            white-space: pre-wrap;
            word-break: break-word;
            font-family: Consolas, monospace;
            font-size: 12px;
        }
        .muted {
            color: #6b7280;
        }
        .header-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 16px;
            margin-bottom: 16px;
        }
        .header-card {
            background: #ffffff;
            border: 1px solid #dbe2ea;
            padding: 16px;
            box-shadow: 0 1px 2px rgba(0,0,0,0.08);
        }
        .difference-list {
            margin: 0;
            padding-left: 18px;
        }
    </style>
</head>
<body>
    <h1>$(HtmlEncode $Title)</h1>
    <div class='header-grid'>
        <div class='header-card'>
            <h3>$(HtmlEncode $LeftLabel)</h3>
            <div><strong>Source:</strong> $(HtmlEncode $leftPath)</div>
        </div>
        <div class='header-card'>
            <h3>$(HtmlEncode $RightLabel)</h3>
            <div><strong>Source:</strong> $(HtmlEncode $rightPath)</div>
        </div>
    </div>

    <h2>Run Summary</h2>
    <table class='meta'>
        <thead>
            <tr>
                <th>Property</th>
                <th>$(HtmlEncode $LeftLabel)</th>
                <th>$(HtmlEncode $RightLabel)</th>
            </tr>
        </thead>
        <tbody>
            $($summaryRows -join [Environment]::NewLine)
        </tbody>
    </table>

    <h2>Simple Behavior Differences</h2>
    <table class='meta'>
        <thead>
            <tr>
                <th>Scenario</th>
                <th>Behavior Summary</th>
            </tr>
        </thead>
        <tbody>
            $($differenceRows -join [Environment]::NewLine)
        </tbody>
    </table>

    <h2>Scenario Comparison</h2>
    <table class='comparison'>
        <thead>
            <tr>
                <th>Scenario</th>
                <th>$(HtmlEncode $LeftLabel)<br/>Outcome</th>
                <th>$(HtmlEncode $RightLabel)<br/>Outcome</th>
                <th>$(HtmlEncode $LeftLabel)<br/>Validation</th>
                <th>$(HtmlEncode $RightLabel)<br/>Validation</th>
                <th>$(HtmlEncode $LeftLabel)<br/>Execution</th>
                <th>$(HtmlEncode $RightLabel)<br/>Execution</th>
                <th>$(HtmlEncode $LeftLabel)<br/>Resolved Mode</th>
                <th>$(HtmlEncode $RightLabel)<br/>Resolved Mode</th>
                <th>$(HtmlEncode $LeftLabel)<br/>Exception</th>
                <th>$(HtmlEncode $RightLabel)<br/>Exception</th>
            </tr>
        </thead>
        <tbody>
            $($comparisonRows -join [Environment]::NewLine)
        </tbody>
    </table>
</body>
</html>
"@

Set-Content -LiteralPath $outputPath -Value $html -Encoding UTF8
Write-Host "Comparison report written to $outputPath" -ForegroundColor Green
