# Example: Simulate guest access to Office 365
# This script demonstrates how to use the WhatIfCA module to simulate
# a guest user attempting to access Office 365 under various conditions

# First, make sure the module is imported
if (-not (Get-Module WhatIfCA -ErrorAction SilentlyContinue)) {
    Import-Module -Name (Join-Path -Path $PSScriptRoot -ChildPath '..\WhatIfCA.psd1')
}

# Cross-platform temp directory
$TempDir = if ($IsMacOS -or $IsLinux) {
    [System.IO.Path]::GetTempPath()
}
else {
    $env:TEMP
}

# Configuration
$OutputPath = Join-Path -Path $TempDir -ChildPath 'GuestAccessReport'
$HtmlReportPath = "$OutputPath.html"
$JsonReportPath = "$OutputPath.json"

# Create the directory if it doesn't exist
if (-not (Test-Path -Path (Split-Path -Path $OutputPath -Parent))) {
    New-Item -Path (Split-Path -Path $OutputPath -Parent) -ItemType Directory -Force | Out-Null
}

# Set InformationPreference to continue to ensure messages are displayed
$currentInformationPreference = $InformationPreference
$InformationPreference = 'Continue'

Write-Information "Simulating guest access scenarios..." -InformationAction Continue -ForegroundColor Cyan

# Scenario 1: Guest accessing Office 365 from trusted network, no MFA
Write-Information "`nScenario 1: Guest accessing Office 365 from trusted network, no MFA" -InformationAction Continue
$scenario1 = Invoke-CAWhatIf `
    -UserId "guest@partner.com" `
    -UserGroups "Guests" `
    -AppId "Office365" `
    -Location "Trusted Network" `
    -ClientAppType "Browser" `
    -DevicePlatform "Windows" `
    -MfaAuthenticated $false `
    -OutputLevel "Detailed"

Write-Information "Access allowed: $($scenario1.AccessAllowed)" -InformationAction Continue
if (-not $scenario1.AccessAllowed) {
    Write-Information "Blocked by policies: $($scenario1.BlockingPolicies.DisplayName -join ', ')" -InformationAction Continue
}
elseif ($scenario1.RequiredControls.Count -gt 0) {
    Write-Information "Required controls: $($scenario1.RequiredControls -join ', ')" -InformationAction Continue
}

# Scenario 2: Guest accessing Office 365 from untrusted network, no MFA
Write-Information "`nScenario 2: Guest accessing Office 365 from untrusted network, no MFA" -InformationAction Continue
$scenario2 = Invoke-CAWhatIf `
    -UserId "guest@partner.com" `
    -UserGroups "Guests" `
    -AppId "Office365" `
    -Location "Untrusted Network" `
    -ClientAppType "Browser" `
    -DevicePlatform "Windows" `
    -MfaAuthenticated $false `
    -OutputLevel "Detailed"

Write-Information "Access allowed: $($scenario2.AccessAllowed)" -InformationAction Continue
if (-not $scenario2.AccessAllowed) {
    Write-Information "Blocked by policies: $($scenario2.BlockingPolicies.DisplayName -join ', ')" -InformationAction Continue
}
elseif ($scenario2.RequiredControls.Count -gt 0) {
    Write-Information "Required controls: $($scenario2.RequiredControls -join ', ')" -InformationAction Continue
}

# Scenario 3: Guest accessing Office 365 from untrusted network, with MFA
Write-Information "`nScenario 3: Guest accessing Office 365 from untrusted network, with MFA" -InformationAction Continue
$scenario3 = Invoke-CAWhatIf `
    -UserId "guest@partner.com" `
    -UserGroups "Guests" `
    -AppId "Office365" `
    -Location "Untrusted Network" `
    -ClientAppType "Browser" `
    -DevicePlatform "Windows" `
    -MfaAuthenticated $true `
    -OutputLevel "Detailed"

Write-Information "Access allowed: $($scenario3.AccessAllowed)" -InformationAction Continue
if (-not $scenario3.AccessAllowed) {
    Write-Information "Blocked by policies: $($scenario3.BlockingPolicies.DisplayName -join ', ')" -InformationAction Continue
}
elseif ($scenario2.RequiredControls.Count -gt 0) {
    Write-Information "Required controls: $($scenario3.RequiredControls -join ', ')" -InformationAction Continue
}
if ($scenario3.SessionControls.Count -gt 0) {
    Write-Information "Session controls: $($scenario3.SessionControls -join ', ')" -InformationAction Continue
}

# Generate a comprehensive HTML report for all scenarios
Write-Information "`nGenerating comprehensive HTML report of all scenarios..." -InformationAction Continue
$allScenarios = @{
    Scenarios = @(
        @{
            Name    = "Guest from trusted network, no MFA"
            Results = $scenario1
        },
        @{
            Name    = "Guest from untrusted network, no MFA"
            Results = $scenario2
        },
        @{
            Name    = "Guest from untrusted network, with MFA"
            Results = $scenario3
        }
    )
}

# Custom HTML report with all scenarios
$html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Guest Access Simulation Report</title>
    <style>
        body { font-family: Segoe UI, Arial, sans-serif; margin: 20px; }
        h1, h2, h3 { color: #0078d4; }
        .container { max-width: 1200px; margin: 0 auto; }
        .scenario { margin-bottom: 30px; padding: 15px; border: 1px solid #edebe9; border-radius: 5px; }
        .scenario-name { font-weight: bold; font-size: 1.2em; margin-bottom: 10px; }
        .allowed { background-color: #dff6dd; color: #107c10; padding: 5px; border-radius: 3px; }
        .blocked { background-color: #fed9cc; color: #d83b01; padding: 5px; border-radius: 3px; }
        .details { margin-top: 10px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Guest Access Simulation Report</h1>
"@

foreach ($scenario in $allScenarios.Scenarios) {
    $html += @"
        <div class="scenario">
            <div class="scenario-name">Scenario: $($scenario.Name)</div>
            <div class="access-status">
                Access: <span class="$(if ($scenario.Results.AccessAllowed) { 'allowed' } else { 'blocked' })">$(if ($scenario.Results.AccessAllowed) { 'ALLOWED' } else { 'BLOCKED' })</span>
            </div>
"@

    if (-not $scenario.Results.AccessAllowed) {
        $html += @"
            <div class="details">
                <div>Blocked by policies:</div>
                <ul>
"@
        foreach ($policy in $scenario.Results.BlockingPolicies) {
            $html += "                    <li>$($policy.DisplayName) (ID: $($policy.PolicyId))</li>`n"
        }
        $html += "                </ul>`n            </div>`n"
    }

    if ($scenario.Results.RequiredControls -and $scenario.Results.RequiredControls.Count -gt 0) {
        $html += @"
            <div class="details">
                <div>Required controls:</div>
                <ul>
"@
        foreach ($control in $scenario.Results.RequiredControls) {
            $html += "                    <li>$control</li>`n"
        }
        $html += "                </ul>`n            </div>`n"
    }

    if ($scenario.Results.SessionControls -and $scenario.Results.SessionControls.Count -gt 0) {
        $html += @"
            <div class="details">
                <div>Session controls:</div>
                <ul>
"@
        foreach ($control in $scenario.Results.SessionControls) {
            $html += "                    <li>$control</li>`n"
        }
        $html += "                </ul>`n            </div>`n"
    }

    $html += "        </div>`n"
}

$html += @"
    </div>
</body>
</html>
"@

# Save the reports
$html | Out-File -FilePath $HtmlReportPath -Encoding utf8
$allScenarios | ConvertTo-Json -Depth 10 | Out-File -FilePath $JsonReportPath -Encoding utf8

Write-Information "`nReports generated:" -InformationAction Continue
Write-Information "HTML report: $HtmlReportPath" -InformationAction Continue
Write-Information "JSON report: $JsonReportPath" -InformationAction Continue

# Restore the original InformationPreference
$InformationPreference = $currentInformationPreference