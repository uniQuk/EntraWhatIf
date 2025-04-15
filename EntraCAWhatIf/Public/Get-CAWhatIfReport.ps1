function Get-CAWhatIfReport {
    <#
    .SYNOPSIS
        Generates a formatted report from Conditional Access WhatIf simulation results.
    
    .DESCRIPTION
        This function takes the results of an Invoke-CAWhatIf simulation and generates
        a formatted report in the specified format (Text, HTML, or JSON).
    
    .PARAMETER SimulationResults
        The results of an Invoke-CAWhatIf simulation.
    
    .PARAMETER Format
        The output format for the report (Text, HTML, or JSON).
    
    .PARAMETER OutputPath
        The file path where the report should be saved. If not specified, the report is returned as a string.
    
    .EXAMPLE
        $results = Invoke-CAWhatIf -UserId "john.doe@contoso.com" -AppId "Office365"
        Get-CAWhatIfReport -SimulationResults $results -Format "Text"
    
    .EXAMPLE
        $results = Invoke-CAWhatIf -UserId "john.doe@contoso.com" -AppId "Office365"
        Get-CAWhatIfReport -SimulationResults $results -Format "HTML" -OutputPath "C:\Reports\CA-WhatIf-Report.html"
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object]$SimulationResults,
        
        [Parameter()]
        [ValidateSet('Text', 'HTML', 'JSON')]
        [string]$Format = 'Text',
        
        [Parameter()]
        [string]$OutputPath
    )
    
    # Function to generate text report
    function Get-TextReport {
        param ($results)
        
        $report = "# Conditional Access WhatIf Simulation Report`n`n"
        
        # Access status summary
        $report += "## Access Status`n`n"
        if ($results.AccessAllowed) {
            $report += "- Access: ALLOWED`n"
        } else {
            $report += "- Access: BLOCKED`n"
            
            # List blocking policies
            $report += "- Blocking Policies:`n"
            foreach ($policy in $results.BlockingPolicies) {
                $report += "  - $($policy.DisplayName) (ID: $($policy.PolicyId))`n"
            }
        }
        
        # Required controls
        if ($results.RequiredControls -and $results.RequiredControls.Count -gt 0) {
            $report += "`n## Required Controls`n`n"
            foreach ($control in $results.RequiredControls) {
                $report += "- $control`n"
            }
        }
        
        # Session controls
        if ($results.SessionControls -and $results.SessionControls.Count -gt 0) {
            $report += "`n## Session Controls`n`n"
            foreach ($control in $results.SessionControls) {
                $report += "- $control`n"
            }
        }
        
        # Detailed policy evaluation results
        if ($results.DetailedResults) {
            $report += "`n## Detailed Policy Evaluation Results`n`n"
            foreach ($policy in $results.DetailedResults) {
                $report += "### $($policy.DisplayName) (ID: $($policy.PolicyId))`n`n"
                $report += "- State: $($policy.State)`n"
                $report += "- Applies to this scenario: $($policy.Applies)`n"
                
                if ($policy.Applies) {
                    $report += "- Access result: $($policy.AccessResult)`n"
                    
                    if ($policy.GrantControlsRequired -and $policy.GrantControlsRequired.Count -gt 0) {
                        $report += "- Grant controls required:`n"
                        foreach ($control in $policy.GrantControlsRequired) {
                            $report += "  - $control`n"
                        }
                    }
                    
                    if ($policy.SessionControlsApplied -and $policy.SessionControlsApplied.Count -gt 0) {
                        $report += "- Session controls applied:`n"
                        foreach ($control in $policy.SessionControlsApplied) {
                            $report += "  - $control`n"
                        }
                    }
                }
                
                $report += "- Evaluation details:`n"
                $report += "  - User in scope: $($policy.EvaluationDetails.UserInScope)`n"
                $report += "  - Resource in scope: $($policy.EvaluationDetails.ResourceInScope)`n"
                $report += "  - Network in scope: $($policy.EvaluationDetails.NetworkInScope)`n"
                $report += "  - Client app in scope: $($policy.EvaluationDetails.ClientAppInScope)`n"
                $report += "  - Device platform in scope: $($policy.EvaluationDetails.DevicePlatformInScope)`n"
                $report += "  - Device state in scope: $($policy.EvaluationDetails.DeviceStateInScope)`n"
                $report += "  - Risk levels in scope: $($policy.EvaluationDetails.RiskLevelsInScope)`n"
                
                $report += "`n"
            }
        }
        
        return $report
    }
    
    # Function to generate HTML report
    function Get-HtmlReport {
        param ($results)
        
        $css = @"
        <style>
            body { font-family: Segoe UI, Arial, sans-serif; margin: 20px; }
            h1, h2, h3 { color: #0078d4; }
            .container { max-width: 1200px; margin: 0 auto; }
            .summary { margin-bottom: 20px; padding: 10px; border-radius: 5px; }
            .allowed { background-color: #dff6dd; color: #107c10; }
            .blocked { background-color: #fed9cc; color: #d83b01; }
            .policy { margin-bottom: 15px; padding: 10px; border: 1px solid #edebe9; border-radius: 5px; }
            .policy-header { font-weight: bold; margin-bottom: 8px; }
            .policy-applies { font-weight: bold; }
            .applies-true { color: #107c10; }
            .applies-false { color: #797775; }
            .controls { margin-top: 10px; }
            .evaluation { margin-top: 10px; font-size: 0.9em; }
            .true { color: #107c10; }
            .false { color: #d83b01; }
            table { border-collapse: collapse; width: 100%; }
            th, td { text-align: left; padding: 8px; border-bottom: 1px solid #edebe9; }
            th { background-color: #f3f2f1; }
        </style>
"@
        
        $html = @"
        <!DOCTYPE html>
        <html>
        <head>
            <title>Conditional Access WhatIf Simulation Report</title>
            $css
        </head>
        <body>
            <div class="container">
                <h1>Conditional Access WhatIf Simulation Report</h1>
                
                <h2>Access Status</h2>
                <div class="summary $(if ($results.AccessAllowed) { 'allowed' } else { 'blocked' })">
                    <p><strong>Access: $(if ($results.AccessAllowed) { 'ALLOWED' } else { 'BLOCKED' })</strong></p>
                    $(if (-not $results.AccessAllowed) {
                        "<p><strong>Blocking Policies:</strong></p><ul>"
                        foreach ($policy in $results.BlockingPolicies) {
                            "<li>$($policy.DisplayName) (ID: $($policy.PolicyId))</li>"
                        }
                        "</ul>"
                    })
                </div>
"@
        
        # Required controls
        if ($results.RequiredControls -and $results.RequiredControls.Count -gt 0) {
            $html += @"
                <h2>Required Controls</h2>
                <ul>
"@
            foreach ($control in $results.RequiredControls) {
                $html += "                    <li>$control</li>`n"
            }
            $html += "                </ul>`n"
        }
        
        # Session controls
        if ($results.SessionControls -and $results.SessionControls.Count -gt 0) {
            $html += @"
                <h2>Session Controls</h2>
                <ul>
"@
            foreach ($control in $results.SessionControls) {
                $html += "                    <li>$control</li>`n"
            }
            $html += "                </ul>`n"
        }
        
        # Detailed policy evaluation results
        if ($results.DetailedResults) {
            $html += @"
                <h2>Detailed Policy Evaluation Results</h2>
"@
            foreach ($policy in $results.DetailedResults) {
                $html += @"
                <div class="policy">
                    <div class="policy-header">$($policy.DisplayName) (ID: $($policy.PolicyId))</div>
                    <div>State: $($policy.State)</div>
                    <div class="policy-applies applies-$($policy.Applies.ToString().ToLower())">Applies to this scenario: $($policy.Applies)</div>
"@
                
                if ($policy.Applies) {
                    $html += @"
                    <div>Access result: $($policy.AccessResult)</div>
"@
                    
                    if ($policy.GrantControlsRequired -and $policy.GrantControlsRequired.Count -gt 0) {
                        $html += @"
                    <div class="controls">
                        <div>Grant controls required:</div>
                        <ul>
"@
                        foreach ($control in $policy.GrantControlsRequired) {
                            $html += "                            <li>$control</li>`n"
                        }
                        $html += "                        </ul>`n                    </div>`n"
                    }
                    
                    if ($policy.SessionControlsApplied -and $policy.SessionControlsApplied.Count -gt 0) {
                        $html += @"
                    <div class="controls">
                        <div>Session controls applied:</div>
                        <ul>
"@
                        foreach ($control in $policy.SessionControlsApplied) {
                            $html += "                            <li>$control</li>`n"
                        }
                        $html += "                        </ul>`n                    </div>`n"
                    }
                }
                
                $html += @"
                    <div class="evaluation">
                        <div>Evaluation details:</div>
                        <table>
                            <tr>
                                <th>Condition</th>
                                <th>In Scope</th>
                            </tr>
                            <tr>
                                <td>User</td>
                                <td class="$($policy.EvaluationDetails.UserInScope.ToString().ToLower())">$($policy.EvaluationDetails.UserInScope)</td>
                            </tr>
                            <tr>
                                <td>Resource</td>
                                <td class="$($policy.EvaluationDetails.ResourceInScope.ToString().ToLower())">$($policy.EvaluationDetails.ResourceInScope)</td>
                            </tr>
                            <tr>
                                <td>Network</td>
                                <td class="$($policy.EvaluationDetails.NetworkInScope.ToString().ToLower())">$($policy.EvaluationDetails.NetworkInScope)</td>
                            </tr>
                            <tr>
                                <td>Client app</td>
                                <td class="$($policy.EvaluationDetails.ClientAppInScope.ToString().ToLower())">$($policy.EvaluationDetails.ClientAppInScope)</td>
                            </tr>
                            <tr>
                                <td>Device platform</td>
                                <td class="$($policy.EvaluationDetails.DevicePlatformInScope.ToString().ToLower())">$($policy.EvaluationDetails.DevicePlatformInScope)</td>
                            </tr>
                            <tr>
                                <td>Device state</td>
                                <td class="$($policy.EvaluationDetails.DeviceStateInScope.ToString().ToLower())">$($policy.EvaluationDetails.DeviceStateInScope)</td>
                            </tr>
                            <tr>
                                <td>Risk levels</td>
                                <td class="$($policy.EvaluationDetails.RiskLevelsInScope.ToString().ToLower())">$($policy.EvaluationDetails.RiskLevelsInScope)</td>
                            </tr>
                        </table>
                    </div>
                </div>
"@
            }
        }
        
        $html += @"
            </div>
        </body>
        </html>
"@
        
        return $html
    }
    
    # Generate report based on format
    $report = $null
    switch ($Format) {
        'Text' {
            $report = Get-TextReport -results $SimulationResults
        }
        'HTML' {
            $report = Get-HtmlReport -results $SimulationResults
        }
        'JSON' {
            $report = $SimulationResults | ConvertTo-Json -Depth 10
        }
    }
    
    # Save report to file if OutputPath is specified
    if ($OutputPath) {
        $report | Out-File -FilePath $OutputPath -Encoding utf8
        Write-Output "Report saved to $OutputPath"
    } else {
        return $report
    }
} 