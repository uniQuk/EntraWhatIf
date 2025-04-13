function Write-DiagnosticOutput {
    <#
    .SYNOPSIS
        Writes detailed diagnostic information about Conditional Access policy evaluation.

    .DESCRIPTION
        This function provides rich, color-coded diagnostic information about the evaluation
        of Conditional Access policies. It can be used to troubleshoot policy evaluation
        results and understand why policies are or are not applying to a sign-in scenario.

    .PARAMETER PolicyId
        The ID of the policy being evaluated.

    .PARAMETER PolicyName
        The display name of the policy being evaluated.

    .PARAMETER Stage
        The evaluation stage (e.g., UserExclusion, UserInclusion, NetworkCheck).

    .PARAMETER Result
        The result of the evaluation (true/false).

    .PARAMETER Message
        Additional details about the evaluation.

    .PARAMETER Details
        An object containing detailed information about the evaluation.

    .PARAMETER Level
        The level of the diagnostic message (Info, Warning, Error, Success).

    .PARAMETER ExportPath
        When specified, diagnostics are also written to this file path.

    .PARAMETER Source
        The source component generating the diagnostic message. Alternative to PolicyId for utility functions.

    .EXAMPLE
        Write-DiagnosticOutput -PolicyId "123" -PolicyName "MFA Policy" -Stage "UserExclusion" -Result $false -Message "User not excluded" -Level "Info"

    .EXAMPLE
        Write-DiagnosticOutput -Source "Get-CAPolicy" -Message "Retrieving all policies from Microsoft Graph" -Level "Info"
    #>
    [CmdletBinding(DefaultParameterSetName = 'Policy')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Policy')]
        [string]$PolicyId,

        [Parameter(Mandatory = $false, ParameterSetName = 'Policy')]
        [string]$PolicyName,

        [Parameter(Mandatory = $true, ParameterSetName = 'Policy')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Utility')]
        [string]$Stage,

        [Parameter(Mandatory = $true, ParameterSetName = 'Policy')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Utility')]
        [bool]$Result,

        [Parameter(Mandatory = $false, ParameterSetName = 'Policy')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Utility')]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [object]$Details,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Info', 'Warning', 'Error', 'Success')]
        [string]$Level = 'Info',

        [Parameter(Mandatory = $false)]
        [string]$ExportPath,

        [Parameter(Mandatory = $true, ParameterSetName = 'Utility')]
        [string]$Source
    )

    # Only proceed if diagnostic output is enabled via Verbose stream
    if (-not $VerbosePreference -or $VerbosePreference -eq 'SilentlyContinue') {
        return
    }

    # Set colors based on level and result
    $headerColor = switch ($Level) {
        'Info' { 'Cyan' }
        'Warning' { 'Yellow' }
        'Error' { 'Red' }
        'Success' { 'Green' }
        default { 'White' }
    }

    $resultColor = if ($Result) { 'Green' } else { 'Yellow' }
    $detailColor = 'Gray'

    # Format the output
    $outputLines = @()

    if ($PSCmdlet.ParameterSetName -eq 'Policy') {
        # Build the header with policy info
        $policyInfo = if ($PolicyName) { "[$PolicyId] $PolicyName" } else { "[$PolicyId]" }
        $outputLines += "Policy $policyInfo - Stage: $Stage"
        $outputLines += "Result: $(if ($Result) { "PASS" } else { "FAIL" })"

        if ($Message) {
            $outputLines += "Message: $Message"
        }
    }
    else {
        # Utility function diagnostics
        $outputLines += "[$Source] $Message"
    }

    # Add detailed output if provided
    if ($Details) {
        $outputLines += "Details:"

        # Serialize details object for display (extract key properties)
        if ($Details -is [System.Collections.IDictionary] -or $Details -is [PSCustomObject]) {
            foreach ($key in $Details.Keys) {
                $value = $Details[$key]
                $outputLines += "  ${key}: ${value}"
            }
        }
        elseif ($Details -is [System.Collections.IEnumerable] -and $Details -isnot [string]) {
            $i = 0
            foreach ($item in $Details) {
                $outputLines += "  [${i}] ${item}"
                $i++
            }
        }
        else {
            $outputLines += "  $Details"
        }
    }

    # Output to console with colors
    Write-Verbose "--- DIAGNOSTIC: $Level ---" -Verbose

    foreach ($line in $outputLines) {
        Write-Verbose $line -Verbose
    }

    Write-Verbose "-----------------------" -Verbose

    # Export to file if path provided
    if ($ExportPath) {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

        if ($PSCmdlet.ParameterSetName -eq 'Policy') {
            $logLine = "[$timestamp] $Level - Policy $policyInfo - Stage: $Stage - Result: $(if ($Result) { "PASS" } else { "FAIL" })"
            if ($Message) {
                $logLine += " - Message: $Message"
            }
        }
        else {
            $logLine = "[$timestamp] $Level - [$Source] $Message"
        }

        if ($Details) {
            $detailsJson = $Details | ConvertTo-Json -Compress
            $logLine += " - Details: $detailsJson"
        }

        try {
            Add-Content -Path $ExportPath -Value $logLine -ErrorAction Stop
        }
        catch {
            Write-Warning "Failed to write diagnostic output to file: $_"
        }
    }
}

function Export-DiagnosticReport {
    <#
    .SYNOPSIS
        Exports a comprehensive diagnostic report for Conditional Access policy evaluation.

    .DESCRIPTION
        This function exports detailed information about the evaluation of Conditional Access policies
        to a file, including all evaluation details, conditions, and reasons for the result.

    .PARAMETER Results
        The detailed results from Invoke-CAWhatIf.

    .PARAMETER Path
        The file path to export the report to.

    .PARAMETER Format
        The format of the export (JSON, CSV, XML).

    .EXAMPLE
        Export-DiagnosticReport -Results $results -Path "C:\Temp\ca-diagnostic-report.json" -Format "JSON"
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [object]$Results,

        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $false)]
        [ValidateSet('JSON', 'CSV', 'XML')]
        [string]$Format = 'JSON'
    )

    process {
        try {
            # Create a report object with metadata
            $report = @{
                Metadata        = @{
                    GeneratedAt  = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    GeneratedBy  = $env:USERNAME
                    ComputerName = $env:COMPUTERNAME
                }
                Summary         = @{
                    TotalPolicies       = $Results.DetailedResults.Count
                    ApplicablePolicies  = ($Results.DetailedResults | Where-Object { $_.Applies -eq $true }).Count
                    BlockingPolicies    = ($Results.DetailedResults | Where-Object { $_.AccessResult -eq "Blocked" }).Count
                    ConditionalPolicies = ($Results.DetailedResults | Where-Object { $_.AccessResult -eq "ConditionallyGranted" }).Count
                    GrantingPolicies    = ($Results.DetailedResults | Where-Object { $_.AccessResult -eq "Granted" }).Count
                    AccessAllowed       = $Results.AccessAllowed
                    RequiredControls    = $Results.RequiredControls
                    SessionControls     = $Results.SessionControls
                }
                DetailedResults = $Results.DetailedResults | ForEach-Object {
                    # Enrich each policy result with additional diagnostic details
                    $evaluationReasons = @()

                    # Add reasons for the policy not applying
                    if (-not $_.Applies) {
                        if (-not $_.EvaluationDetails.UserInScope) {
                            $evaluationReasons += "User not in scope: $($_.EvaluationDetails.Reasons.User)"
                        }
                        if (-not $_.EvaluationDetails.ResourceInScope) {
                            $evaluationReasons += "Resource not in scope: $($_.EvaluationDetails.Reasons.Resource)"
                        }
                        if (-not $_.EvaluationDetails.NetworkInScope) {
                            $evaluationReasons += "Network not in scope: $($_.EvaluationDetails.Reasons.Network)"
                        }
                        if (-not $_.EvaluationDetails.ClientAppInScope) {
                            $evaluationReasons += "Client app not in scope: $($_.EvaluationDetails.Reasons.ClientApp)"
                        }
                        if (-not $_.EvaluationDetails.DevicePlatformInScope) {
                            $evaluationReasons += "Device platform not in scope: $($_.EvaluationDetails.Reasons.DevicePlatform)"
                        }
                        if (-not $_.EvaluationDetails.DeviceStateInScope) {
                            $evaluationReasons += "Device state not in scope: $($_.EvaluationDetails.Reasons.DeviceState)"
                        }
                        if (-not $_.EvaluationDetails.UserRiskLevelInScope) {
                            $evaluationReasons += "User risk level not in scope: $($_.EvaluationDetails.Reasons.UserRiskLevel)"
                        }
                        if (-not $_.EvaluationDetails.SignInRiskLevelInScope) {
                            $evaluationReasons += "Sign-in risk level not in scope: $($_.EvaluationDetails.Reasons.SignInRiskLevel)"
                        }
                    }
                    else {
                        # Add access result and controls
                        $evaluationReasons += "Access result: $($_.AccessResult)"
                        if ($_.GrantControlsRequired.Count -gt 0) {
                            $evaluationReasons += "Required controls: $($_.GrantControlsRequired -join ', ')"
                        }
                        if ($_.SessionControlsApplied.Count -gt 0) {
                            $evaluationReasons += "Session controls: $($_.SessionControlsApplied -join ', ')"
                        }
                    }

                    # Return enriched object
                    return @{
                        PolicyId          = $_.PolicyId
                        DisplayName       = $_.DisplayName
                        State             = $_.State
                        Applies           = $_.Applies
                        AccessResult      = $_.AccessResult
                        EvaluationDetails = $_.EvaluationDetails
                        DiagnosticReasons = $evaluationReasons
                    }
                }
            }

            # Export in the desired format
            switch ($Format) {
                'JSON' {
                    $report | ConvertTo-Json -Depth 10 | Out-File -FilePath $Path -Encoding utf8
                }
                'CSV' {
                    # Convert to a flattened structure for CSV
                    $csvRecords = $report.DetailedResults | ForEach-Object {
                        $flatRecord = @{
                            PolicyId               = $_.PolicyId
                            DisplayName            = $_.DisplayName
                            State                  = $_.State
                            Applies                = $_.Applies
                            AccessResult           = $_.AccessResult
                            UserInScope            = $_.EvaluationDetails.UserInScope
                            ResourceInScope        = $_.EvaluationDetails.ResourceInScope
                            NetworkInScope         = $_.EvaluationDetails.NetworkInScope
                            ClientAppInScope       = $_.EvaluationDetails.ClientAppInScope
                            DevicePlatformInScope  = $_.EvaluationDetails.DevicePlatformInScope
                            DeviceStateInScope     = $_.EvaluationDetails.DeviceStateInScope
                            UserRiskLevelInScope   = $_.EvaluationDetails.UserRiskLevelInScope
                            SignInRiskLevelInScope = $_.EvaluationDetails.SignInRiskLevelInScope
                            DiagnosticReasons      = ($_.DiagnosticReasons -join "; ")
                        }
                        return [PSCustomObject]$flatRecord
                    }
                    $csvRecords | Export-Csv -Path $Path -NoTypeInformation -Encoding utf8
                }
                'XML' {
                    $report | Export-Clixml -Path $Path
                }
            }

            Write-Verbose "Diagnostic report exported to $Path"
            return $Path
        }
        catch {
            Write-Error "Failed to export diagnostic report: $_"
        }
    }
}

Export-ModuleMember -Function Write-DiagnosticOutput, Export-DiagnosticReport