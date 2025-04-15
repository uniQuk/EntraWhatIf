# Add this helper function before the main Invoke-ConditionalAccessWhatIf function
function Test-SimpleMFAPolicy {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Policy
    )

    # Check if this is a simple "MFA for all" policy with null conditions meaning "all"
    try {
        # Check if it requires MFA
        $requiresMFA = $false
        if ($Policy.grantControls -and
            $Policy.grantControls.builtInControls -and
            $Policy.grantControls.builtInControls -contains "mfa") {
            $requiresMFA = $true
        }

        # Check if it applies to all users
        $allUsers = $false
        if ($Policy.conditions.users.includeUsers -and
            $Policy.conditions.users.includeUsers -contains "All") {
            $allUsers = $true
        }

        # Check if it applies to all apps
        $allApps = $false
        if ($Policy.conditions.applications.includeApplications -and
            $Policy.conditions.applications.includeApplications -contains "All") {
            $allApps = $true
        }

        # Check if the other conditions are null or all
        $allClientApps = $false
        if ($null -eq $Policy.conditions.clientAppTypes -or
            $Policy.conditions.clientAppTypes.Count -eq 0 -or
            $Policy.conditions.clientAppTypes -contains "all" -or
            $Policy.conditions.clientAppTypes -contains "All") {
            $allClientApps = $true
        }

        # Check devices, platforms, locations are null
        $nullConditions = $null -eq $Policy.conditions.devices -and
        $null -eq $Policy.conditions.platforms -and
        $null -eq $Policy.conditions.locations

        # If it has all the characteristics of a simple MFA policy
        return $requiresMFA -and $allUsers -and $allApps -and $allClientApps -and $nullConditions
    }
    catch {
        Write-Verbose "Error in Test-SimpleMFAPolicy: $_"
        return $false
    }
}

# Modify the main function to use our Test-SimpleMFAPolicy check before doing a full evaluation
function Invoke-ConditionalAccessWhatIf {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Policy,
        [Parameter(Mandatory = $true)]
        [object]$UserContext,
        [Parameter(Mandatory = $true)]
        [object]$ResourceContext,
        [Parameter(Mandatory = $true)]
        [object]$DeviceContext,
        [Parameter(Mandatory = $true)]
        [object]$RiskContext,
        [Parameter(Mandatory = $true)]
        [object]$LocationContext
    )

    # Evaluate if the policy applies
    Write-Verbose "Evaluating policy: $($Policy.DisplayName) (ID: $($Policy.Id))"

    # Add a quick check for simple MFA policies (optimization for common case)
    $isSimpleMFAPolicy = Test-SimpleMFAPolicy -Policy $Policy
    if ($isSimpleMFAPolicy) {
        Write-Verbose "This is a simple MFA for all policy with no restrictions - bypassing conditional evaluation"
        $policyResult = @{
            Applies           = $true
            EvaluationDetails = $null
            Reason            = "Simple MFA for all policy with no restrictions"
        }
    }
    else {
        # Do the full evaluation
        $policyResult = Resolve-CACondition -Policy $Policy -UserContext $UserContext -ResourceContext $ResourceContext -DeviceContext $DeviceContext -RiskContext $RiskContext -LocationContext $LocationContext
    }

    return $policyResult
}