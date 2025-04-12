function Resolve-CAGrantControl {
    <#
    .SYNOPSIS
        Evaluates the grant controls for a Conditional Access policy that applies to a sign-in scenario.

    .DESCRIPTION
        This function evaluates the grant controls of a Conditional Access policy to determine
        if access is blocked, granted, or conditionally granted based on the policy's requirements
        and the provided user and device contexts.

    .PARAMETER Policy
        The Conditional Access policy to evaluate.

    .PARAMETER UserContext
        The user context for the sign-in scenario.

    .PARAMETER DeviceContext
        The device context for the sign-in scenario.

    .EXAMPLE
        Resolve-CAGrantControl -Policy $policy -UserContext $UserContext -DeviceContext $DeviceContext
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param (
        [Parameter(Mandatory = $true)]
        [object]$Policy,

        [Parameter(Mandatory = $true)]
        [object]$UserContext,

        [Parameter(Mandatory = $true)]
        [object]$DeviceContext
    )

    # If no grant controls specified, access is granted
    if (-not $Policy.GrantControls -or -not $Policy.GrantControls.BuiltInControls) {
        return @{
            AccessResult          = "Granted"
            GrantControlsRequired = @()
        }
    }

    $controls = $Policy.GrantControls.BuiltInControls
    $operator = $Policy.GrantControls._Operator  # AND or OR

    # If block is specified, access is blocked regardless of other controls
    if ($controls -contains "block") {
        return @{
            AccessResult          = "Blocked"
            GrantControlsRequired = @()
        }
    }

    # Create a hashtable to track the status of each control
    $controlStatus = @{}
    $requiredControls = @()

    # Check each control
    foreach ($control in $controls) {
        switch ($control) {
            "mfa" {
                $controlStatus[$control] = $UserContext.MfaAuthenticated
                if (-not $UserContext.MfaAuthenticated) {
                    $requiredControls += "Multi-factor authentication"
                }
            }
            "compliantDevice" {
                $controlStatus[$control] = $DeviceContext.Compliance
                if (-not $DeviceContext.Compliance) {
                    $requiredControls += "Compliant device"
                }
            }
            "domainJoinedDevice" {
                $controlStatus[$control] = ($DeviceContext.JoinType -eq "Hybrid")
                if ($DeviceContext.JoinType -ne "Hybrid") {
                    $requiredControls += "Hybrid Azure AD joined device"
                }
            }
            "approvedApplication" {
                $controlStatus[$control] = $DeviceContext.ApprovedApplication
                if (-not $DeviceContext.ApprovedApplication) {
                    $requiredControls += "Approved client app"
                }
            }
            "compliantApplication" {
                $controlStatus[$control] = $DeviceContext.AppProtectionPolicy
                if (-not $DeviceContext.AppProtectionPolicy) {
                    $requiredControls += "App protection policy"
                }
            }
            "passwordChange" {
                # For simulation, always require password change if specified
                $controlStatus[$control] = $false
                $requiredControls += "Password change"
            }
            "terms" {
                # For simulation, always require terms if specified
                $controlStatus[$control] = $false
                $requiredControls += "Terms of use"
            }
            default {
                # Unsupported control, assume not satisfied
                $controlStatus[$control] = $false
                $requiredControls += $control
            }
        }
    }

    # Determine access result based on operator
    if ($operator -eq "AND") {
        # All controls must be satisfied
        $allSatisfied = $true
        foreach ($control in $controls) {
            if (-not $controlStatus[$control]) {
                $allSatisfied = $false
                break
            }
        }

        if ($allSatisfied) {
            return @{
                AccessResult          = "Granted"
                GrantControlsRequired = @()
            }
        }
        else {
            return @{
                AccessResult          = "ConditionallyGranted"
                GrantControlsRequired = $requiredControls
            }
        }
    }
    elseif ($operator -eq "OR") {
        # At least one control must be satisfied
        $anySatisfied = $false
        foreach ($control in $controls) {
            if ($controlStatus[$control]) {
                $anySatisfied = $true
                break
            }
        }

        if ($anySatisfied) {
            return @{
                AccessResult          = "Granted"
                GrantControlsRequired = @()
            }
        }
        else {
            return @{
                AccessResult          = "ConditionallyGranted"
                GrantControlsRequired = $requiredControls
            }
        }
    }
    else {
        # Default to AND behavior
        return @{
            AccessResult          = "ConditionallyGranted"
            GrantControlsRequired = $requiredControls
        }
    }
}