function Resolve-CASessionControl {
    <#
    .SYNOPSIS
        Evaluates the session controls for a Conditional Access policy.

    .DESCRIPTION
        This function evaluates the session controls of a Conditional Access policy and returns
        the applicable session controls.

    .PARAMETER Policy
        The Conditional Access policy to evaluate.

    .EXAMPLE
        Resolve-CASessionControl -Policy $policy
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param (
        [Parameter(Mandatory = $true)]
        [object]$Policy
    )

    # If no session controls specified, return empty array
    if (-not $Policy.SessionControls) {
        return @{
            SessionControlsApplied = @()
        }
    }

    $sessionControls = @()

    # Check app enforced restrictions
    if ($Policy.SessionControls.ApplicationEnforced -and $Policy.SessionControls.ApplicationEnforced.IsEnabled) {
        $sessionControls += "App enforced restrictions"
    }

    # Check Cloud App Security
    if ($Policy.SessionControls.CloudAppSecurity -and $Policy.SessionControls.CloudAppSecurity.IsEnabled) {
        $mode = $Policy.SessionControls.CloudAppSecurity.CloudAppSecurityType
        $sessionControls += "Microsoft Defender for Cloud Apps: $mode"
    }

    # Check sign-in frequency
    if ($Policy.SessionControls.SignInFrequency -and $Policy.SessionControls.SignInFrequency.IsEnabled) {
        $value = $Policy.SessionControls.SignInFrequency.Value
        $type = $Policy.SessionControls.SignInFrequency.Type
        $sessionControls += "Sign-in frequency: $value $type"
    }

    # Check persistent browser
    if ($Policy.SessionControls.PersistentBrowser -and $Policy.SessionControls.PersistentBrowser.IsEnabled) {
        $mode = $Policy.SessionControls.PersistentBrowser.Mode
        $sessionControls += "Persistent browser session: $mode"
    }

    # Check continuous access evaluation
    if ($Policy.SessionControls.ContinuousAccessEvaluation -and $Policy.SessionControls.ContinuousAccessEvaluation.Mode) {
        $mode = $Policy.SessionControls.ContinuousAccessEvaluation.Mode
        $sessionControls += "Continuous access evaluation: $mode"
    }

    # Check resilience defaults
    if ($Policy.SessionControls.DisableResilienceDefaults) {
        $sessionControls += "Resilience defaults disabled"
    }

    return @{
        SessionControlsApplied = $sessionControls
    }
}