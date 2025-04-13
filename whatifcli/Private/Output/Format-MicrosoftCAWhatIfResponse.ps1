function Format-MicrosoftCAWhatIfResponse {
    <#
    .SYNOPSIS
        Formats Conditional Access WhatIf evaluation results to match Microsoft's API response format.

    .DESCRIPTION
        This function takes the internal evaluation results from the WhatIf tool and formats them
        to match the structure of responses from Microsoft's official Conditional Access evaluation API.
        This ensures consistency between our tool and Microsoft's implementation.

    .PARAMETER Results
        The raw evaluation results to format.

    .PARAMETER FormatType
        The type of format to return (Json, Object).

    .EXAMPLE
        Format-MicrosoftCAWhatIfResponse -Results $evaluationResults -FormatType Object

    .EXAMPLE
        Format-MicrosoftCAWhatIfResponse -Results $evaluationResults -FormatType Json
    #>
    [CmdletBinding()]
    [OutputType([System.Object], [System.String])]
    param (
        [Parameter(Mandatory = $true)]
        [object[]]$Results,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Json', 'Object')]
        [string]$FormatType = 'Object'
    )

    # Convert our internal result format to Microsoft's API format
    $formattedResponse = @{
        odatacontext = "https://graph.microsoft.com/beta/`$metadata#conditionalAccess/policies/evaluate"
        value        = @()
    }

    foreach ($result in $Results) {
        # Convert AccessResult to Microsoft's format
        $accessResult = switch ($result.AccessResult) {
            "Blocked" { "blocked" }
            "Granted" { "allowed" }
            "ConditionallyGranted" { "conditionNotSatisfied" }
            default { "notApplicable" }
        }

        # Format the result reasons in Microsoft standard format
        $resultReasons = @()

        # Add reason if policy doesn't apply
        if (-not $result.Applies) {
            # Map our internal reasons to Microsoft reason codes
            if (-not $result.EvaluationDetails.UserInScope) {
                $resultReasons += @{
                    code    = "PolicyNotApplicable"
                    detail  = "User not in scope"
                    service = "ConditionalAccess"
                }
            }
            elseif (-not $result.EvaluationDetails.ResourceInScope) {
                $resultReasons += @{
                    code    = "PolicyNotApplicable"
                    detail  = "Resource not in scope"
                    service = "ConditionalAccess"
                }
            }
            elseif (-not $result.EvaluationDetails.ClientAppInScope) {
                $resultReasons += @{
                    code    = "PolicyNotApplicable"
                    detail  = "Client app not in scope"
                    service = "ConditionalAccess"
                }
            }
            elseif (-not $result.EvaluationDetails.DevicePlatformInScope) {
                $resultReasons += @{
                    code    = "PolicyNotApplicable"
                    detail  = "Device platform not in scope"
                    service = "ConditionalAccess"
                }
            }
            elseif (-not $result.EvaluationDetails.DeviceStateInScope) {
                $resultReasons += @{
                    code    = "PolicyNotApplicable"
                    detail  = "Device state not in scope"
                    service = "ConditionalAccess"
                }
            }
            elseif (-not $result.EvaluationDetails.NetworkInScope) {
                $resultReasons += @{
                    code    = "PolicyNotApplicable"
                    detail  = "Network not in scope"
                    service = "ConditionalAccess"
                }
            }
            elseif (-not $result.EvaluationDetails.UserRiskLevelInScope) {
                $resultReasons += @{
                    code    = "PolicyNotApplicable"
                    detail  = "User risk level not in scope"
                    service = "ConditionalAccess"
                }
            }
            elseif (-not $result.EvaluationDetails.SignInRiskLevelInScope) {
                $resultReasons += @{
                    code    = "PolicyNotApplicable"
                    detail  = "Sign-in risk level not in scope"
                    service = "ConditionalAccess"
                }
            }
            else {
                $resultReasons += @{
                    code    = "PolicyNotApplicable"
                    detail  = "Policy conditions not met"
                    service = "ConditionalAccess"
                }
            }
        }
        # Add reason if conditional grant controls not satisfied
        elseif ($result.AccessResult -eq "ConditionallyGranted") {
            $resultReasons += @{
                code    = "GrantControlNotSatisfied"
                detail  = "Required controls: $($result.GrantControlsRequired -join ', ')"
                service = "ConditionalAccess"
            }
        }

        # Format the final policy result in Microsoft's format
        $policyResult = @{
            id          = $result.PolicyId
            displayName = $result.DisplayName
            state       = $result.State
            result      = @{
                reference                  = "conditionalAccess"
                accessDecision             = $accessResult
                appliedConditionSets       = @(
                    @{
                        reference  = "conditionalAccess"
                        result     = if ($result.Applies) { "satisfied" } else { "notSatisfied" }
                        reasons    = $resultReasons
                        conditions = @{
                            users            = @{
                                inScope    = $result.EvaluationDetails.UserInScope
                                notInScope = ($result.EvaluationDetails.UserExcluded -eq $true)
                            }
                            applications     = @{
                                inScope    = $result.EvaluationDetails.ResourceInScope
                                notInScope = ($result.EvaluationDetails.ResourceExcluded -eq $true)
                            }
                            clientApps       = @{
                                inScope = $result.EvaluationDetails.ClientAppInScope
                            }
                            devicePlatforms  = @{
                                inScope = $result.EvaluationDetails.DevicePlatformInScope
                            }
                            locations        = @{
                                inScope = $result.EvaluationDetails.NetworkInScope
                            }
                            deviceState      = @{
                                inScope = $result.EvaluationDetails.DeviceStateInScope
                            }
                            signInRiskLevels = @{
                                inScope = $result.EvaluationDetails.SignInRiskLevelInScope
                            }
                            userRiskLevels   = @{
                                inScope = $result.EvaluationDetails.UserRiskLevelInScope
                            }
                        }
                    }
                )
                authenticationRequirements = if ($result.AccessResult -eq "ConditionallyGranted") {
                    @{
                        mfa             = if ($result.GrantControlsRequired -contains "mfa") { $true } else { $false }
                        mfaRegistration = if ($result.GrantControlsRequired -contains "mfaRegistrationRequirement") { $true } else { $false }
                    }
                }
                else { @{} }
                sessionRequirements        = if ($result.SessionControlsApplied.Count -gt 0) {
                    @{
                        signInFrequency            = if ($result.SessionControlsApplied -contains "signInFrequency") { $true } else { $false }
                        persistentBrowser          = if ($result.SessionControlsApplied -contains "persistentBrowser") { $true } else { $false }
                        appEnforcedRestrictions    = if ($result.SessionControlsApplied -contains "applicationEnforcedRestrictions") { $true } else { $false }
                        cloudAppSecurity           = if ($result.SessionControlsApplied -contains "cloudAppSecurity") { $true } else { $false }
                        continuousAccessEvaluation = if ($result.SessionControlsApplied -contains "continuousAccessEvaluation") { $true } else { $false }
                    }
                }
                else { @{} }
            }
        }

        $formattedResponse.value += $policyResult
    }

    # Return in the requested format
    if ($FormatType -eq 'Json') {
        return $formattedResponse | ConvertTo-Json -Depth 10
    }
    else {
        return $formattedResponse
    }
}

Export-ModuleMember -Function Format-MicrosoftCAWhatIfResponse