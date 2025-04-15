function Test-UserActionInScope {
    <#
    .SYNOPSIS
        Tests if a user action is in scope for a Conditional Access policy.

    .DESCRIPTION
        This function evaluates if a user action is in scope for a Conditional Access policy.
        User actions represent specific activities like registering security info or
        performing privileged actions rather than accessing applications.

    .PARAMETER Policy
        The Conditional Access policy to evaluate.

    .PARAMETER UserActionContext
        The user action context for evaluation, containing the UserAction value.

    .EXAMPLE
        Test-UserActionInScope -Policy $policy -UserActionContext $UserActionContext
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param (
        [Parameter(Mandatory = $true)]
        [object]$Policy,

        [Parameter(Mandatory = $true)]
        [object]$UserActionContext
    )

    $result = @{
        InScope = $false
        Reason  = $null
    }

    # First check if the policy has any user action conditions
    if (-not $Policy.Conditions.Applications -or
        -not $Policy.Conditions.Applications.IncludeUserActions -or
        $Policy.Conditions.Applications.IncludeUserActions.Count -eq 0) {

        $result.Reason = "Policy does not include any user actions"
        return $result
    }

    # Extract user action from context
    $userAction = $UserActionContext.UserAction

    # Check if this user action is excluded
    if ($Policy.Conditions.Applications.ExcludeUserActions -and
        $Policy.Conditions.Applications.ExcludeUserActions -contains $userAction) {

        $result.Reason = "User action '$userAction' is explicitly excluded"
        return $result
    }

    # Check if this user action is included
    if ($Policy.Conditions.Applications.IncludeUserActions -contains $userAction) {
        $result.InScope = $true
        $result.Reason = "User action '$userAction' is explicitly included"
        return $result
    }

    # If we get here, the action is not explicitly included
    $result.Reason = "User action '$userAction' is not in the included actions list"
    return $result
}

function Get-SupportedUserActions {
    <#
    .SYNOPSIS
        Gets the list of supported user actions for Conditional Access policies.

    .DESCRIPTION
        This function returns the list of supported user actions that can be
        evaluated in Conditional Access policies, along with their descriptions.

    .EXAMPLE
        Get-SupportedUserActions
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param ()

    return @{
        # Authentication-related actions
        "urn:user:registersecurityinfo"                                = "Register security information"
        "urn:user:registerdevice"                                      = "Register a device"
        "urn:user:registeroath"                                        = "Register OATH tokens"
        "urn:user:updatepassword"                                      = "Change password"
        "urn:user:selfservicepasswordreset"                            = "Self-service password reset"
        "urn:user:checkcloudpwdpolicy"                                 = "Check password requirements"
        "urn:user:selfservicewritebackpwdreset"                        = "Self-service password reset writeback"
        "urn:user:selfregisterlicenseddevice"                          = "Register licensed device"

        # Admin-related actions
        "urn:microsoft:pim:elevation"                                  = "Privilege Identity Management elevation"
        "urn:microsoft:pim:submission"                                 = "PIM request submission"
        "urn:microsoft:pim:approval"                                   = "PIM request approval"
        "urn:user:adminregisterdevice"                                 = "Register devices (admin)"
        "urn:microsoft:azure:iam:rolemanagement:submission"            = "Role management submission"
        "urn:microsoft:azure:iam:rolemanagement:approval"              = "Role management approval"

        # Other actions
        "urn:user:attributeverification"                               = "User attribute verification"
        "urn:microsoft:userPreferredAuthenticationMethod:modification" = "Modify authentication methods"
    }
}

function Validate-UserAction {
    <#
    .SYNOPSIS
        Validates if a user action is supported by Conditional Access.

    .DESCRIPTION
        This function checks if a given user action is in the list of
        supported user actions for Conditional Access policies.

    .PARAMETER UserAction
        The user action to validate.

    .EXAMPLE
        Validate-UserAction -UserAction "urn:user:registersecurityinfo"
    #>
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param (
        [Parameter(Mandatory = $true)]
        [string]$UserAction
    )

    $supportedActions = Get-SupportedUserActions
    return $supportedActions.ContainsKey($UserAction)
}

# Export the functions
Export-ModuleMember -Function Test-UserActionInScope, Get-SupportedUserActions, Validate-UserAction