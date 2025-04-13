function Invoke-CAWhatIf {
    <#
    .SYNOPSIS
        Simulates the evaluation of Conditional Access policies for a given scenario.

    .DESCRIPTION
        This function simulates how Microsoft Entra Conditional Access policies would evaluate
        against a hypothetical sign-in scenario with the specified parameters.

    .PARAMETER UserId
        The user's object ID or user principal name (UPN).

    .PARAMETER UserGroups
        The groups that the user is a member of.

    .PARAMETER UserRoles
        The directory roles assigned to the user.

    .PARAMETER UserRiskLevel
        The user risk level (None, Low, Medium, High).

    .PARAMETER AppId
        The application ID to simulate access to.

    .PARAMETER AppDisplayName
        The display name of the application.

    .PARAMETER IpAddress
        The IP address from which the sign-in is occurring.

    .PARAMETER Location
        The named location from which the sign-in is occurring.

    .PARAMETER ClientAppType
        The client application type (Browser, MobileAppsAndDesktopClients, ExchangeActiveSync, Other).

    .PARAMETER DevicePlatform
        The device platform (Windows, iOS, Android, macOS, Linux, Other).

    .PARAMETER DeviceCompliant
        Whether the device is compliant with Intune policies.

    .PARAMETER DeviceJoinType
        The device join type (AzureAD, Hybrid, Registered, Personal).

    .PARAMETER SignInRiskLevel
        The sign-in risk level (None, Low, Medium, High).

    .PARAMETER MfaAuthenticated
        Whether MFA has already been performed for this session.

    .PARAMETER ApprovedApplication
        Whether the application is an approved client app.

    .PARAMETER AppProtectionPolicy
        Whether the device has app protection policy.

    .PARAMETER BrowserPersistence
        Whether browser persistence is enabled.

    .PARAMETER PolicyIds
        Specific policy IDs to evaluate. If not specified, all policies are evaluated.

    .PARAMETER IncludeReportOnly
        Whether to include policies in report-only mode in the evaluation.

    .PARAMETER OutputLevel
        The level of detail to include in the output (Basic, Detailed, Table).

    .PARAMETER Diagnostic
        Whether to enable verbose output for policy evaluation.

    .EXAMPLE
        Invoke-CAWhatIf -UserId "john.doe@contoso.com" -AppId "Office365" -DevicePlatform "Windows"

    .EXAMPLE
        Invoke-CAWhatIf -UserId "john.doe@contoso.com" -UserGroups "Sales", "VPN Users" -AppId "00000002-0000-0ff1-ce00-000000000000" -ClientAppType "Browser" -DevicePlatform "Windows" -DeviceCompliant $true -OutputLevel "Detailed"
    #>
    [CmdletBinding()]
    param (
        # User parameters
        [Parameter()]
        [string]$UserId,

        [Parameter()]
        [string[]]$UserGroups,

        [Parameter()]
        [string[]]$UserRoles,

        [Parameter()]
        [ValidateSet('None', 'Low', 'Medium', 'High')]
        [string]$UserRiskLevel = 'None',

        # Resource parameters
        [Parameter()]
        [string]$AppId,

        [Parameter()]
        [string]$AppDisplayName,

        # Sign-in context
        [Parameter()]
        [string]$IpAddress,

        [Parameter()]
        [string]$Location,

        [Parameter()]
        [ValidateSet('Browser', 'MobileAppsAndDesktopClients', 'ExchangeActiveSync', 'Other')]
        [string]$ClientAppType = 'Browser',

        [Parameter()]
        [ValidateSet('Windows', 'iOS', 'Android', 'macOS', 'Linux', 'Other')]
        [string]$DevicePlatform,

        [Parameter()]
        [bool]$DeviceCompliant = $false,

        [Parameter()]
        [ValidateSet('AzureAD', 'Hybrid', 'Registered', 'Personal')]
        [string]$DeviceJoinType = 'Personal',

        [Parameter()]
        [ValidateSet('None', 'Low', 'Medium', 'High')]
        [string]$SignInRiskLevel = 'None',

        [Parameter()]
        [bool]$MfaAuthenticated = $false,

        [Parameter()]
        [bool]$ApprovedApplication = $false,

        [Parameter()]
        [bool]$AppProtectionPolicy = $false,

        [Parameter()]
        [bool]$BrowserPersistence = $false,

        # Filtering parameters
        [Parameter()]
        [string[]]$PolicyIds,

        [Parameter()]
        [switch]$IncludeReportOnly = $true,

        # Output parameters
        [Parameter()]
        [ValidateSet('Basic', 'Detailed', 'Table')]
        [string]$OutputLevel = 'Table',

        # Diagnostic mode
        [Parameter()]
        [switch]$Diagnostic
    )

    begin {
        # Ensure we're connected to Microsoft Graph
        try {
            $graphConnection = Get-MgContext
            if (-not $graphConnection) {
                Connect-MgGraph -Scopes "Policy.Read.All", "Directory.Read.All"
            }
        }
        catch {
            Write-Error "Failed to connect to Microsoft Graph. Please ensure you have the necessary permissions."
            return
        }

        # Resolve the user identity (convert UPN to GUID or vice versa)
        try {
            $resolvedUser = Resolve-UserIdentity -UserIdOrUpn $UserId
            if ($resolvedUser.Success) {
                # Use the resolved GUID for all internal operations
                $UserGuid = $resolvedUser.Id
                $UserPrincipalName = $resolvedUser.UserPrincipalName
                $UserDisplayName = $resolvedUser.DisplayName

                Write-Verbose ("Resolved user '{0}' to: {1} ({2})" -f $UserId, $UserDisplayName, $UserGuid)
            }
            else {
                # Continue with what was provided
                $UserGuid = $UserId
                $UserPrincipalName = $UserId
                $UserDisplayName = "Unknown User"

                Write-Warning ("Could not resolve user identity for '{0}'. Using as-is." -f $UserId)
            }
        }
        catch {
            # Fall back to the provided ID
            $UserGuid = $UserId
            $UserPrincipalName = $UserId
            $UserDisplayName = "Unknown User"

            Write-Warning ("Error resolving user identity: {0}" -f $_.Exception.Message)
        }

        # If no groups were provided, but we have a valid user ID, get the user's groups
        if ((-not $UserGroups -or $UserGroups.Count -eq 0) -and $resolvedUser.Success) {
            try {
                $userGroupMemberships = Resolve-GroupMembership -UserId $UserGuid -IncludeNestedGroups
                if ($userGroupMemberships.Success -and $userGroupMemberships.Groups.Count -gt 0) {
                    # Extract just the group IDs for the context
                    $UserGroups = $userGroupMemberships.Groups | ForEach-Object { $_.Id }

                    Write-Verbose ("Retrieved {0} groups for user {1}" -f $UserGroups.Count, $UserDisplayName)
                }
            }
            catch {
                Write-Warning ("Could not retrieve group memberships: {0}" -f $_.Exception.Message)
            }
        }

        # Create context objects
        $UserContext = @{
            Id               = $UserGuid
            UPN              = $UserPrincipalName
            DisplayName      = $UserDisplayName
            MemberOf         = $UserGroups
            DirectoryRoles   = $UserRoles
            UserRiskLevel    = $UserRiskLevel
            MfaAuthenticated = $MfaAuthenticated
        }

        $ResourceContext = @{
            AppId               = $AppId
            DisplayName         = $AppDisplayName
            ClientAppType       = $ClientAppType
            ApprovedApplication = $ApprovedApplication
        }

        $DeviceContext = @{
            Platform            = $DevicePlatform
            Compliance          = $DeviceCompliant
            JoinType            = $DeviceJoinType
            AppProtectionPolicy = $AppProtectionPolicy
            BrowserPersistence  = $BrowserPersistence
        }

        $RiskContext = @{
            SignInRiskLevel = $SignInRiskLevel
            UserRiskLevel   = $UserRiskLevel
        }

        $LocationContext = @{
            IpAddress     = $IpAddress
            NamedLocation = $Location
        }
    }

    process {
        # Load policies
        $policies = Get-CAPolicy -PolicyIds $PolicyIds -IncludeReportOnly:$IncludeReportOnly

        if (-not $policies -or $policies.Count -eq 0) {
            Write-Warning "No Conditional Access policies found."
            return
        }

        $results = @()

        # Evaluate each policy
        foreach ($policy in $policies) {
            $result = @{
                PolicyId               = $policy.Id
                DisplayName            = $policy.DisplayName
                State                  = $policy.State  # Enabled, Disabled, Report-only
                Applies                = $false
                AccessResult           = $null
                GrantControlsRequired  = @()
                SessionControlsApplied = @()
                EvaluationDetails      = @{
                    UserInScope           = $false
                    ResourceInScope       = $false
                    NetworkInScope        = $false
                    ClientAppInScope      = $false
                    DevicePlatformInScope = $false
                    DeviceStateInScope    = $false
                    RiskLevelsInScope     = $false
                }
            }

            # Only evaluate enabled or report-only policies
            if ($policy.State -eq "enabled" -or ($policy.State -eq "enabledForReportingButNotEnforced" -and $IncludeReportOnly) -or $policy.State -eq "disabled") {

                # --- CORE EVALUATION LOGIC (MOVED OUTSIDE DIAGNOSTIC BLOCK) ---
                Write-Verbose "Evaluating policy: $($policy.DisplayName) (ID: $($policy.Id))" # General evaluation message

                # Check if policy applies to this sign-in scenario
                $policyEvaluation = Resolve-CACondition -Policy $policy -UserContext $UserContext -ResourceContext $ResourceContext -DeviceContext $DeviceContext -RiskContext $RiskContext -LocationContext $LocationContext

                $result.EvaluationDetails = $policyEvaluation.EvaluationDetails
                $result.Applies = $policyEvaluation.Applies

                # If policy applies, evaluate grant and session controls
                if ($result.Applies) {
                    $grantControlResult = Resolve-CAGrantControl -Policy $policy -UserContext $UserContext -DeviceContext $DeviceContext
                    $result.AccessResult = $grantControlResult.AccessResult
                    $result.GrantControlsRequired = $grantControlResult.GrantControlsRequired

                    # If access is granted or conditional, check session controls
                    if ($result.AccessResult -eq "Granted" -or $result.AccessResult -eq "ConditionallyGranted") {
                        $sessionControlResult = Resolve-CASessionControl -Policy $policy
                        $result.SessionControlsApplied = $sessionControlResult.SessionControlsApplied
                    }
                }
                # --- END OF CORE EVALUATION LOGIC ---


                # --- DIAGNOSTIC LOGGING (Remains conditional) ---
                if ($Diagnostic) {
                    $verbosePreference = $VerbosePreference
                    $VerbosePreference = 'Continue' # Temporarily enable verbose for this section

                    Write-Verbose "--- Diagnostic Start: Policy '$($policy.DisplayName)' ---"
                    Write-Verbose "User ID being evaluated: $UserId ($UserGuid)"
                    Write-Verbose "Policy State: $($policy.State)"
                    Write-Verbose "Include Report-Only: $IncludeReportOnly"

                    # Enhanced diagnostic for user exclusion checking
                    if ($policy.Conditions.Users.ExcludeUsers) {
                        Write-Verbose ("Policy excludes these users/GUIDs: {0}" -f ($policy.Conditions.Users.ExcludeUsers -join ', '))
                        $excludedUserDetails = @()
                        foreach ($excludedUser in $policy.Conditions.Users.ExcludeUsers) {
                            # Try to resolve excluded user to get more details
                            try {
                                $resolvedExcludedUser = Resolve-UserIdentity -UserIdOrUpn $excludedUser
                                if ($resolvedExcludedUser.Success) {
                                    $excludedUserDetails += "{0} ({1})" -f $resolvedExcludedUser.DisplayName, $resolvedExcludedUser.UserPrincipalName
                                }
                                else {
                                    $excludedUserDetails += $excludedUser
                                }
                            }
                            catch {
                                $excludedUserDetails += $excludedUser
                            }

                            # Validate if the excluded user is in GUID format
                            $guidPattern = "^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$"
                            $isGuid = $excludedUser -match $guidPattern

                            if ($isGuid) {
                                # Check for exact GUID match
                                if ($excludedUser -eq $UserGuid) {
                                    Write-Verbose ("MATCH FOUND: User ID '{0}' exactly matches excluded user ID '{1}'" -f $UserGuid, $excludedUser)
                                }
                                else {
                                    # Perform a case-insensitive comparison to check for case sensitivity issues
                                    if ($excludedUser.ToLower() -eq $UserGuid.ToLower()) {
                                        Write-Verbose ("CASE-SENSITIVE ISSUE: User ID '{0}' matches excluded user ID '{1}' but with different casing" -f $UserGuid, $excludedUser)
                                    }
                                    else {
                                        Write-Verbose ("NO MATCH: User ID '{0}' does not match excluded user ID '{1}'" -f $UserGuid, $excludedUser)
                                    }
                                }
                            }
                            else {
                                # Handle UPN comparison if not a GUID
                                if ($UserPrincipalName) {
                                    if ($excludedUser -eq $UserPrincipalName) {
                                        Write-Verbose ("MATCH FOUND: User UPN '{0}' exactly matches excluded user '{1}'" -f $UserPrincipalName, $excludedUser)
                                    }
                                    else {
                                        Write-Verbose ("NO MATCH: User UPN '{0}' does not match excluded user '{1}'" -f $UserPrincipalName, $excludedUser)
                                    }
                                }
                            }
                        }
                        Write-Verbose ("Excluded users (resolved): {0}" -f ($excludedUserDetails -join ", "))

                    }
                    else {
                        Write-Verbose "No excluded users defined for this policy."
                    }

                    # Check for groups in the policy conditions
                    if ($policy.Conditions.Users.IncludeGroups -or $policy.Conditions.Users.ExcludeGroups) {
                        # Process included groups
                        if ($policy.Conditions.Users.IncludeGroups) {
                            Write-Verbose ("Policy includes these groups: {0}" -f ($policy.Conditions.Users.IncludeGroups -join ', '))
                            $includedGroupChecks = Resolve-GroupMembership -UserId $UserGuid -GroupIds $policy.Conditions.Users.IncludeGroups
                            if ($includedGroupChecks.Success) {
                                $memberOfAnyIncludedGroup = $false; $groupDetails = @()
                                foreach ($group in $includedGroupChecks.MemberOfSpecificGroups.Values) {
                                    $groupDetails += "{0} ({1}): {2}" -f $group.DisplayName, $group.GroupId, $(if ($group.IsMember) { "Member" } else { "Not Member" }); if ($group.IsMember) { $memberOfAnyIncludedGroup = $true }
                                }
                                Write-Verbose ("User is member of included groups: {0}" -f $memberOfAnyIncludedGroup)
                                Write-Verbose ("Included groups checks (resolved): {0}" -f ($groupDetails -join ", "))
                            }
                            else { Write-Warning "Could not resolve included group membership for diagnostic." }
                        }
                        else { Write-Verbose "No included groups defined." }

                        # Process excluded groups
                        if ($policy.Conditions.Users.ExcludeGroups) {
                            Write-Verbose ("Policy excludes these groups: {0}" -f ($policy.Conditions.Users.ExcludeGroups -join ', '))
                            $excludedGroupChecks = Resolve-GroupMembership -UserId $UserGuid -GroupIds $policy.Conditions.Users.ExcludeGroups
                            if ($excludedGroupChecks.Success) {
                                $memberOfAnyExcludedGroup = $false; $groupDetails = @()
                                foreach ($group in $excludedGroupChecks.MemberOfSpecificGroups.Values) {
                                    $groupDetails += "{0} ({1}): {2}" -f $group.DisplayName, $group.GroupId, $(if ($group.IsMember) { "Member" } else { "Not Member" }); if ($group.IsMember) { $memberOfAnyExcludedGroup = $true }
                                }
                                Write-Verbose ("User is member of excluded groups: {0}" -f $memberOfAnyExcludedGroup)
                                Write-Verbose ("Excluded groups checks (resolved): {0}" -f ($groupDetails -join ", "))
                            }
                            else { Write-Warning "Could not resolve excluded group membership for diagnostic." }
                        }
                        else { Write-Verbose "No excluded groups defined." }
                    }
                    else { Write-Verbose "No include/exclude groups defined." }


                    # Log the result of the policy evaluation (already performed above)
                    Write-Verbose "--- Evaluation Result ---"
                    Write-Verbose "Policy applies: $($result.Applies)"
                    Write-Verbose "User in scope: $($result.EvaluationDetails.UserInScope)"
                    Write-Verbose "Resource in scope: $($result.EvaluationDetails.ResourceInScope)"
                    Write-Verbose "Platform in scope: $($result.EvaluationDetails.DevicePlatformInScope)"
                    Write-Verbose "Network in scope: $($result.EvaluationDetails.NetworkInScope)"
                    Write-Verbose "Device state in scope: $($result.EvaluationDetails.DeviceStateInScope)"
                    Write-Verbose "Risk levels in scope: $($result.EvaluationDetails.RiskLevelsInScope)"
                    if ($result.Applies) {
                        Write-Verbose "Access Result: $($result.AccessResult)"
                        Write-Verbose "Grant Controls Required: $($result.GrantControlsRequired -join ', ')"
                        Write-Verbose "Session Controls Applied: $($result.SessionControlsApplied -join ', ')"
                    }
                    else {
                        # Add reasoning if available from Resolve-CACondition (assuming Reasons property exists)
                        if ($result.EvaluationDetails.Reasons) {
                            Write-Verbose "Reason Not Applied: $($result.EvaluationDetails.Reasons | ConvertTo-Json -Depth 1)"
                        }
                        else {
                            Write-Verbose "Reason Not Applied: Check individual scope conditions."
                        }
                    }
                    Write-Verbose "--- Diagnostic End: Policy '$($policy.DisplayName)' ---`n"

                    # Restore verbose preference
                    $VerbosePreference = $verbosePreference
                } # --- END OF DIAGNOSTIC LOGGING ---

                $results += $result
            }
        }

        # Process results to determine final outcome
        # Consider ALL applicable policies for the final access decision, regardless of state
        $applicablePolicies = $results | Where-Object { $_.Applies -eq $true }

        $finalResult = @{
            AccessAllowed    = $true
            BlockingPolicies = @()
            RequiredControls = @()
            SessionControls  = @()
            DetailedResults  = $results
        }

        # Check if any policy blocks access
        $blockingPolicies = $applicablePolicies | Where-Object { $_.AccessResult -eq "Blocked" }
        if ($blockingPolicies.Count -gt 0) {
            $finalResult.AccessAllowed = $false
            $finalResult.BlockingPolicies = $blockingPolicies
        }

        # Collect all required controls from applicable policies
        $conditionalPolicies = $applicablePolicies | Where-Object { $_.AccessResult -eq "ConditionallyGranted" }
        foreach ($policy in $conditionalPolicies) {
            $finalResult.RequiredControls += $policy.GrantControlsRequired | Where-Object { $_ -notin $finalResult.RequiredControls }
        }

        # Collect all session controls from applicable policies
        foreach ($policy in $applicablePolicies) {
            $finalResult.SessionControls += $policy.SessionControlsApplied | Where-Object { $_ -notin $finalResult.SessionControls }
        }

        # Return appropriate level of detail
        if ($OutputLevel -eq 'Table') {
            # Display formatted table in console
            Write-Host "Conditional Access WhatIf Results for User: $UserId" -ForegroundColor Cyan
            Write-Host "===============================================================" -ForegroundColor Cyan

            # Show input parameters
            $paramSummary = "Parameters:"
            if ($AppId) { $paramSummary += " App=$AppId" }
            if ($DevicePlatform) { $paramSummary += " Platform=$DevicePlatform" }
            if ($ClientAppType) { $paramSummary += " ClientApp=$ClientAppType" }
            if ($IpAddress) { $paramSummary += " IP=$IpAddress" }
            if ($DeviceCompliant -ne $false) { $paramSummary += " Compliant=$DeviceCompliant" }
            if ($MfaAuthenticated -ne $false) { $paramSummary += " MFA=$MfaAuthenticated" }
            Write-Host $paramSummary -ForegroundColor Yellow
            Write-Host ""

            # Summary header
            $accessStatus = if ($finalResult.AccessAllowed) { "GRANTED" } else { "BLOCKED" }
            $accessColor = if ($finalResult.AccessAllowed) { "Green" } else { "Red" }
            Write-Host "Access Status: " -NoNewline
            Write-Host $accessStatus -ForegroundColor $accessColor

            if ($finalResult.RequiredControls.Count -gt 0) {
                Write-Host "Required Controls: " -NoNewline
                Write-Host ($finalResult.RequiredControls -join ", ") -ForegroundColor Yellow
            }

            if ($finalResult.SessionControls.Count -gt 0) {
                Write-Host "Session Controls: " -NoNewline
                Write-Host ($finalResult.SessionControls -join ", ") -ForegroundColor Cyan
            }

            # Policy count information
            $enabledCount = ($results | Where-Object { $_.State -eq "enabled" }).Count
            $reportOnlyCount = ($results | Where-Object { $_.State -eq "enabledForReportingButNotEnforced" }).Count
            $disabledCount = ($results | Where-Object { $_.State -eq "disabled" }).Count
            $totalCount = $results.Count
            $applicableCount = ($results | Where-Object { $_.Applies -eq $true }).Count

            Write-Host "`nPolicy Counts:" -ForegroundColor Cyan
            Write-Host "Total Policies: $totalCount (Enabled: $enabledCount, Report-Only: $reportOnlyCount, Disabled: $disabledCount)" -ForegroundColor White
            Write-Host "Applicable to this scenario: $applicableCount" -ForegroundColor White

            Write-Host "`nPolicy Evaluation Details:" -ForegroundColor Cyan
            Write-Host "===============================================================" -ForegroundColor Cyan

            # Sort policies: applicable policies first, then by state (enabled, report-only, disabled)
            $sortedResults = $results | ForEach-Object {
                $_ | Add-Member -NotePropertyName AppliesSortOrder -NotePropertyValue $(if ($_.Applies) { 1 } else { 2 }) -PassThru |
                    Add-Member -NotePropertyName StateSortOrder -NotePropertyValue $(
                        switch ($_.State) {
                            "enabled" { 1 }
                            "enabledForReportingButNotEnforced" { 2 }
                            "disabled" { 3 }
                            default { 4 }
                        }
                    ) -PassThru
                } | Sort-Object -Property AppliesSortOrder, StateSortOrder

            # Define column widths
            $nameWidth = 40
            $stateWidth = 12
            $appliesWidth = 10
            $conditionsWidth = 25
            $resultWidth = 12
            $reasonWidth = 30

            # Write table header
            Write-Host ("{0,-$nameWidth} {1,-$stateWidth} {2,-$appliesWidth} {3,-$conditionsWidth} {4,-$resultWidth} {5,-$reasonWidth}" -f
                "Policy Name", "State", "Applies", "Conditions", "Result", "Reason/Controls") -ForegroundColor Cyan
            Write-Host ("{0,-$nameWidth} {1,-$stateWidth} {2,-$appliesWidth} {3,-$conditionsWidth} {4,-$resultWidth} {5,-$reasonWidth}" -f
                ("-" * ($nameWidth - 1)), ("-" * ($stateWidth - 1)), ("-" * ($appliesWidth - 1)), ("-" * ($conditionsWidth - 1)), ("-" * ($resultWidth - 1)), ("-" * ($reasonWidth - 1))) -ForegroundColor Cyan

            # Write each policy row with proper coloring
            foreach ($result in $sortedResults) {
                # Truncate policy name if too long
                $policyName = $result.DisplayName
                if ($policyName.Length -gt $nameWidth - 3) {
                    $policyName = $policyName.Substring(0, $nameWidth - 6) + "..."
                }

                # Format the state column
                $stateText = switch ($result.State) {
                    "enabled" { "Enabled" }
                    "enabledForReportingButNotEnforced" { "Report" }
                    "disabled" { "Disabled" }
                    default { "Unknown" }
                }

                # Format the applies column
                $appliesText = if ($result.Applies) { "YES" } else { "NO" }

                # Format the conditions column
                $conditions = "{0}{1}{2}{3}" -f
                $(if ($result.EvaluationDetails.UserInScope) { "U✓" } else { "U✗" }),
                $(if ($result.EvaluationDetails.ResourceInScope) { " A✓" } else { " A✗" }),
                $(if ($result.EvaluationDetails.DevicePlatformInScope) { " P✓" } else { " P✗" }),
                $(if ($result.EvaluationDetails.NetworkInScope) { " N✓" } else { " N✗" })

                # Format the result column
                $resultText = if ($result.Applies) {
                    switch ($result.AccessResult) {
                        "Blocked" { "BLOCKED" }
                        "Granted" { "GRANTED" }
                        "ConditionallyGranted" { "CONDITIONAL" }
                        default { "-" }
                    }
                }
                else { "-" }

                # Format the reason/controls column
                $reasonOrControls = if (-not $result.Applies) {
                    if (-not $result.EvaluationDetails.UserInScope) {
                        # Use the detailed reason from evaluation if available
                        if ($result.EvaluationDetails.Reasons -and $result.EvaluationDetails.Reasons.User) {
                            $result.EvaluationDetails.Reasons.User
                        }
                        else {
                            "User not in scope"
                        }
                    }
                    elseif (-not $result.EvaluationDetails.ResourceInScope) { "App not in scope" }
                    elseif (-not $result.EvaluationDetails.DevicePlatformInScope) { "Platform not in scope" }
                    elseif (-not $result.EvaluationDetails.NetworkInScope) { "Network not in scope" }
                    elseif (-not $result.EvaluationDetails.DeviceStateInScope) { "Device state not in scope" }
                    elseif (-not $result.EvaluationDetails.RiskLevelsInScope) { "Risk level not in scope" }
                    else { "Not applicable" }
                }
                else {
                    ($result.GrantControlsRequired -join ", ")
                }

                # Truncate reason/controls if too long
                if ($reasonOrControls.Length -gt $reasonWidth - 3) {
                    $reasonOrControls = $reasonOrControls.Substring(0, $reasonWidth - 6) + "..."
                }

                # Write row with appropriate colors
                Write-Host ("{0,-$nameWidth} " -f $policyName) -NoNewline

                # State with color
                $stateColor = switch ($result.State) {
                    "enabled" { "Green" }
                    "enabledForReportingButNotEnforced" { "Yellow" }
                    "disabled" { "DarkGray" }
                    default { "DarkGray" }
                }
                Write-Host ("{0,-$stateWidth} " -f $stateText) -NoNewline -ForegroundColor $stateColor

                # Applies with color
                $appliesColor = if ($result.Applies) { "Green" } else { "DarkGray" }
                Write-Host ("{0,-$appliesWidth} " -f $appliesText) -NoNewline -ForegroundColor $appliesColor

                # Conditions - mix of colors
                Write-Host ("{0,-$conditionsWidth} " -f $conditions) -NoNewline

                # Result with color
                $resultColor = switch ($result.AccessResult) {
                    "Blocked" { "Red" }
                    "Granted" { "Green" }
                    "ConditionallyGranted" { "Yellow" }
                    default { "White" }
                }
                Write-Host ("{0,-$resultWidth} " -f $resultText) -NoNewline -ForegroundColor $resultColor

                # Reason/Controls
                $reasonColor = if ($result.Applies) { "Yellow" } else { "DarkGray" }
                Write-Host ("{0,-$reasonWidth}" -f $reasonOrControls) -ForegroundColor $reasonColor
            }

            # Reset colors
            Write-Host ""

            # Return the final result object for pipeline usage
            return $finalResult | Select-Object -Property AccessAllowed, BlockingPolicies, RequiredControls, SessionControls
        }
        elseif ($OutputLevel -eq 'Basic') {
            return $finalResult | Select-Object -Property AccessAllowed, BlockingPolicies, RequiredControls, SessionControls
        }
        else {
            return $finalResult
        }
    }

    end {
        # Clean up
    }
}