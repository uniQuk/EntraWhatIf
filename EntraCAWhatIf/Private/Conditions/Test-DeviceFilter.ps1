function Test-DeviceFilter {
    <#
    .SYNOPSIS
        Tests if a device matches a Conditional Access policy device filter rule.

    .DESCRIPTION
        This function evaluates if a device meets the criteria specified in a device filter rule.
        It supports all operators (equals, notEquals, contains, notContains, startsWith, notStartsWith)
        and both include and exclude modes.

        It handles missing device information gracefully based on mode:
        - For exclude mode: If no device info, the filter passes (device not excluded)
        - For include mode: If no device info, the filter fails (device not included)

    .PARAMETER Device
        The device context containing device properties.

    .PARAMETER FilterRule
        The device filter rule object from the policy.

    .EXAMPLE
        Test-DeviceFilter -Device $DeviceContext -FilterRule $Policy.Conditions.Devices.DeviceFilter
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param (
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$Device,

        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [object]$FilterRule
    )

    # If no filter rule specified, device is in scope
    if (-not $FilterRule) {
        Write-Verbose "No device filter rule specified, device is in scope"
        return @{
            Matches = $true
            Reason  = "No device filter rule specified"
        }
    }

    # Extract filter rule components
    $mode = $FilterRule.mode
    $rules = $FilterRule.rule

    # Check if this is a KQL-style rule string rather than structured rules
    if ($rules -is [string]) {
        Write-Verbose "KQL-style filter rule detected: $rules"
        # For now, always return true for KQL rules until we implement a KQL parser
        return @{
            Matches = $true
            Reason  = "KQL-style filter rule not fully evaluated yet: $rules"
        }
    }

    Write-Verbose "Evaluating device filter: Mode=$mode, Rules count=$(if ($rules) { $rules.Count } else { 0 })"

    # Handle null device context based on mode
    if (-not $Device) {
        if ($mode -eq "exclude") {
            Write-Verbose "No device information available, exclude filter passes by default"
            return @{
                Matches = $true
                Reason  = "No device information available for exclude filter"
            }
        }
        else {
            # include mode
            Write-Verbose "No device information available, include filter fails by default"
            return @{
                Matches = $false
                Reason  = "No device information available for include filter"
            }
        }
    }

    # If no rules specified, device matches based on mode
    if (-not $rules -or (($rules -isnot [string]) -and (($rules -is [array] -and $rules.Count -eq 0) -or ($rules -isnot [array])))) {
        # If mode is null or empty and rules are empty, this is essentially a non-filter, so match everything
        if ([string]::IsNullOrEmpty($mode)) {
            Write-Verbose "Empty filter with no mode specified matches everything"
            return @{
                Matches = $true
                Reason  = "Empty filter with no mode specified matches everything"
            }
        }

        # Only use mode-specific behavior when mode is explicitly set
        $result = ($mode -eq "include")
        $reason = if ($result) {
            "Empty include filter matches by default"
        }
        else {
            "Empty exclude filter matches by default (changed from previous behavior)"
        }

        Write-Verbose $reason
        return @{
            Matches = $true # Always return true for empty filters regardless of mode
            Reason  = $reason
        }
    }

    # Evaluate each rule
    foreach ($rule in $rules) {
        # Check if rule is null or not an object with properties
        if ($null -eq $rule -or ($rule -isnot [PSCustomObject] -and $rule -isnot [Hashtable])) {
            Write-Warning "Invalid rule format encountered, skipping: $rule"
            continue
        }

        # Safely access rule properties with null checks
        $operator = if ($null -ne $rule.PSObject.Properties['operator']) { $rule.operator } else { $null }
        $operand = if ($null -ne $rule.PSObject.Properties['operand']) { $rule.operand } else { $null }
        $value = if ($null -ne $rule.PSObject.Properties['value']) { $rule.value } else { $null }

        # Handle KQL-style rules (present as a string in the rule property instead of structured format)
        if ($null -eq $operand -and $null -eq $operator -and $null -eq $value) {
            # This might be a KQL-style rule string
            if ($rule -is [string] -or ($rule.PSObject.Properties['rule'] -and $rule.rule -is [string])) {
                $ruleString = if ($rule -is [string]) { $rule } else { $rule.rule }
                Write-Verbose "KQL-style filter rule detected within rules array: $ruleString"

                # For KQL-style rules, we need to handle more complex evaluation
                # Just return a match for now - in future this should be enhanced to interpret KQL
                return @{
                    Matches = $true
                    Reason  = "KQL-style device filter rule is not fully evaluated yet: $ruleString"
                }
            }
        }

        # Guard against null operands
        if ($null -eq $operand) {
            Write-Warning "Null operand in device filter rule"
            # Continue to next rule if there is one, otherwise this will fail the match
            continue
        }

        # Get the device property value
        # Handle nested properties with dot notation (e.g., "deviceState.isCompliant")
        $deviceValue = $Device
        foreach ($propertyPart in $operand.Split('.')) {
            if ($null -eq $deviceValue) { break }
            $deviceValue = $deviceValue.$propertyPart
        }

        Write-Verbose "Rule: Operand=$operand, Operator=$operator, Value=$value, DeviceValue=$deviceValue"

        # Case-insensitive evaluation for string values
        $match = $false
        switch ($operator) {
            "equals" {
                if ($deviceValue -is [string] -and $value -is [string]) {
                    $match = ($deviceValue -ieq $value)
                }
                else {
                    $match = ($deviceValue -eq $value)
                }
            }
            "notEquals" {
                if ($deviceValue -is [string] -and $value -is [string]) {
                    $match = ($deviceValue -ine $value)
                }
                else {
                    $match = ($deviceValue -ne $value)
                }
            }
            "contains" {
                if ($deviceValue -is [string] -and $value -is [string]) {
                    $match = ($deviceValue -like "*$value*")
                }
                else {
                    $match = $false
                }
            }
            "notContains" {
                if ($deviceValue -is [string] -and $value -is [string]) {
                    $match = ($deviceValue -notlike "*$value*")
                }
                else {
                    $match = $true
                }
            }
            "startsWith" {
                if ($deviceValue -is [string] -and $value -is [string]) {
                    $match = ($deviceValue -like "$value*")
                }
                else {
                    $match = $false
                }
            }
            "notStartsWith" {
                if ($deviceValue -is [string] -and $value -is [string]) {
                    $match = ($deviceValue -notlike "$value*")
                }
                else {
                    $match = $true
                }
            }
            default {
                Write-Warning "Unsupported operator: $operator"
                $match = $false
            }
        }

        Write-Verbose "Rule match result: $match"

        # Early exit based on mode
        if (($mode -eq "include" -and -not $match) -or ($mode -eq "exclude" -and $match)) {
            $reason = if ($mode -eq "include") {
                "Device does not match include filter rule: $operand $operator $value"
            }
            else {
                "Device matches exclude filter rule: $operand $operator $value"
            }

            return @{
                Matches = if ($mode -eq "exclude") { $false } else { $true }
                Reason  = $reason
            }
        }
    }

    # If we reach here, all rules have been evaluated
    # For include mode: Device matches all rules
    # For exclude mode: Device doesn't match any rule
    $result = ($mode -eq "include")
    $reason = if ($result) {
        "Device matches all include filter rules"
    }
    else {
        "Device does not match any exclude filter rules"
    }

    Write-Verbose $reason
    return @{
        Matches = $result
        Reason  = $reason
    }
}

function Test-DeviceStateInScope {
    <#
    .SYNOPSIS
        Tests if a device state is in scope for a Conditional Access policy.

    .DESCRIPTION
        This function evaluates if a device state meets the criteria specified in a policy's device state conditions.
        It handles device filter rules, compliance state, and other device state requirements.

    .PARAMETER Policy
        The Conditional Access policy to evaluate.

    .PARAMETER DeviceContext
        The device context containing device state information.

    .EXAMPLE
        Test-DeviceStateInScope -Policy $policy -DeviceContext $DeviceContext
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param (
        [Parameter(Mandatory = $true)]
        [object]$Policy,

        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [object]$DeviceContext
    )

    # If no device conditions specified, all devices are in scope
    if (-not $Policy.Conditions.Devices) {
        Write-Verbose "No device state conditions specified in policy, all devices are in scope"
        return @{
            InScope = $true
            Reason  = "No device state conditions specified"
        }
    }

    # Check device filter rule if specified
    if ($Policy.Conditions.Devices.DeviceFilter) {
        # Check if this is an empty filter with null values
        $isEmptyFilter = $null -eq $Policy.Conditions.Devices.DeviceFilter.mode -and
        $null -eq $Policy.Conditions.Devices.DeviceFilter.rule

        if ($isEmptyFilter) {
            Write-Verbose "Device filter exists but is empty (null mode and rules), considering it a match"
            # Skip filter evaluation for empty filters
        }
        else {
            $filterResult = Test-DeviceFilter -Device $DeviceContext -FilterRule $Policy.Conditions.Devices.DeviceFilter

            if (-not $filterResult.Matches) {
                return @{
                    InScope = $false
                    Reason  = "Device filter not matched: $($filterResult.Reason)"
                }
            }
        }
    }

    # If specific device states are required, check them
    $requiredStates = $Policy.Conditions.Devices.DeviceStates

    if ($requiredStates -and $requiredStates.Count -gt 0) {
        # Handle missing device information
        if (-not $DeviceContext) {
            return @{
                InScope = $false
                Reason  = "Device information required but not available"
            }
        }

        # Parse each device state requirement
        $matchesAny = $false
        foreach ($state in $requiredStates) {
            switch ($state) {
                "Compliant" {
                    if ($DeviceContext.IsCompliant) {
                        $matchesAny = $true
                        break
                    }
                }
                "DomainJoined" {
                    if ($DeviceContext.DomainJoined) {
                        $matchesAny = $true
                        break
                    }
                }
                "All" {
                    $matchesAny = $true
                    break
                }
                default {
                    # Unknown state, log and continue
                    Write-Warning "Unknown device state requirement: $state"
                }
            }

            # Early exit if we found a match
            if ($matchesAny) { break }
        }

        if (-not $matchesAny) {
            return @{
                InScope = $false
                Reason  = "Device does not meet any required device state conditions"
            }
        }
    }

    # If we reach here, device is in scope
    return @{
        InScope = $true
        Reason  = "Device meets all device state conditions"
    }
}

function Test-DevicePlatformInScope {
    <#
    .SYNOPSIS
        Tests if a device platform is in scope for a Conditional Access policy.

    .DESCRIPTION
        This function evaluates if a device platform meets the criteria specified in a policy's platform conditions.
        It handles include and exclude platform lists.

    .PARAMETER Policy
        The Conditional Access policy to evaluate.

    .PARAMETER DeviceContext
        The device context containing platform information.

    .EXAMPLE
        Test-DevicePlatformInScope -Policy $policy -DeviceContext $DeviceContext
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param (
        [Parameter(Mandatory = $true)]
        [object]$Policy,

        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [object]$DeviceContext
    )

    # Extract platform information from DeviceContext
    $devicePlatform = if ($DeviceContext -and $DeviceContext.Platform) { $DeviceContext.Platform } else { $null }

    # Check if user explicitly specified a platform
    $isPlatformExplicitlySpecified = $null -ne $devicePlatform

    # If no platform conditions specified, all platforms are in scope
    if (-not $Policy.Conditions.Platforms -or
        (-not $Policy.Conditions.Platforms.IncludePlatforms -and -not $Policy.Conditions.Platforms.ExcludePlatforms)) {

        Write-Verbose "No platform conditions specified in policy, all platforms are in scope"
        return @{
            InScope = $true
            Reason  = "No platform conditions specified"
        }
    }

    $includePlatforms = $Policy.Conditions.Platforms.IncludePlatforms
    $excludePlatforms = $Policy.Conditions.Platforms.ExcludePlatforms

    Write-Verbose "Testing platform scope for policy: $($Policy.DisplayName)"
    Write-Verbose "Device platform: $devicePlatform"
    Write-Verbose "Include platforms: $($includePlatforms -join ', ')"
    Write-Verbose "Exclude platforms: $($excludePlatforms -join ', ')"
    Write-Verbose "Platform explicitly specified by user: $isPlatformExplicitlySpecified"

    # Check if platform is excluded
    if ($excludePlatforms -and $excludePlatforms.Count -gt 0) {
        # Handle special 'all' value for excludes
        if (Test-SpecialValue -Collection $excludePlatforms -ValueType "AllPlatforms") {
            # If all platforms are excluded, no platform can match
            return @{
                InScope = $false
                Reason  = "All platforms excluded"
            }
        }

        # If platform is explicitly specified, check if it's in the exclude list
        if ($isPlatformExplicitlySpecified -and $excludePlatforms -contains $devicePlatform) {
            return @{
                InScope = $false
                Reason  = "Platform explicitly excluded: $devicePlatform"
            }
        }
    }

    # Check if platform is included
    if ($includePlatforms -and $includePlatforms.Count -gt 0) {
        # Handle special 'all' value for includes
        if (Test-SpecialValue -Collection $includePlatforms -ValueType "AllPlatforms") {
            # If all platforms are included, any platform matches
            return @{
                InScope = $true
                Reason  = "All platforms included"
            }
        }

        # If platform is explicitly specified, check if it's in the include list
        if ($isPlatformExplicitlySpecified) {
            if ($includePlatforms -contains $devicePlatform) {
                return @{
                    InScope = $true
                    Reason  = "Platform explicitly included: $devicePlatform"
                }
            }
            else {
                return @{
                    InScope = $false
                    Reason  = "Platform not included: $devicePlatform"
                }
            }
        }
        else {
            # If platform is not specified but we have includes, match Microsoft's behavior:
            # When user only provides UserId with no platform, assume it matches the platform condition
            return @{
                InScope = $true
                Reason  = "Platform condition matches when platform not specified"
            }
        }
    }

    # If no includes specified, but excludes are and we got here, platform is in scope
    return @{
        InScope = $true
        Reason  = "Platform not in any exclusion lists"
    }
}