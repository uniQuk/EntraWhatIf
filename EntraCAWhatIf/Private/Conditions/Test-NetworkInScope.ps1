function Test-NetworkInScope {
    <#
    .SYNOPSIS
        Evaluates if a network location is in scope for a Conditional Access policy.

    .DESCRIPTION
        This function evaluates if a network location is in scope for a Conditional Access policy
        based on IP address, named location, and special location combinations.

        It supports:
        - CIDR notation for IP ranges
        - Special value combinations ("All", "AllTrusted")
        - Named location evaluation (trusted vs untrusted)
        - Country/region-based location matching

    .PARAMETER Policy
        The Conditional Access policy to evaluate.

    .PARAMETER LocationContext
        The location context for the sign-in scenario, containing IP address and/or named location information.

    .EXAMPLE
        Test-NetworkInScope -Policy $policy -LocationContext $LocationContext
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param (
        [Parameter(Mandatory = $true)]
        [object]$Policy,

        [Parameter(Mandatory = $true)]
        [object]$LocationContext
    )

    # If no location conditions specified or the locations object is null, all networks are in scope
    if (-not $Policy.Conditions.Locations -or
        $null -eq $Policy.Conditions.Locations -or
        (-not $Policy.Conditions.Locations.PSObject.Properties.Name -contains "IncludeLocations" -and
        -not $Policy.Conditions.Locations.PSObject.Properties.Name -contains "ExcludeLocations") -or
        (($null -eq $Policy.Conditions.Locations.IncludeLocations -or
            $Policy.Conditions.Locations.IncludeLocations.Count -eq 0) -and
         ($null -eq $Policy.Conditions.Locations.ExcludeLocations -or
        $Policy.Conditions.Locations.ExcludeLocations.Count -eq 0))) {
        Write-Verbose "No location conditions specified in policy, all networks are in scope"
        return @{
            InScope = $true
            Reason  = "No location conditions specified"
        }
    }

    $includeLocations = $Policy.Conditions.Locations.IncludeLocations
    $excludeLocations = $Policy.Conditions.Locations.ExcludeLocations

    # Extract location context information
    $ipAddress = $LocationContext.IpAddress
    $namedLocationId = $LocationContext.NamedLocationId
    $countryCode = $LocationContext.CountryCode
    $isTrustedLocation = $LocationContext.IsTrustedLocation

    Write-Verbose "Testing network scope for policy: $($Policy.DisplayName)"
    Write-Verbose "IP: $ipAddress, Named Location ID: $namedLocationId, Country: $countryCode, Trusted: $isTrustedLocation"

    # Get all named locations
    $namedLocations = Get-NamedLocations

    # When only user ID is provided (no network context), be more permissive
    # Microsoft's behavior in this case is to assume a location that matches the policy
    if (-not $ipAddress -and -not $namedLocationId -and -not $countryCode -and -not [bool]::TryParse($isTrustedLocation, [ref]$null)) {
        # If "All" is included, policy should apply when no network information is supplied
        if ($includeLocations -contains "All") {
            # Only if AllTrusted is not in exclusions
            if (-not ($excludeLocations -contains "AllTrusted")) {
                Write-Verbose "All locations included and no network info provided, assuming match"
                return @{
                    InScope = $true
                    Reason  = "All locations included, no network info specified"
                }
            }
        }

        # Check for country-based named locations when no location info is provided
        # Microsoft treats user-only queries as matching any country-based policy
        foreach ($locationId in $includeLocations) {
            # Skip special values
            if ($locationId -eq "All" -or $locationId -eq "AllTrusted") {
                continue
            }

            # Check if the location exists in our cache
            if (-not $namedLocations.ContainsKey($locationId)) {
                Write-Verbose "Included location ID '$locationId' not found in cache, skipping"
                continue
            }

            $location = $namedLocations[$locationId]

            # Check if this is a country/region location
            # Microsoft treats user-only queries as matching ANY country location, not just those with includeUnknownCountriesAndRegions=true
            if ($location.Type -eq "CountryOrRegion") {
                Write-Verbose "Country location '$($location.DisplayName)' included and no location info provided"

                # Check if the location is excluded by AllTrusted
                if ($excludeLocations -contains "AllTrusted" -and $location.IsTrusted) {
                    Write-Verbose "Location is trusted but AllTrusted is excluded"
                    continue
                }

                return @{
                    InScope = $true
                    Reason  = "Country location included and no location specified"
                }
            }
        }
    }

    # If named location ID is provided but no trust status, determine it
    if ($namedLocationId -and -not [bool]::TryParse($isTrustedLocation, [ref]$null)) {
        $isTrustedLocation = Test-LocationIsTrusted -LocationId $namedLocationId
        Write-Verbose "Determined trust status from named location: $isTrustedLocation"
    }

    # If IP address is provided without trust status, check if it's in any trusted location
    if ($ipAddress -and -not [bool]::TryParse($isTrustedLocation, [ref]$null)) {
        $locationResult = Test-TrustedLocation -IpAddress $ipAddress
        $isTrustedLocation = $locationResult.IsInTrustedLocation
        Write-Verbose "Determined IP trust status by checking locations: $isTrustedLocation"

        # If IP is in a trusted location, add the first location ID to the context for future reference
        if ($isTrustedLocation -and $locationResult.MatchingLocations.Count -gt 0 -and -not $namedLocationId) {
            $namedLocationId = $locationResult.MatchingLocations[0].LocationId
            Write-Verbose "Adding named location ID from trusted location check: $namedLocationId"
        }
    }

    # Update the LocationContext with the verified trusted status and location ID if found
    $LocationContext.IsTrustedLocation = $isTrustedLocation
    if ($namedLocationId) {
        $LocationContext.NamedLocationId = $namedLocationId
    }

    # Check for ExcludeTrustedLocations flag in the conditions
    # This should be evaluated immediately with no special cases
    $excludeTrustedLocations = $Policy.Conditions.Locations.ExcludeTrustedLocations
    if ($excludeTrustedLocations) {
        if ($isTrustedLocation) {
            Write-Verbose "Policy excludes trusted locations and current location is trusted"
            return @{
                InScope = $false
                Reason  = "Policy excludes trusted locations and current location is trusted"
            }
        }
        # If location is not trusted, we continue with normal evaluation
        # Do not add any automatic InScope=true here
        Write-Verbose "Policy excludes trusted locations but current location is not a trusted location"
    }

    # Special values check before checking specific named locations
    if ($excludeLocations) {
        # Check for "All" exclusion
        if ($excludeLocations -contains "All") {
            Write-Verbose "All locations excluded"
            return @{
                InScope = $false
                Reason  = "All locations excluded"
            }
        }

        # Check for "AllTrusted" exclusion
        if ($excludeLocations -contains "AllTrusted") {
            if ($isTrustedLocation) {
                Write-Verbose "All trusted locations excluded and IP is in a trusted location"
                return @{
                    InScope = $false
                    Reason  = "All trusted locations excluded and IP is in a trusted location"
                }
            }
            else {
                Write-Verbose "All trusted locations excluded but IP is not in a trusted location (passes this check)"
                # Continue evaluation - we don't return here
            }
        }
    }

    # Check for special values in include locations
    if ($includeLocations) {
        # Check for "All" inclusion
        if ($includeLocations -contains "All") {
            # Special case: All included but AllTrusted excluded
            if ($excludeLocations -and $excludeLocations -contains "AllTrusted") {
                if ($isTrustedLocation) {
                    Write-Verbose "All locations included but trusted locations excluded, and IP is in a trusted location"
                    return @{
                        InScope = $false
                        Reason  = "All locations included except trusted locations, and IP is in a trusted location"
                    }
                }
                else {
                    Write-Verbose "All locations included but trusted locations excluded, and IP is not in a trusted location"
                    return @{
                        InScope = $true
                        Reason  = "All locations included except trusted locations, and IP is not in a trusted location"
                    }
                }
            }

            # If "All" is included with specific named locations in exclusions, we need to check if IP is in any of those
            if ($excludeLocations -and $excludeLocations.Count -gt 0) {
                $isExcluded = $false

                # First check if IP is in any excluded named location
                foreach ($locationId in $excludeLocations) {
                    # Skip special values
                    if ($locationId -eq "All" -or $locationId -eq "AllTrusted") {
                        continue
                    }

                    # Check if the location exists in our cache
                    if (-not $namedLocations.ContainsKey($locationId)) {
                        Write-Verbose "Excluded location ID '$locationId' not found in cache, skipping"
                        continue
                    }

                    $excludedLocation = $namedLocations[$locationId]

                    # Check if IP matches an excluded location
                    if ($ipAddress -and $excludedLocation.Type -eq "IP") {
                        if (Test-LocationContainsIp -NamedLocation $excludedLocation -IpAddress $ipAddress) {
                            $isExcluded = $true
                            Write-Verbose "IP address '$ipAddress' in excluded named location '$($excludedLocation.DisplayName)'"
                            break
                        }
                    }
                    # Check if country code matches an excluded location
                    elseif ($countryCode -and $excludedLocation.Type -eq "CountryOrRegion") {
                        if (Test-LocationContainsCountry -NamedLocation $excludedLocation -CountryCode $countryCode) {
                            $isExcluded = $true
                            Write-Verbose "Country code '$countryCode' in excluded named location '$($excludedLocation.DisplayName)'"
                            break
                        }
                    }
                }

                if ($isExcluded) {
                    return @{
                        InScope = $false
                        Reason  = "All locations included but IP is in a specific excluded location"
                    }
                }
                else {
                    # IP is not in any excluded location, so it's in scope
                    Write-Verbose "All locations included and IP is not in any excluded location"
                    return @{
                        InScope = $true
                        Reason  = "All locations included and IP is not in any excluded location"
                    }
                }
            }

            # If "All" is included but there are no exclusions
            Write-Verbose "All locations included and no exclusions"
            return @{
                InScope = $true
                Reason  = "All locations included"
            }
        }

        # Check for "AllTrusted" inclusion
        if ($includeLocations -contains "AllTrusted") {
            if ($isTrustedLocation) {
                # If the location is trusted and "AllTrusted" is included, check if there are specific exclusions
                if (-not $excludeLocations -or $excludeLocations.Count -eq 0) {
                    Write-Verbose "All trusted locations included, no exclusions, and IP is in a trusted location"
                    return @{
                        InScope = $true
                        Reason  = "All trusted locations included"
                    }
                }
            }
            else {
                # If "AllTrusted" is the only inclusion but the location is not trusted, it's not in scope
                if ($includeLocations.Count -eq 1) {
                    Write-Verbose "Only trusted locations are included, but IP is not in a trusted location"
                    return @{
                        InScope = $false
                        Reason  = "IP not in a trusted location"
                    }
                }
            }
        }
    }

    # Check against excluded named locations
    if ($excludeLocations -and $excludeLocations.Count -gt 0) {
        # Check if named location ID is explicitly excluded
        if ($namedLocationId -and $excludeLocations -contains $namedLocationId) {
            Write-Verbose "Named location ID '$namedLocationId' explicitly excluded"
            return @{
                InScope = $false
                Reason  = "Named location explicitly excluded"
            }
        }

        # Check each excluded location
        foreach ($locationId in $excludeLocations) {
            # Skip special values which were handled above
            if ($locationId -eq "All" -or $locationId -eq "AllTrusted") {
                continue
            }

            # Check if the location exists in our cache
            if (-not $namedLocations.ContainsKey($locationId)) {
                Write-Verbose "Excluded location ID '$locationId' not found in cache, skipping"
                continue
            }

            $excludedLocation = $namedLocations[$locationId]

            # Check if IP matches an excluded location
            if ($ipAddress -and $excludedLocation.Type -eq "IP") {
                if (Test-LocationContainsIp -NamedLocation $excludedLocation -IpAddress $ipAddress) {
                    Write-Verbose "IP address '$ipAddress' in excluded named location '$($excludedLocation.DisplayName)'"
                    return @{
                        InScope = $false
                        Reason  = "IP address in excluded named location"
                    }
                }
            }

            # Check if country code matches an excluded location
            if ($countryCode -and $excludedLocation.Type -eq "CountryOrRegion") {
                if (Test-LocationContainsCountry -NamedLocation $excludedLocation -CountryCode $countryCode) {
                    Write-Verbose "Country code '$countryCode' in excluded named location '$($excludedLocation.DisplayName)'"
                    return @{
                        InScope = $false
                        Reason  = "Country in excluded named location"
                    }
                }
            }
        }
    }

    # Check if location is included (if no special "All" value handled above)
    $isIncluded = $false
    $includeReason = ""

    if ($includeLocations -and $includeLocations.Count -gt 0) {
        # Check if named location ID is explicitly included
        if ($namedLocationId -and $includeLocations -contains $namedLocationId) {
            Write-Verbose "Named location ID '$namedLocationId' explicitly included"
            $isIncluded = $true
            $includeReason = "Named location explicitly included"
        }

        # Check each included location if we haven't found a match yet
        if (-not $isIncluded) {
            foreach ($locationId in $includeLocations) {
                # Skip special values which were handled above
                if ($locationId -eq "All" -or $locationId -eq "AllTrusted") {
                    continue
                }

                # Check if the location exists in our cache
                if (-not $namedLocations.ContainsKey($locationId)) {
                    Write-Verbose "Included location ID '$locationId' not found in cache, skipping"
                    continue
                }

                $includedLocation = $namedLocations[$locationId]

                # Check if IP matches an included location
                if ($ipAddress -and $includedLocation.Type -eq "IP") {
                    if (Test-LocationContainsIp -NamedLocation $includedLocation -IpAddress $ipAddress) {
                        Write-Verbose "IP address '$ipAddress' in included named location '$($includedLocation.DisplayName)'"
                        $isIncluded = $true
                        $includeReason = "IP address in included named location"
                        break
                    }
                }

                # Check if country code matches an included location
                if ($countryCode -and $includedLocation.Type -eq "CountryOrRegion") {
                    if (Test-LocationContainsCountry -NamedLocation $includedLocation -CountryCode $countryCode) {
                        Write-Verbose "Country code '$countryCode' in included named location '$($includedLocation.DisplayName)'"
                        $isIncluded = $true
                        $includeReason = "Country in included named location"
                        break
                    }
                }
            }
        }
    }

    # ADDED: Special case for user-only queries with no network info
    # If we got this far and have no specific network info, be more permissive with location criteria
    if (-not $isIncluded && -not $ipAddress && -not $namedLocationId && -not $countryCode) {
        Write-Verbose "No network information provided, assuming this is a user-only query"

        # Already checked for country-based locations and "All" above, so this is a fallback
        # for any other type of location-based policies
        foreach ($locationId in $includeLocations) {
            # Skip special values which were handled above
            if ($locationId -eq "All" -or $locationId -eq "AllTrusted") {
                continue
            }

            # Check if the location exists in our cache
            if (-not $namedLocations.ContainsKey($locationId)) {
                continue
            }

            $location = $namedLocations[$locationId]

            # Check if this is a country location
            if ($location.Type -eq "CountryOrRegion") {
                $isIncluded = $true
                $includeReason = "Country-based location with no location specified"
                break
            }
        }
    }

    if ($isIncluded) {
        return @{
            InScope = $true
            Reason  = $includeReason
        }
    }
    else {
        # Provide more specific reason based on what information was provided
        $specificReason = if ($ipAddress) {
            if ($isTrustedLocation -eq $true) {
                "IP address $ipAddress is in a trusted location but not included in policy scope"
            }
            elseif ($isTrustedLocation -eq $false) {
                "IP address $ipAddress is not in any included location/network"
            }
            else {
                "IP address $ipAddress not found in any included locations"
            }
        }
        elseif ($namedLocationId) {
            "Named location '$namedLocationId' not in any inclusion lists"
        }
        elseif ($countryCode) {
            "Country '$countryCode' not in any inclusion lists"
        }
        else {
            "Location not in any inclusion lists"
        }

        Write-Verbose $specificReason
        return @{
            InScope = $false
            Reason  = $specificReason
        }
    }
}

function Test-IpInNamedLocation {
    <#
.SYNOPSIS
    Tests if an IP address is contained within a named location.

.DESCRIPTION
    This function evaluates if an IP address falls within any of the
    IP ranges defined in a named location, supporting CIDR notation.

.PARAMETER IpAddress
    The IP address to check.

.PARAMETER NamedLocation
    The named location object containing IP ranges.

.EXAMPLE
    Test-IpInNamedLocation -IpAddress "192.168.1.1" -NamedLocation $namedLocation
#>
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param (
        [Parameter(Mandatory = $true)]
        [string]$IpAddress,

        [Parameter(Mandatory = $true)]
        [object]$NamedLocation
    )

    # If named location has no IP ranges, the IP cannot be in it
    if (-not $NamedLocation.IpRanges -or $NamedLocation.IpRanges.Count -eq 0) {
        return $false
    }

    foreach ($ipRange in $NamedLocation.IpRanges) {
        # Check if range is in CIDR notation
        if ($ipRange -match "^(.+)/(\d+)$") {
            $networkAddress = $matches[1]
            $cidrPrefix = [int]$matches[2]

            if (Test-IpInCidrRange -IpAddress $IpAddress -NetworkAddress $networkAddress -CidrPrefix $cidrPrefix) {
                return $true
            }
        }
        # Check if range is a simple IP address (exact match)
        elseif ($ipRange -eq $IpAddress) {
            return $true
        }
        # Check if range is in start-end format
        elseif ($ipRange -match "^(.+)-(.+)$") {
            $startIp = $matches[1]
            $endIp = $matches[2]

            if (Test-IpInRange -IpAddress $IpAddress -StartIp $startIp -EndIp $endIp) {
                return $true
            }
        }
    }

    return $false
}

function Test-IpInCidrRange {
    <#
.SYNOPSIS
    Tests if an IP address is within a CIDR range.

.DESCRIPTION
    This function determines if an IP address falls within the range
    specified by a network address and CIDR prefix.

.PARAMETER IpAddress
    The IP address to check.

.PARAMETER NetworkAddress
    The network address of the CIDR range.

.PARAMETER CidrPrefix
    The CIDR prefix (subnet mask) of the range.

.EXAMPLE
    Test-IpInCidrRange -IpAddress "192.168.1.1" -NetworkAddress "192.168.0.0" -CidrPrefix 16
#>
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param (
        [Parameter(Mandatory = $true)]
        [string]$IpAddress,

        [Parameter(Mandatory = $true)]
        [string]$NetworkAddress,

        [Parameter(Mandatory = $true)]
        [int]$CidrPrefix
    )

    try {
        # Convert IP address string to bytes
        $ipBytes = [System.Net.IPAddress]::Parse($IpAddress).GetAddressBytes()

        # Convert network address string to bytes
        $networkBytes = [System.Net.IPAddress]::Parse($NetworkAddress).GetAddressBytes()

        # If IPv6, handle separately
        if ($ipBytes.Length -ne 4) {
            Write-Verbose "IPv6 address detected. IPv6 handling not fully implemented."
            return $false # For now, we'll skip IPv6 handling for simplicity
        }

        # Calculate subnet mask from CIDR prefix
        $mask = [UInt32](-bnot (([UInt32]1 -shl (32 - $CidrPrefix)) - 1))

        # Convert IP address and network to integers for comparison
        $ipInt = ([UInt32]$ipBytes[0] -shl 24) -bor ([UInt32]$ipBytes[1] -shl 16) -bor ([UInt32]$ipBytes[2] -shl 8) -bor $ipBytes[3]
        $networkInt = ([UInt32]$networkBytes[0] -shl 24) -bor ([UInt32]$networkBytes[1] -shl 16) -bor ([UInt32]$networkBytes[2] -shl 8) -bor $networkBytes[3]

        # Apply mask to both IP and network, then compare
        return (($ipInt -band $mask) -eq ($networkInt -band $mask))
    }
    catch {
        Write-Warning "Error testing IP in CIDR range: $_"
        return $false
    }
}

function Test-IpInRange {
    <#
.SYNOPSIS
    Tests if an IP address is within a range specified by start and end IPs.

.DESCRIPTION
    This function determines if an IP address falls between a start and end IP address.

.PARAMETER IpAddress
    The IP address to check.

.PARAMETER StartIp
    The starting IP address of the range.

.PARAMETER EndIp
    The ending IP address of the range.

.EXAMPLE
    Test-IpInRange -IpAddress "192.168.1.10" -StartIp "192.168.1.1" -EndIp "192.168.1.20"
#>
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param (
        [Parameter(Mandatory = $true)]
        [string]$IpAddress,

        [Parameter(Mandatory = $true)]
        [string]$StartIp,

        [Parameter(Mandatory = $true)]
        [string]$EndIp
    )

    try {
        # Convert IP addresses to bytes
        $ipBytes = [System.Net.IPAddress]::Parse($IpAddress).GetAddressBytes()
        $startBytes = [System.Net.IPAddress]::Parse($StartIp).GetAddressBytes()
        $endBytes = [System.Net.IPAddress]::Parse($EndIp).GetAddressBytes()

        # If IPv6, handle separately
        if ($ipBytes.Length -ne 4) {
            Write-Verbose "IPv6 address detected. IPv6 handling not fully implemented."
            return $false # For now, we'll skip IPv6 handling for simplicity
        }

        # Convert IP addresses to integers for comparison
        $ipInt = ([UInt32]$ipBytes[0] -shl 24) -bor ([UInt32]$ipBytes[1] -shl 16) -bor ([UInt32]$ipBytes[2] -shl 8) -bor $ipBytes[3]
        $startInt = ([UInt32]$startBytes[0] -shl 24) -bor ([UInt32]$startBytes[1] -shl 16) -bor ([UInt32]$startBytes[2] -shl 8) -bor $startBytes[3]
        $endInt = ([UInt32]$endBytes[0] -shl 24) -bor ([UInt32]$endBytes[1] -shl 16) -bor ([UInt32]$endBytes[2] -shl 8) -bor $endBytes[3]

        # Check if IP is within the range
        return ($ipInt -ge $startInt -and $ipInt -le $endInt)
    }
    catch {
        Write-Warning "Error testing IP in range: $_"
        return $false
    }
}

function Get-NamedLocation {
    <#
.SYNOPSIS
    Retrieves a named location by ID.

.DESCRIPTION
    This function retrieves a named location from Microsoft Graph API or from a cache.
    It supports retrieving both IP-based and country/region-based named locations.

.PARAMETER LocationId
    The ID of the named location to retrieve.

.EXAMPLE
    Get-NamedLocation -LocationId "a1b2c3d4-e5f6-7890-1234-567890abcdef"
#>
    [CmdletBinding()]
    [OutputType([System.Object])]
    param (
        [Parameter(Mandatory = $true)]
        [string]$LocationId
    )

    # Check if location is in cache
    if ($script:NamedLocationsCache -and $script:NamedLocationsCache.ContainsKey($LocationId)) {
        Write-Verbose "Retrieved named location '$LocationId' from cache"
        return $script:NamedLocationsCache[$LocationId]
    }

    try {
        # Retrieve named location from Graph API
        $location = Get-MgIdentityConditionalAccessNamedLocation -NamedLocationId $LocationId

        # Initialize cache if not exists
        if (-not $script:NamedLocationsCache) {
            $script:NamedLocationsCache = @{}
        }

        # Add to cache
        $script:NamedLocationsCache[$LocationId] = $location

        return $location
    }
    catch {
        Write-Warning "Error retrieving named location '$LocationId': $_"
        return $null
    }
}