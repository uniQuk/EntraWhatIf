function Test-TrustedLocation {
    <#
    .SYNOPSIS
        Tests if an IP address is in a trusted named location.

    .DESCRIPTION
        This function checks if a given IP address is within any trusted named location
        defined in your Microsoft Entra ID tenant. It's useful for debugging Conditional
        Access location-based policies.

    .PARAMETER IpAddress
        The IP address to check.

    .PARAMETER Verbose
        If specified, provides detailed information about the matching process.

    .EXAMPLE
        Test-TrustedLocation -IpAddress "82.37.35.24"

    .EXAMPLE
        Test-TrustedLocation -IpAddress "82.38.35.24" -Verbose
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$IpAddress
    )

    Write-Verbose "Testing if IP address $IpAddress is in a trusted location"

    # Get all named locations
    $namedLocations = Get-NamedLocations -ForceRefresh

    Write-Verbose "Retrieved $($namedLocations.Count) named locations"

    $isInTrustedLocation = $false
    $matchingLocations = @()

    # Check each location
    foreach ($locationId in $namedLocations.Keys) {
        $location = $namedLocations[$locationId]

        # Skip non-IP locations
        if ($location.Type -ne "IP") {
            Write-Verbose "Skipping non-IP location: $($location.DisplayName)"
            continue
        }

        Write-Verbose "Checking location: $($location.DisplayName) (Trusted: $($location.IsTrusted))"

        # Test if IP is in this location
        $isInLocation = Test-LocationContainsIp -NamedLocation $location -IpAddress $IpAddress

        if ($isInLocation) {
            Write-Verbose "IP $IpAddress is in location: $($location.DisplayName)"
            $matchingLocations += [PSCustomObject]@{
                LocationId  = $location.Id
                DisplayName = $location.DisplayName
                IsTrusted   = $location.IsTrusted
                IpRanges    = $location.IpRanges -join ', '
            }

            if ($location.IsTrusted) {
                $isInTrustedLocation = $true
            }
        }
    }

    # Output results
    $result = [PSCustomObject]@{
        IpAddress           = $IpAddress
        IsInTrustedLocation = $isInTrustedLocation
        MatchingLocations   = $matchingLocations
    }

    # Format output
    if ($matchingLocations.Count -gt 0) {
        Write-Host "IP address $IpAddress is in these locations:" -ForegroundColor Cyan
        $matchingLocations | Format-Table -AutoSize

        if ($isInTrustedLocation) {
            Write-Host "Result: IP address IS in a trusted location" -ForegroundColor Green
        }
        else {
            Write-Host "Result: IP address is NOT in a trusted location" -ForegroundColor Yellow
        }
    }
    else {
        Write-Host "IP address $IpAddress is not in any named location" -ForegroundColor Yellow
    }

    return $result
}

Export-ModuleMember -Function Test-TrustedLocation