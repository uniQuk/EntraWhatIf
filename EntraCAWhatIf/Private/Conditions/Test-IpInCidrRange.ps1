function Test-IpInCidrRange {
    <#
    .SYNOPSIS
        Tests if an IP address is within a CIDR range with improved debugging.

    .DESCRIPTION
        This function determines if an IP address falls within the range
        specified by a network address and CIDR prefix, with additional
        verbose logging to help diagnose IP matching issues.

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
        Write-Verbose "Testing if IP $IpAddress is in CIDR range $NetworkAddress/$CidrPrefix"

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
        $maskFormatted = [System.Net.IPAddress]::new([byte[]]@(
            ($mask -shr 24) -band 0xFF,
            ($mask -shr 16) -band 0xFF,
            ($mask -shr 8) -band 0xFF,
                $mask -band 0xFF
            ))

        Write-Verbose "Using subnet mask: $($maskFormatted.ToString())"

        # Convert IP address and network to integers for comparison
        $ipInt = ([UInt32]$ipBytes[0] -shl 24) -bor ([UInt32]$ipBytes[1] -shl 16) -bor ([UInt32]$ipBytes[2] -shl 8) -bor $ipBytes[3]
        $networkInt = ([UInt32]$networkBytes[0] -shl 24) -bor ([UInt32]$networkBytes[1] -shl 16) -bor ([UInt32]$networkBytes[2] -shl 8) -bor $networkBytes[3]

        # Format for logging
        $ipNetworkPart = $ipInt -band $mask
        $networkNetworkPart = $networkInt -band $mask

        $ipNetworkFormatted = [System.Net.IPAddress]::new([byte[]]@(
            ($ipNetworkPart -shr 24) -band 0xFF,
            ($ipNetworkPart -shr 16) -band 0xFF,
            ($ipNetworkPart -shr 8) -band 0xFF,
                $ipNetworkPart -band 0xFF
            ))

        $networkNetworkFormatted = [System.Net.IPAddress]::new([byte[]]@(
            ($networkNetworkPart -shr 24) -band 0xFF,
            ($networkNetworkPart -shr 16) -band 0xFF,
            ($networkNetworkPart -shr 8) -band 0xFF,
                $networkNetworkPart -band 0xFF
            ))

        Write-Verbose "IP network part: $($ipNetworkFormatted.ToString())"
        Write-Verbose "CIDR network part: $($networkNetworkFormatted.ToString())"

        # Apply mask to both IP and network, then compare
        $result = (($ipInt -band $mask) -eq ($networkInt -band $mask))

        Write-Verbose "IP $IpAddress is$(if(-not $result) { " NOT" }) in CIDR range $NetworkAddress/$CidrPrefix"

        return $result
    }
    catch {
        Write-Warning "Error testing IP in CIDR range: $_"
        return $false
    }
}