function Get-CAWhatIfDiagnostic {
    <#
    .SYNOPSIS
        Provides diagnostic information about the EntraCAWhatIf tool compared to Microsoft's implementation.

    .DESCRIPTION
        This function explains the differences between Microsoft's Conditional Access WhatIf API
        and this PowerShell module's implementation, focusing on key differences in handling parameters.

    .PARAMETER Feature
        The specific feature to get diagnostic information about. Valid options are:
        - Location: Information about IP vs Country handling differences
        - Platform: Information about device platform handling
        - All: All diagnostic information

    .EXAMPLE
        Get-CAWhatIfDiagnostic -Feature Location

    .EXAMPLE
        Get-CAWhatIfDiagnostic -Feature All
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [ValidateSet('Location', 'Platform', 'All')]
        [string]$Feature = 'All'
    )

    function Write-FeatureHeader {
        param ([string]$Title)

        Write-Host "`n$('=' * $Title.Length)"
        Write-Host $Title
        Write-Host "$('=' * $Title.Length)"
    }

    if ($Feature -eq 'Location' -or $Feature -eq 'All') {
        Write-FeatureHeader "LOCATION HANDLING"

        Write-Host "Microsoft API vs EntraCAWhatIf module:" -ForegroundColor Yellow
        Write-Host "Microsoft's Conditional Access WhatIf API requires both IP address and country code" -ForegroundColor Cyan
        Write-Host "EntraCAWhatIf allows either IP address or country code (or both)" -ForegroundColor Green

        Write-Host "`nKey differences:" -ForegroundColor Yellow
        Write-Host "1. Microsoft requires both parameters even if only one is used in policy evaluation" -ForegroundColor White
        Write-Host "2. EntraCAWhatIf is more flexible - you can provide only what you need" -ForegroundColor White
        Write-Host "3. IP-based trust detection is automatic in EntraCAWhatIf" -ForegroundColor White

        Write-Host "`nRecommendations:" -ForegroundColor Yellow
        Write-Host "• When a CA policy uses 'AllTrusted' exclusion:" -ForegroundColor White
        Write-Host "  - Provide an IP address so trust status can be determined" -ForegroundColor White
        Write-Host "  - OR explicitly set -IsTrustedLocation parameter" -ForegroundColor White
        Write-Host "• For most accurate results, provide both IP and country when possible" -ForegroundColor White

        Write-Host "`nTesting tools:" -ForegroundColor Yellow
        Write-Host "• Use Test-TrustedLocation function to check if an IP is in a trusted location" -ForegroundColor White
        Write-Host "  Example: Test-TrustedLocation -IpAddress '82.37.35.24' -Verbose" -ForegroundColor Gray
    }

    if ($Feature -eq 'Platform' -or $Feature -eq 'All') {
        Write-FeatureHeader "DEVICE PLATFORM HANDLING"

        Write-Host "Microsoft API vs EntraCAWhatIf module:" -ForegroundColor Yellow
        Write-Host "Microsoft's API requires explicit platform specification" -ForegroundColor Cyan
        Write-Host "EntraCAWhatIf is more flexible with platform handling" -ForegroundColor Green

        Write-Host "`nKey differences:" -ForegroundColor Yellow
        Write-Host "1. When platform parameter isn't specified:" -ForegroundColor White
        Write-Host "   - Policies with 'all' platforms will still apply" -ForegroundColor White
        Write-Host "   - Policies with specific platform requirements may be skipped" -ForegroundColor White
        Write-Host "2. The 'all' platform value is case-sensitive in Microsoft's implementation" -ForegroundColor White
        Write-Host "   - EntraCAWhatIf handles 'all', 'All', or 'ALL' equally" -ForegroundColor White

        Write-Host "`nRecommendations:" -ForegroundColor Yellow
        Write-Host "• Always specify -DevicePlatform when testing policies with platform conditions" -ForegroundColor White
        Write-Host "• Use lowercase 'windows', 'ios', 'android', etc. for platform values" -ForegroundColor White
    }

    if ($Feature -eq 'All') {
        Write-FeatureHeader "ABOUT ENTRACAWHATIF"

        Write-Host "EntraCAWhatIf is an unofficial implementation of Microsoft's Conditional Access WhatIf API" -ForegroundColor Yellow
        Write-Host "It aims to provide similar functionality with greater flexibility and transparency"
        Write-Host "For more information, run: Get-Help Invoke-CAWhatIf -Full"
    }
}

Export-ModuleMember -Function Get-CAWhatIfDiagnostic