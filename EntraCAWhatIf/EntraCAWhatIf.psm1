# whatifcli - Conditional Access WhatIf PowerShell Module
# This module simulates the evaluation of Microsoft Entra Conditional Access policies
# against hypothetical sign-in scenarios

# Get the directory where this script is located
$PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition

# Dot source the public functions
. "$PSScriptRoot\Public\Invoke-CAWhatIf.ps1"
. "$PSScriptRoot\Public\Get-CAWhatIfReport.ps1"
. "$PSScriptRoot\Public\Test-TrustedLocation.ps1"
. "$PSScriptRoot\Public\Get-CAWhatIfDiagnostic.ps1"

# Dot source private functions by category
# Identity functions
. "$PSScriptRoot\Private\Identity\Resolve-UserIdentity.ps1"
. "$PSScriptRoot\Private\Identity\Resolve-ServicePrincipalIdentity.ps1"
. "$PSScriptRoot\Private\Identity\Resolve-GroupMembership.ps1"

# Condition evaluation functions
. "$PSScriptRoot\Private\Conditions\Resolve-CACondition.ps1"
. "$PSScriptRoot\Private\Conditions\Test-SpecialValue.ps1"
. "$PSScriptRoot\Private\Conditions\Test-NetworkInScope.ps1"
. "$PSScriptRoot\Private\Conditions\Test-DeviceFilter.ps1"
. "$PSScriptRoot\Private\Conditions\Test-AuthenticationStrength.ps1"
. "$PSScriptRoot\Private\Conditions\Test-ServicePrincipalInScope.ps1"
. "$PSScriptRoot\Private\Conditions\Test-UserActionInScope.ps1"
. "$PSScriptRoot\Private\Conditions\Test-AuthenticationContextInScope.ps1"

# Control evaluation functions
. "$PSScriptRoot\Private\Controls\Resolve-CAGrantControl.ps1"
. "$PSScriptRoot\Private\Controls\Resolve-CASessionControl.ps1"

# Caching and API optimization functions
. "$PSScriptRoot\Private\Cache\Get-CAPolicy.ps1"
. "$PSScriptRoot\Private\Cache\Get-NamedLocations.ps1"
. "$PSScriptRoot\Private\Cache\Invoke-GraphBatchRequest.ps1"
. "$PSScriptRoot\Private\Cache\Get-OptimizedGroupMembership.ps1"
. "$PSScriptRoot\Private\Cache\Get-CacheManager.ps1"

# Output and formatting functions
. "$PSScriptRoot\Private\Output\Format-MicrosoftCAWhatIfResponse.ps1"
. "$PSScriptRoot\Private\Output\Write-DiagnosticOutput.ps1"

# Export the public functions
Export-ModuleMember -Function 'Invoke-CAWhatIf', 'Get-CAWhatIfReport', 'Test-TrustedLocation', 'Get-CAWhatIfDiagnostic'

# Create an alias
New-Alias -Name 'cawhatif' -Value 'Invoke-CAWhatIf'
Export-ModuleMember -Alias 'cawhatif'