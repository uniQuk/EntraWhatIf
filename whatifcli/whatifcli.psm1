# whatifcli - Conditional Access WhatIf PowerShell Module
# This module simulates the evaluation of Microsoft Entra Conditional Access policies
# against hypothetical sign-in scenarios

# Get the directory where this script is located
$PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition

# Dot source the functions directly
. "$PSScriptRoot\Public\Invoke-CAWhatIf.ps1"
. "$PSScriptRoot\Public\Get-CAWhatIfReport.ps1"
. "$PSScriptRoot\Private\Resolve-UserIdentity.ps1"
. "$PSScriptRoot\Private\Resolve-GroupMembership.ps1"
. "$PSScriptRoot\Private\Resolve-CACondition.ps1"
. "$PSScriptRoot\Private\Resolve-CAGrantControl.ps1"
. "$PSScriptRoot\Private\Resolve-CASessionControl.ps1"
. "$PSScriptRoot\Private\Get-CAPolicy.ps1"

# Export the public functions
Export-ModuleMember -Function 'Invoke-CAWhatIf', 'Get-CAWhatIfReport'

# Create an alias
New-Alias -Name 'cawhatif' -Value 'Invoke-CAWhatIf'
Export-ModuleMember -Alias 'cawhatif'