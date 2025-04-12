# WhatIfCA - Conditional Access WhatIf PowerShell Module
# This module simulates the evaluation of Microsoft Entra Conditional Access policies
# against hypothetical sign-in scenarios

# Module Variables
$script:CAPolicies = @()
$script:NamedLocations = @()
$script:CAApplications = @()

# Load dependent modules
if (-not (Get-Module Microsoft.Graph.Identity.SignIns -ListAvailable)) {
    Write-Warning "Microsoft.Graph.Identity.SignIns module not found. Installing..."
    Install-Module Microsoft.Graph.Identity.SignIns -Scope CurrentUser -Force
}

if (-not (Get-Module Microsoft.Graph.Authentication -ListAvailable)) {
    Write-Warning "Microsoft.Graph.Authentication module not found. Installing..."
    Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force
}

# Import submodules
$ModulePath = Split-Path -Path $MyInvocation.MyCommand.Path -Parent
$PublicPath = Join-Path -Path $ModulePath -ChildPath 'Public'
$PrivatePath = Join-Path -Path $ModulePath -ChildPath 'Private'

function ImportIndividualFunctions {
    param (
        [string]$Path,
        [string]$ErrorActionPreference = 'Stop'
    )

    if (Test-Path -Path $Path -ErrorAction SilentlyContinue) {
        $Functions = @(Get-ChildItem -Path $Path -Filter "*.ps1" -ErrorAction SilentlyContinue)

        foreach ($Function in $Functions) {
            try {
                Write-Verbose "Importing $($Function.FullName)"
                . $Function.FullName
            }
            catch {
                Write-Error "Failed to import $($Function.FullName): $_"
                continue
            }
        }
    }
}

# Clear any previously imported module functions
$ExportedFunctions = @()

# Import all Private module functions
$PrivatePath = Join-Path -Path $PSScriptRoot -ChildPath 'Private'
ImportIndividualFunctions -Path $PrivatePath

# Import all Public module functions
$PublicPath = Join-Path -Path $PSScriptRoot -ChildPath 'Public'
ImportIndividualFunctions -Path $PublicPath

# Export all Public module functions
$PublicFunctions = @(Get-ChildItem -Path $PublicPath -Filter "*.ps1" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty BaseName)
Export-ModuleMember -Function $PublicFunctions

# Create/update any aliases and export them
Set-Alias -Name 'cawhatif' -Value 'Invoke-CAWhatIf'
Export-ModuleMember -Alias 'cawhatif'

# Export the main function
Export-ModuleMember -Function 'Invoke-CAWhatIf', 'Get-CAWhatIfReport'