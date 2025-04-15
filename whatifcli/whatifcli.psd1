# Module manifest for module 'whatifcli'
@{
    # Script module or binary module file associated with this manifest.
    RootModule        = 'whatifcli.psm1'

    # Version number of this module.
    ModuleVersion     = '0.1.0'

    # ID used to uniquely identify this module
    GUID              = '52f62b7a-8d7d-4f81-a260-72b2beee77af'

    # Author of this module
    Author            = 'Josh - https://github.com/uniQuk'

    # Company or vendor of this module
    CompanyName       = 'North7'

    # Copyright statement for this module
    Copyright         = 'MIT License (c) 2025 Josh'

    # Description of the functionality provided by this module
    Description       = 'A module to simulate Microsoft Entra Conditional Access policy evaluation for hypothetical sign-in scenarios.'

    # Minimum version of the PowerShell engine required by this module
    PowerShellVersion = '7.0.0'

    # Modules that must be imported into the global environment prior to importing this module
    RequiredModules   = @(
        @{
            ModuleName    = 'Microsoft.Graph.Authentication'
            ModuleVersion = '2.26.0'
        },
        @{
            ModuleName    = 'Microsoft.Graph.Identity.SignIns'
            ModuleVersion = '2.26.0'
        }
    )

    # Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
    FunctionsToExport = @(
        'Invoke-CAWhatIf',
        'Get-CAWhatIfReport',
        'Resolve-UserIdentity',
        'Resolve-GroupMembership'
    )

    # Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
    CmdletsToExport   = @()

    # Variables to export from this module
    VariablesToExport = '*'

    # Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
    AliasesToExport   = @('cawhatif')

    # Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
    PrivateData       = @{
        PSData = @{
            # Tags applied to this module. These help with module discovery in online galleries.
            Tags         = @('EntraID', 'AzureAD', 'ConditionalAccess', 'WhatIf', 'Security')

            # A URL to the license for this module.
            LicenseUri   = 'https://github.com/uniQuk/EntraWhatIf/blob/main/LICENSE'

            # A URL to the main website for this project.
            ProjectUri   = 'https://github.com/uniQuk/EntraWhatIf'

            # ReleaseNotes of this module
            ReleaseNotes = 'Initial release of the WhatIfCA module.'
        }
    }
}