try {
    # Import the module
    Write-Output "Importing module..."
    Import-Module -Name './whatifcli.psd1' -Force -ErrorAction Stop

    # Get module info
    $module = Get-Module -Name whatifcli

    # Display module info
    Write-Output "Module successfully imported!"
    Write-Output "Module Name: $($module.Name)"
    Write-Output "Version: $($module.Version)"
    Write-Output "Path: $($module.Path)"
    Write-Output "Exported Functions: $($module.ExportedFunctions.Keys -join ', ')"
}
catch {
    Write-Error "Failed to import module: $_"
    Write-Error $_.ScriptStackTrace
}