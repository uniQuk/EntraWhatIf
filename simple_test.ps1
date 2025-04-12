# Get any existing paths where PowerShell looks for modules
$paths = $env:PSModulePath -split ":" | Where-Object { Test-Path $_ }
Write-Host "Current module paths:"
$paths | ForEach-Object { Write-Host "  $_" }

# Add the current directory to the module path
$currentDir = (Get-Location).Path
$env:PSModulePath = "$currentDir;$env:PSModulePath"
Write-Host "Added current directory to module path: $currentDir"

# Try to import the module
Write-Host "Attempting to import module..."
Import-Module whatifcli -Force -Verbose

# Check if it was loaded
if (Get-Module whatifcli) {
    Write-Host "Module loaded successfully" -ForegroundColor Green

    # List available commands
    Write-Host "Available commands:"
    Get-Command -Module whatifcli
}
else {
    Write-Host "Failed to load module" -ForegroundColor Red
}