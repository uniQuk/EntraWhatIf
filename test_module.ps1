# Test script for module loading
$ErrorActionPreference = 'Continue'

Write-Host "Current location: $(Get-Location)"
Write-Host "Module directory exists: $(Test-Path -Path './whatifcli')"

# First remove the module if it's already loaded
if (Get-Module -Name whatifcli) {
    Remove-Module -Name whatifcli -Force
    Write-Host "Removed existing whatifcli module"
}

# Import the module using absolute path
$modulePath = Join-Path -Path (Get-Location).Path -ChildPath "whatifcli"
Write-Host "Attempting to import module from: $modulePath"

Import-Module $modulePath -Verbose

# Check if the module was loaded
if (Get-Module -Name whatifcli) {
    Write-Host "Module whatifcli loaded successfully" -ForegroundColor Green
    Write-Host "Exported functions:"
    Get-Command -Module whatifcli | Format-Table -Property Name, CommandType
}
else {
    Write-Host "Failed to load whatifcli module" -ForegroundColor Red
}

# Try to invoke the function
try {
    Write-Host "Attempting to run Invoke-CAWhatIf..."
    Get-Command Invoke-CAWhatIf -ErrorAction Stop
    Write-Host "Invoke-CAWhatIf command exists." -ForegroundColor Green

    # Try to run the function with a test user
    Write-Host "Testing the function with a user..."
    Invoke-CAWhatIf -UserId "test@example.com" -Diagnostic
}
catch {
    Write-Host "Error: $_" -ForegroundColor Red
}