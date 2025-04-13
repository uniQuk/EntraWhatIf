$moduleRoot = $PSScriptRoot
Write-Output "Module root: $moduleRoot"

# Check if module manifest exists
$manifestPath = Join-Path -Path $moduleRoot -ChildPath "whatifcli.psd1"
if (Test-Path -Path $manifestPath) {
    Write-Output "Module manifest found: $manifestPath"
}
else {
    Write-Error "Module manifest not found at: $manifestPath"
}

# Check if module script exists
$moduleScriptPath = Join-Path -Path $moduleRoot -ChildPath "whatifcli.psm1"
if (Test-Path -Path $moduleScriptPath) {
    Write-Output "Module script found: $moduleScriptPath"
}
else {
    Write-Error "Module script not found at: $moduleScriptPath"
}

# Check subdirectories
$privateDir = Join-Path -Path $moduleRoot -ChildPath "Private"
if (Test-Path -Path $privateDir -PathType Container) {
    $privateDirs = Get-ChildItem -Path $privateDir -Directory
    Write-Output "Private subdirectories:"
    $privateDirs | ForEach-Object { Write-Output "  - $($_.Name)" }

    # Check if required files are in the correct subdirectories
    $requiredFiles = @{
        "Cache"      = @("Get-CacheManager.ps1", "Get-CAPolicy.ps1")
        "Identity"   = @("Resolve-UserIdentity.ps1", "Resolve-GroupMembership.ps1")
        "Conditions" = @("Resolve-CACondition.ps1", "Test-SpecialValue.ps1")
        "Controls"   = @("Resolve-CAGrantControl.ps1", "Resolve-CASessionControl.ps1")
        "Output"     = @("Format-MicrosoftCAWhatIfResponse.ps1", "Write-DiagnosticOutput.ps1")
    }

    foreach ($dir in $requiredFiles.Keys) {
        $dirPath = Join-Path -Path $privateDir -ChildPath $dir
        if (-not (Test-Path -Path $dirPath -PathType Container)) {
            Write-Error "Required directory not found: $dirPath"
        }
        else {
            foreach ($file in $requiredFiles[$dir]) {
                $filePath = Join-Path -Path $dirPath -ChildPath $file
                if (-not (Test-Path -Path $filePath -PathType Leaf)) {
                    Write-Warning "Required file missing: $filePath"
                }
            }
        }
    }
}
else {
    Write-Error "Private directory not found at: $privateDir"
}

$publicDir = Join-Path -Path $moduleRoot -ChildPath "Public"
if (Test-Path -Path $publicDir -PathType Container) {
    $publicFiles = Get-ChildItem -Path $publicDir -Filter "*.ps1"
    Write-Output "Public files:"
    $publicFiles | ForEach-Object { Write-Output "  - $($_.Name)" }
}
else {
    Write-Error "Public directory not found at: $publicDir"
}