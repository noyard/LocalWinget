param (
    [Parameter(Mandatory = $true)]
    [ValidatePattern("^C:\\")]
    [string]$FolderPath
)

# Check if the folder exists
if (Test-Path -Path $FolderPath) {
    Write-Host "The folder '$FolderPath' exists. Listing contents:" -ForegroundColor Green
    Get-ChildItem -Path $FolderPath
} else {
    Write-Host "The folder '$FolderPath' does not exist." -ForegroundColor Red
}

## Register Winget if not registered
$package = Get-AppxPackage -Name Microsoft.DesktopAppInstaller -ErrorAction SilentlyContinue

if ($package) {
    Write-Output "Microsoft.DesktopAppInstaller is installed."
    if ($package.PackageFamilyName -and $package.InstallLocation) {
        Write-Output "Microsoft.DesktopAppInstaller is registered."
    } else {
        Write-Output "Microsoft.DesktopAppInstaller is installed but not properly registered."
	$WinGet =$(Get-AppxPackage "Microsoft.DesktopAppInstaller")
	Add-AppxPackage -DisableDevelopmentMode -Register "$($Winget.InstallLocation)\AppXManifest.xml"
    }
} else {
    Write-Output "Microsoft.DesktopAppInstaller is not installed."
}

## Set winget to enable local manifest files
winget settings --enable LocalManifestFiles

## Set winget to disable scanning of compressed files
winget settings --enable LocalArchiveMalwareScanOverride

## bypass smart screen for winget installs
$registryPath = "HKCU:\Software\Classes\exefile\shell\open"
$registryName = "NoSmartScreen"
$registryValue = 1

# Check if the registry path exists
if (!(Test-Path $registryPath)) {
    [void](New-Item -Path $registryPath -Force)
}

# Create the DWORD value
[void](New-ItemProperty -Path $registryPath -Name $registryName -Value $registryValue -PropertyType DWORD -Force)
Write-Output "DWORD value 'NoSmartScreen' has been created under $registryPath."

# Read the YAML file
if(test-path "$($FolderPath)/*installer.yaml")
    {
        $Yaml = (Get-ChildItem "$($FolderPath)/*installer.yaml").FullName

}else{
        $Yaml = (Get-ChildItem "$($FolderPath)/*.yaml").FullName
}      
$yamlContent = Get-Content -Path $Yaml -Raw

# Convert YAML to PowerShell objects
$parsedData = ConvertFrom-Yaml -Yaml $yamlContent
$packageIdentifier = $parseddata.PackageIdentifier
$Version = $parsedData.PackageVersion  

## copy files to %temp%\winget\
$destination = "$($env:TEMP)\winget\$($packageIdentifier).$($version)"
# Get all items recursively except *.yaml files
Get-ChildItem -Path $FolderPath -Recurse -File | Where-Object { $_.Extension -ne ".yaml" } | ForEach-Object {
    # Determine the relative path to preserve structure
    $relativePath = $_.FullName.Substring($FolderPath.Length)
    $targetPath = Join-Path $destination $relativePath

    # Create the target directory if it doesn't exist
    $targetDir = Split-Path $targetPath
    if (-not (Test-Path $targetDir)) {
        New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
    }

    # Move the file
    Move-Item -Path $_.FullName -Destination $targetPath -Force
}

## start winget install. 
Winget install --manifest "$($folderpath)"
 
## logs
$logs ="%LOCALAPPDATA%\Packages\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\LocalState\DiagOutputDir"