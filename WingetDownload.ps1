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
 
Foreach ($Installer in $parseddata.Installers)
    {
        $DestinationFile = "$($FolderPath)\$($Installer.InstallerUrl | Split-Path -Leaf)"
        If (!(Test-Path "$($DestinationFile).SKIP")){
            If (!(Test-Path $DestinationFile)) {
                "Downloading $DestinationFile"
                Invoke-WebRequest -Uri $Installer.InstallerUrl -OutFile $DestinationFile
            }
            $calculatedHash = Get-FileHash -Path $DestinationFile -Algorithm SHA256
            if ($calculatedHash.Hash -eq $Installer.InstallerSha256) {
                "$($DestinationFile) hash matches. The file integrity is verified."
            } else {
                "$($DestinationFile) hash does not match. The file may be corrupted."
            }
        }
    }


