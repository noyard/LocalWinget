function Winget-Install {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$AppName,
        [string]$Version
    )
    
    # Check if running as administrator
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $isAdmin) {
        Write-Error "This script must be run as Administrator. Please restart PowerShell as Administrator and try again."
        throw "Administrator privileges required"
    }
    
    Write-Verbose "[DEBUG] Running as Administrator - OK"
    
    # Check for required PowerShell modules
    try {
        if (-not (Get-Command "ConvertFrom-Yaml" -ErrorAction SilentlyContinue)) {
            Write-Warning "ConvertFrom-Yaml command not found. Attempting to install powershell-yaml module..."
            try {
                Install-Module -Name powershell-yaml -Force -Scope CurrentUser -ErrorAction Stop
                Import-Module powershell-yaml -Force
                ##Copy-item -Path .\powershell-yaml.0.4.12 -Destination "C:\Program Files\PowerShell\Modules\powershell-yaml" -Recurse
                Write-Verbose "[DEBUG] Successfully installed and imported powershell-yaml module"
            } catch {
                Write-Error "Failed to install powershell-yaml module. Please install it manually: Install-Module powershell-yaml"
                throw "Required module missing"
            }
        } else {
            Write-Verbose "[DEBUG] powershell-yaml module is available"
        }
    } catch {
        Write-Error "Error checking PowerShell modules: $_"
        throw "Module validation failed"
    }
    
    # Exclude skip versions
    $SkipVersions = @("Alpha","Beta","alpha","beta","Canary","CLI","Dev","Insiders","Preview","RC",".validation")

    ###$VerbosePreference = "Continue"

    ## Register Appx if not registered 
    if (Get-Module -Name Appx) {
        Write-Output "Appx module is already loaded."
    } else {
        Write-Output "Appx module is not loaded. Attempting to load it..."
        try {
            Import-Module Appx -UseWindowsPowerShell -ErrorAction Stop
            Write-Output "Appx module loaded successfully."
        } catch {
            Write-Output "Error: Failed to load Appx module. $($_.Exception.Message)"
        }
    }

    try {
        $package = Get-AppxPackage -Name Microsoft.DesktopAppInstaller -ErrorAction SilentlyContinue

        if ($package) {
            Write-Output "Microsoft.DesktopAppInstaller is installed."
            if ($package.PackageFamilyName -and $package.InstallLocation) {
                Write-Output "Microsoft.DesktopAppInstaller is registered."
            } else {
                Write-Output "Microsoft.DesktopAppInstaller is installed but not properly registered."
                try {
                    $WinGet = $(Get-AppxPackage "Microsoft.DesktopAppInstaller")
                    Add-AppxPackage -DisableDevelopmentMode -Register "$($Winget.InstallLocation)\AppXManifest.xml"
                    Write-Output "Successfully registered Microsoft.DesktopAppInstaller"
                } catch {
                    Write-Warning "Failed to register Microsoft.DesktopAppInstaller: $_"
                }
            }
        } else {
            Write-Error "Microsoft.DesktopAppInstaller is not installed. Please install winget first."
            throw "Winget not available"
        }
    } catch {
        Write-Error "Failed to check winget installation status: $_"
        throw "Winget verification failed"
    }

    $wingetVersion = winget --version 
    $wingetVersion = $wingetVersion -replace '^v', ''
    if ($wingetVersion) {
        $parsedVersion = [version]$wingetVersion
        if ($parsedVersion -gt [version]"1.8") {
            Write-Output "winget version is $($wingetVersion)"
        } else {
            Write-Output "winget version is 1.8 or lower, please update"
        }
    } else {
        Write-Output "winget is not installed or not available"
        Write-Output "re-registering Microsoft.DesktopAppInstaller"
        $WinGet = $(Get-AppxPackage "Microsoft.DesktopAppInstaller")
        Add-AppxPackage -DisableDevelopmentMode -Register "$($Winget.InstallLocation)\AppXManifest.xml"
    }


    ## Set winget to enable local manifest files
    try {
        $result = winget settings --enable LocalManifestFiles 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "Failed to enable LocalManifestFiles: $result"
        } else {
            Write-Verbose "[DEBUG] LocalManifestFiles enabled successfully"
        }
    } catch {
        Write-Warning "Error configuring LocalManifestFiles: $_"
    }

    ## Set winget to disable scanning of compressed files
    try {
        $result = winget settings --enable LocalArchiveMalwareScanOverride 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "Failed to enable LocalArchiveMalwareScanOverride: $result"
        } else {
            Write-Verbose "[DEBUG] LocalArchiveMalwareScanOverride enabled successfully"
        }
    } catch {
        Write-Warning "Error configuring LocalArchiveMalwareScanOverride: $_"
    }

    ## bypass smart screen for winget exe installs
    try {
        $registryPath = "HKCU:\Software\Classes\exefile\shell\open"
        $registryName = "NoSmartScreen"
        $registryValue = 1

        # Check if the registry path exists
        if (!(Test-Path $registryPath)) {
            [void](New-Item -Path $registryPath -Force)
            Write-Verbose "[DEBUG] Created registry path: $registryPath"
        }

        # Create the DWORD value
        [void](New-ItemProperty -Path $registryPath -Name $registryName -Value $registryValue -PropertyType DWORD -Force)
        Write-Output "DWORD value 'NoSmartScreen' has been created under $registryPath."
    } catch {
        Write-Warning "Failed to configure SmartScreen bypass: $_"
    }

    ## bypass smart screen for winget msi installs
    try {
        $registryPath = "HKCU:\Software\Classes\Msi.Package\shell\open"
        $registryName = "NoSmartScreen"
        $registryValue = 1

        # Check if the registry path exists
        if (!(Test-Path $registryPath)) {
            [void](New-Item -Path $registryPath -Force)
            Write-Verbose "[DEBUG] Created registry path: $registryPath"
        }

        # Create the DWORD value
        [void](New-ItemProperty -Path $registryPath -Name $registryName -Value $registryValue -PropertyType DWORD -Force)
        Write-Output "DWORD value 'NoSmartScreen' has been created under $registryPath."
    } catch {
        Write-Warning "Failed to configure SmartScreen bypass: $_"
    }

    # Consistent casing for variables
    if ($AppName -notmatch "\.") {
        throw "AppName must contain at least one dot (e.g., Publisher.PackageName)"
    }
    
    # Validate AppName structure
    if ($AppName -match "^\.|\.{2,}|\.$") {
        throw "AppName has invalid dot placement. Format should be Publisher.PackageName"
    }
    
    # Validate no invalid characters
    if ($AppName -match '[<>:"/\\|?*]') {
        throw "AppName contains invalid characters. Only alphanumeric, dots, and hyphens are allowed"
    }
    
    if ($Version) {
        $Version = $Version.Trim()
        # Remove any leading 'v' or 'V'
        if ($Version -match "^[vV](.+)$") {
            $Version = $Matches[1]
        }
        
        # Validate version format
        if ($Version -match '[<>:"/\\|?*]') {
            throw "Version contains invalid characters"
        }
        
        if ([string]::IsNullOrWhiteSpace($Version)) {
            throw "Version cannot be empty after processing"
        }
    }

    $Publisher = $AppName -split "\." | Select-Object -First 1
    $PackageParts = $AppName -split "\."
    $PackageName = $PackageParts[1..($PackageParts.Length - 1)] -join "/"
    $PublisherFirst = ($Publisher.Substring(0, 1)).ToLower()

    # Validate parsed components
    if ([string]::IsNullOrWhiteSpace($Publisher)) {
        throw "Publisher name cannot be empty"
    }
    
    if ([string]::IsNullOrWhiteSpace($PackageName)) {
        throw "Package name cannot be empty"
    }
    
    if ($PackageParts.Length -lt 2) {
        throw "AppName must have at least Publisher.PackageName format"
    }

    Write-Verbose "[DEBUG] AppName: $AppName"
    Write-Verbose "[DEBUG] Version: $Version"
    Write-Verbose "[DEBUG] Publisher: $Publisher"
    Write-Verbose "[DEBUG] PackageName: $PackageName"
    Write-Verbose "[DEBUG] PublisherFirst: $PublisherFirst"

    try {
        # Check if manifest files already exist locally
        if (Test-Path "./$PublisherFirst/$Publisher/$PackageName") {
            Write-Verbose "[DEBUG] Manifest files exist for: $AppName"
            if (-not $Version) {
                try {
                    $availableVersions = Get-ChildItem "./$PublisherFirst/$Publisher/$PackageName" | 
                        Where-Object { $SkipVersions -notcontains $_.Name } | 
                        Sort-Object { [System.Version]$_.Name } -Descending | 
                        Select-Object -First 1
                    
                    if (-not $availableVersions) {
                        throw "No valid versions found for $AppName"
                    }
                    
                    $Version = $availableVersions.Name
                    Write-Verbose "[DEBUG] Available versions: $((Get-ChildItem ./$PublisherFirst/$Publisher/$PackageName | ForEach-Object { $_.Name }) -join ', ')"
                    Write-Verbose "[DEBUG] Selected version: $Version"
                } catch {
                    Write-Error "Failed to determine version for $AppName`: $_"
                    return
                }
            }
            # TODO: Check to see if the install files in installer.json exist in ../binaries/$PublisherFirst/$Publisher/$PackageName
            if (Test-Path "../binaries/$PublisherFirst/$Publisher/$PackageName") {
                Write-Verbose "[DEBUG] Install files exist for: $AppName"
                
                try {
                    $Files = Get-ChildItem "./$PublisherFirst/$Publisher/$PackageName/$Version" | Where-Object { $_.Name -like "*Installer*" }
                    
                    if (-not $Files -or $Files.Count -eq 0) {
                        Write-Warning "No installer YAML files found for $AppName version $Version"
                        return
                    }
                    
                    Write-Verbose "[DEBUG] Found $($Files.Count) installer file(s)"
                } catch {
                    Write-Error "Failed to enumerate installer files for $AppName version $Version`: $_"
                    return
                }
                
                foreach ($file in $Files) {
                    Write-Verbose "[DEBUG] Processing installer YAML: $($file.FullName -replace [regex]::Escape((Get-Location).Path), '.')"
                    
                    if ($file.FullName) {
                        $yamlPath = $file.FullName
                    } else {
                        $yamlPath = "./$($file.Name)"
                    }
                    if (!(Test-Path $yamlPath)) {
                        Write-Warning "YAML file not found: $yamlPath"
                        continue
                    }
                    
                    try {
                        $yamlContent = Get-Content -Path $yamlPath -Raw
                        $parsedData = ConvertFrom-Yaml -Yaml $yamlContent
                    } catch {
                        Write-Warning "Failed to parse YAML file $yamlPath`: $_"
                        continue
                    }

                    if (-not $parsedData) {
                        Write-Warning "YAML file $yamlPath contains no data or failed to parse"
                        continue
                    }

                    if ($parsedData.installers.installerlocale) {
                        $InstallerUrls = $parsedData.installers | Where-Object InstallerLocale -eq "en"
                    } else {
                        $InstallerUrls = $parsedData.Installers
                    }
                    
                    # Create binary folder path
                    $PackageNamePath = $PackageName -replace "/", "."
                    $BinaryFolder = "$($env:TEMP)\winget\$($Publisher).$($PackageNamePath).$($Version)"
                    try {
                        if (!(Test-Path $BinaryFolder)) { 
                            New-Item -Path $BinaryFolder -ItemType "Directory" -Force | Out-Null 
                            Write-Verbose "[DEBUG] Created binary folder: $BinaryFolder"
                        }
                    } catch {
                        Write-Warning "Failed to create binary folder $BinaryFolder`: $_"
                        continue
                    }

                    if (-not $InstallerUrls -or $InstallerUrls.Count -eq 0) {
                        Write-Warning "No installer URLs found in YAML file: $yamlPath"
                        continue
                    }

                    foreach ($Installer in $InstallerUrls) {
                        if (-not $Installer.InstallerUrl) {
                            Write-Verbose "[DEBUG] Skipping installer with no URL"
                            continue
                        }
                        
                        try {
                            Write-Verbose "[DEBUG] Installer URL: $($Installer.InstallerUrl)"
                            $url = "$($Installer.InstallerUrl)"
                            $cleanUrl = if ($url -like "*/download") { $url -replace "/download$", "" } else { $url }
                            #$DestinationFile = "$BinaryFolder\$($cleanUrl | Split-Path -Leaf)"
                            $DestinationFile = "$BinaryFolder\$($($Installer.InstallerSha256).Tolower())"
                            Write-Verbose "[DEBUG] Cleaned Installer URL: $($cleanUrl)"
                            Write-Verbose "[DEBUG] Destination: $DestinationFile"
                            
                            if (!(Test-Path $DestinationFile)) {
                                Write-Host "Copying $DestinationFile"
                                $SourcePath = "../binaries/$PublisherFirst/$Publisher/$PackageName/$Version/$($($cleanUrl) | Split-Path -Leaf)"
                                
                                if (!(Test-Path $SourcePath)) {
                                    Write-Warning "Source file not found: $SourcePath"
                                    continue
                                }
                                
                                Copy-Item -Path $SourcePath -Destination $DestinationFile -ErrorAction Stop
                                Unblock-file -Path $DestinationFile
                                Write-Verbose "[DEBUG] Successfully copied installer file"
                            }
                            
                            # Verify hash if file exists and hash is provided
                            if ((Test-Path $DestinationFile) -and $Installer.InstallerSha256) {
                                try {
                                    $calculatedHash = Get-FileHash -Path $DestinationFile -Algorithm SHA256
                                    Write-Verbose "[DEBUG] Calculated hash: $($calculatedHash.Hash), Expected: $($Installer.InstallerSha256)"
                                    if ($calculatedHash.Hash -eq $Installer.InstallerSha256) {
                                        Write-Verbose "$DestinationFile hash matches. The file integrity is verified."
                                    } else {
                                        Write-Warning "$DestinationFile hash does not match. Expected: $($Installer.InstallerSha256), Got: $($calculatedHash.Hash)"
                                    }
                                } catch {
                                    Write-Warning "Failed to calculate hash for $DestinationFile`: $_"
                                }
                            }
                        } catch {
                            Write-Warning "Failed to process installer $($Installer.InstallerUrl): $_"
                            continue
                        }
                    }
                    
                    ## Start winget install
                    Write-Host "Starting winget install for $AppName"
                    try {
                        $manifestPath = "./$PublisherFirst/$Publisher/$PackageName/$Version"
                        
                        # Verify manifest path exists before attempting install
                        if (!(Test-Path $manifestPath)) {
                            throw "Manifest path not found: $manifestPath"
                        }
                        
                        # Check if manifest files are valid
                        $manifestFiles = Get-ChildItem $manifestPath -Filter "*.yaml" -ErrorAction SilentlyContinue
                        if (-not $manifestFiles -or $manifestFiles.Count -eq 0) {
                            throw "No manifest YAML files found in: $manifestPath"
                        }
                        
                        Write-Verbose "[DEBUG] Installing from manifest: $manifestPath"
                        $installResult = winget install --manifest $manifestPath 2>&1
                        
                        if ($LASTEXITCODE -eq 0) {
                            Write-Host "Successfully installed $AppName" -ForegroundColor Green
                        } else {
                            Write-Warning "Winget install completed with exit code: $LASTEXITCODE"
                            Write-Warning "Output: $installResult"
                        }
                    } catch {
                        Write-Error "Failed to install $AppName`: $_"
                    }
                }
            } else {
                Write-Verbose "[DEBUG] Install files do not exist for: $AppName"
            }
        } else {
            Write-Verbose "[DEBUG] Manifest files do not exist for: $AppName"
        }
    } catch {
        Write-Error "An error occurred: $_"
    }
}