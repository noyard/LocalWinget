Setup---
This will parse the manifest, identify the install files, and download the files to the specified folder.

1. create a folder on your C:\ drive
2. Copy your Winget manifest files to that folder. Manifests can be downloaded from https:\\aka.ms\winget, manifests folder. 
3. Run the Powershell script .\Wingetdownload.ps1 '{c:\ folder path}'


Install---
To install the Winget package locally without downloading files from the internet or touching a Winget install source.  
(if your PC is not connected to the internet, or using a software distribution program like [Microsoft Configuration Manager](https://www.microsoft.com/en-us/evalcenter/evaluate-microsoft-endpoint-configuration-manager)

1. Copy the folder created in the Setup steps above to the C:\ drive
2. Run the Powershell script .\WingetRun.ps1 '{c:\ folder path}'
