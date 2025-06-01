# Script MUST run as administrator, on the main account that will be used (the Azure AD joined one)

Write-Host "==>  Script vm-dev-base-install.ps1 STARTED  < =="
Write-Host
# Choco logs will be here: C:\ProgramData\chocolatey\logs\chocolatey.log

# 1. Install Chocolatey
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

# 2. Chocolatey functions
Function Install-ChocoPackage {
    param (
        [Parameter(Mandatory = $true)]
        [Object]$Packages
    )

    foreach ($package in $Packages) {
        $command = "choco install $package -y"
        Write-Host
        Write-Host "Install-ChocoPackage => Executing: $command"
        Invoke-Expression $command
    }
}
Function Update-ChocoPackages {
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$Packages
    )

    foreach ($package in $Packages) {
        $command = "choco upgrade $package -y"
        Write-Host
        Write-Host "Update-ChocoPackages => Executing: $command"
        Invoke-Expression $command
    }
}
Function Uninstall-ChocoPackage {
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$Packages
    )

    $installed = $(choco list)

    foreach ($package in $Packages) {
        if ($installed -match $package) {
            $command = "choco uninstall $package -y"
            Write-Host
            Write-Host "Uninstall-ChocoPackage => Executing: $command"
            Invoke-Expression $command
        }
    }
}

# 4. Install packages
# Package library: https://community.chocolatey.org/packages

$core_dev_packages = @(
    "firefox",
    "wireshark",
    "notepadplusplus",
    "git",
    "gh",
    "azure-cli",
    "vscode",
    "sysinternals",
    "microsoftazurestorageexplorer",
    "terraform",
    "python3",
    "kubectx",
    "kubens",
    "kubernetes-cli",
    "azure-kubelogin",
    "kubernetes-helm",
    "openlens",
    "azure-powershell",
    "powershell-core",
    "winscp",
    "7zip",
    "nerd-fonts-cascadiacode",
    "nerd-fonts-jetbrainsmono",
    "nerd-fonts-firamono",
    "nerd-fonts-firacode",
    "cascadiamono",
    "cascadiacode",
    "ubuntu.font",
    "oh-my-posh",
    "jq",
    "openssl",
    "bind-toolsonly", # installs dig
    "telnet"
)

# $kubernetes_packages = @(
#     "azure-cli",
#     "kubectx",
#     "kubens",
#     "kubernetes-cli",
#     "azure-kubelogin",
#     "kubernetes-helm",
#     "openlens"
# )

# $secondary_packages = @(
#     # "paint.net",
#     # "syncbackfree",
#     # "nvidia-display-driver",
#     # "vlc",
#     # "vnc-viewer",
#     # "dropbox",
#     # "zoomit",
#     # "brave",
#     # "adobereader",
#     "wireshark",
#     "postman",
#     "docker-desktop",
#     "azure-functions-core-tools --params='/x64:true'",
#     "azure-data-studio",
#     "rdm",
#     "openvpn",
#     "zoom",
#     # "visualstudio2022enterprise",
#     "resharper",
#     "dotnet",
#     "dotnet-8.0-runtime"
# )

# $third_packages = @(
#     # "jdk8",
#     # "krew",
#     # "flux",
#     # "argocd-cli",
#     # "visioviewer",
#     # "sonos-s1-controller",
#     # "filezilla",
#     # "telegram",
#     # "github-desktop",
#     # "skype",
#     # "freshbing",
#     # "nodejs" # 'nodejs-lts --version="20.18.0"'
# )


# $install_packages = @(
#     "wireshark",
#     "postman",
#     "adobereader",
#     "firefox",
#     "notepadplusplus",
#     "zoomit",
#     "git",
#     "gh",
#     "azure-cli",
#     "vscode",
#     "visualstudio2022enterprise",
#     "sysinternals",
#     "microsoftazurestorageexplorer",
#     "jdk8",
#     "docker-desktop",
#     "azure-functions-core-tools --params='/x64:true'",
#     "terraform",
#     "python3",
#     "azure-data-studio",
#     "kubectx",
#     "kubens",
#     "kubernetes-cli",
#     "azure-kubelogin",
#     "kubernetes-helm",
#     "krew",
#     "flux",
#     "argocd-cli",
#     "openlens",
#     "visioviewer",
#     "azure-powershell",
#     "powershell-core",
#     "vnc-viewer",
#     "dropbox",
#     "sonos-s1-controller",
#     "winscp",
#     "filezilla",
#     "telegram",
#     "vlc",
#     "7zip",
#     "paint.net",
#     "tunein-radio",
#     "spotify",
#     "rdm",
#     "openvpn",
#     "github-desktop",
#     "itunes",
#     "syncbackfree",
#     "skype",
#     "whatsapp", #whatsapp --version 2.2306.9
#     "zoom",
#     "freshbing",
#     "icloud",
#     "logi-tune",
#     "nvidia-display-driver",
#     "resharper",
#     "dotnet",
#     "dotnet-8.0-runtime",
#     "nerd-fonts-cascadiacode",
#     "nerd-fonts-jetbrainsmono",
#     "nerd-fonts-firamono",
#     "nerd-fonts-firacode",
#     "cascadiamono",
#     "cascadiacode",
#     "ubuntu.font",
#     "oh-my-posh",
#     "jq",
#     "openssl",
#     "bind-toolsonly",
#     "telnet",
#     "nodejs" # 'nodejs-lts --version="20.18.0"'
# )
#$json = Get-Content -Path './choco-packages.json' | ConvertFrom-Json
#$install_packagesJson = $json | Sort-Object -Property install_order | $_.package

Install-ChocoPackage -Packages $core_dev_packages

# 5. Install Ubuntu 22.04 distro in WSL
# wsl --set-default-version 2
# wsl --install -d Ubuntu-22.04
# wsl -l -v

# Install AKS CLI - should not be needed anymore with the right choco packages
#az aks install-cli

# Setting Powershell settings
# Showing all profiles files used:
$profilePaths = @(
    $Profile
    $Profile.AllUsersCurrentHost
    $Profile.CurrentUserAllHosts
    $Profile.AllUsersAllHosts
)
$existingProfilePaths = $profilePaths | Where-Object { Test-Path $_ }
$existingProfilePaths

# My PowerShell profile is stored here:
Get-Content "$env:USERPROFILE\Documents\PowerShell\Microsoft.PowerShell_profile.ps1"
# It should include the oh-my-posh theme and the Aliases for K8S commands

# Setup Oh my posh theme
Invoke-Expression (oh-my-posh --init --shell pwsh --config " C:\Program Files (x86)/oh-my-posh/themes/themename.omp.json")

Write-Host "  Processing PowerShell Aliases"
If (!(test-path $PsHome\profile.ps1)) {
    New-Item -Force -Path $PsHome\profile.ps1
}
$content = Get-Content -Path $PsHome\profile.ps1
$shortcuts = @{ tf = "terraform"; k = "kubectl"; kctx = "kubectx"; kns = "kubens" }
$shortcuts.keys | ForEach-Object { 
    Write-Host "    Processing shortcut: $_ for $($shortcuts.$_).exe"
    $aliasToCheckAdd = "Set-Alias -Name $_ -Value $($shortcuts.$_).exe" # $path\$($shortcuts.$_).exe
    Write-Host "    Checking: ""$aliasToCheckAdd"""
    if (($content -eq $null) -or (!$content.Contains($aliasToCheckAdd))) {
        Write-Host "    Alias is not present, creating it."
        Add-Content $PsHome\profile.ps1 $aliasToCheckAdd -Force
    }
    else { Write-Host "    Alias is present." }
}
Write-Host "  Done with PowerShell Aliases"


# Set the git user and email
git config --global user.email "emm@trash.com"
git config --global user.name "Emmanuel"

# # Install PIP packages
# pip install azure-cli
# pip install PyYAML

# # Install Angular CLI
# # winget install --id OpenJS.NodeJS
# npm install -g @angular/cli

# Install Hyper-V
# DISM /Online /Enable-Feature /All /FeatureName:Microsoft-Hyper-V

# # Pull docker images
# docker image pull mcr.microsoft.com/mssql/server:2022-latest
# docker image pull mcr.microsoft.com/dotnet/aspnet:8.0
# docker image pull mcr.microsoft.com/dotnet/sdk:8.0
# docker image pull mcr.microsoft.com/dotnet/runtime:8.0

# Install Microsoft Whiteboard from Microsoft Store

# Setup VS Code settings sync with GitHub account

# Install WinGet packages
winget install --id Microsoft.PowerToys --source winget

# Add C:\Z.bin to the path
$binPath = "C:\Z.bin"
$env:Path += ";$($binPath)"

$pyScriptsPath = "$env:USERPROFILE\AppData\Roaming\Python\Python312\Scripts"
$env:Path += ";$($pyScriptsPath)"

# 6. Display installed packages
choco list

# 7. Displaying end of script
Write-Host
Write-Host "==>  Script vm-dev-base-install.ps1 ENDED  <=="

# 8. Display Restart message
Write-Host
Write-Host "***  RESTART the Computer to setup Docker Desktop  ***"
Write-Host "***     Restart : 'Restart-Computer'  ***"

