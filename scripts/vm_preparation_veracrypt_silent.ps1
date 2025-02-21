# Run as Administrator
Set-ExecutionPolicy Bypass -Scope Process -Force

# 1. Ensure NuGet Provider is Installed (No User Input)
Write-Host "Installing NuGet Provider..."
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force

# 2. Ensure Winget is Installed
Write-Host "Checking for Winget..."
if (-Not (Get-Command winget -ErrorAction SilentlyContinue)) {
    Write-Host "Winget not found. Installing..."
    $wingetInstaller = "$env:TEMP\winget.msixbundle"
    Invoke-WebRequest -Uri "https://github.com/microsoft/winget-cli/releases/latest/download/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle" -OutFile $wingetInstaller
    Add-AppxPackage -Path $wingetInstaller
}

# 3. Install VeraCrypt Silently (No User Prompts)
Write-Host "Installing VeraCrypt..."
winget install --id IDRIX.VeraCrypt -e --silent --accept-source-agreements --accept-package-agreements

# 4. Set Network Profile to Private
Write-Host "Setting Network Profile to Private..."
$network = Get-NetConnectionProfile
if ($network) {
    Set-NetConnectionProfile -Name $network.Name -NetworkCategory Private
}

# 5. Disable Notifications
Write-Host "Disabling Windows Notifications..."
$RegPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications"
Set-ItemProperty -Path $RegPath -Name ToastEnabled -Value 0

# 6. Disable 'SecureBootEncodeUEFI' in Task Scheduler
Write-Host "Disabling SecureBootEncodeUEFI Task..."
$taskName = "\Microsoft\Windows\PI\SecureBootEncodeUEFI"
if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
    Disable-ScheduledTask -TaskName $taskName
}

# 7. Apply Windows Updates (No User Input)
Write-Host "Applying Windows Updates..."
Install-Module PSWindowsUpdate -Force -SkipPublisherCheck
Install-WindowsUpdate -AcceptAll -IgnoreReboot

# 8. Restart the System if Updates Require It
Write-Host "Restarting System..."
shutdown /r /t 10

# 9. After VM Shutdown, Take a Snapshot (Run from Host)
Write-Host "Once the VM shuts down, take a snapshot from the host machine:"
Write-Host "virsh snapshot-create-as win10_bios 'veracrypt' 'Snapshot after installation' --atomic"
