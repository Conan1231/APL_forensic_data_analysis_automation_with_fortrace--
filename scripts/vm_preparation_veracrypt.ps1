# Run as Administrator

# 1. Install VeraCrypt using winget
Write-Host "Installing VeraCrypt..."
winget install --id IDRIX.VeraCrypt -e

# 2. Set Network Profile to Private
Write-Host "Setting Network Profile to Private..."
$network = Get-NetConnectionProfile
if ($network) {
    Set-NetConnectionProfile -Name $network.Name -NetworkCategory Private
}

# 3. Disable Notifications
Write-Host "Disabling Windows Notifications..."
$RegPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications"
Set-ItemProperty -Path $RegPath -Name ToastEnabled -Value 0

# 4. Disable 'SecureBootEncodeUEFI' in Task Scheduler
Write-Host "Disabling SecureBootEncodeUEFI Task..."
$taskName = "\Microsoft\Windows\PI\SecureBootEncodeUEFI"
if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
    Disable-ScheduledTask -TaskName $taskName
}

# 5. Apply Windows Updates
Write-Host "Applying Windows Updates..."
Install-Module PSWindowsUpdate -Force -SkipPublisherCheck
Install-WindowsUpdate -AcceptAll -IgnoreReboot

# 6. Restart the System if Updates Require It
Write-Host "Restarting System..."
shutdown /r /t 10
