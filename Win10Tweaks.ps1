##########
# Win10 Initial Setup Script
##########

# Ask For Elevated Permissions if Required
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
	Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
	Exit
}

##########
# Privacy Settings
##########

# Disable Telemetry
Write-Host "Disabling Telemetry..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0

#### For Insider builds change values 0 > 3 ####

# Disable Wi-Fi Sense
Write-Host "Disabling Wi-Fi Sense..."
If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting")) {
	New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Type DWord -Value 0

# Disable SmartScreen Filter
Write-Host "Disabling SmartScreen Filter..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Type String -Value "Off"
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation" -Type DWord -Value 0

# Disable Bing Search In Start Menu
Write-Host "Disabling Bing Search In Start Menu..."
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type DWord -Value 0
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Type DWord -Value 1

# Disable Start Menu Suggestions
Write-Host "Disabling Start Menu suggestions..."
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0

# Disable Automatically Installing Suggested Apps
Write-Host "Disabling automatically installing suggested apps..."
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type DWord -Value 0

# Disable Location Tracking
Write-Host "Disabling Location Tracking..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type DWord -Value 0

# Disable Feedback
Write-Host "Disabling Feedback..."
If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules")) {
	New-Item -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0

# Disable Advertising ID
Write-Host "Disabling Advertising ID..."
If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo")) {
	New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Type DWord -Value 0

# Restrict Windows Update P2P Only To Local Network
Write-Host "Restricting Windows Update P2P Only To Local Network..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Type DWord -Value 0
If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization")) {
	New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization" | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization" -Name "SystemSettingsDownloadMode" -Type DWord -Value 3

# Remove AutoLogger File and Restrict Directory
Write-Host "Removing AutoLogger File and Restricting Directory..."
$autoLoggerDir = "$env:PROGRAMDATA\Microsoft\Diagnosis\ETLLogs\AutoLogger"
If (Test-Path "$autoLoggerDir\AutoLogger-Diagtrack-Listener.etl") {
	Remove-Item "$autoLoggerDir\AutoLogger-Diagtrack-Listener.etl"
}
icacls $autoLoggerDir /deny SYSTEM:`(OI`)`(CI`)F | Out-Null

# Stop and disable Diagnostics Tracking Service
Write-Host "Stopping and disabling Diagnostics Tracking Service..."
Stop-Service "DiagTrack"
Set-Service "DiagTrack" -StartupType Disabled

# Stop and Disable WAP Push Service
Write-Host "Stopping and disabling WAP Push Service..."
Stop-Service "dmwappushservice"
Set-Service "dmwappushservice" -StartupType Disabled

##########
# Service Tweaks
##########

# Lower UAC Level
Write-Host "Lowering UAC Level..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 0

# Enable Sharing Mapped Drives Between Users
Write-Host "Enabling Sharing Mapped Drives Between Users..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLinkedConnections" -Type DWord -Value 1

# Disable Implicit Administrative Shares
Write-Host "Disabling Implicit Administrative Shares..."
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoShareWks" -Type DWord -Value 0

# Disable Offering Of Malicious Software Removal Tool Through Windows Update
Write-Host "Disabling Offering Of Malicious Software Removal Tool Through Windows Update..."
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT")) {
	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT" | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT" -Name "DontOfferThroughWUAU" -Type DWord -Value 1

# Disable Windows Update Automatic Restart
Write-Host "Disabling Windows Update Automatic Restart..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "UxOption" -Type DWord -Value 1
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU")) {
	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -Type DWord -Value 1

# Stop and Disable Home Groups Services
Write-Host "Stopping and disabling Home Groups services..."
Stop-Service "HomeGroupListener"
Set-Service "HomeGroupListener" -StartupType Disabled
Stop-Service "HomeGroupProvider"
Set-Service "HomeGroupProvider" -StartupType Disabled

# Disable Remote Assistance
Write-Host "Disabling Remote Assistance..."
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 0

# Enable Remote Desktop w/o Network Level Authentication
Write-Host "Enabling Remote Desktop w/o Network Level Authentication..."
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Type DWord -Value 0

#Turn Driver Updates Off
Write-Host "Turn Driver Updates Off..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" -Name "SearchOrderConfig" -Type DWord -Value 0
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate")) {
	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ExcludeWUDriversInQualityUpdate" -Type DWord -Value 1

#Change DNS
Write-Host "Changing And Flushing The DNS..."
Set-DnsClientServerAddress -InterfaceIndex 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 15, 17, 18, 19, 20 -ServerAddresses ("37.235.1.174","37.235.1.177") 2>&1 | Out-Null
ipconfig.exe /flushdns 2>&1 | Out-Null
ipconfig.exe /renew 2>&1 | Out-Null

##########
# UI Tweaks
##########

# Disable "You have new apps that can open this type of file"
Write-Host "Disabling You Have New Apps That Can Open This Type Of File"
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Explorer" -Name "NoNewAppAlert" -Type DWord -Value 1

# Disable Look For An App In The Store
Write-Host "Disabling Look For An App In The Store..."
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Explorer" -Name "NoUseStoreOpenWith" -Type DWord -Value 1

# Enable Dark Mode
Write-Host "Enabling Dark Mode..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Type DWord -Value 0
If (!(Test-Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize")) {
	New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" | Out-Null
}
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "Append Completion" -Type String -Value "yes"

# Raise The Wallpaper Quality
Write-Host "Raising The Wallpaper Quality..."
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "JPEGImportQuality" -Type DWord -Value 100

# Enable Auto Complete In Explorer
Write-Host "Enabling Auto Complete In Explorer..."
If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoComplete")) {
	New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoComplete" | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoComplete" -Name "Append Completion" -Type String -Value "yes"

# Disable Lock Screen
Write-Host "Disabling Lock Screen..."
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization")) {
	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreen" -Type DWord -Value 1

# Disable Lock Lcreen (Anniversary Update Workaround)
If ([System.Environment]::OSVersion.Version.Build -gt 14392) { # Apply only for Redstone 1 or newer
	$service = New-Object -com Schedule.Service
	$service.Connect()
	$task = $service.NewTask(0)
	$task.Settings.DisallowStartIfOnBatteries = $false
	$trigger = $task.Triggers.Create(9)
	$trigger = $task.Triggers.Create(11)
	$trigger.StateChange = 8
	$action = $task.Actions.Create(0)
	$action.Path = "reg.exe"
	$action.Arguments = "add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\SessionData /t REG_DWORD /v AllowLockScreen /d 0 /f"
	$service.GetFolder("\").RegisterTaskDefinition("Disable LockScreen", $task, 6, "NT AUTHORITY\SYSTEM", $null, 4) | Out-Null
}

# Disable Autoplay
Write-Host "Disabling Autoplay..."
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Type DWord -Value 1

# Disable Autorun For All Drives
Write-Host "Disabling Autorun For All Drives..."
If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
	New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Type DWord -Value 255

# Disable Sticky Keys Prompt
Write-Host "Disabling Sticky Keys Prompt..."
Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Type String -Value "506"

# Hide Search Box/Button
Write-Host "Hiding Search Box/Button..."
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0

# Hide Task View Button
Write-Host "Hiding Task View Button..."
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0

# Show Hidden Files
Write-Host "Showing Hidden Files..."
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type DWord -Value 1

# Change Default Explorer View To This PC
Write-Host "Changing Default Explorer View To This PC..."
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 1

# Show This PC Shortcut On Desktop
Write-Host "Showing This PC Shortcut On Desktop..."
If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu")) {
	New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Type DWord -Value 0

# Show User Folder On Dekstop
Write-Host "Showing User Folder On Dekstop..."
If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu")) {
	New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -Type DWord -Value 0

# Add Recycle Bin To Navigation Pane
Write-Host "Adding Recycle Bin To Navigation Pane..."
If (!(Test-Path "HKCU:\Software\Classes\CLSID\{645FF040-5081-101B-9F08-00AA002F954E}")) {
	New-Item -Path "HKCU:\Software\Classes\CLSID\{645FF040-5081-101B-9F08-00AA002F954E}" | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Classes\CLSID\{645FF040-5081-101B-9F08-00AA002F954E}" -Name "System.IsPinnedToNameSpaceTree" -Type DWord -Value 1

# Enable NumLock After Startup
Write-Host "Enabling NumLock After Startup..."
If (!(Test-Path "HKU:")) {
	New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
}
Set-ItemProperty -Path "HKU:\.DEFAULT\Control Panel\Keyboard" -Name "InitialKeyboardIndicators" -Type DWord -Value 2147483650
Set-ItemProperty -Path "HKU:\S-1-5-19\Control Panel\Keyboard" -Name "InitialKeyboardIndicators" -Type DWord -Value 2147483650
Set-ItemProperty -Path "HKU:\S-1-5-20\Control Panel\Keyboard" -Name "InitialKeyboardIndicators" -Type DWord -Value 2147483650

# Disable Error Reporting
Write-Host "Disable Error Reporting..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type DWord -Value 00000001
Stop-Service "WerSvc"
Set-Service "WerSvc" -StartupType Disabled

# Faster Menu Delay
Write-Host "Changing Menu Delay..."
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -Type String -Value "50"

# Adjust For Best Appearance
Write-Host "Adjusting For Best Appearance..."
New-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects' -Name VisualFXSetting -PropertyType DWORD -Value 1 -Force 2>&1 | Out-Null

# Stop App Suggestion
Write-Host "Stopping App Suggestion..."

If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" | Out-Null
}
Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableWindowsConsumerFeatures" 1

##########
# Remove unwanted applications
##########

# Uninstall Default Microsoft Applications
Write-Host "Uninstalling Default Microsoft Applications..."
Get-AppxPackage -AllUsers | where-object {$_.name -notlike "*store*"} | Remove-AppxPackage 2>&1 | Out-Null

# Unpin Apps From The Start Menu
Write-Host "Unpinning Apps From The Start Menu..."
function unpin {  param(
        [string]$appname,
        [switch]$unpin
    )
    try{
        if ($unpin.IsPresent){
            ((New-Object -Com Shell.Application).NameSpace('shell:::{4234d49b-0245-4df3-b780-3893943456e1}').Items() | Where-Object{$_.Name -eq $appname}).Verbs() | Where-Object{$_.Name.replace('&','') -match 'From "Start" UnPin|Unpin from Start'} | Foreach-Object{$_.DoIt()}
            return "App '$appname' unpinned from Start"
        }else{
            ((New-Object -Com Shell.Application).NameSpace('shell:::{4234d49b-0245-4df3-b780-3893943456e1}').Items() | Where-Object{$_.Name -eq $appname}).Verbs() | Where-Object{$_.Name.replace('&','') -match 'To "Start" Pin|Pin to Start'} | Foreach-Object{$_.DoIt()}
            return "App '$appname' pinned to Start"
        }
    }catch{
        Write-Error "Error Pinning/Unpinning App! (App-Name correct?)"
    }
}
unpin "Store" -unpin
unpin "Connect" -unpin
unpin "Microsoft Edge" -unpin

# Disable Xbox DVR
Write-Host "Disablng Xbox DVR"
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR")) {
	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Type DWord -Value 0

# Uninstall Windows Media Player
Write-Host "Uninstalling Windows Media Player..."
dism /online /Disable-Feature /FeatureName:WindowsMediaPlayer /Quiet /NoRestart

# Uninstall Work Folders Client
Write-Host "Uninstalling Work Folders Client..."
dism /online /Disable-Feature /FeatureName:WorkFolders-Client /Quiet /NoRestart

# Install Linux Subsystem
If ([System.Environment]::OSVersion.Version.Build -gt 14392) { # Apply only for Redstone 1 or newer
	Write-Host "Installing Linux Subsystem..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowDevelopmentWithoutDevLicense" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowAllTrustedApps" -Type DWord -Value 1
	dism /online /Enable-Feature /FeatureName:Microsoft-Windows-Subsystem-Linux /Quiet /NoRestart
}

# Uninstall Internet Explorer 11
Write-Host "Uninstalling Internet Explorer 11..."
dism /online /Disable-Feature /FeatureName:internet-explorer-optional-amd64 /Quiet /NoRestart

##########
# Extras
##########

# Markc Mouse Fix
Write-Host "Installing Markc Mouse Fix..."
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSensitivity" -Type DWord -Value 10
If ((Get-ItemPropertyValue -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "AppliedDPI") -eq 96) {
	$XCurve = [byte[]](0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0xCC, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00,0x80, 0x99, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x66, 0x26, 0x00, 0x00,0x00, 0x00, 0x00, 0x00, 0x33, 0x33, 0x00, 0x00, 0x00, 0x00, 0x00)
	$YCurve = [byte[]](0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x38, 0x00, 0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x70, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xA8, 0x00, 0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00)
}
If ((Get-ItemPropertyValue -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "AppliedDPI") -eq 120) {
	$XCurve = [byte[]](0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00)
	$YCurve = [byte[]](0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x38, 0x00, 0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x70, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xA8, 0x00, 0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00)
}
If ((Get-ItemPropertyValue -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "AppliedDPI") -eq 144) {
	$XCurve = [byte[]](0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x33, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00,0x60, 0x66, 0x26, 0x00, 0x00, 0x00, 0x00, 0x00, 0x90, 0x99, 0x39, 0x00, 0x00,0x00, 0x00, 0x00, 0xC0, 0xCC, 0x4C, 0x00, 0x00, 0x00, 0x00, 0x00)
	$YCurve = [byte[]](0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x38, 0x00, 0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x70, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xA8, 0x00, 0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00)
}
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "SmoothMouseXCurve" -Value $XCurve
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "SmoothMouseYCurve" -Value $XYurve
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSpeed" -Type String -Value "0"
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold1" -Type String -Value "0"
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold2" -Type String -Value "0"
If (!(Test-Path "HKU:")) {
	New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
}
Set-ItemProperty -Path "HKU:\.DEFAULT\Control Panel\Mouse" -Name "MouseSpeed" -Type String -Value "0"
Set-ItemProperty -Path "HKU:\.DEFAULT\Control Panel\Mouse" -Name "MouseThreshold1" -Type String -Value "0"
Set-ItemProperty -Path "HKU:\.DEFAULT\Control Panel\Mouse" -Name "MouseThreshold2" -Type String -Value "0"

# Download Ninite
Write-Host "Downloading Ninite ..."
$url = "https://ninite.com/.net4.6.2-air-chrome-firefox-foobar-gimp-inkscape-irfanview-java8-klitecodecs-libreoffice-notepadplusplus-paint.net-peazip-qbittorrent-shockwave-silverlight-spotify-steam-sumatrapdf-vscode/ninite.exe"
$output = "C:\Users\$env:username\Desktop\Ninite.exe"
Invoke-WebRequest $url -OutFile $output

# Download Hosts File
Write-Host "Downloading Hosts File..."
$url = "http://winhelp2002.mvps.org/hosts.txt"
$output = "C:\Users\$env:username\Desktop\hosts"
Invoke-WebRequest $url -OutFile $output

# Changing Hosts File
Write-Host "Changing Hosts File..."
Rename-Item "C:\Windows\System32\drivers\etc\hosts" HOSTS.MVP 2>&1 | Out-Null
Copy-Item "C:\Users\$env:username\Desktop\hosts" -Destination "C:\Windows\System32\drivers\etc\hosts" 2>&1 | Out-Null
Remove-Item C:\Users\$env:username\Desktop\hosts

# Create Links File
Write-Host "Creating Links File..."
New-Item C:\Users\$env:username\Desktop\Links.txt -type file -value "DDU								https://goo.gl/kjadrs
Old AMD 16.5.3 Hotfix			https://goo.gl/1g8YQG
AMD Latest						https://goo.gl/aaliln
Intel Latest					https://goo.gl/Z97hRB
CCleaner						https://goo.gl/CHoJp6
Driver Booster					https://goo.gl/eGR62y
DriverPack						https://goo.gl/P9OmU6
EZ								https://goo.gl/XFZjeU
HP Driver  						https://goo.gl/PejnMG
Send anywhere 					https://goo.gl/sIZB9B
SmartSwitch						https://goo.gl/OMSB8V
PS4 Remote Play					https://goo.gl/IuHsk1
PopCornTime						https://goo.gl/QWbGeC
Air Skin 						https://goo.gl/CPASM4
F.lux							https://goo.gl/wNm6sD
PushBullet						https://goo.gl/1Fi8RC
UPlay							https://goo.gl/AdlN4o
Origin							https://goo.gl/25734z" 2>&1 | Out-Null

# Install Programs
Write-Host "Installing Programs..."
Start-Process -FilePath "C:\Users\$env:username\Desktop\OldCalc.exe" -ArgumentList "/S /silent /s" 2>&1 | Out-Null
Start-Process -FilePath "C:\Users\$env:username\Desktop\Ninite.exe" -Wait -Verb runas 2>&1 | Out-Null
Remove-Item C:\Users\$env:username\Desktop\OldCalc.exe

# Change Program Association
Write-Host "Changing Program Association..."
Dism.exe /Online /Import-DefaultAppAssociations:C:\Users\$env:username\Desktop\AppAssociations.xml  2>&1 | Out-Null
Remove-Item C:\Users\$env:username\Desktop\AppAssociations.xml

# Copy Ninite
Write-Host "Copying Ninite..."
New-Item C:\Task\ -type directory 2>&1 | Out-Null
Copy-Item Ninite.exe C:\Task\ 2>&1 | Out-Null
Remove-Item C:\Users\$env:username\Desktop\Ninite.exe

# Create A Schedule Task
Write-Host "Creating A Schedule Task..."
$taskname = "Ninite"
$descreption = "Update your Apps!"
$action = New-ScheduledTaskAction -Execute "C:\Task\Ninite.exe"
$trigger =  New-ScheduledTaskTrigger -Weekly -WeeksInterval 2 -DaysOfWeek Sunday -At 1pm
Register-ScheduledTask -TaskName $taskname -Action $action -Trigger $trigger -Description $descreption 2>&1 | Out-Null

# Enable F8 Boot Menu Options
Write-Host "Enabling F8 Boot Menu Options..."
bcdedit /set `{current`} bootmenupolicy Legacy | Out-Null

# Rename The PC
Write-Host "Renaming The PC..."
Rename-Computer -NewName "JKaw" 2>&1 | Out-Null

# Delete Files
	$tempfolders = @("C:\Windows\Temp\*", "C:\Windows\Prefetch\*", "C:\Documents and Settings\*\Local Settings\temp\*", "C:\Users\*\Appdata\Local\Temp\*")
	Remove-Item $tempfolders -force -recurse 2>&1 | Out-Null
	function Delete() {
		$Invocation = (Get-Variable MyInvocation -Scope 1).Value
		$Path =  $Invocation.MyCommand.Path  
		Remove-Item $Path
	} 

##########
# Restart
##########

Write-Host
Write-Host "Press Any Key To Restart Your System..." -ForegroundColor Black -BackgroundColor White
$key = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
Delete
Write-Host "Restarting..."
Restart-Computer
