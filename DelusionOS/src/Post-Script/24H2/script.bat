@echo off && SetLocal EnableDelayedExpansion && title POST-INSTALL && mode con: cols=90 lines=20

:: request administrator privileges
DISM >nul || (
    PowerShell Start -Verb RunAs '%0' 2> nul || (
        echo error: right-click on the "%~f0" script and select "Run as administrator"
        pause
    )
    exit /b 1
)

:: version 1.0 non-release 24H2 (..?? october to release)

:: Delusion LLC
:: working for script - hickerdicker, couwthynokap, clqwnless, e1uen
:: license Attribution-NonCommercial 4.0 International

call :Colors
timeout /t 3 /nobreak > NUL

echo  !B_BLACK!Execution Policy To Unrestricted...
C:\Windows\MinSudo.exe --NoLogo --TrustedInstaller --Privileged cmd /c "powershell Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope LocalMachine -Force"
C:\Windows\MinSudo.exe --NoLogo --TrustedInstaller --Privileged cmd /c "powershell Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser -Force"
C:\Windows\MinSudo.exe --NoLogo --TrustedInstaller --Privileged cmd /c "powershell Get-MMAgent"
C:\Windows\MinSudo.exe --NoLogo --TrustedInstaller --Privileged cmd /c "PowerShell Disable-MMAgent -MemoryCompression -PageCombining -ApplicationPreLaunch"

setx DOTNET_CLI_TELEMETRY_OPTOUT 1 & setx POWERSHELL_TELEMETRY_OPTOUT 1 >nul

echo  !B_BLACK!Configuration for start...
taskkill /f /im smartscreen.exe >nul & ren C:\Windows\System32\smartscreen.exe smartscreen.exee
net accounts /maxpwage:unlimited >nul
Reg.exe add "HKCU\Control Panel\Desktop" /v "Wallpaper" /t REG_SZ /d "C:\%windir%\deluos.jpg" /f >nul
timeout /t 1 /nobreak > NUL

:: --- Packages DelusionOS ---
echo  !S_GRAY!Install Visual AIO Libraries..
"%windir%"\Visual AIO.exe /aiA /gm2 > NUL 2>&1

echo  !S_GRAY!Install DirectX...
"%windir%"\dxwebsetup.exe /silent > NUL 2>&1

:: --- MOUSE TWEAKS ---
echo  !S_WHITE!Configuring Mouse tweaks...
@REM Made by Couwthy

:: disable usb idling
FOR /F %%m in ('WMIC PATH Win32_USBHub GET DeviceID^| FINDSTR /L "VID_"') DO (
	REG ADD "HKLM\SYSTEM\CurrentControlSet\Enum\%%r\Device Parameters" /F /V "EnhancedPowerManagementEnabled" /T REG_DWORD /d "0" >nul
	REG ADD "HKLM\SYSTEM\CurrentControlSet\Enum\%%r\Device Parameters" /F /V "AllowIdleIrpInD3" /T REG_DWORD /d "0" >nul
	REG ADD "HKLM\SYSTEM\CurrentControlSet\Enum\%%r\Device Parameters" /F /V "SelectiveSuspendOn" /T REG_DWORD /d "0" >nul
	REG ADD "HKLM\SYSTEM\CurrentControlSet\Enum\%%r\Device Parameters" /F /V "DeviceSelectiveSuspended" /T REG_DWORD /d "0" >nul
	REG ADD "HKLM\SYSTEM\CurrentControlSet\Enum\%%r\Device Parameters" /F /V "SelectiveSuspendEnabled" /T REG_DWORD /d "0" >nul
        REG ADD "HKLM\SYSTEM\CurrentControlSet\Enum\%%r\Device Parameters" /F /V "IdleInWorkingState" /T REG_DWORD /d "0" >nul
	ECHO Disabling USB idling for %%m
)

for %%r in (
	EnhancedPowerManagementEnabled
	AllowIdleIrpInD3
	EnableSelectiveSuspend
	DeviceSelectiveSuspended
	SelectiveSuspendEnabled
	SelectiveSuspendOn
	EnumerationRetryCount
	ExtPropDescSemaphore
	WaitWakeEnabled
	D3ColdSupported
	WdfDirectedPowerTransitionEnable
	EnableIdlePowerManagement
	IdleInWorkingState
	IoLatencyCap
	DmaRemappingCompatible
	DmaRemappingCompatibleSelfhost
) do for /f "delims=" %%b in ('reg query "HKLM\SYSTEM\CurrentControlSet\Enum" /s /f "%%b" ^| findstr "HKEY"') do reg add "%%b" /v "%%b" /t REG_DWORD /d "0" /f >nul

:: disable driver power saving
powershell.exe -command "Get-WmiObject MSPower_DeviceEnable -Namespace root\wmi | ForEach-Object { $_.enable = $false; $_.psbase.put(); }"

:: start tweaking for Mouse
bcdedit /set disabledynamictick Yes >nul
bcdedit /deletevalue useplatformclock >nul
bcdedit /deletevalue useplatformtick >nul

:: input service
Reg.exe add "HKLM\SOFTWARE\Microsoft\Input" /v "InputServiceEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Input" /v "InputServiceEnabledForCCI" /t REG_DWORD /d "0" /f >nul

:: disable mouse accel
reg add "HKCU\Control Panel\Mouse" /v "MouseSpeed" /t REG_SZ /d "0" /f >nul
reg add "HKCU\Control Panel\Mouse" /v "MouseThreshold1" /t REG_SZ /d "0" /f >nul
reg add "HKCU\Control Panel\Mouse" /v "MouseThreshold2" /t REG_SZ /d "0" /f >nul

:: --- SCHEDULED TASKS ---
echo  !B_BLACK!Configuring Scheduled Tasks...
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /f && reg add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Office\Common\ClientTelemetry" /v "DisableTelemetry" /t REG_DWORD /d "1" /f

for %%x in ("Application Experience\Microsoft Compatibility Appraiser" "Application Experience\ProgramDataUpdater"
    "Application Experience\StartupAppTask" "Customer Experience Improvement Program\Consolidator"
	"Customer Experience Improvement Program\KernelCeipTask" "Customer Experience Improvement Program\UsbCeip"
    "Customer Experience Improvement Program\Uploader" "Autochk\Proxy" "CloudExperienceHost\CreateObjectTask"
    "DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" "DiskFootprint\Diagnostics"
    "UpdateOrchestrator\Schedule Scan" "WindowsUpdate\Scheduled Start" "Servicing\StartComponentCleanup" 
    "Recovery Environment\VerifyWinRE" "EDP\StorageCardEncryption Task" "BitLocker\BitLocker Encrypt All Drives" 
    "BitLocker\BitLocker MDM policy Refresh" "ApplicationData\DsSvcCleanup" "International\Synchronize Language Settings") do schtasks /change /tn "\Microsoft\Windows\%%~x" /disable
for %%p in ("InstallService\ScanForUpdates" "InstallService\ScanForUpdatesAsUser" "InstallService\SmartRetry" "\Microsoft\Windows\Defrag\ScheduledDefrag") do schtasks /change /tn "\Microsoft\Windows\%%~p" /disable

schtasks /delete /tn "\Microsoft\Windows\Application Experience\AitAgent" /f
powershell -Command "Disable-ScheduledTask -TaskPath '\\Microsoft\\Windows\\AppxDeploymentClient' -TaskName 'UCPD velocity'"

:: --- SERVICES ---
echo  !B_BLACK!Configuring Services...
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e967-e325-11ce-bfc1-08002be10318}" /v "LowerFilters" /t REG_MULTI_SZ /d "" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{71a27cdd-812a-11d0-bec7-08002be2092f}" /v "LowerFilters" /t REG_MULTI_SZ /d "" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{71a27cdd-812a-11d0-bec7-08002be2092f}" /v "UpperFilters" /t REG_MULTI_SZ /d "" /f >nul

Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dhcp" /v "DependOnService" /t REG_MULTI_SZ /d "NSI\0Afd" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache" /v "DependOnService" /t REG_MULTI_SZ /d "nsi" /f >nul

"%ProgramFiles%\Windows Defender\MpCmdRun.exe" -DisableService
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Features" /v "TamperProtection" /t REG_DWORD /d "0" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\MsSecCore" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\MsSecFlt" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\MsSecWfp" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WdBoot" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WdNisDrv" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WdNisSvc" /v "Start" /t REG_DWORD /d "4" /f >nul

reg add "HKLM\SYSTEM\CurrentControlSet\Services\bluetoothuserservice" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\btagservice" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\bthserv" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\btha2dp" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\bthenum" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\bthhfenum" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\bthleenum" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\bthmini" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\bthmodem" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\bthport" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\bthusb" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\hidbth" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\microsoft_bluetooth_avrcptransport" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\rfcomm" /v "Start" /t REG_DWORD /d "4" /f >nul
devmanview.exe /disable "Generic Bluetooth Adapter"
powerrun "schtasks.exe" /change /disable /TN "\Microsoft\Windows\Bluetooth\UninstallDeviceTask" >nul

reg add "HKLM\SYSTEM\CurrentControlSet\Services\wercplsupport" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\afunix" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\CldFlt" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\ALG" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AJRouter" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\cbdhsvc" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\StiSvc" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\W32Time" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\HvHost" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\bttflt" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\wudfsvc" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\vmicguestinterface" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\vmicheartbeat" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\vmickvpexchange" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\vmicdrv" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\vmicshutdown" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\vmictimesync" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\vmicvmsession" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\vmicvss" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\gencounter" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\hvservice" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\hyperkbd" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\HyperVideo" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\storflt" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\vmbus" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\vmgid" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\embeddedmode" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WdBoot" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WdNisDrv" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WdNisSvc" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\MDCoreSvc" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\FontCache" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\FontCache3.0.0.0" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DPS" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\wlidsvc" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\cdfs" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\cdrom" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Telemetry" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WdiServiceHost" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WdiSystemHost" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SENS" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SensrSvc" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Sense" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SSDPSRV" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\webthreatdefsvc" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\webthreatusersvc" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SensorDataService" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SensorService" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\scardsvr" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\scdeviceenum" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\scpolicysvc" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\diagsvc" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\bam" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NetTcpPortSharing" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SEMgrSvc" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\UCPD" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\installservice" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\RasMan" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\BDESVC" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DusmSvc" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DsSvc" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\RmSvc" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\BFE" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\EFS" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SstpSvc" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\PimIndexMaintenanceSvc" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WarpJITSvc" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\PrintNotify" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Spooler" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\PrintWorkFlowUserSvc" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\P9RdrService" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\PenService" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WalletService" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\MapsBroker" /v "Start" /t REG_DWORD /d "4" /f >nul
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\ssh-agent" /f >nul
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\sedsvc" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\ShellHWDetection" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\GraphicsPerfSvc" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\GpuEnergyDrv" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NcbService" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\PcaSvc" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\printworkflowusersvc" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\UevAgentService" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\UevAgentDriver" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\PrintNotify" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\PhoneSvc" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\RetailDemo" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\TroubleshootingSvc" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SharedRealitySvc" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\spooler" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\smphost" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\TrkWks" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\tzautoupdate" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WerSvc" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WSearch" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\wuauserv" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\wisvc" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\wscsvc" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Vid" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\RemoteAccess" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\RemoteRegistry" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\p2pimsvc" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\p2psvc" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AxInstSV" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\TapiSrv" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WpnService" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\CSC" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\cnghwassist" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\CscService" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WEPHOSTSVC" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\QWAVE" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\QWAVEdrv" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\BITS" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Wecsvc" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\UsoSvc" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AssignedAccessManagerSvc" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\shpamsvc" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\uhssvc" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WmanSvc" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\StorSvc" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\XblAuthManager" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\GameInputSvc" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\XblGameSave" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\xboxgip" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\XboxGipSvc" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\XboxNetApiSvc" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\xinputhid" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\dosvc" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\lfsvc" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\iphlpsvc" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Themes" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AppIDSvc" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\ClipSVC" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\mpssvc" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\MSDTC" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\CaptureService" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\IKEEXT" /v "Start" /t REG_DWORD /d "4" /f >nul

:: disabled drivers
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Beep" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\bindflt" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\bowser" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\cdrom" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dfsc" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\FileCrypt" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\FileInfo" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\GpuEnergyDrv" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\luafv" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\PEAUTH" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\QWAVEdrv" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\rdbss" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\tcpipreg" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\tdx" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\wanarp" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\wanarpv6" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WindowsTrustedRT" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WindowsTrustedRTProxy" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Wof" /v "Start" /t REG_DWORD /d "4" /f >nul

:: --- TWEAKS REGEDIT/GPEDIT ---
echo  !B_BLACK!Configuring tweaks regedit...
@REM Creator couwthynokap, e1uen
fsutil behavior set disable8dot3 1 >nul
fsutil behavior set disablelastaccess 1 >nul
fsutil behavior set disabledeletenotify 0 >nul
fsutil behavior set memoryusage 2 >nul
Reg.exe add "HKLM\System\ControlSet001\Control\PnP" /v "DisableLKG" /t REG_DWORD /d "1" /f >nul
reg add "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "SensorPermissionState" /t REG_DWORD /d "0" /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "SensorPermissionState" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "CEIPEnable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "MDMEnrollment" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "CortanaConsent" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Privacy" /v "InkAndTypingPersonalizationEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" /v "FaultTolerantHeap" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "NotifyUserOnOutOfSupport" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /v "Manufacturer" /t REG_SZ /d "DelusionOS 11" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /v "Model" /t REG_SZ /d "DelusionOS 24H2" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /v "SupportURL" /t REG_SZ /d "https://dsc.gg/delusionos/" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /v "SupportPhone" /t REG_SZ /d "https://dsc.gg/delusionos/" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "MaximumRecordLength" /t REG_QWORD /d "0x00D088C310000000" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "SystemAudioGain" /t REG_QWORD /d "0x1027000000000000" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "MicrophoneGain" /t REG_QWORD /d "0x1027000000000000" /f >nul
Reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoFolderOptions" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Class\USB\0000" /v "IdleEnable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Control Panel\Keyboard" /v "InitialKeyboardIndicators" /t REG_SZ /d "2" /f >nul
Reg.exe add "HKCU\Control Panel\Keyboard" /v "KeyboardDelay" /t REG_SZ /d "0" /f >nul
Reg.exe add "HKCU\Control Panel\Keyboard" /v "KeyboardSpeed" /t REG_SZ /d "31" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\CI\Config" /v "VulnerableDriverBlocklistEnable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\501a4d13-42af-4429-9fd1-a8218c268e20\ee12f906-d277-404b-b6da-e5fa1a576df5" /v "SettingValue" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009" /v "SettingValue" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\0" /v "SettingValue" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\USB" /v "DisableSelectiveSuspend" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Test\LowSpecChaos" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Class\USB\0001" /v "IdleEnable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Class\USB\0002" /v "IdleEnable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Class\USB\0003" /v "IdleEnable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Class\USB\0004" /v "IdleEnable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Class\USB\0005" /v "IdleEnable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Class\USB\0006" /v "IdleEnable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Class\USB\0007" /v "IdleEnable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Class\USB\0008" /v "IdleEnable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Class\USB\0009" /v "IdleEnable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Class\USB\0010" /v "IdleEnable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Class\USB\0011" /v "IdleEnable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Class\USB\0012" /v "IdleEnable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Class\USB\0013" /v "IdleEnable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Class\USB\0014" /v "IdleEnable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Class\USB\0015" /v "IdleEnable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Class\USB\0016" /v "IdleEnable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Class\USB\0017" /v "IdleEnable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Class\USB\0018" /v "IdleEnable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Class\USB\0019" /v "IdleEnable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Class\USB\0020" /v "IdleEnable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Class\USB\0021" /v "IdleEnable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Class\USB\0022" /v "IdleEnable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Class\USB\0023" /v "IdleEnable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Class\USB\0024" /v "IdleEnable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Class\USB\0025" /v "IdleEnable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Class\USB\0026" /v "IdleEnable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Class\USB\0027" /v "IdleEnable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Class\USB\0028" /v "IdleEnable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Class\USB\0029" /v "IdleEnable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Class\USB\0030" /v "IdleEnable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Class\USB\0031" /v "IdleEnable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Class\USB\0032" /v "IdleEnable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{36FC9E60-C465-11CF-8056-444553540000}\0000" /v "IdleEnable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{36FC9E60-C465-11CF-8056-444553540000}\0001" /v "IdleEnable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{36FC9E60-C465-11CF-8056-444553540000}\0002" /v "IdleEnable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{36FC9E60-C465-11CF-8056-444553540000}\0003" /v "IdleEnable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{36FC9E60-C465-11CF-8056-444553540000}\0004" /v "IdleEnable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{36FC9E60-C465-11CF-8056-444553540000}\0005" /v "IdleEnable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{36FC9E60-C465-11CF-8056-444553540000}\0006" /v "IdleEnable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{36FC9E60-C465-11CF-8056-444553540000}\0007" /v "IdleEnable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{36FC9E60-C465-11CF-8056-444553540000}\0008" /v "IdleEnable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{36FC9E60-C465-11CF-8056-444553540000}\0009" /v "IdleEnable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{36FC9E60-C465-11CF-8056-444553540000}\0010" /v "IdleEnable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{36FC9E60-C465-11CF-8056-444553540000}\0011" /v "IdleEnable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{36FC9E60-C465-11CF-8056-444553540000}\0012" /v "IdleEnable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{36FC9E60-C465-11CF-8056-444553540000}\0013" /v "IdleEnable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{36FC9E60-C465-11CF-8056-444553540000}\0014" /v "IdleEnable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{36FC9E60-C465-11CF-8056-444553540000}\0015" /v "IdleEnable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{36FC9E60-C465-11CF-8056-444553540000}\0016" /v "IdleEnable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{36FC9E60-C465-11CF-8056-444553540000}\0017" /v "IdleEnable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{36FC9E60-C465-11CF-8056-444553540000}\0018" /v "IdleEnable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{36FC9E60-C465-11CF-8056-444553540000}\0019" /v "IdleEnable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{36FC9E60-C465-11CF-8056-444553540000}\0020" /v "IdleEnable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{36FC9E60-C465-11CF-8056-444553540000}\0021" /v "IdleEnable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{36FC9E60-C465-11CF-8056-444553540000}\0022" /v "IdleEnable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{36FC9E60-C465-11CF-8056-444553540000}\0023" /v "IdleEnable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{36FC9E60-C465-11CF-8056-444553540000}\0024" /v "IdleEnable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{36FC9E60-C465-11CF-8056-444553540000}\0025" /v "IdleEnable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{36FC9E60-C465-11CF-8056-444553540000}\0026" /v "IdleEnable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{36FC9E60-C465-11CF-8056-444553540000}\0027" /v "IdleEnable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{36FC9E60-C465-11CF-8056-444553540000}\0028" /v "IdleEnable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{36FC9E60-C465-11CF-8056-444553540000}\0029" /v "IdleEnable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{36FC9E60-C465-11CF-8056-444553540000}\0030" /v "IdleEnable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{36FC9E60-C465-11CF-8056-444553540000}\0031" /v "IdleEnable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{36FC9E60-C465-11CF-8056-444553540000}\0032" /v "IdleEnable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "StartupBoostEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "HardwareAccelerationModeEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "BackgroundModeEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "EnableTransparency" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\NetBT" /v "Start" /t REG_DWORD /d "4" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\FVE" /v "DisableExternalDMAUnderLock" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /v "AllowInputPersonalization" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "DisableNotificationCenter" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\Ndu" /v "Start" /t REG_DWORD /d "4" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DistributeTimers" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "PowerOffFrozenProcessors" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "EnableWerUserReporting" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel" /v "DisableTsx" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationAuditOptions" /t REG_BINARY /d "222222222222222" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationOptions" /t REG_BINARY /d "222222222222222" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" /v "value" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\GameBar" /v "ShowStartupPanel" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\GameBar" /v "GamePanelStartupTipIndex" /t REG_DWORD /d "3" /f >nul
Reg.exe add "HKCU\Software\Microsoft\GameBar" /v "AllowAutoGameMode" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\GameBar" /v "AutoGameModeEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\GameBar" /v "UseNexusForGameBarEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SYSTEM\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SYSTEM\GameConfigStore" /v "GameDVR_FSEBehaviorMode" /t REG_DWORD /d "2" /f >nul
Reg.exe add "HKCU\SYSTEM\GameConfigStore" /v "GameDVR_FSEBehavior" /t REG_DWORD /d "2" /f >nul
Reg.exe add "HKCU\SYSTEM\GameConfigStore" /v "GameDVR_HonorUserFSEBehaviorMode" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\SYSTEM\GameConfigStore" /v "GameDVR_DXGIHonorFSEWindowsCompatible" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\SYSTEM\GameConfigStore" /v "GameDVR_EFSEFeatureFlags" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SYSTEM\GameConfigStore" /v "GameDVR_DSEBehavior" /t REG_DWORD /d "2" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v "AllowGameDVR" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\Dnscache\Parameters" /v "CacheHashTableBucketSize" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\Dnscache\Parameters" /v "CacheHashTableSize" /t REG_DWORD /d "384" /f >nul
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\Dnscache\Parameters" /v "MaxCacheEntryTtlLimit" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\Dnscache\Parameters" /v "MaxSOACacheEntryTtlLimit" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\Dnscache\Parameters" /v "NegativeCacheTime" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\Dnscache\Parameters" /v "NetFailureCacheTime" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\Dnscache\Parameters" /v "NegativeSOACacheTime" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\Dnscache\Parameters" /v "MaxCacheTtl" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\Dnscache\Parameters" /v "MaxNegativeCacheTtl" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\Dnscache\Parameters" /v "EnableAutoDOH" /t REG_DWORD /d "2" /f >nul
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\Dnscache\Parameters\DnsActiveIfs" /f >nul
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\Dnscache\Parameters\DnsConnections" /f >nul
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\Dnscache\Parameters\DnsConnectionsProxies" /f >nul
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\Dnscache\Parameters\DnsPolicyConfig" /f >nul
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\Dnscache\Parameters\DohWellKnownServers\1.0.0.1" /v "Template" /t REG_SZ /d "https://cloudflare-dns.com/dns-query" /f >nul
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\Dnscache\Parameters\DohWellKnownServers\1.1.1.1" /v "Template" /t REG_SZ /d "https://cloudflare-dns.com/dns-query" /f >nul
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\Dnscache\Parameters\DohWellKnownServers\149.112.112.112" /v "Template" /t REG_SZ /d "https://dns.quad9.net/dns-query" /f >nul
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\Dnscache\Parameters\DohWellKnownServers\2001:4860:4860::8844" /v "Template" /t REG_SZ /d "https://dns.google/dns-query" /f >nul
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\Dnscache\Parameters\DohWellKnownServers\2001:4860:4860::8888" /v "Template" /t REG_SZ /d "https://dns.google/dns-query" /f >nul
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\Dnscache\Parameters\DohWellKnownServers\2606:4700:4700::1001" /v "Template" /t REG_SZ /d "https://cloudflare-dns.com/dns-query" /f >nul
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\Dnscache\Parameters\DohWellKnownServers\2606:4700:4700::1111" /v "Template" /t REG_SZ /d "https://cloudflare-dns.com/dns-query" /f >nul
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\Dnscache\Parameters\DohWellKnownServers\2620:fe::9" /v "Template" /t REG_SZ /d "https://dns.quad9.net/dns-query" /f >nul
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\Dnscache\Parameters\DohWellKnownServers\2620:fe::fe" /v "Template" /t REG_SZ /d "https://dns.quad9.net/dns-query" /f >nul
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\Dnscache\Parameters\DohWellKnownServers\8.8.4.4" /v "Template" /t REG_SZ /d "https://dns.google/dns-query" /f >nul
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\Dnscache\Parameters\DohWellKnownServers\8.8.8.8" /v "Template" /t REG_SZ /d "https://dns.google/dns-query" /f >nul
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\Dnscache\Parameters\DohWellKnownServers\9.9.9.9" /v "Template" /t REG_SZ /d "https://dns.quad9.net/dns-query" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\DefaultMediaCost" /v "3G" /t REG_DWORD /d "2" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\DefaultMediaCost" /v "4G" /t REG_DWORD /d "2" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\DefaultMediaCost" /v "Default" /t REG_DWORD /d "2" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\DefaultMediaCost" /v "Ethernet" /t REG_DWORD /d "2" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\DefaultMediaCost" /v "WiFi" /t REG_DWORD /d "2" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackProgs" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "HubMode" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "EnableAutoTray" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Education" /v "EnableEduThemes" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f >nul
Reg.exe add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "1000" /f >nul
Reg.exe add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "2000" /f >nul
Reg.exe add "HKCU\Control Panel\Desktop" /v "LowLevelHooksTimeout" /t REG_SZ /d "1000" /f >nul
Reg.exe add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\SYSTEM" /v "AllowExperimentation" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Speech" /v "AllowSpeechModelUpdate" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowDeviceNameInTelemetry" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowCommercialDataPipeline" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowBuildPreview" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DisableEnterpriseAuthProxy" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DisableTelemetryOptInSettingsUx" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DisableTelemetryOptInChangeNotification" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "LimitDiagnosticLogCollection" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "LimitDumpCollection" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "MicrosoftEdgeDataOptIn" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Bluetooth" /v "AllowAdvertising" /t REG_DWORD /d "0" /f >nul
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\DiagTrack" /f >nul
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\diagnosticshub.standardcollector.service" /v "Start" /t REG_DWORD /d "4" /f >nul
Reg.exe add "HKCU\Software\Classes\ID\{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Classes\ID\{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d "0" /f >nul
Reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" /f >nul
Reg.exe delete "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "HubMode" /t REG_DWORD /d "1" /f >nul
Reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{f874310e-b6b7-47dc-bc84-b9e6b38f5903}" /f >nul
Reg.exe add "HKCU\Software\Classes\ID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" /ve /t REG_SZ /d "" /f >nul
Reg.exe delete "HKCU\SYSTEM\GameConfigStore" /v "Win32_AutoGameModeDefaultProfile" /f >nul
Reg.exe delete "HKCU\SYSTEM\GameConfigStore" /v "Win32_GameModeRelatedProcesses" /f >nul
Reg.exe delete "HKCU\SYSTEM\GameConfigStore\Children" /f >nul
Reg.exe delete "HKCU\SYSTEM\GameConfigStore\Parents" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /v "EnableFirewall" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" /v "EnableFirewall" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" /v "EnableFirewall" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" /v "DisableNotifications" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" /v "MaintenanceDisabled" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" /v "DontShowUI" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" /v "DontSendAdditionalData" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" /v "LoggingDisabled" /t REG_DWORD /d "1" /f >nul
Reg.exe delete "HKLM\SYSTEM\Maps" /f >nul
Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\Maps" /f >nul
Reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableFirstLogonAnimation" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortanaAboveLock" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCloudSearch" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowCortana" /v "value" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorSpeed" /v "CursorUpdateInterval" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy" /v "TelemetryMaxApplication" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy" /v "TelemetryMaxTagPerApplication" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability" /v "TimeStampInterval" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseHoverTime" /t REG_SZ /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\SYSTEM\AllowExperimentation" /v "value" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableWindowsLocationProvider" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocationScripting" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocation" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableSoftLanding" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableTailoredExperiencesWithDiagnosticData" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableThirdPartySuggestions" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SYSTEM" /v "AllowClipboardHistory" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SYSTEM" /v "EnableActivityFeed" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SYSTEM" /v "PublishUserActivities" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SYSTEM" /v "UploadUserActivities" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SYSTEM" /v "DisableLogonBackgroundImage" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SYSTEM" /v "EnableCdp" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "DisableNotificationCenter" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "DisableSearchBoxSuggestions" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "DisableThumbsDBOnNetworkFolders" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "EnableLegacyBalloonNotifications" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "HidePeopleBar" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "2000" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v "DisplayParameters" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\FTH" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Control Panel\Accessibility" /v "Sound on Activation" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Control Panel\Accessibility" /v "Warning Sounds" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Control Panel\Accessibility" /v "StickyKeys" /t REG_SZ /d "0" /f >nul
Reg.exe add "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d "2" /f >nul
Reg.exe add "HKCU\Control Panel\Accessibility\ToggleKeys" /v "Flags" /t REG_SZ /d "34" /f >nul
Reg.exe add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "DelayBeforeAcceptance" /t REG_SZ /d "0" /f >nul
Reg.exe add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "AutoRepeatRate" /t REG_SZ /d "0" /f >nul
Reg.exe add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "AutoRepeatDelay" /t REG_SZ /d "0" /f >nul
Reg.exe add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Flags" /t REG_SZ /d "2" /f >nul
Reg.exe add "HKCU\Control Panel\Accessibility\HighContrast" /v "Flags" /t REG_SZ /d "4218" /f >nul
Reg.exe add "HKCU\Control Panel\Accessibility\MouseKeys" /v "Flags" /t REG_SZ /d "130" /f >nul
Reg.exe add "HKCU\Control Panel\Accessibility\MouseKeys" /v "MaximumSpeed" /t REG_SZ /d "39" /f >nul
Reg.exe add "HKCU\Control Panel\Accessibility\MouseKeys" /v "TimeToMaximumSpeed" /t REG_SZ /d "3000" /f >nul
Reg.exe add "HKCU\Control Panel\Accessibility\SoundSentry" /v "Flags" /t REG_SZ /d "0" /f >nul
Reg.exe add "HKCU\Control Panel\Accessibility\SoundSentry" /v "FSTextEffect" /t REG_SZ /d "0" /f >nul
Reg.exe add "HKCU\Control Panel\Accessibility\SoundSentry" /v "TextEffect" /t REG_SZ /d "0" /f >nul
Reg.exe add "HKCU\Control Panel\Accessibility\SoundSentry" /v "WindowsEffect" /t REG_SZ /d "0" /f >nul
Reg.exe add "HKCU\Control Panel\Accessibility\SlateLaunch" /v "ATapp" /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\Control Panel\Accessibility\SlateLaunch" /v "LaunchAT" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d "3333333333" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Superfetch/Main" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Superfetch/PfApLog" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Superfetch/StoreLog" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "link" /t REG_BINARY /d "00000000" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" /v "Startupdelayinmsec" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\SYSTEM" /v "DisableAutomaticRestartSignOn" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications" /v "ToastEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\PushNotifications" /v "ToastEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoToastApplicationNotification" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "SbEnable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableEngine" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisablePCA" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableInventory" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v "ProtectionMode" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\GameBar" /v "AutoGameModeEnabled" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AudioEncodingBitrate" /t REG_DWORD /d "128000" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AudioCaptureEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "CustomVideoEncodingBitrate" /t REG_DWORD /d "4000000" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "CustomVideoEncodingHeight" /t REG_DWORD /d "720" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "CustomVideoEncodingWidth" /t REG_DWORD /d "1280" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "HistoricalBufferLength" /t REG_DWORD /d "30" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "HistoricalBufferLengthUnit" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "HistoricalCaptureEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "HistoricalCaptureOnBatteryAllowed" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "HistoricalCaptureOnWirelessDisplayAllowed" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "VideoEncodingBitrateMode" /t REG_DWORD /d "2" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "VideoEncodingResolutionMode" /t REG_DWORD /d "2" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "VideoEncodingFrameRateMode" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "EchoCancellationEnabled" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "CursorCaptureEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "VKToggleGameBar" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "VKMToggleGameBar" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "VKSaveHistoricalVideo" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "VKMSaveHistoricalVideo" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "VKToggleRecording" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "VKMToggleRecording" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "VKTakeScreenshot" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "VKMTakeScreenshot" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "VKToggleRecordingIndicator" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "VKMToggleRecordingIndicator" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "VKToggleMicrophoneCapture" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "VKMToggleMicrophoneCapture" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "VKToggleCameraCapture" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "VKMToggleCameraCapture" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "VKToggleBroadcast" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "VKMToggleBroadcast" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "MicrophoneCaptureEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\ScheduledDiagnostics" /v "EnabledExecution" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\input\Settings" /v "InsightsEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\Maps" /v "AutoUpdateEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Appx" /v "AllowAutomaticAppArchiving" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Wallpapers" /v "BackgroundType" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "AppsUseLightTheme" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "SystemUsesLightTheme" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "AppsUseLightTheme" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Accent" /v "StartColorMenu" /t REG_DWORD /d "4282203969" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Accent" /v "AccentColorMenu" /t REG_DWORD /d "4282927692" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Accent" /v "AccentPalette" /t REG_BINARY /d "DFDEDC00A6A5A100686562004C4A4800413F3D0027252400100D0D00107C1000" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\DWM" /v "EnableWindowColorization" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\DWM" /v "AccentColor" /t REG_DWORD /d "4282927692" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\DWM" /v "ColorizationColor" /t REG_DWORD /d "3293334088" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\DWM" /v "ColorizationAfterglow" /t REG_DWORD /d "3293334088" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "ShowOrHideMostUsedApps" /t REG_DWORD /d "2" /f >nul
Reg.exe delete "HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "ShowOrHideMostUsedApps" /f >nul
Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" /f >nul
Reg.exe delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoStartMenuMFUprogramsList" /f >nul
Reg.exe delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInstrumentation" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /f >nul
Reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoStartMenuMFUprogramsList" /f >nul
Reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInstrumentation" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" /v "StoragePoliciesChanged" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" /v "StoragePoliciesNotified" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" /v "01" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" /v "04" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" /v "08" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CDP" /v "NearShareChannelUserAuthzPolicy" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVerison\CDP" /v "CdpSessionUserAuthzPolicy" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Terminal Server" /v "fDenyTSConnections" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Terminal Server" /v "updateRDStatus" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\InstallService\Stubification\S-1-5-21-2296936333-280572394-256428770-1000" /v "EnableAppOffloading" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\debugregsvc\Parameters" /v "DebugState" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_Layout" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "HideRecentlyAddedApps" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "HideRecentlyAddedApps" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_AccountNotifications" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackDocs" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarMn" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowTaskViewButton" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Dsh" /v "AllowNewsAndInterests" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowCopilotButton" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "HideSCAMeetNow" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" /v "EnableFeeds" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Lighting" /v "AmbientLightingEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Lighting" /v "ControlledByForegroundApp" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Lighting" /v "UseSystemAccentColor" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\TabletTip\1.7" /v "IsKeyBackgroundEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_IrisRecommendations" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarSn" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Control Panel\Desktop" /v "LogPixels" /t REG_DWORD /d "96" /f >nul
Reg.exe add "HKCU\Control Panel\Desktop" /v "Win8DpiScaling" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\DWM" /v "UseDpiScaling" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Control Panel\Desktop" /v "EnablePerProcessSystemDPI" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "HwSchMode" /t REG_DWORD /d "2" /f >nul
Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "DirectXUserGlobalSettings" /t REG_SZ /d "SwapEffectUpgradeEnable=1;VRROptimizeEnable=0;" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\windows.immersivecontrolpanel_cw5n1h2txyewy!microsoft.windows.immersivecontrolpanel" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.CapabilityAccess" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.StartupApp" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338389Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\UserProfileEngagement" /v "ScoobeSystemSettingEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\VideoSettings" /v "VideoQualityOnBattery" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\StorageSense" /v "AllowStorageSenseGlobal" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "SnapAssist" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DITest" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "EnableSnapBar" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "EnableTaskGroups" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "EnableSnapAssistFlyout" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "SnapFill" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "JointResize" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "MultiTaskingAltTabFilter" /t REG_DWORD /d "3" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CDP" /v "RomeSdkChannelUserAuthzPolicy" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CDP" /v "CdpSessionUserAuthzPolicy" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsStore" /v "AutoDownload" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "StartupBoostEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "HardwareAccelerationModeEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "BackgroundModeEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "HighEfficiencyModeEnabled" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\GoogleChromeElevationService" /v "Start" /t REG_DWORD /d "4" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\gupdate" /v "Start" /t REG_DWORD /d "4" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\gupdatem" /v "Start" /t REG_DWORD /d "4" /f >nul
Reg.exe add "HKCU\Software\NVIDIA Corporation\NvTray" /v "StartOnLogin" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsRunInBackground" /t REG_DWORD /d "2" /f >nul
Reg.exe add "HKCU\Software\Microsoft\input" /v "IsInputAppPreloadEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Dsh" /v "IsPrelaunchEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Policies\Microsoft\Windows\Explorer" /v "DisableSearchBoxSuggestions" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\Software\Policies\Microsoft\Windows\WindowsCopilot" /v "TurnOffWindowsCopilot" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" /v "TurnOffWindowsCopilot" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\NewsAndInterests\AllowNewsAndInterests" /v "value" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\FTS" /v "EnableGR535" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMax" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" /v "SearchOrderConfig" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseSensitivity" /t REG_SZ /d "10" /f >nul
Reg.exe add "HKU\.DEFAULT\Control Panel\Mouse" /v "MouseSpeed" /t REG_SZ /d "0" /f >nul
Reg.exe add "HKU\.DEFAULT\Control Panel\Mouse" /v "MouseThreshold1" /t REG_SZ /d "0" /f >nul
Reg.exe add "HKU\.DEFAULT\Control Panel\Mouse" /v "MouseThreshold2" /t REG_SZ /d "0" /f >nul
Reg.exe add "HKCU\Control Panel\Accessibility\MouseKeys" /v "Flags" /t REG_SZ /d "0" /f >nul
Reg.exe add "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d "0" /f >nul
Reg.exe add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Flags" /t REG_SZ /d "0" /f >nul
Reg.exe add "HKCU\Control Panel\Accessibility\ToggleKeys" /v "Flags" /t REG_SZ /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\Software\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\NDIS\Parameters" /v "DisableNDISWatchDog" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\NDIS\Parameters" /v "DisableNaps" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\NDIS\Parameters" /v "DisableWDIWatchdogForceBugcheck" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\NDIS\Parameters" /v "DisableReenumerationTimeoutBugcheck" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\NDIS\Parameters" /v "EnableNicAutoPowerSaverInSleepStudy" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Wdf" /v "WdfGlobalLogsDisabled" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Wdf" /v "WdfGlobalSleepStudyDisabled" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettings" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d "3" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d "3" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl\Parameters" /v "ThreadPriority" /t REG_DWORD /d "15" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\Parameters" /v "ThreadPriority" /t REG_DWORD /d "31" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\USBHUB3\Parameters" /v "ThreadPriority" /t REG_DWORD /d "15" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\USBXHCI\Parameters" /v "ThreadPriority" /t REG_DWORD /d "15" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "10" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "10" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NoLazyMode" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Priority" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Scheduling Category" /t REG_SZ /d "Low" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Latency Sensitive" /t REG_SZ /d "False" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "BackgroundPriority" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "Priority" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "Scheduling Category" /t REG_SZ /d "Low" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "Latency Sensitive" /t REG_SZ /d "False" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "BackgroundPriority" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "Priority" /t REG_DWORD /d "8" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "Scheduling Category" /t REG_SZ /d "High" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "Latency Sensitive" /t REG_SZ /d "False" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "Latency Sensitive" /t REG_SZ /d "False" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "Priority" /t REG_DWORD /d "8" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "Scheduling Category" /t REG_SZ /d "High" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Latency Sensitive" /t REG_SZ /d "False" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "Latency Sensitive" /t REG_SZ /d "False" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Latency Sensitive" /t REG_SZ /d "False" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "Latency Sensitive" /t REG_SZ /d "False" /f >nul
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMAERRForceDisable" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMNoECCFuseCheck" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMDisableRCOnDBE" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RM1441072" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMAERRHandling" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v "ProtectionMode" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v "EnableWerUserReporting" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "SleepStudyDisabled" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "IdleScanInterval" /t REG_DWORD /d "300" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MSDisabled" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "PerfCalculateActualUtilization" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DisableVsyncLatencyUpdate" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "ExitLatencyCheckEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "EnergyEstimationEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "FxAccountingTelemetryDisabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "CoalescingFlushInterval" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "Latency" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceDefault" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceVSyncEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceFSVP" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceIdleResiliency" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePageCombining" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "MoveImages" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HibernateEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\Dwm" /v "OverlayTestMode" /t REG_DWORD /d "5" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PreferSystemMemoryContiguous" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" /v "PreferSystemMemoryContiguous" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Ole" /v "EnableDCOM" /t REG_SZ /d "N" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "DpiMapIommuContiguous" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Nls\CodePage" /v "1251" /t REG_SZ /d "c_1251.nls" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Nls\CodePage" /v "1252" /t REG_SZ /d "c_1251.nls" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Nls\CodePage" /v "1253" /t REG_SZ /d "c_1251.nls" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Nls\CodePage" /v "1254" /t REG_SZ /d "c_1251.nls" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Nls\CodePage" /v "1255" /t REG_SZ /d "c_1251.nls" /f >nul
Reg.exe add "HKCR\*\shell\runas" /ve /t REG_SZ /d "Take Ownership" /f >nul
Reg.exe add "HKCR\*\shell\runas" /v "NoWorkingDirectory" /t REG_SZ /d "" /f >nul
Reg.exe add "HKCR\*\shell\runas\command" /ve /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\" && ica \"%%1\" /grant administrators:F" /f >nul
Reg.exe add "HKCR\*\shell\runas\command" /v "IsolatedCommand" /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\" && ica \"%%1\" /grant administrators:F" /f >nul
Reg.exe add "HKCR\Directory\shell\runas" /ve /t REG_SZ /d "Take Ownership" /f >nul
Reg.exe add "HKCR\Directory\shell\runas" /v "NoWorkingDirectory" /t REG_SZ /d "" /f >nul
Reg.exe add "HKCR\Directory\shell\runas\command" /ve /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\" /r /d y && ica \"%%1\" /grant administrators:F /t" /f >nul
Reg.exe add "HKCR\Directory\shell\runas\command" /v "IsolatedCommand" /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\" /r /d y && ica \"%%1\" /grant administrators:F /t" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableDynamicPstate" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" /v "DisableDynamicPstate" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" /v "DisableDynamicPstate" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" /v "DisableDynamicPstate" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0004" /v "DisableDynamicPstate" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\GameBar" /v "AllowAutoGameMode" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\GameBar" /v "AutoGameModeEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\GameBar" /v "GamePanelStartupTipIndex" /t REG_DWORD /d "3" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\GameBar" /v "ShowStartupPanel" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\GameBar" /v "UseNexusForGameBarEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Nls\CodePage" /v "ACP" /t REG_SZ /d "1251" /f >nul
Reg.exe add "HKCU\SYSTEM\GameConfigStore" /v "GameDVR_HonorUserFSEBehaviorMode" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SYSTEM\GameConfigStore" /v "GameDVR_DXGIHonorFSEWindowsCompatible" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\MMCSS" /v "Start" /t REG_DWORD /d "2" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "FastSendDatagramThreshold" /t REG_DWORD /d "65536" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" /v "MaximumPortsServiced" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" /v "SendOutputToAllPorts" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\mouhid\Parameters" /v "UseOnlyMice" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\mouhid\Parameters" /v "TreatAbsolutePointerAsAbsolute" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Perflib" /v "Disable Performance Counters" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableSuperfetch" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableSuperfetch" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SysMain" /v "Start" /t REG_DWORD /d "4" /f >nul
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "24" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Control Panel\International\User Profile" /v "HttpAcceptLanguageOptOut" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackProgs" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338393Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353694Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353696Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "ShowedToastAtLevel" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\EventTranscriptKey" /v "EnableEventTranscript" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d "0" /f >nul
Reg.exe delete "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSyncProviderNotifications" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenOverlayEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-310093Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-314563Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338387Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338388Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338389Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353698Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /t REG_DWORD /d "1" /f >nul

Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "RSoPLogging" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\ClickToRun\OverRide" /v "DisableLogManagement" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Office\ClickToRun\Configuration" /v "TimerInterval" /t REG_SZ /d "900000" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v "AutoApproveOSDumps" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v "LoggingDisabled" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "DontShowUI" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\Software\Microsoft\Windows\Windows Error Reporting\Consent" /v "DefaultConsent" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\Software\Microsoft\Windows\Windows Error Reporting\Consent" /v "DefaultOverrideBehavior" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting\Consent" /v "0" /t REG_SZ /d "" /f >nul

Reg.exe add "HKCU\Software\Microsoft\Office\16.0\Common" /v "sendcustomerdata" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Office\16.0\Common\Feedback" /v "enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Office\16.0\Common\Feedback" /v "includescreenshot" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Office\16.0\Outlook\Options\Mail" /v "EnableLogging" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Office\16.0\Word\Options" /v "EnableLogging" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Policies\Microsoft\Office\16.0\Common" /v "qmenable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Policies\Microsoft\Office\16.0\Common" /v "updatereliabilitydata" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Policies\Microsoft\Office\16.0\Common\General" /v "shownfirstrunoptin" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Policies\Microsoft\Office\16.0\Common\General" /v "skydrivesigninoption" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Policies\Microsoft\Office\16.0\Common\ptwatson" /v "ptwoptin" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Policies\Microsoft\Office\16.0\Firstrun" /v "disablemovie" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\Software\Policies\Microsoft\Office\16.0\OSM" /v "Enablelogging" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Policies\Microsoft\Office\16.0\OSM" /v "EnableUpload" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Policies\Microsoft\Office\16.0\OSM\preventedapplications" /v "accesssolution" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\Software\Policies\Microsoft\Office\16.0\OSM\preventedapplications" /v "olksolution" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\Software\Policies\Microsoft\Office\16.0\OSM\preventedapplications" /v "onenotesolution" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\Software\Policies\Microsoft\Office\16.0\OSM\preventedapplications" /v "pptsolution" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\Software\Policies\Microsoft\Office\16.0\OSM\preventedapplications" /v "projectsolution" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\Software\Policies\Microsoft\Office\16.0\OSM\preventedapplications" /v "publishersolution" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\Software\Policies\Microsoft\Office\16.0\OSM\preventedapplications" /v "visiosolution" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\Software\Policies\Microsoft\Office\16.0\OSM\preventedapplications" /v "wdsolution" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\Software\Policies\Microsoft\Office\16.0\OSM\preventedapplications" /v "xlsolution" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\Software\Policies\Microsoft\Office\16.0\OSM\preventedsolutiontypes" /v "agave" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\Software\Policies\Microsoft\Office\16.0\OSM\preventedsolutiontypes" /v "appaddins" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\Software\Policies\Microsoft\Office\16.0\OSM\preventedsolutiontypes" /v "comaddins" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\Software\Policies\Microsoft\Office\16.0\OSM\preventedsolutiontypes" /v "documentfiles" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\Software\Policies\Microsoft\Office\16.0\OSM\preventedsolutiontypes" /v "templatefiles" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\EdgeUpdate" /v "DoNotUpdateToEdgeWithChromium" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Mozilla\Firefox" /v "DisableAppUpdate" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\MicrosoftEdgeElevationService" /v "Start" /t REG_DWORD /d "4" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\edgeupdate" /v "Start" /t REG_DWORD /d "4" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\edgeupdatem" /v "Start" /t REG_DWORD /d "4" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\4faab71a-92e5-4726-b531-224559672d19" /v "SettingValue" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2E601130-5351-4d9d-8E04-252966BAD054\D502F7EE-1DC7-4EFD-A55D-F04B6F5C0545" /v "SettingValue" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\238C9FA8-0AAD-41ED-83F4-97BE242C8F20\25DFA149-5DD1-4736-B5AB-E8A37B5B8187" /v "SettingValue" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "NOC_GLOBAL_SETTING_ALLOW_TOASTS_ABOVE_LOCK" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "NOC_GLOBAL_SETTING_ALLOW_CRITICAL_TOASTS_ABOVE_LOCK" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "NOC_GLOBAL_SETTING_TOASTS_ENABLED" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoTileApplicationNotification" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "3" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "3" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\kdnic" /v "Start" /t REG_DWORD /d "4" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\NdisVirtualBus" /v "Start" /t REG_DWORD /d "4" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Vid" /v "Start" /t REG_DWORD /d "4" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".tif" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".tiff" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".bmp" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".dib" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".gif" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".jfif" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".jpe" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".jpeg" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".jpg" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".jxr" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".png" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Gaming.GameBar.PresenceServer.Internal.PresenceWriter" /v "ActivationType" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Update" /v "ExcludeWUDriversInQualityUpdate" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Update" /v "ExcludeWUDriversInQualityUpdate" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "ExcludeWUDriversInQualityUpdate" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "ExcludeWUDriversInQualityUpdate" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Update\ExcludeWUDriversInQualityUpdate" /v "value" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v "PreventDeviceMetadataFromNetwork" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" /v "DontSearchWindowsUpdate" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\Input\Buttons" /v "HardwareButtonsAsVKeys" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v "ConfigureSystemGuardLaunch" /t REG_DWORD /d "2" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v "HypervisorEnforcedCodeIntegrity" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v "LsaCfgFlags" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v "HVCIMATRequired" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v "RequirePlatformSecurityFeatures" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\NDIS\Parameters" /v "TrackNblOwner" /t REG_DWORD /d "2" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BackgroundAppGlobalToggle" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /v "DODownloadMode" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\SYSTEM" /v "EnableVirtualization" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\SYSTEM" /v "EnableInstallerDetection" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\SYSTEM" /v "PromptOnSecureDesktop" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\SYSTEM" /v "EnableLUA" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\SYSTEM" /v "EnableSecureUIAPaths" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\SYSTEM" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\SYSTEM" /v "ValidateAdminCodeSignatures" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\SYSTEM" /v "EnableUIADesktopToggle" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\SYSTEM" /v "ConsentPromptBehaviorUser" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\SYSTEM" /v "FilterAdministratorToken" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched" /v "MaxOutstandingSends" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched" /v "NonBestEffortLimit" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched" /v "TimerResolution" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\SOFTWARE\Policies\Microsoft\Windows\HotspotAuthentication" /v "Enable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\SOFTWARE\Policies\Microsoft\Windows\Network Connections" /v "NC_StdDomainUserSetLocation1" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\wcmsvc\wifinetworkmanager\config" /v "AutoConnectAllowedOEM" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\WwanSvc\CellularDataAccess" /v "LetAppsAccessCellularData" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\SOFTWARE\Policies\Microsoft\Windows\NetCache" /v "OnlineCachingLatencyThreshold" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\SOFTWARE\Policies\Microsoft\Windows\NetCache" /v "SyncEnabledForCostedNetwork" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\SOFTWARE\Policies\Microsoft\Windows\NetCache" /v "ExcludedFileTypes" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\SOFTWARE\Policies\Microsoft\Windows\NetCache" /v "EconomicalAdminPinning" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\SOFTWARE\Policies\Microsoft\Windows\NetCache" /v "ReminderBalloonTimeoutSeconds" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\SOFTWARE\Policies\Microsoft\Windows\NetCache" /v "GoOfflineAction" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\SOFTWARE\Policies\Microsoft\Windows\NetCache" /v "NoCacheViewer" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\SOFTWARE\Policies\Microsoft\Windows\NetCache" /v "NoConfigCache" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\SOFTWARE\Policies\Microsoft\Windows\NetCache" /v "InitialBalloonTimeoutSeconds" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\SOFTWARE\Policies\Microsoft\Windows\NetCache" /v "SlowLinkEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\SOFTWARE\Policies\Microsoft\Windows\NetCache" /v "SlowLinkSpeed" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\SOFTWARE\Policies\Microsoft\Windows\NetCache" /v "BackgroundSyncEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\SOFTWARE\Policies\Microsoft\Windows\NetCache" /v "ExcludeExtensions" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\SOFTWARE\Policies\Microsoft\Windows\NetCache" /v "CacheQuotaLimit" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\SOFTWARE\Policies\Microsoft\Windows\NetCache" /v "CacheQuotaLimitUnpinned" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\SOFTWARE\Policies\Microsoft\Windows\NetCache" /v "NoReminders" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\SOFTWARE\Policies\Microsoft\Windows\NetCache" /v "PurgeOnlyAutoCacheAtLogoff" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\SOFTWARE\Policies\Microsoft\Windows\NetCache" /v "PurgeAtLogoff" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\SOFTWARE\Policies\Microsoft\Windows\NetCache" /v "DefCacheSize" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\SOFTWARE\Policies\Microsoft\Windows\NetCache" /v "AlwaysPinSubFolders" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\SOFTWARE\Policies\Microsoft\Windows\NetCache" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\SOFTWARE\Policies\Microsoft\Windows\NetCache" /v "SyncAtLogoff" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\SOFTWARE\Policies\Microsoft\Windows\NetCache" /v "SyncAtSuspend" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\SOFTWARE\Policies\Microsoft\Windows\NetCache" /v "WorkOfflineDisabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\SOFTWARE\Policies\Microsoft\Windows\NetCache" /v "NoMakeAvailableOffline" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\SOFTWARE\Policies\Microsoft\Windows\NetCache" /v "ReminderFreqMinutes" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\SOFTWARE\Policies\Microsoft\Windows\NetCache" /v "SyncAtLogon" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\.NET CLR Data\Performance" /v "Disable Performance Counters" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\.NET CLR Networking\Performance" /v "Disable Performance Counters" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\.NET CLR Networking 4.0.0.0\Performance" /v "Disable Performance Counters" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\.NET Data Provider for Oracle\Performance" /v "Disable Performance Counters" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\.NET Data Provider for SqlServer\Performance" /v "Disable Performance Counters" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\.NET Memory Cache 4.0\Performance" /v "Disable Performance Counters" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\.NETFramework\Performance" /v "Disable Performance Counters" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\BITS\Performance" /v "Disable Performance Counters" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\ESENT\Performance" /v "Disable Performance Counters" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Lsa\Performance" /v "Disable Performance Counters" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\MSDTC\Performance" /v "Disable Performance Counters" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\MSDTC Bridge 4.0.0.0\Performance" /v "Disable Performance Counters" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\MSSCNTRS\Performance" /v "Disable Performance Counters" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\rdyboost\Performance" /v "Disable Performance Counters" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SMSvcHost 4.0.0.0\Performance" /v "Disable Performance Counters" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Spooler\Performance" /v "Disable Performance Counters" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\TapiSrv\Performance" /v "Disable Performance Counters" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\UGatherer\Performance" /v "Disable Performance Counters" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\UGTHRSVC\Performance" /v "Disable Performance Counters" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\usbhub\Performance" /v "Disable Performance Counters" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Windows Workflow Foundation 4.0.0.0\Performance" /v "Disable Performance Counters" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WSearchIdxPi\Performance" /v "Disable Performance Counters" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet" /v "ActiveDnsProbeContent" /t REG_SZ /d "208.67.222.222" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet" /v "ActiveDnsProbeContentV6" /t REG_SZ /d "2620:119:35::35" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet" /v "ActiveDnsProbeHost" /t REG_SZ /d "resolver1.opendns.com" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet" /v "ActiveDnsProbeHostV6" /t REG_SZ /d "resolver1.opendns.com" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet" /v "ActiveWebProbeContent" /t REG_SZ /d "success" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet" /v "ActiveWebProbeContentV6" /t REG_SZ /d "success" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet" /v "ActiveWebProbeHost" /t REG_SZ /d "detectportal.firefox.com" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet" /v "ActiveWebProbeHostV6" /t REG_SZ /d "detectportal.firefox.com" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet" /v "ActiveWebProbePath" /t REG_SZ /d "success.txt" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet" /v "ActiveWebProbePathV6" /t REG_SZ /d "success.txt" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator" /v "NoActiveProbe" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Connectivity\DisallowNetworkConnectivityActiveTests" /v "value" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters" /v "ShowDomainEndpointInterfaces" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet" /v "EnableActiveProbing" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet" /v "EnableNoGatewayLocationDetection" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "LargeIrpStackLocations" /t REG_DWORD /d "8" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCPL" /v "AutoPlay" /t REG_SZ /d "AutoPlay" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCPL" /v "File History" /t REG_SZ /d "File History" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCPL" /v "Credential Manager" /t REG_SZ /d "Credential Manager" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCPL" /v "Windows To Go" /t REG_SZ /d "Windows To Go" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCPL" /v "Work Folders" /t REG_SZ /d "Work Folders" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCPL" /v "Flash Player" /t REG_SZ /d "Flash Player" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCPL" /v "Troubleshooting" /t REG_SZ /d "Troubleshooting" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCPL" /v "Speech Recognition" /t REG_SZ /d "Speech Recognition" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCPL" /v "BitLocker Drive Encryption" /t REG_SZ /d "BitLocker Drive Encryption" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCPL" /v "Security and Maintenance" /t REG_SZ /d "Security and Maintenance" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCPL" /v "Phone and Modem" /t REG_SZ /d "Phone and Modem" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCPL" /v "Windows Mobility Center" /t REG_SZ /d "Windows Mobility Center" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCPL" /v "Backup and Restore (Windows 7)" /t REG_SZ /d "Backup and Restore (Windows 7)" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCPL" /v "RemoteApp And Desktop Connections" /t REG_SZ /d "RemoteApp And Desktop Connections" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCPL" /v "Storage Spaces" /t REG_SZ /d "Storage Spaces" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCPL" /v "Indexing Options" /t REG_SZ /d "Indexing Options" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCPL" /v "Internet Options" /t REG_SZ /d "Internet Options" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCPL" /v "Sync Center" /t REG_SZ /d "Sync Center" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCPL" /v "Default Programs" /t REG_SZ /d "Default Programs" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCPL" /v "Taskbar And Navigation" /t REG_SZ /d "Taskbar And Navigation" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCPL" /v "Color Management" /t REG_SZ /d "Color Management" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" /v "CertificateRevocation" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" /v "DisableCachingOfSSLPages" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" /v "PrivacyAdvanced" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" /v "SecureProtocols" /t REG_DWORD /d "10912" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" /v "EnableNegotiate" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MigrateProxy" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" /v "ProxyEnable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" /v "WarnonZoneCrossing" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" /v "EnableHttp1_1" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" /v "ProxyHttp1.1" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" /v "EnableHTTP2" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" /v "EnablePunycode" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" /v "UrlEncoding" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" /v "DisableIDNPrompt" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" /v "ShowPunycode" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" /v "WarnonBadCertRecving" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" /v "WarnOnPostRedirect" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" /v "SyncMode5" /t REG_DWORD /d "3" /f >nul
Reg.exe add "HKU\.DEFAULT\Microsoft\Windows\CurrentVersion\Internet Settings" /v "CertificateRevocation" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKU\.DEFAULT\Microsoft\Windows\CurrentVersion\Internet Settings" /v "DisableCachingOfSSLPages" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKU\.DEFAULT\Microsoft\Windows\CurrentVersion\Internet Settings" /v "PrivacyAdvanced" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKU\.DEFAULT\Microsoft\Windows\CurrentVersion\Internet Settings" /v "SecureProtocols" /t REG_DWORD /d "10912" /f >nul
Reg.exe add "HKU\.DEFAULT\Microsoft\Windows\CurrentVersion\Internet Settings" /v "EnableNegotiate" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKU\.DEFAULT\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MigrateProxy" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKU\.DEFAULT\Microsoft\Windows\CurrentVersion\Internet Settings" /v "ProxyEnable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKU\.DEFAULT\Microsoft\Windows\CurrentVersion\Internet Settings" /v "WarnonZoneCrossing" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKU\.DEFAULT\Microsoft\Windows\CurrentVersion\Internet Settings" /v "EnableHttp1_1" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKU\.DEFAULT\Microsoft\Windows\CurrentVersion\Internet Settings" /v "ProxyHttp1.1" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKU\.DEFAULT\Microsoft\Windows\CurrentVersion\Internet Settings" /v "EnableHTTP2" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKU\.DEFAULT\Microsoft\Windows\CurrentVersion\Internet Settings" /v "EnablePunycode" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKU\.DEFAULT\Microsoft\Windows\CurrentVersion\Internet Settings" /v "UrlEncoding" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKU\.DEFAULT\Microsoft\Windows\CurrentVersion\Internet Settings" /v "DisableIDNPrompt" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKU\.DEFAULT\Microsoft\Windows\CurrentVersion\Internet Settings" /v "ShowPunycode" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKU\.DEFAULT\Microsoft\Windows\CurrentVersion\Internet Settings" /v "WarnonBadCertRecving" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKU\.DEFAULT\Microsoft\Windows\CurrentVersion\Internet Settings" /v "WarnOnPostRedirect" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKU\.DEFAULT\Microsoft\Windows\CurrentVersion\Internet Settings" /v "SyncMode5" /t REG_DWORD /d "3" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" /v "CertificateRevocation" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" /v "DisableCachingOfSSLPages" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" /v "PrivacyAdvanced" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" /v "SecureProtocols" /t REG_DWORD /d "10912" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" /v "EnableNegotiate" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MigrateProxy" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" /v "ProxyEnable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" /v "WarnonZoneCrossing" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" /v "EnableHttp1_1" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" /v "ProxyHttp1.1" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" /v "EnableHTTP2" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" /v "EnablePunycode" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" /v "UrlEncoding" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" /v "DisableIDNPrompt" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" /v "ShowPunycode" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" /v "WarnonBadCertRecving" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" /v "WarnOnPostRedirect" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" /v "SyncMode5" /t REG_DWORD /d "3" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "140C" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "270C" /t REG_DWORD /d "3" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "1806" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "180E" /t REG_DWORD /d "3" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "2301" /t REG_DWORD /d "3" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "1004" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "1802" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "140C" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "270C" /t REG_DWORD /d "3" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1806" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "180E" /t REG_DWORD /d "3" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "2301" /t REG_DWORD /d "3" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1004" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1802" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" /v "140C" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" /v "270C" /t REG_DWORD /d "3" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" /v "1806" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" /v "180E" /t REG_DWORD /d "3" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" /v "2301" /t REG_DWORD /d "3" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" /v "1004" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" /v "1802" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1" /v "140C" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1" /v "270C" /t REG_DWORD /d "3" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1" /v "1806" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1" /v "180E" /t REG_DWORD /d "3" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1" /v "2301" /t REG_DWORD /d "3" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1" /v "1004" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1" /v "1802" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0" /v "140C" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0" /v "270C" /t REG_DWORD /d "3" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0" /v "1806" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0" /v "180E" /t REG_DWORD /d "3" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0" /v "2301" /t REG_DWORD /d "3" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0" /v "1004" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0" /v "1802" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\0" /v "140C" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\0" /v "270C" /t REG_DWORD /d "3" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\0" /v "1806" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\0" /v "180E" /t REG_DWORD /d "3" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\0" /v "2301" /t REG_DWORD /d "3" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\0" /v "1004" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\0" /v "1802" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\1" /v "140C" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\1" /v "270C" /t REG_DWORD /d "3" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\1" /v "1806" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\1" /v "180E" /t REG_DWORD /d "3" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\1" /v "2301" /t REG_DWORD /d "3" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\1" /v "1004" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\1" /v "1802" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\2" /v "140C" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\2" /v "270C" /t REG_DWORD /d "3" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\2" /v "1806" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\2" /v "180E" /t REG_DWORD /d "3" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\2" /v "2301" /t REG_DWORD /d "3" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\2" /v "1004" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\2" /v "1802" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\3" /v "140C" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\3" /v "270C" /t REG_DWORD /d "3" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\3" /v "1806" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\3" /v "180E" /t REG_DWORD /d "3" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\3" /v "2301" /t REG_DWORD /d "3" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\3" /v "1004" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\3" /v "1802" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\4" /v "140C" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\4" /v "270C" /t REG_DWORD /d "3" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\4" /v "1806" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\4" /v "180E" /t REG_DWORD /d "3" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\4" /v "2301" /t REG_DWORD /d "3" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\4" /v "1004" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\4" /v "1802" /t REG_DWORD /d "0" /f >nul
reg.exe add "HKCR\ID\{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}\ShellFolder" /v "Attributes" /t REG_DWORD /d "2962489444" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Narrator\NoRoam" /v "DuckAudio" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Narrator\NoRoam" /v "WinEnterLaunchEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Narrator\NoRoam" /v "ScriptingEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Narrator\NoRoam" /v "OnlineServicesEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Narrator" /v "NarratorCursorHighlight" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Narrator" /v "CoupleNarratorCursorKeyboard" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SystemSettings\AccountNotifications" /v "EnableAccountNotifications" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t REG_SZ /d "Deny" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CPSS\Store\UserLocationOverridePrivacySetting" /v "Value" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" /v "Value" /t REG_SZ /d "Allow" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Speech_OneCore\Settings\VoiceActivation\UserPreferenceForAllApps" /v "AgentActivationEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Speech_OneCore\Settings\VoiceActivation\UserPreferenceForAllApps" /v "AgentActivationLastUsed" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener" /v "Value" /t REG_SZ /d "Deny" /f >nul
Reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" /v "Value" /t REG_SZ /d "Deny" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" /v "Value" /t REG_SZ /d "Deny" /f >nul
Reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments" /v "Value" /t REG_SZ /d "Deny" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCall" /v "Value" /t REG_SZ /d "Deny" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory" /v "Value" /t REG_SZ /d "Deny" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email" /v "Value" /t REG_SZ /d "Deny" /f >nul
Reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks" /v "Value" /t REG_SZ /d "Deny" /f >nul
Reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat" /v "Value" /t REG_SZ /d "Deny" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios" /v "Value" /t REG_SZ /d "Deny" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetoothSync" /v "Value" /t REG_SZ /d "Deny" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" /v "Value" /t REG_SZ /d "Deny" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary" /v "Value" /t REG_SZ /d "Deny" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\downloadsFolder" /v "Value" /t REG_SZ /d "Deny" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\musicLibrary" /v "Value" /t REG_SZ /d "Deny" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary" /v "Value" /t REG_SZ /d "Deny" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary" /v "Value" /t REG_SZ /d "Deny" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess" /v "Value" /t REG_SZ /d "Deny" /f >nul
Reg.exe add "HKCU\Software\Policies\Microsoft\Windows\EdgeUI" /v "DisableMFUTracking" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\EdgeUI" /v "DisableMFUTracking" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\ScreenMagnifier" /v "FollowCaret" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\ScreenMagnifier" /v "FollowNarrator" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\ScreenMagnifier" /v "FollowMouse" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\ScreenMagnifier" /v "FollowFocus" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Narrator" /v "IntonationPause" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Narrator" /v "ReadHints" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Narrator" /v "ErrorNotificationType" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Narrator" /v "EchoChars" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Narrator" /v "EchoWords" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Narrator\NarratorHome" /v "MinimizeType" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Narrator\NarratorHome" /v "AutoStart" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Narrator\NoRoam" /v "EchoToggleKeys" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Control Panel\Keyboard" /v "PrintScreenKeyForSnippingEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SmartActionPlatform\SmartClipboard" /v "Disabled" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\??windows.data.notifications.quiethourssettings\Current" /v "Data" /t REG_BINARY /d "02000000B4672B68F00BD8010000000043420100C20A01D214284D006900630072006F0073006F00660074002E005100750069006500740048006F00750072007300500072006F00660069006C0065002E0055006E007200650073007400720069006300740065006400CA28D014020000" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\?quietmomentfullscreen?windows.data.notifications.quietmoment\Current" /v "Data" /t REG_BINARY /d "02000000971D2D68F00BD8010000000043420100C20A01D21E264D006900630072006F0073006F00660074002E005100750069006500740048006F00750072007300500072006F00660069006C0065002E0041006C00610072006D0073004F006E006C007900C22801CA500000" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\?quietmomentgame?windows.data.notifications.quietmoment\Current" /v "Data" /t REG_BINARY /d "020000006C392D68F00BD8010000000043420100C20A01D21E284D006900630072006F0073006F00660074002E005100750069006500740048006F00750072007300500072006F00660069006C0065002E005000720069006F0072006900740079004F006E006C007900C22801CA500000" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\?quietmomentpostoobe?windows.data.notifications.quietmoment\Current" /v "Data" /t REG_BINARY /d "0200000006542D68F00BD8010000000043420100C20A01D21E284D006900630072006F0073006F00660074002E005100750069006500740048006F00750072007300500072006F00660069006C0065002E005000720069006F0072006900740079004F006E006C007900C22801CA500000" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\?quietmomentpresentation?windows.data.notifications.quietmoment\Current" /v "Data" /t REG_BINARY /d "02000000836E2D68F00BD8010000000043420100C20A01D21E264D006900630072006F0073006F00660074002E005100750069006500740048006F00750072007300500072006F00660069006C0065002E0041006C00610072006D0073004F006E006C007900C22801CA500000" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\?quietmomentscheduled?windows.data.notifications.quietmoment\Current" /v "Data" /t REG_BINARY /d "020000002E8A2D68F00BD8010000000043420100C20A01D21E284D006900630072006F0073006F00660074002E005100750069006500740048006F00750072007300500072006F00660069006C0065002E005000720069006F0072006900740079004F006E006C007900C22801D13280E0AA8A9930D13C80E0F6C5D50ECA500000" /f >nul
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Messaging" /v "AllowMessageSync" /t REG_DWORD /d "0" /f >nul
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\$$windows.data.notifications.quiethourssettings\Current" /v "Data" /t REG_BINARY /d "02000000B4672B68F00BD8010000000043420100C20A01D214284D006900630072006F0073006F00660074002E005100750069006500740048006F00750072007300500072006F00660069006C0065002E0055006E007200650073007400720069006300740065006400CA28D014020000" /f >nul
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\$quietmomentfullscreen$windows.data.notifications.quietmoment\Current" /v "Data" /t REG_BINARY /d "02000000971D2D68F00BD8010000000043420100C20A01D21E264D006900630072006F0073006F00660074002E005100750069006500740048006F00750072007300500072006F00660069006C0065002E0041006C00610072006D0073004F006E006C007900C22801CA500000" /f >nul
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\$quietmomentgame$windows.data.notifications.quietmoment\Current" /v "Data" /t REG_BINARY /d "020000006C392D68F00BD8010000000043420100C20A01D21E284D006900630072006F0073006F00660074002E005100750069006500740048006F00750072007300500072006F00660069006C0065002E005000720069006F0072006900740079004F006E006C007900C22801CA500000" /f >nul
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\$quietmomentpostoobe$windows.data.notifications.quietmoment\Current" /v "Data" /t REG_BINARY /d "0200000006542D68F00BD8010000000043420100C20A01D21E284D006900630072006F0073006F00660074002E005100750069006500740048006F00750072007300500072006F00660069006C0065002E005000720069006F0072006900740079004F006E006C007900C22801CA500000" /f >nul
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\$quietmomentpresentation$windows.data.notifications.quietmoment\Current" /v "Data" /t REG_BINARY /d "02000000836E2D68F00BD8010000000043420100C20A01D21E264D006900630072006F0073006F00660074002E005100750069006500740048006F00750072007300500072006F00660069006C0065002E0041006C00610072006D0073004F006E006C007900C22801CA500000" /f >nul
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\$quietmomentscheduled$windows.data.notifications.quietmoment\Current" /v "Data" /t REG_BINARY /d "020000002E8A2D68F00BD8010000000043420100C20A01D21E284D006900630072006F0073006F00660074002E005100750069006500740048006F00750072007300500072006F00660069006C0065002E005000720069006F0072006900740079004F006E006C007900C22801D13280E0AA8A9930D13C80E0F6C5D50ECA500000" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\DeviceCensus.exe" /v "Debugger" /t REG_SZ /d "%windir%\System32\taskkill.exe" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\BingChatInstaller.exe" /v "Debugger" /t REG_SZ /d "%windir%\System32\taskkill.exe" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\BGAUpsell.exe" /v "Debugger" /t REG_SZ /d "%windir%\System32\taskkill.exe" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\BCILauncher.exe" /v "Debugger" /t REG_SZ /d "%windir%\System32\taskkill.exe" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe" /v "Debugger" /t REG_SZ /d "%windir%\System32\taskkill.exe" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\AggregatorHost.exe" /v "Debugger" /t REG_SZ /d "%windir%\System32\taskkill.exe" /f >nul
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Reporting" /v "DisableGenericRePorts" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows Security Health\State" /v "AccountProtection_MicrosoftAccount_Disconnected" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKU\.DEFAULT\Software\Microsoft\Windows Security Health\State" /v "AccountProtection_MicrosoftAccount_Disconnected" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" /v "EnableCortanaVoice" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OOBE" /v "EnableCortanaVoice" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" /v "DisableVoice" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OOBE" /v "DisableVoice" /t REG_DWORD /d "1" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HibernateEnabled" /t REG_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HibernateEnabledDefault" /t REG_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{01090065-b467-4503-9b28-533766761087}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{06edcfeb-0fd0-4e53-acca-a6f8bbf81bcb}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{08466062-aed4-4834-8b04-cddb414504e5}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{0888e5ef-9b98-4695-979d-e92ce4247224}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{09608c12-c1da-4104-a6fe-b959cf57560a}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{09ac07b9-6ac9-43bc-a50f-58419a797c69}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{09ec9687-d7ad-40ca-9c5e-78a04a5ae993}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{0dd4d48e-2bbf-452f-a7ec-ba3dba8407ae}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{0ff1c24b-7f05-45c0-abdc-3c8521be4f62}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{10a208dd-a372-421c-9d99-4fad6db68b62}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{1139c61b-b549-4251-8ed3-27250a1edec8}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{11a75546-3234-465e-bec8-2d301cb501ac}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{126cdb97-d346-4894-8a34-658da5eea1b6}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{134ea407-755d-4a93-b8a6-f290cd155023}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{13bc4371-4e21-4e46-a84f-8c0ffb548ced}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{1418ef04-b0b4-4623-bf7e-d74ab47bbdaa}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{15a7a4f8-0072-4eab-abad-f98a4d666aed}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{1b8b402d-78dc-46fb-bf71-46e64aedf165}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{1bda2ab1-bbc1-4acb-a849-c0ef2b249672}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{1db28f2e-8f80-4027-8c5a-a11f7f10f62d}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{1ed6976a-4171-4764-b415-7ea08bc46c51}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{1edeee53-0afe-4609-b846-d8c0b2075b1f}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{21d79db0-8e03-41cd-9589-f3ef7001a92a}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{23b8d46b-67dd-40a3-b636-d43e50552c6d}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{27a8c1e2-eb19-463e-8424-b399df27a216}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{287d59b6-79ba-4741-a08b-2fedeede6435}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{28aa95bb-d444-4719-a36f-40462168127e}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{28e25b07-c47f-473d-8b24-2e171cca808a}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{2a45d52e-bbf3-4843-8e18-b356ed5f6a65}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{2a576b87-09a7-520e-c21a-4942f0271d67}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{2cd58181-0bb6-463e-828a-056ff837f966}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{2d318b91-e6e7-4c46-bd04-bfe6db412cf9}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{2ed299d2-2f6b-411d-8d15-f4cc6fde0c70}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{2f94e1cc-a8c5-4fe7-a1c3-53d7bda8e73e}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{30336ed4-e327-447c-9de0-51b652c86108}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{314de49f-ce63-4779-ba2b-d616f6963a88}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{315a8872-923e-4ea2-9889-33cd4754bf64}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{319122a9-1485-4e48-af35-7db2d93b8ad2}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{32254f6c-aa33-46f0-a5e3-1cbcc74bf683}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{3527cb55-1298-49d4-ab94-1243db0fcaff}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{3663a992-84be-40ea-bba9-90c7ed544222}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{36c23e18-0e66-11d9-bbeb-505054503030}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{3a5bef13-d0f7-4e7f-9ec8-5e707df711d0}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{3a718a68-6974-4075-abd3-e8243caef398}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{3aa52b8b-6357-4c18-a92e-b53fb177853b}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{3ae1ea61-c002-47fb-b06c-4022a8c98929}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{3c088e51-65be-40d1-9b90-62bfec076737}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{3cb40aaa-1145-4fb8-b27b-7e30f0454316}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{3cc2d4af-da5e-4ed4-bcbe-3cf995940483}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{3d42a67d-9ce8-4284-b755-2550672b0ce0}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{3da494e4-0fe2-415c-b895-fb5265c5c83b}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{3f471139-acb7-4a01-b7a7-ff5da4ba2d43}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{40ab57c2-1c53-4df9-9324-ff7cf898a02c}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{41862974-da3b-4f0b-97d5-bb29fbb9b71e}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{442c11c5-304b-45a4-ae73-dc2194c4e876}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{46098845-8a94-442d-9095-366a6bcfefa9}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{4a104570-ec6d-4560-a40f-858fa955e84f}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{4a933674-fb3d-4e8d-b01d-17ee14e91a3e}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{4cb314df-c11f-47d7-9c04-65fb0051561b}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{4de9bc9c-b27a-43c9-8994-0915f1a5e24f}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{4eacb4d0-263b-4b93-8cd6-778a278e5642}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{50df9e12-a8c4-4939-b281-47e1325ba63e}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{50f99b2d-96d2-421f-be4c-222c4140da9f}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{530fb9b9-c515-4472-9313-fb346f9255e3}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{5402e5ea-1bdd-4390-82be-e108f1e634f5}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{54164045-7c50-4905-963f-e5bc1eef0cca}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{57003e21-269b-4bdc-8434-b3bf8d57d2d5}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{579402a2-883c-45d8-b70a-9bc856407751}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{58980f4b-bd39-4a3e-b344-492ed2254a4e}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{595f33ea-d4af-4f4d-b4dd-9dacdd17fc6e}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{5b0a651a-8807-45cc-9656-7579815b6af0}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{5b5ab841-7d2e-4a95-bb4f-095cdf66d8f0}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{5bbca4a8-b209-48dc-a8c7-b23d3e5216fb}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{5d674230-ca9f-11da-a94d-0800200c9a66}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{5d896912-022d-40aa-a3a8-4fa5515c76d7}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{5ec13d8e-4b3f-422e-a7e7-3121a1d90c7a}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{5f0e257f-c224-43e5-9555-2adcb8540a58}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{63b530f8-29c9-4880-a5b4-b8179096e7b8}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{63d2bb1d-e39a-41b8-9a3d-52dd06677588}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{6489b27f-7c43-5886-1d00-0a61bb2a375b}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{64a98c25-9e00-404e-84ad-6700dfe02529}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{64ef2b1c-4ae1-4e64-8599-1636e441ec88}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{66a5c15c-4f8e-4044-bf6e-71d896038977}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{67d07935-283a-4791-8f8d-fa9117f3e6f2}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{699e309c-e782-4400-98c8-e21d162d7b7b}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{69c8ca7e-1adf-472b-ba4c-a0485986b9f6}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{6a1f2b00-6a90-4c38-95a5-5cab3b056778}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{6b1ffe48-5b1e-4793-9f7f-ae926454499d}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{6d7662a9-034e-4b1f-a167-67819c401632}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{6d8a3a60-40af-445a-98ca-99359e500146}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{6df57621-e7e4-410f-a7e9-e43eeb61b11f}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{6e400999-5b82-475f-b800-cef6fe361539}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{6eb8db94-fe96-443f-a366-5fe0cee7fb1c}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{712abb2d-d806-4b42-9682-26da01d8b307}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{72561cf0-c85c-4f78-9e8d-cba9093df62d}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{728b02d9-bf21-49f6-be3f-91bc06f7467e}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{72d211e1-4c54-4a93-9520-4901681b2271}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{73370bd6-85e5-430b-b60a-fea1285808a7}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{741bb90c-a7a3-49d6-bd82-1e6b858403f7}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{741fc222-44ed-4ba7-98e3-f405b2d2c4b4}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{747ef6fd-e535-4d16-b510-42c90f6873a1}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{75ebc33e-0870-49e5-bdce-9d7028279489}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{75ebc33e-0936-4a55-9d26-5f298f3180bf}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{75ebc33e-0cc6-49da-8cd9-8903a5222aa0}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{75ebc33e-77b8-4ba8-9474-4f4a9db2f5c6}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{75ebc33e-8670-4eb6-b535-3b9d6bb222fd}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{75ebc33e-997f-49cf-b49f-ecc50184b75d}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{75ebc33e-c8ae-4f93-9ca1-683a53e20cb6}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{76ab12d5-c986-4e60-9d7c-2a092b284cdd}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{770ca594-b467-4811-b355-28f5e5706987}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{777ba8fe-2498-4875-933a-3067de883070}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{7d29d58a-931a-40ac-8743-48c733045548}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{7d7b0c39-93f6-4100-bd96-4dda859652c5}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{7e58e69a-e361-4f06-b880-ad2f4b64c944}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{7e87506f-bace-4bf1-bc09-3a1f37045c71}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{7eafcf79-06a7-460b-8a55-bd0a0c9248aa}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{8127f6d4-59f9-4abf-8952-3e3a02073d5f}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{83d6e83b-900b-48a3-9835-57656b6f6474}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{8530db6e-51c0-43d6-9d02-a8c2088526cd}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{85a62a0d-7e17-485f-9d4f-749a287193a6}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{85be49ea-38f1-4547-a604-80060202fb27}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{85fe7609-ff4a-48e9-9d50-12918e43e1da}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{88c09888-118d-48fc-8863-e1c6d39ca4df}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{88cd9180-4491-4640-b571-e3bee2527943}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{8939299f-2315-4c5c-9b91-abb86aa0627d}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{89592015-d996-4636-8f61-066b5d4dd739}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{89a2278b-c662-4aff-a06c-46ad3f220bca}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{89b1e9f0-5aff-44a6-9b44-0a07a7ce5845}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{8bcdf442-3070-4118-8c94-e8843be363b3}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{8ce93926-bdae-4409-9155-2fe4799ef4d3}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{906b8a99-63ce-58d7-86ab-10989bbd5567}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{91f5fb12-fdea-4095-85d5-614b495cd9de}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{9213c3e1-0d6c-52dd-78ea-f3b082111406}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{9363ccd9-d429-4452-9adb-2501e704b810}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{93a19ab3-fb2c-46eb-91ef-56b0a318b983}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{952773bf-c2b7-49bc-88f4-920744b82c43}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{95353826-4fbe-41d4-9c42-f521c6e86360}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{9580d7dd-0379-4658-9870-d5be7d52d6de}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{968f313b-097f-4e09-9cdd-bc62692d138b}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{96f4a050-7e31-453c-88be-9634f4e02139}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{973143dd-f3c7-4ef5-b156-544ac38c39b6}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{97ca8142-10b1-4baa-9fbb-70a7d11231c3}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{9803daa0-81ba-483a-986c-f0e395b9f8d1}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{98bf1cd3-583e-4926-95ee-a61bf3f46470}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{98e0765d-8c42-44a3-a57b-760d7f93225a}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{9c2a37f3-e5fd-5cae-bcd1-43dafeee1ff0}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{9cc0413e-5717-4af5-82eb-6103d8707b45}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{9d55b53d-449b-4824-a637-24f9d69aa02f}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{9f973c1d-d056-4e38-84a5-7be81cdd6ab6}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{9fc66dd7-98c7-4b83-8293-46a18439b03b}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{a0c1853b-5c40-4b15-8766-3cf1c58f985a}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{a615acb9-d5a4-4738-b561-1df301d207f8}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{a7975c8f-ac13-49f1-87da-5a984a4ab417}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{a83fa99f-c356-4ded-9fd6-5a5eb8546d68}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{a9c11050-9e93-4fa4-8fe0-7c4750a345b2}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{aa4c798d-d91b-4b07-a013-787f5803d6fc}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{aabf8b86-7936-4fa2-acb0-63127f879dbf}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{aaeac398-3028-487c-9586-44eacad03637}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{aaf67066-0bf8-469f-ab76-275590c434ee}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{add0de40-32b0-4b58-9d5e-938b2f5c1d1f}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{ae4bd3be-f36f-45b6-8d21-bdd6fb832853}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{b059b83f-d946-4b13-87ca-4292839dc2f2}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{b2fcd41f-9a40-4150-8c92-b224b7d8c8aa}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{b447b4db-7780-11e0-ada3-18a90531a85a}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{b447b4de-7780-11e0-ada3-18a90531a85a}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{b447b4df-7780-11e0-ada3-18a90531a85a}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{b447b4e1-7780-11e0-ada3-18a90531a85a}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{b6cc0d55-9ecc-49a8-b929-2b9022426f2a}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{b6d775ef-1436-4fe6-bad3-9e436319e218}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{b92cf7fd-dc10-4c6b-a72d-1613bf25e597}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{b977cf02-76f6-df84-cc1a-6a4b232322b6}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{b9da9fe6-ae5f-4f3e-b2fa-8e623c11dc75}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{ba093605-3909-4345-990b-26b746adee0a}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{ba723d81-0d0c-4f1e-80c8-54740f508ddf}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{bd12f3b8-fc40-4a61-a307-b7a013a069c1}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{bea18b89-126f-4155-9ee4-d36038b02680}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{bf406804-6afa-46e7-8a48-6c357e1d6d61}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{bff15e13-81bf-45ee-8b16-7cfead00da86}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{c2f36562-a1e4-4bc3-a6f6-01a7adb643e8}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{c4efc9bb-2570-4821-8923-1bad317d2d4b}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{c651f5f6-1c0d-492e-8ae1-b4efd7c9d503}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{c6bf6832-f7bd-4151-ac21-753ce4707453}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{c76baa63-ae81-421c-b425-340b4b24157f}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{c9bdb4eb-9287-4c8e-8378-6896f0d1c5ef}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{cab2b8a5-49b9-4eec-b1b0-fac21da05a3b}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{cb070027-1534-4cf3-98ea-b9751f508376}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{cbda4dbf-8d5d-4f69-9578-be14aa540d22}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{cd7cf0d0-02cc-4872-9b65-0dba0a90efe8}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{cf3f502e-b40d-4071-996f-00981edf938e}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{d0e22efc-ac66-4b25-a72d-382736b5e940}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{d1bc9aff-2abf-4d71-9146-ecb2a986eb85}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{d2e990da-8504-4702-a5e5-367fc2f823bf}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{d39b6336-cfcb-483b-8c76-7c3e7d02bcb8}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{d3f29eda-805d-428a-9902-b259b937f84b}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{d710d46c-235d-4798-ac20-9f83e1dcd557}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{d8965fcf-7397-4e0e-b750-21a4580bd880}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{dab3b18c-3c0f-43e8-80b1-e44bc0dad901}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{db00dfb6-29f9-4a9c-9b3b-1f4f9e7d9770}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{dbe9b383-7cf3-4331-91cc-a3cb16a3b538}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{dcbe5aaa-16e2-457c-9337-366950045f0a}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{de095dbe-8667-4168-94c2-48ca61665aca}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{de513a55-c345-438b-9a74-e18cac5c5cc5}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{de7b24ea-73c8-4a09-985d-5bdadcfa9017}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{e0c6f6de-258a-50e0-ac1a-103482d118bc}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{e1dd7e52-621d-44e3-a1ad-0370c2b25946}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{e4d53f84-7de3-11d8-9435-505054503030}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{e4f68870-5ae8-4e5b-9ce7-ca9ed75b0245}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{e53df8ba-367a-4406-98d5-709ffb169681}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{e5c16d49-2464-4382-bb20-97a4b5465db9}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{e6307a09-292c-497e-aad6-498f68e2b619}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{e6835967-e0d2-41fb-bcec-58387404e25a}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{e7558269-3fa5-46ed-9f4d-3c6e282dde55}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{ea8cd8a5-78ff-4418-b292-aadc6a7181df}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{ec23f986-ae2d-4269-b52f-4e20765c1a94}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{ed8b9bd3-f66e-4ff2-b86b-75c7925f72a9}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{eef54e71-0661-422d-9a98-82fd4940b820}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{f0be35f8-237b-4814-86b5-ade51192e503}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{f0db7ef8-b6f3-4005-9937-feb77b9e1b43}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{f1201b5a-e170-42b6-8d20-b57ac57e6416}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{f1394de0-32c7-4a76-a6de-b245e48f4615}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{f1ef270a-0d32-4352-ba52-dbab41e1d859}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{f2311b48-32be-4902-a22a-7240371dbb2c}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{f3f53c76-b06d-4f15-b412-61164a0d2b73}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{f43c3c35-22e2-53eb-f169-07594054779e}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{f4aed7c7-a898-4627-b053-44a7caa12fcd}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{f5dbaa02-15d6-4644-a784-7032d508bf64}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{f82fb576-e941-4956-a2c7-a0cf83f6450a}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{f8ad09ba-419c-5134-1750-270f4d0fb889}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{f9fe3908-44b8-48d9-9a32-5a763ff5ed79}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{fa773482-f6ed-4895-8a7d-4f5850678e59}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{fae10392-f0af-4ac0-b8ff-9f4d920c3cdf}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{fae96d09-ade1-5223-0098-af7b67348531}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{fb829150-cd7d-44c3-af5b-711a3c31cedc}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{fbcfac3f-8459-419f-8e48-1f0b49cdb85e}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{ff79a477-c45f-4a52-8ae0-2b324346d4e4}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{01979c6a-42fa-414c-b8aa-eee2c8202018}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{04268430-d489-424d-b914-0cff741d6684}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{059f0f37-910e-4ff0-a7ee-ae8d49dd319b}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{05f02597-fe85-4e67-8542-69567ab8fd4f}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{06edcfeb-0fd0-4e53-acca-a6f8bbf81bcb}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{0b886108-1899-4d3a-9c0d-42d8fc4b9108}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{0b9fdccc-451c-449c-9bd8-6756fcc6091a}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{0bf2fb94-7b60-4b4d-9766-e82f658df540}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{0c478c5b-0351-41b1-8c58-4a6737da32e3}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{0d4fdc09-8c27-494a-bda0-505e4fd8adae}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{0f67e49f-fe51-4e9f-b490-6f2948cc6027}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{0fa2ee03-1feb-5057-3bb3-eb25521b8482}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{11c5d8ad-756a-42c2-8087-eb1b4a72a846}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{11cd958a-c507-4ef3-b3f2-5fd9dfbd2c78}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{125f2cf1-2768-4d33-976e-527137d080f8}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{15a7a4f8-0072-4eab-abad-f98a4d666aed}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{15ca44ff-4d7a-4baa-bba5-0998955e531e}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{199fe037-2b82-40a9-82ac-e1d46c792b99}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{1b562e86-b7aa-4131-badc-b6f3a001407e}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{1b6b0772-251b-4d42-917d-faca166bc059}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{1c95126e-7eea-49a9-a3fe-a378b03ddb4d}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{1db28f2e-8f80-4027-8c5a-a11f7f10f62d}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{1e9a4978-78c2-441e-8858-75b5d1326bc5}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{1f678132-5938-4686-9fdc-c8ff68f15c85}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{206f6dea-d3c5-4d10-bc72-989f03c8b84b}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{21b7c16e-c5af-4a69-a74a-7245481c1b97}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{2a274310-42d5-4019-b816-e4b8c7abe95c}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{2e35aaeb-857f-4beb-a418-2e6c0e54d988}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{2e6cb42e-161d-413b-a6c1-84ca4c1e5890}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{2f07e2ee-15db-40f1-90ef-9d7ba282188a}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{2ff3e6b7-cb90-4700-9621-443f389734ed}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{306c4e0b-e148-543d-315b-c618eb93157c}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{30e1d284-5d88-459c-83fd-6345b39b19ec}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{331c3b3a-2005-44c2-ac5e-77220c37d6b4}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{355c44fe-0c8e-4bf8-be28-8bc7b5a42720}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{3629dd4d-d6f1-4302-a623-0768b51501c7}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{36c23e18-0e66-11d9-bbeb-505054503030}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{3903d5b9-988d-4c31-9ccd-4022f96703f0}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{3cb2a168-fe19-4a4e-bdad-dcf422f13473}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{3e59a529-b0b3-4a11-8129-9ffe6bb46eb9}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{3f471139-acb7-4a01-b7a7-ff5da4ba2d43}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{3ff37a1c-a68d-4d6e-8c9b-f79e8b16c482}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{40783728-8921-45d0-b231-919037b4b4fd}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{412bdff2-a8c4-470d-8f33-63fe0d8c20e2}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{43e63da5-41d1-4fbf-aded-1bbed98fdd1d}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{45eec9e5-4a1b-5446-7ad8-a4ab1313c437}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{46c78e5c-a213-46a8-8a6b-622f6916201d}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{47bc9477-a8ba-452e-b951-4f2ed3593cf9}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{47bfa2b7-bd54-4fac-b70b-29021084ca8f}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{494e7a3d-8db9-4ec4-b43e-2844af6e38d6}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{4af188ac-e9c4-4c11-b07b-1fabc07dfeb2}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{4cb314df-c11f-47d7-9c04-65fb0051561b}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{4cec9c95-a65f-4591-b5c4-30100e51d870}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{4ee76bd8-3cf4-44a0-a0ac-3937643e37a3}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{52fc89f8-995e-434c-a91e-199986449890}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{530fb9b9-c515-4472-9313-fb346f9255e3}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{538cbbad-4877-4eb2-b26e-7caee8f0f8cb}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{54cb22ff-26b4-4393-a8c2-6b0715912c5f}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{555908d1-a6d7-4695-8e1e-26931d2012f4}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{55ab77f6-fa04-43ef-af45-688fbf500482}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{595f7f52-c90a-4026-a125-8eb5e083f15e}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{5d674230-ca9f-11da-a94d-0800200c9a66}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{5d896912-022d-40aa-a3a8-4fa5515c76d7}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{5f92bc59-248f-4111-86a9-e393e12c6139}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{62de9e48-90c6-4755-8813-6a7d655b0802}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{632f767e-0ec3-47b9-ba1c-a0e62a74728a}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{63d1e632-95cc-4443-9312-af927761d52a}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{64ef2b1c-4ae1-4e64-8599-1636e441ec88}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{651df93b-5053-4d1e-94c5-f6e6d25908d0}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{66a5c15c-4f8e-4044-bf6e-71d896038977}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{67fe2216-727a-40cb-94b2-c02211edb34a}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{6a1f2b00-6a90-4c38-95a5-5cab3b056778}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{6b93bf66-a922-4c11-a617-cf60d95c133d}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{6bba3851-2c7e-4dea-8f54-31e5afd029e3}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{7237fff9-a08a-4804-9c79-4a8704b70b87}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{72cd9ff7-4af8-4b89-aede-5f26fda13567}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{73a33ab2-1966-4999-8add-868c41415269}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{73e9c9de-a148-41f7-b1db-4da051fdc327}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{74c2135f-cc76-45c3-879a-ef3bb1eeaf86}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{75ebc33e-997f-49cf-b49f-ecc50184b75d}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{7725b5f9-1f2e-4e21-baeb-b2af4690bc87}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{7b563579-53c8-44e7-8236-0f87b9fe6594}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{7b6bc78c-898b-4170-bbf8-1a469ea43fc5}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{7d5387b0-cbe0-11da-a94d-0800200c9a66}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{7da4fe0e-fd42-4708-9aa5-89b77a224885}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{85a62a0d-7e17-485f-9d4f-749a287193a6}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{89203471-d554-47d4-bde4-7552ec219999}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{89592015-d996-4636-8f61-066b5d4dd739}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{89fe8f40-cdce-464e-8217-15ef97d4c7c3}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{8c416c79-d49b-4f01-a467-e56d3aa8234c}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{8e6a5303-a4ce-498f-afdb-e03a8a82b077}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{945a8954-c147-4acd-923f-40c45405a658}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{951b41ea-c830-44dc-a671-e2c9958809b8}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{95353826-4fbe-41d4-9c42-f521c6e86360}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{9580d7dd-0379-4658-9870-d5be7d52d6de}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{96f4a050-7e31-453c-88be-9634f4e02139}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{9741fd4e-3757-479f-a3c6-fc49f6d5edd0}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{988c59c5-0a1c-45b6-a555-0c62276e327d}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{991f8fe6-249d-44d6-b93d-5a3060c1dedb}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{9988748e-c2e8-4054-85f6-0c3e1cad2470}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{9c205a39-1250-487d-abd7-e831c6290539}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{9f650c63-9409-453c-a652-83d7185a2e83}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{9f7b5df4-b902-48bc-bc94-95068c6c7d26}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{a0e3d8ea-c34f-4419-a1db-90435b8b21d0}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{a4445c76-ed85-c8a3-02c1-532a38614a9e}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{a67075c2-3e39-4109-b6cd-6d750058a731}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{a68ca8b7-004f-d7b6-a698-07e2de0f1f5d}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{a6ad76e3-867a-4635-91b3-4904ba6374d7}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{a7f2235f-be51-51ed-decf-f4498812a9a2}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{a8a1f2f6-a13a-45e9-b1fe-3419569e5ef2}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{aa3aa23b-bb6d-425a-b58c-1d7e37f5d02a}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{abf1f586-2e50-4ba8-928d-49044e6f0db7}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{ac43300d-5fcc-4800-8e99-1bd3f85f0320}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{ac52ad17-cc01-4f85-8df5-4dce4333c99b}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{ad5162d8-daf0-4a25-88a7-01cbeb33902e}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{ae4bd3be-f36f-45b6-8d21-bdd6fb832853}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{aea1b4fa-97d1-45f2-a64c-4d69fffd92c9}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{aec5c129-7c10-407d-be97-91a042c61aaa}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{b0aa8734-56f7-41cc-b2f4-de228e98b946}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{b2fcd41f-9a40-4150-8c92-b224b7d8c8aa}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{b675ec37-bdb6-4648-bc92-f3fdc74d3ca2}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{b977cf02-76f6-df84-cc1a-6a4b232322b6}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{b99317e5-89b7-4c0d-abd1-6e705f7912dc}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{ba093605-3909-4345-990b-26b746adee0a}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{ba2ffb5c-e20a-4fb9-91b4-45f61b4b66a0}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{babda89a-4d5e-48eb-af3d-e0e8410207c0}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{bc0669e1-a10d-4a78-834e-1ca3c806c93b}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{c02afc2b-e24e-4449-ad76-bcc2c2575ead}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{c03715ce-ea6f-5b67-4449-da1d1e1afeb8}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{c18672d1-dc18-4dfd-91e4-170cf37160cf}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{c26c4f3c-3f66-4e99-8f8a-39405cfed220}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{c4636a1e-7986-4646-bf10-7bc3b4a76e8e}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{c76baa63-ae81-421c-b425-340b4b24157f}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{c914f0df-835a-4a22-8c70-732c9a80c634}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{cb017cd2-1f37-4e65-82bc-3e91f6a37559}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{cbda4dbf-8d5d-4f69-9578-be14aa540d22}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{cd9c6198-bf73-4106-803b-c17d26559018}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{cdc05e28-c449-49c6-b9d2-88cf761644df}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{cdead503-17f5-4a3e-b7ae-df8cc2902eb9}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{ce8dee0b-d539-4000-b0f8-77bed049c590}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{cfc18ec0-96b1-4eba-961b-622caee05b0a}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{d0e22efc-ac66-4b25-a72d-382736b5e940}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{d1bc9aff-2abf-4d71-9146-ecb2a986eb85}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{d48ce617-33a2-4bc3-a5c7-11aa4f29619e}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{d5c25f9a-4d47-493e-9184-40dd397a004d}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{d6f68875-cdf5-43a5-a3e3-53ffd683311c}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{dbe9b383-7cf3-4331-91cc-a3cb16a3b538}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{dd70bc80-ef44-421b-8ac3-cd31da613a4e}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{de29cf61-5ee6-43ff-9aac-959c4e13cc6c}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{de7b24ea-73c8-4a09-985d-5bdadcfa9017}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{dea07764-0790-44de-b9c4-49677b17174f}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{e104fb41-6b04-4f3a-b47d-f0df2f02b954}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{e2816346-87f4-4f85-95c3-0c79409aa89d}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{e3bac9f8-27be-4823-8d7f-1cc320c05fa7}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{e4480490-85b6-11dd-ad8b-0800200c9a66}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{e4f68870-5ae8-4e5b-9ce7-ca9ed75b0245}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{e595f735-b42a-494b-afcd-b68666945cd3}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{e5ba83f6-07d0-46b1-8bc7-7e669a1d31dc}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{e670a5a2-ce74-4ab4-9347-61b815319f4c}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{e8f9af91-afbe-5a03-dfec-5d591686326c}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{ea216962-877b-5b73-f7c5-8aef5375959e}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{eee173ef-7ed2-45de-9877-01c70a852fbd}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{ef1cc15b-46c1-414e-bb95-e76b077bd51e}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{f029ac39-38f0-4a40-b7de-404d244004cb}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{f2e2ce31-0e8a-4e46-a03b-2e0fe97e93c2}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{f3c5e28e-63f6-49c7-a204-e48a1bc4b09d}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{f5d05b38-80a6-4653-825d-c414e4ab3c68}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{f708c483-4880-11e6-9121-5cf37068b67b}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{f717d024-f5b4-4f03-9ab9-331b2dc38ffb}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{f9fe3908-44b8-48d9-9a32-5a763ff5ed79}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{fae10392-f0af-4ac0-b8ff-9f4d920c3cdf}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{fc4e8f51-7a04-4bab-8b91-6321416f72ab}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{fcbb06bb-6a2a-46e3-abaa-246cb4e508b2}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\LwtNetLog\{01578F96-C270-4602-ADE0-578D9C29FC0C}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\LwtNetLog\{0BD3506A-9030-4F76-9B88-3E8FE1F7CFB6}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\LwtNetLog\{12d25187-6c0d-4783-ad3a-84caa135acfd}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\LwtNetLog\{15A7A4F8-0072-4EAB-ABAD-F98A4D666AED}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\LwtNetLog\{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\LwtNetLog\{1E39B4CE-D1E6-46CE-B65B-5AB05D6CC266}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\LwtNetLog\{2F07E2EE-15DB-40F1-90EF-9D7BA282188A}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\LwtNetLog\{314DE49F-CE63-4779-BA2B-D616F6963A88}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\LwtNetLog\{315a8872-923e-4ea2-9889-33cd4754bf64}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\LwtNetLog\{3CB40AAA-1145-4FB8-B27B-7E30F0454316}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\LwtNetLog\{3EB875EB-8F4A-4800-A00B-E484C97D7551}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\LwtNetLog\{43D1A55C-76D6-4F7E-995C-64C711E5CAFE}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\LwtNetLog\{63B530F8-29C9-4880-A5B4-B8179096E7B8}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\LwtNetLog\{67D07935-283A-4791-8F8D-FA9117F3E6F2}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\LwtNetLog\{6A1F2B00-6A90-4C38-95A5-5CAB3B056778}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\LwtNetLog\{7868B0D4-1423-4681-AFDF-27913575441E}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\LwtNetLog\{88CD9180-4491-4640-B571-E3BEE2527943}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\LwtNetLog\{9580D7DD-0379-4658-9870-D5BE7D52D6DE}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\LwtNetLog\{A6BF0DEB-3659-40AD-9F81-E25AF62CE3C7}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\LwtNetLog\{AB0D8EF9-866D-4D39-B83F-453F3B8F6325}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\LwtNetLog\{CDEAD503-17F5-4A3E-B7AE-DF8CC2902EB9}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\LwtNetLog\{DF271536-4298-45E1-B0F2-E88F78619C5D}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\LwtNetLog\{e6835967-e0d2-41fb-bcec-58387404e25a}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\LwtNetLog\{FBCFAC3F-8459-419F-8E48-1F0B49CDB85E}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SetupPlatform\{0063715b-eeda-4007-9429-ad526f62696e}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SetupPlatform\{11CD958A-C507-4EF3-B3F2-5FD9DFBD2C78}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SetupPlatform\{30336ed4-e327-447c-9de0-51b652c86108}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SetupPlatform\{331c3b3a-2005-44c2-ac5e-77220c37d6b4}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SetupPlatform\{530FB9B9-C515-4472-9313-FB346F9255E3}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SetupPlatform\{75EBC33E-0CC6-49da-8CD9-8903A5222AA0}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SetupPlatform\{75EBC33E-77B8-4ba8-9474-4F4A9DB2F5C6}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SetupPlatform\{75EBC33E-8670-4eb6-B535-3B9D6BB222FD}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SetupPlatform\{75EBC33E-997F-49cf-B49F-ECC50184B75D}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SetupPlatform\{75EBC33E-C8AE-4f93-9CA1-683A53E20CB6}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SetupPlatform\{75EBC33E-D017-4D0F-93AB-0B4F86579164}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SetupPlatform\{B9DA9FE6-AE5F-4f3e-B2FA-8E623C11DC75}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SetupPlatform\{C553CED4-9BA3-478F-98EA-906CE99C2E4F}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SetupPlatform\{f0be35f8-237b-4814-86b5-ade51192e503}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SetupPlatform\{f5dbaa02-15d6-4644-a784-7032d508bf64}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SpoolerLogger\{19E464A4-7408-49BD-B960-53446AE47820}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SpoolerLogger\{19E93940-A1BD-497F-BC58-CA333880BAB4}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SpoolerLogger\{3048407B-56AA-4D41-82B2-7d5F4b1CDD39}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SpoolerLogger\{402E812D-04E6-4E66-ABDB-32E5F79D36A2}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SpoolerLogger\{49868e3d-77fb-5083-9e09-61e3f37e0309}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SpoolerLogger\{62A0EB6C-3E3E-471d-960C-7C574A72534C}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SpoolerLogger\{6d5ca4bb-df8e-41bc-b554-8aeab241f206}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SpoolerLogger\{6fb61ac3-3455-4da4-8313-c1a855ee64c5}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SpoolerLogger\{836767A6-AF31-4938-B4C0-EF86749A9AEF}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SpoolerLogger\{9558985e-3bc8-45ef-a2fd-2e6ff06fb886}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SpoolerLogger\{99F5F45C-FD1E-439F-A910-20D0DC759D28}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SpoolerLogger\{acf1e4a7-9241-4fbf-9555-c27638434f8d}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SpoolerLogger\{B795C7DF-07BC-4362-938E-E8ABD81A9A01}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SpoolerLogger\{C9BF4A01-D547-4d11-8242-E03A18B5BE01}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SpoolerLogger\{C9BF4A02-D547-4d11-8242-E03A18B5BE01}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SpoolerLogger\{C9BF4A03-D547-4d11-8242-E03A18B5BE01}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SpoolerLogger\{C9BF4A05-D547-4d11-8242-E03A18B5BE01}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SpoolerLogger\{C9BF4A9E-D547-4d11-8242-E03A18B5BE01}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SpoolerLogger\{C9BF4A9F-D547-4d11-8242-E03A18B5BE01}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\AnimateMinMax" /v "DefaultApplied" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ComboBoxAnimation" /v "DefaultApplied" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ControlAnimations" /v "DefaultApplied" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\CursorShadow" /v "DefaultApplied" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DragFullWindows" /v "DefaultApplied" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DropShadow" /v "DefaultApplied" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DWMAeroPeekEnabled" /v "DefaultApplied" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DWMEnabled" /v "DefaultApplied" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DWMSaveThumbnailEnabled" /v "DefaultApplied" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\FontSmoothing" /v "DefaultApplied" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ListBoxSmoothScrolling" /v "DefaultApplied" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ListviewAlphaSelect" /v "DefaultApplied" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ListviewShadow" /v "DefaultApplied" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\MenuAnimation" /v "DefaultApplied" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\SelectionFade" /v "DefaultApplied" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\TaskbarAnimations" /v "DefaultApplied" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\Themes" /v "DefaultApplied" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ThumbnailsOrIcon" /v "DefaultApplied" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\TooltipAnimation" /v "DefaultApplied" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{047FB417-39E6-4B79-A52C-C436B60011AD}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{0BD3506A-9030-4f76-9B88-3E8FE1F7CFB6}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{111ffc99-3987-4bf8-8398-61853120cb3d}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{1193FF07-26A3-4ECA-9384-12CCF39CAE03}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{21ba7b61-05f8-41f1-9048-c09493dcfe38}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{2D0CC56C-874F-422C-B25F-246F286A24BA}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{314DE49F-CE63-4779-BA2B-D616F6963A88}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{3496b396-5c43-45e7-b38e-d509b79ae721}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{3D42A67D-9CE8-4284-B755-2550672B0CE0}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{4D946A46-275B-4C9D-B835-0B2160559256}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{58980F4B-BD39-4a3e-B344-492ED2254A4E}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{5CA18737-22AC-4050-85BC-B8DBB9F7D986}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{681E3481-7510-4053-8C87-A6305EAFC4FA}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{6BE684E4-194C-43B0-B9B8-8269646DE989}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{6eb8db94-fe96-443f-a366-5fe0cee7fb1c}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{7D7180B3-A452-4FFF-8D1F-7B32B248AB70}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{802ec45b-1e99-4b83-9920-87c98277ba9d}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{814182FF-58F7-11E1-853C-78E7D1CA7337}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{90BBBABB-255B-4FE3-A06F-685A15E93A4C}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{914598a6-28f0-42ac-bf3d-a29c6047a739}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{949D7457-6151-4FA0-9E46-D82A6F9927CF}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{9580d7dd-0379-4658-9870-d5be7d52d6de}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{999AC137-42DC-41D3-BA9D-A325A9E1A986}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{9B322459-4AD9-4F81-8EEA-DC77CDD18CA6}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{9B694F87-000E-4BE6-91AC-FE2E50D61A6F}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{9CC0413E-5717-4af5-82EB-6103D8707B45}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{9CC9BEB7-9D24-47C7-8F9D-CCC9DCAC29EB}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{AB0D8EF9-866D-4d39-B83F-453F3B8F6325}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{abe47285-c002-46d1-95e4-c4aec3c78f50}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{B8794785-F7E3-4C2D-A33D-7B0BA0D30E18}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{c02edc8d-d627-46c9-abd9-c8b78f88c223}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{C100BECE-D33A-4A4B-BF23-BBEF4663D017}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{c7491fe4-66f4-4421-9954-b55f03db3186}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{D28262A1-8066-492D-BCE8-635DA75368B7}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{E5C16D49-2464-4382-BB20-97A4B5465DB9}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{e6dec100-4e0f-4927-92be-e69d7c15c821}" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WUDF" /v "LogEnable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WUDF" /v "LogLevel" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Firefox\LockPref" /v "toolkit.telemetry.enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Wacom\Analytics" /v "Analytics_On" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Reliability" /v "TimeStampEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Reliability" /v "IncludeShutdownErrs" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Reliability" /v "SnapShot" /t REG_DWORD /d "0" /f >nul
Reg.exe delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Census" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\AppModel" /v "Start" /t REG_DWORD /d "0" /f  >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Cellcore" /v "Start" /t REG_DWORD /d "0" /f  >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Circular Kernel Context Logger" /v "Start" /t REG_DWORD /d "0" /f  >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\CloudExperienceHostOobe" /v "Start" /t REG_DWORD /d "0" /f  >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DataMarket" /v "Start" /t REG_DWORD /d "0" /f  >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" /v "Start" /t REG_DWORD /d "0" /f  >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger" /v "Start" /t REG_DWORD /d "0" /f  >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DiagLog" /v "Start" /t REG_DWORD /d "0" /f  >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Diagtrack-Listener" /v "Start" /t REG_DWORD /d "0" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\HolographicDevice" /v "Start" /t REG_DWORD /d "0" /f  >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\iClient" /v "Start" /t REG_DWORD /d "0" /f  >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\iProxy" /v "Start" /t REG_DWORD /d "0" /f  >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\LwtNetLog" /v "Start" /t REG_DWORD /d "0" /f  >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Mellanox-Kernel" /v "Start" /t REG_DWORD /d "0" /f  >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Microsoft-Windows-AssignedAccess-Trace" /v "Start" /t REG_DWORD /d "0" /f  >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Microsoft-Windows-Setup" /v "Start" /t REG_DWORD /d "0" /f  >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\NBSMBLOGGER" /v "Start" /t REG_DWORD /d "0" /f  >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\PEAuthLog" /v "Start" /t REG_DWORD /d "0" /f  >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\RdrLog" /v "Start" /t REG_DWORD /d "0" /f  >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\ReadyBoot" /v "Start" /t REG_DWORD /d "0" /f  >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SetupPlatform" /v "Start" /t REG_DWORD /d "0" /f  >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SetupPlatformTel" /v "Start" /t REG_DWORD /d "0" /f  >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SocketHeciServer" /v "Start" /t REG_DWORD /d "0" /f  >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SpoolerLogger" /v "Start" /t REG_DWORD /d "0" /f  >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SQMLogger" /v "Start" /t REG_DWORD /d "0" /f  >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\TCPIPLOGGER" /v "Start" /t REG_DWORD /d "0" /f  >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\TileStore" /v "Start" /t REG_DWORD /d "0" /f  >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Tpm" /v "Start" /t REG_DWORD /d "0" /f  >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\TPMProvisioningService" /v "Start" /t REG_DWORD /d "0" /f  >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\UBPM" /v "Start" /t REG_DWORD /d "0" /f  >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WdiContextLog" /v "Start" /t REG_DWORD /d "0" /f  >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WFP-IPsec Trace" /v "Start" /t REG_DWORD /d "0" /f  >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiDriverIHVSession" /v "Start" /t REG_DWORD /d "0" /f  >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiDriverIHVSessionRepro" /v "Start" /t REG_DWORD /d "0" /f  >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession" /v "Start" /t REG_DWORD /d "0" /f  >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WinPhoneCritical" /v "Start" /t REG_DWORD /d "0" /f  >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WUDF" /v "LogEnable" /t REG_DWORD /d "0" /f  >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WUDF" /v "LogLevel" /t REG_DWORD /d "0" /f  >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Credssp" /v "DebugLogLevel" /t REG_DWORD /d "0" /f >nul
Reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WUDF" /v "LogEnable" /t Reg_DWORD /d "0" /f  >nul
Reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WUDF" /v "LogLevel" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\AppModel" /v "Start" /t Reg_DWORD /d "0" /f  >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Cellcore" /v "Start" /t Reg_DWORD /d "0" /f  >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Circular Kernel Context Logger" /v "Start" /t Reg_DWORD /d "0" /f  >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\CloudExperienceHostOobe" /v "Start" /t Reg_DWORD /d "0" /f  >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DataMarket" /v "Start" /t Reg_DWORD /d "0" /f  >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" /v "Start" /t Reg_DWORD /d "0" /f  >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger" /v "Start" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DiagLog" /v "Start" /t Reg_DWORD /d "0" /f  >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\HolographicDevice" /v "Start" /t Reg_DWORD /d "0" /f  >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\iClient" /v "Start" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\iProxy" /v "Start" /t Reg_DWORD /d "0" /f  >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\LwtNetLog" /v "Start" /t Reg_DWORD /d "0" /f  >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Mellanox-Kernel" /v "Start" /t Reg_DWORD /d "0" /f  >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Microsoft-Windows-AssignedAccess-Trace" /v "Start" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Microsoft-Windows-Setup" /v "Start" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\NBSMBLOGGER" /v "Start" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\PEAuthLog" /v "Start" /t Reg_DWORD /d "0" /f  >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\RdrLog" /v "Start" /t Reg_DWORD /d "0" /f  >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\ReadyBoot" /v "Start" /t Reg_DWORD /d "0" /f  >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SetupPlatform" /v "Start" /t Reg_DWORD /d "0" /f  >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SetupPlatformTel" /v "Start" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SocketHeciServer" /v "Start" /t Reg_DWORD /d "0" /f  >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SpoolerLogger" /v "Start" /t Reg_DWORD /d "0" /f  >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SQMLogger" /v "Start" /t Reg_DWORD /d "0" /f  >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\TCPIPLOGGER" /v "Start" /t Reg_DWORD /d "0" /f  >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\TileStore" /v "Start" /t Reg_DWORD /d "0" /f  >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Tpm" /v "Start" /t Reg_DWORD /d "0" /f  >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\TPMProvisioningService" /v "Start" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\UBPM" /v "Start" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WdiContextLog" /v "Start" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WFP-IPsec Trace" /v "Start" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiDriverIHVSession" /v "Start" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiDriverIHVSessionRepro" /v "Start" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession" /v "Start" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WinPhoneCritical" /v "Start" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{01979c6a-42fa-414c-b8aa-eee2c8202018}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{04268430-d489-424d-b914-0cff741d6684}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{059f0f37-910e-4ff0-a7ee-ae8d49dd319b}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{05f02597-fe85-4e67-8542-69567ab8fd4f}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{06edcfeb-0fd0-4e53-acca-a6f8bbf81bcb}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{0b886108-1899-4d3a-9c0d-42d8fc4b9108}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{0b9fdccc-451c-449c-9bd8-6756fcc6091a}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{0bf2fb94-7b60-4b4d-9766-e82f658df540}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{0c478c5b-0351-41b1-8c58-4a6737da32e3}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{0d4fdc09-8c27-494a-bda0-505e4fd8adae}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{0f67e49f-fe51-4e9f-b490-6f2948cc6027}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{0fa2ee03-1feb-5057-3bb3-eb25521b8482}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{11c5d8ad-756a-42c2-8087-eb1b4a72a846}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{11cd958a-c507-4ef3-b3f2-5fd9dfbd2c78}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{125f2cf1-2768-4d33-976e-527137d080f8}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{15a7a4f8-0072-4eab-abad-f98a4d666aed}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{15ca44ff-4d7a-4baa-bba5-0998955e531e}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{199fe037-2b82-40a9-82ac-e1d46c792b99}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{1b562e86-b7aa-4131-badc-b6f3a001407e}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{1b6b0772-251b-4d42-917d-faca166bc059}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{1c95126e-7eea-49a9-a3fe-a378b03ddb4d}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{1db28f2e-8f80-4027-8c5a-a11f7f10f62d}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{1e9a4978-78c2-441e-8858-75b5d1326bc5}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{1f678132-5938-4686-9fdc-c8ff68f15c85}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{206f6dea-d3c5-4d10-bc72-989f03c8b84b}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{21b7c16e-c5af-4a69-a74a-7245481c1b97}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{2a274310-42d5-4019-b816-e4b8c7abe95c}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{2e35aaeb-857f-4beb-a418-2e6c0e54d988}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{2e6cb42e-161d-413b-a6c1-84ca4c1e5890}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{2f07e2ee-15db-40f1-90ef-9d7ba282188a}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{2ff3e6b7-cb90-4700-9621-443f389734ed}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{306c4e0b-e148-543d-315b-c618eb93157c}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{30e1d284-5d88-459c-83fd-6345b39b19ec}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{331c3b3a-2005-44c2-ac5e-77220c37d6b4}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{355c44fe-0c8e-4bf8-be28-8bc7b5a42720}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{3629dd4d-d6f1-4302-a623-0768b51501c7}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{36c23e18-0e66-11d9-bbeb-505054503030}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{3903d5b9-988d-4c31-9ccd-4022f96703f0}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{3cb2a168-fe19-4a4e-bdad-dcf422f13473}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{3e59a529-b0b3-4a11-8129-9ffe6bb46eb9}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{3f471139-acb7-4a01-b7a7-ff5da4ba2d43}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{3ff37a1c-a68d-4d6e-8c9b-f79e8b16c482}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{40783728-8921-45d0-b231-919037b4b4fd}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{412bdff2-a8c4-470d-8f33-63fe0d8c20e2}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{43e63da5-41d1-4fbf-aded-1bbed98fdd1d}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{45eec9e5-4a1b-5446-7ad8-a4ab1313c437}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{46c78e5c-a213-46a8-8a6b-622f6916201d}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{47bc9477-a8ba-452e-b951-4f2ed3593cf9}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{47bfa2b7-bd54-4fac-b70b-29021084ca8f}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{494e7a3d-8db9-4ec4-b43e-2844af6e38d6}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{4af188ac-e9c4-4c11-b07b-1fabc07dfeb2}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{4cb314df-c11f-47d7-9c04-65fb0051561b}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{4cec9c95-a65f-4591-b5c4-30100e51d870}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{4ee76bd8-3cf4-44a0-a0ac-3937643e37a3}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{52fc89f8-995e-434c-a91e-199986449890}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{530fb9b9-c515-4472-9313-fb346f9255e3}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{538cbbad-4877-4eb2-b26e-7caee8f0f8cb}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{54cb22ff-26b4-4393-a8c2-6b0715912c5f}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{555908d1-a6d7-4695-8e1e-26931d2012f4}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{55ab77f6-fa04-43ef-af45-688fbf500482}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{595f7f52-c90a-4026-a125-8eb5e083f15e}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{5d674230-ca9f-11da-a94d-0800200c9a66}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{5d896912-022d-40aa-a3a8-4fa5515c76d7}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{5f92bc59-248f-4111-86a9-e393e12c6139}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{62de9e48-90c6-4755-8813-6a7d655b0802}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{632f767e-0ec3-47b9-ba1c-a0e62a74728a}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{63d1e632-95cc-4443-9312-af927761d52a}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{64ef2b1c-4ae1-4e64-8599-1636e441ec88}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{651df93b-5053-4d1e-94c5-f6e6d25908d0}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{66a5c15c-4f8e-4044-bf6e-71d896038977}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{67fe2216-727a-40cb-94b2-c02211edb34a}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{6a1f2b00-6a90-4c38-95a5-5cab3b056778}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{6b93bf66-a922-4c11-a617-cf60d95c133d}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{6bba3851-2c7e-4dea-8f54-31e5afd029e3}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{7237fff9-a08a-4804-9c79-4a8704b70b87}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{72cd9ff7-4af8-4b89-aede-5f26fda13567}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{73a33ab2-1966-4999-8add-868c41415269}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{73e9c9de-a148-41f7-b1db-4da051fdc327}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{74c2135f-cc76-45c3-879a-ef3bb1eeaf86}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{75ebc33e-997f-49cf-b49f-ecc50184b75d}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{7725b5f9-1f2e-4e21-baeb-b2af4690bc87}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{7b563579-53c8-44e7-8236-0f87b9fe6594}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{7b6bc78c-898b-4170-bbf8-1a469ea43fc5}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{7d5387b0-cbe0-11da-a94d-0800200c9a66}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{7da4fe0e-fd42-4708-9aa5-89b77a224885}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{85a62a0d-7e17-485f-9d4f-749a287193a6}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{89203471-d554-47d4-bde4-7552ec219999}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{89592015-d996-4636-8f61-066b5d4dd739}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{89fe8f40-cdce-464e-8217-15ef97d4c7c3}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{8c416c79-d49b-4f01-a467-e56d3aa8234c}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{8e6a5303-a4ce-498f-afdb-e03a8a82b077}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{945a8954-c147-4acd-923f-40c45405a658}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{951b41ea-c830-44dc-a671-e2c9958809b8}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{95353826-4fbe-41d4-9c42-f521c6e86360}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{9580d7dd-0379-4658-9870-d5be7d52d6de}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{96f4a050-7e31-453c-88be-9634f4e02139}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{9741fd4e-3757-479f-a3c6-fc49f6d5edd0}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{988c59c5-0a1c-45b6-a555-0c62276e327d}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{991f8fe6-249d-44d6-b93d-5a3060c1dedb}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{9988748e-c2e8-4054-85f6-0c3e1cad2470}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{9c205a39-1250-487d-abd7-e831c6290539}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{9f650c63-9409-453c-a652-83d7185a2e83}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{9f7b5df4-b902-48bc-bc94-95068c6c7d26}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{a0e3d8ea-c34f-4419-a1db-90435b8b21d0}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{a4445c76-ed85-c8a3-02c1-532a38614a9e}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{a67075c2-3e39-4109-b6cd-6d750058a731}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{a68ca8b7-004f-d7b6-a698-07e2de0f1f5d}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{a6ad76e3-867a-4635-91b3-4904ba6374d7}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{a7f2235f-be51-51ed-decf-f4498812a9a2}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{a8a1f2f6-a13a-45e9-b1fe-3419569e5ef2}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{aa3aa23b-bb6d-425a-b58c-1d7e37f5d02a}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{abf1f586-2e50-4ba8-928d-49044e6f0db7}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{ac43300d-5fcc-4800-8e99-1bd3f85f0320}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{ac52ad17-cc01-4f85-8df5-4dce4333c99b}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{ad5162d8-daf0-4a25-88a7-01cbeb33902e}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{ae4bd3be-f36f-45b6-8d21-bdd6fb832853}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{aea1b4fa-97d1-45f2-a64c-4d69fffd92c9}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{aec5c129-7c10-407d-be97-91a042c61aaa}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{b0aa8734-56f7-41cc-b2f4-de228e98b946}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{b2fcd41f-9a40-4150-8c92-b224b7d8c8aa}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{b675ec37-bdb6-4648-bc92-f3fdc74d3ca2}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{b977cf02-76f6-df84-cc1a-6a4b232322b6}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{b99317e5-89b7-4c0d-abd1-6e705f7912dc}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{ba093605-3909-4345-990b-26b746adee0a}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{ba2ffb5c-e20a-4fb9-91b4-45f61b4b66a0}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{babda89a-4d5e-48eb-af3d-e0e8410207c0}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{bc0669e1-a10d-4a78-834e-1ca3c806c93b}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{c02afc2b-e24e-4449-ad76-bcc2c2575ead}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{c03715ce-ea6f-5b67-4449-da1d1e1afeb8}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{c18672d1-dc18-4dfd-91e4-170cf37160cf}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{c26c4f3c-3f66-4e99-8f8a-39405cfed220}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{c4636a1e-7986-4646-bf10-7bc3b4a76e8e}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{c76baa63-ae81-421c-b425-340b4b24157f}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{c914f0df-835a-4a22-8c70-732c9a80c634}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{cb017cd2-1f37-4e65-82bc-3e91f6a37559}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{cbda4dbf-8d5d-4f69-9578-be14aa540d22}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{cd9c6198-bf73-4106-803b-c17d26559018}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{cdc05e28-c449-49c6-b9d2-88cf761644df}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{cdead503-17f5-4a3e-b7ae-df8cc2902eb9}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{ce8dee0b-d539-4000-b0f8-77bed049c590}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{cfc18ec0-96b1-4eba-961b-622caee05b0a}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{d0e22efc-ac66-4b25-a72d-382736b5e940}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{d1bc9aff-2abf-4d71-9146-ecb2a986eb85}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{d48ce617-33a2-4bc3-a5c7-11aa4f29619e}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{d5c25f9a-4d47-493e-9184-40dd397a004d}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{d6f68875-cdf5-43a5-a3e3-53ffd683311c}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{dbe9b383-7cf3-4331-91cc-a3cb16a3b538}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{dd70bc80-ef44-421b-8ac3-cd31da613a4e}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{de29cf61-5ee6-43ff-9aac-959c4e13cc6c}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{de7b24ea-73c8-4a09-985d-5bdadcfa9017}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{dea07764-0790-44de-b9c4-49677b17174f}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{e104fb41-6b04-4f3a-b47d-f0df2f02b954}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{e2816346-87f4-4f85-95c3-0c79409aa89d}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{e3bac9f8-27be-4823-8d7f-1cc320c05fa7}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{e4480490-85b6-11dd-ad8b-0800200c9a66}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{e4f68870-5ae8-4e5b-9ce7-ca9ed75b0245}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{e595f735-b42a-494b-afcd-b68666945cd3}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{e5ba83f6-07d0-46b1-8bc7-7e669a1d31dc}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{e670a5a2-ce74-4ab4-9347-61b815319f4c}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{e8f9af91-afbe-5a03-dfec-5d591686326c}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{ea216962-877b-5b73-f7c5-8aef5375959e}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{eee173ef-7ed2-45de-9877-01c70a852fbd}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{ef1cc15b-46c1-414e-bb95-e76b077bd51e}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{f029ac39-38f0-4a40-b7de-404d244004cb}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{f2e2ce31-0e8a-4e46-a03b-2e0fe97e93c2}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{f3c5e28e-63f6-49c7-a204-e48a1bc4b09d}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{f5d05b38-80a6-4653-825d-c414e4ab3c68}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{f708c483-4880-11e6-9121-5cf37068b67b}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{f717d024-f5b4-4f03-9ab9-331b2dc38ffb}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{f9fe3908-44b8-48d9-9a32-5a763ff5ed79}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{fae10392-f0af-4ac0-b8ff-9f4d920c3cdf}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{fc4e8f51-7a04-4bab-8b91-6321416f72ab}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-SYSTEM\{fcbb06bb-6a2a-46e3-abaa-246cb4e508b2}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\LwtNetLog\{01578F96-C270-4602-ADE0-578D9C29FC0C}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\LwtNetLog\{0BD3506A-9030-4F76-9B88-3E8FE1F7CFB6}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\LwtNetLog\{12d25187-6c0d-4783-ad3a-84caa135acfd}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\LwtNetLog\{15A7A4F8-0072-4EAB-ABAD-F98A4D666AED}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\LwtNetLog\{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\LwtNetLog\{1E39B4CE-D1E6-46CE-B65B-5AB05D6CC266}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\LwtNetLog\{2F07E2EE-15DB-40F1-90EF-9D7BA282188A}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\LwtNetLog\{314DE49F-CE63-4779-BA2B-D616F6963A88}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\LwtNetLog\{315a8872-923e-4ea2-9889-33cd4754bf64}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\LwtNetLog\{3CB40AAA-1145-4FB8-B27B-7E30F0454316}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\LwtNetLog\{3EB875EB-8F4A-4800-A00B-E484C97D7551}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\LwtNetLog\{43D1A55C-76D6-4F7E-995C-64C711E5CAFE}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\LwtNetLog\{63B530F8-29C9-4880-A5B4-B8179096E7B8}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\LwtNetLog\{67D07935-283A-4791-8F8D-FA9117F3E6F2}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\LwtNetLog\{6A1F2B00-6A90-4C38-95A5-5CAB3B056778}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\LwtNetLog\{7868B0D4-1423-4681-AFDF-27913575441E}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\LwtNetLog\{88CD9180-4491-4640-B571-E3BEE2527943}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\LwtNetLog\{9580D7DD-0379-4658-9870-D5BE7D52D6DE}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\LwtNetLog\{A6BF0DEB-3659-40AD-9F81-E25AF62CE3C7}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\LwtNetLog\{AB0D8EF9-866D-4D39-B83F-453F3B8F6325}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\LwtNetLog\{CDEAD503-17F5-4A3E-B7AE-DF8CC2902EB9}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\LwtNetLog\{DF271536-4298-45E1-B0F2-E88F78619C5D}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\LwtNetLog\{e6835967-e0d2-41fb-bcec-58387404e25a}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\LwtNetLog\{FBCFAC3F-8459-419F-8E48-1F0B49CDB85E}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SetupPlatform\{0063715b-eeda-4007-9429-ad526f62696e}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SetupPlatform\{11CD958A-C507-4EF3-B3F2-5FD9DFBD2C78}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SetupPlatform\{30336ed4-e327-447c-9de0-51b652c86108}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SetupPlatform\{331c3b3a-2005-44c2-ac5e-77220c37d6b4}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SetupPlatform\{530FB9B9-C515-4472-9313-FB346F9255E3}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SetupPlatform\{75EBC33E-0CC6-49da-8CD9-8903A5222AA0}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SetupPlatform\{75EBC33E-77B8-4ba8-9474-4F4A9DB2F5C6}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SetupPlatform\{75EBC33E-8670-4eb6-B535-3B9D6BB222FD}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SetupPlatform\{75EBC33E-997F-49cf-B49F-ECC50184B75D}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SetupPlatform\{75EBC33E-C8AE-4f93-9CA1-683A53E20CB6}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SetupPlatform\{75EBC33E-D017-4D0F-93AB-0B4F86579164}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SetupPlatform\{B9DA9FE6-AE5F-4f3e-B2FA-8E623C11DC75}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SetupPlatform\{C553CED4-9BA3-478F-98EA-906CE99C2E4F}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SetupPlatform\{f0be35f8-237b-4814-86b5-ade51192e503}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SetupPlatform\{f5dbaa02-15d6-4644-a784-7032d508bf64}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SpoolerLogger\{19E464A4-7408-49BD-B960-53446AE47820}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SpoolerLogger\{19E93940-A1BD-497F-BC58-CA333880BAB4}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SpoolerLogger\{3048407B-56AA-4D41-82B2-7d5F4b1CDD39}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SpoolerLogger\{402E812D-04E6-4E66-ABDB-32E5F79D36A2}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SpoolerLogger\{49868e3d-77fb-5083-9e09-61e3f37e0309}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SpoolerLogger\{62A0EB6C-3E3E-471d-960C-7C574A72534C}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SpoolerLogger\{6d5ca4bb-df8e-41bc-b554-8aeab241f206}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SpoolerLogger\{6fb61ac3-3455-4da4-8313-c1a855ee64c5}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SpoolerLogger\{836767A6-AF31-4938-B4C0-EF86749A9AEF}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SpoolerLogger\{9558985e-3bc8-45ef-a2fd-2e6ff06fb886}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SpoolerLogger\{99F5F45C-FD1E-439F-A910-20D0DC759D28}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SpoolerLogger\{acf1e4a7-9241-4fbf-9555-c27638434f8d}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SpoolerLogger\{B795C7DF-07BC-4362-938E-E8ABD81A9A01}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SpoolerLogger\{C9BF4A01-D547-4d11-8242-E03A18B5BE01}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SpoolerLogger\{C9BF4A02-D547-4d11-8242-E03A18B5BE01}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SpoolerLogger\{C9BF4A03-D547-4d11-8242-E03A18B5BE01}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SpoolerLogger\{C9BF4A05-D547-4d11-8242-E03A18B5BE01}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SpoolerLogger\{C9BF4A9E-D547-4d11-8242-E03A18B5BE01}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SpoolerLogger\{C9BF4A9F-D547-4d11-8242-E03A18B5BE01}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{047FB417-39E6-4B79-A52C-C436B60011AD}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{0BD3506A-9030-4f76-9B88-3E8FE1F7CFB6}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{111ffc99-3987-4bf8-8398-61853120cb3d}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{1193FF07-26A3-4ECA-9384-12CCF39CAE03}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{21ba7b61-05f8-41f1-9048-c09493dcfe38}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{2D0CC56C-874F-422C-B25F-246F286A24BA}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{314DE49F-CE63-4779-BA2B-D616F6963A88}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{3496b396-5c43-45e7-b38e-d509b79ae721}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{3D42A67D-9CE8-4284-B755-2550672B0CE0}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{4D946A46-275B-4C9D-B835-0B2160559256}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{58980F4B-BD39-4a3e-B344-492ED2254A4E}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{5CA18737-22AC-4050-85BC-B8DBB9F7D986}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{681E3481-7510-4053-8C87-A6305EAFC4FA}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{6BE684E4-194C-43B0-B9B8-8269646DE989}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{6eb8db94-fe96-443f-a366-5fe0cee7fb1c}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{7D7180B3-A452-4FFF-8D1F-7B32B248AB70}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{802ec45b-1e99-4b83-9920-87c98277ba9d}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{814182FF-58F7-11E1-853C-78E7D1CA7337}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{90BBBABB-255B-4FE3-A06F-685A15E93A4C}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{914598a6-28f0-42ac-bf3d-a29c6047a739}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{949D7457-6151-4FA0-9E46-D82A6F9927CF}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{9580d7dd-0379-4658-9870-d5be7d52d6de}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{999AC137-42DC-41D3-BA9D-A325A9E1A986}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{9B322459-4AD9-4F81-8EEA-DC77CDD18CA6}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{9B694F87-000E-4BE6-91AC-FE2E50D61A6F}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{9CC0413E-5717-4af5-82EB-6103D8707B45}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{9CC9BEB7-9D24-47C7-8F9D-CCC9DCAC29EB}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{AB0D8EF9-866D-4d39-B83F-453F3B8F6325}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{abe47285-c002-46d1-95e4-c4aec3c78f50}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{B8794785-F7E3-4C2D-A33D-7B0BA0D30E18}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{c02edc8d-d627-46c9-abd9-c8b78f88c223}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{C100BECE-D33A-4A4B-BF23-BBEF4663D017}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{c7491fe4-66f4-4421-9954-b55f03db3186}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{D28262A1-8066-492D-BCE8-635DA75368B7}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{E5C16D49-2464-4382-BB20-97A4B5465DB9}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{e6dec100-4e0f-4927-92be-e69d7c15c821}" /v "Enabled" /t Reg_DWORD /d "0" /f >nul
Auditpol /set /category:* /Success:Disable
dism /online /set-reservedstoragestate /state:disabled
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe" /v "UseLargePages" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe" /v "AuditLevel" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\dllhost.exe" /v "UseLargePages" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\dllhost.exe" /v "AuditLevel" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\dwm.exe" /v "UseLargePages" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\dwm.exe" /v "AuditLevel" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\explorer.exe" /v "UseLargePages" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\explorer.exe" /v "AuditLevel" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ExtExport.exe" /v "AuditLevel" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ie4uinit.exe" /v "AuditLevel" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ieinstal.exe" /v "AuditLevel" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ielowutil.exe" /v "AuditLevel" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ieUnatt.exe" /v "AuditLevel" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\iexplore.exe" /v "AuditLevel" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsm.exe" /v "UseLargePages" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsm.exe" /v "AuditLevel" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MicrosoftEdgeUpdate.exe" /v "AuditLevel" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\mscorsvw.exe" /v "AuditLevel" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\mscorsvw.exe" /v "UseLargePages" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\msfeedssync.exe" /v "AuditLevel" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\mshta.exe" /v "AuditLevel" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ngen.exe" /v "AuditLevel" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ngentask.exe" /v "AuditLevel" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\PresentationHost.exe" /v "AuditLevel" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\PrintDialog.exe" /v "AuditLevel" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\PrintIsolationHost.exe" /v "AuditLevel" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\runtimebroker.exe" /v "AuditLevel" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\services.exe" /v "UseLargePages" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\services.exe" /v "AuditLevel" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\smss.exe" /v "UseLargePages" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\smss.exe" /v "AuditLevel" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\splwow64.exe" /v "AuditLevel" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\spoolsv.exe" /v "AuditLevel" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\svchost.exe" /v "UseLargePages" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\svchost.exe" /v "AuditLevel" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SystemSettings.exe" /v "AuditLevel" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\taskeng.exe" /v "UseLargePages" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\taskeng.exe" /v "AuditLevel" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\wininit.exe" /v "UseLargePages" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\wininit.exe" /v "AuditLevel" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\WmiPrvSE.exe" /v "UseLargePages" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\WmiPrvSE.exe" /v "AuditLevel" /t REG_DWORD /d "0" /f >nul

echo  !B_BLACK!fixing languages if needed
REG ADD "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v "DoNotConnectToWindowsUpdateInternetLocations" /t REG_DWORD /d "0" /f >nul
REG ADD "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "UseWUServer" /t REG_DWORD /d "0" /f >nul

echo  !B_BLACK!Enabling MSI mode & set to undefined
for /f %%c in ('wmic path Win32_USBController get PNPDeviceID^| findstr /L "PCI\VEN_"') do reg add "HKLM\System\CurrentControlSet\Enum\%%c\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t REG_DWORD /d "1" /f
for /f %%c in ('wmic path Win32_USBController get PNPDeviceID^| findstr /L "PCI\VEN_"') do reg delete "HKLM\System\CurrentControlSet\Enum\%%c\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /f >nul 2>nul
:: Probably will be reset by installing GPU driver
for /f %%c in ('wmic path Win32_VideoController get PNPDeviceID^| findstr /L "PCI\VEN_"') do reg add "HKLM\System\CurrentControlSet\Enum\%%c\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t REG_DWORD /d "1" /f
for /f %%c in ('wmic path Win32_VideoController get PNPDeviceID^| findstr /L "PCI\VEN_"') do reg add "HKLM\System\CurrentControlSet\Enum\%%c\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /f >nul 2>nul
for /f %%c in ('wmic path Win32_NetworkAdapter get PNPDeviceID^| findstr /L "PCI\VEN_"') do reg add "HKLM\System\CurrentControlSet\Enum\%%c\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t REG_DWORD /d "1" /f
for /f %%c in ('wmic path Win32_IDEController get PNPDeviceID^| findstr /L "PCI\VEN_"') do reg add "HKLM\System\CurrentControlSet\Enum\%%c\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t REG_DWORD /d "1" /f
for /f %%c in ('wmic path Win32_IDEController get PNPDeviceID^| findstr /L "PCI\VEN_"') do reg add "HKLM\System\CurrentControlSet\Enum\%%c\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /f >nul 2>nul
for /f %%c in ('wmic path Win32_NetworkAdapter get PNPDeviceID^| findstr /L "PCI\VEN_"') do reg add "HKLM\System\CurrentControlSet\Enum\%%c\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /f >nul 2>nul
:: Fix VMware
wmic computersystem get manufacturer /format:value | findstr /i /C:VMWare && (
    for /f %%a in ('wmic path Win32_NetworkAdapter get PNPDeviceID ^| findstr /l "PCI\VEN_"') do (
        reg add "HKLM\System\CurrentControlSet\Enum\%%a\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /t REG_DWORD /d "2"  /f > nul 2>nul
    )
)

echo  !B_BLACK!Configuring boot windows...
bcdedit /set {globalsettings} custom:16000067 true >nul
bcdedit /set {globalsettings} custom:16000068 true >nul
bcdedit /set {globalsettings} custom:16000069 true >nul
bcdedit /timeout 0 >nul
bcdedit /set hypervisorlaunchtype No >nul
bcdedit /set isolatedcontext No >nul
bcdedit /set vsmlaunchtype Off >nul
bcdedit /set vm No >nul
bcdedit /set allowedinmemorysettings 0 >nul
bcdedit /set fircefipscrypto No >nul
bcdedit /set perfmem 0
bcdedit /set configflags 0
bcdedit /deletevalue usefirmwarepcisettings >nul
bcdedit /set quietboot Yes >nul
bcdedit /set integrityservices disable >nul
bcdedit /set nx AlwaysOff >nul
bcdedit /set bootux Disabled >nul
bcdedit /set bootmenupolicy legacy >nul
bcdedit /set {current} description "DelusionOS 24H2" >nul
label C: DelusionOS 24H2 >nul

powercfg -import "%windir%\deluos.pow" 00000000-16f6-45a6-9fcf-0fa130b83c00 >nul
powercfg -setactive 00000000-16f6-45a6-9fcf-0fa130b83c00 >nul
powercfg -delete a1841308-3541-4fab-bc81-f71556f20b4a >nul
for %a in ("SleepStudy" "Kernel-Processor-Power" "UserModePowerService") do (wevtutil sl Microsoft-Windows-%~l/Diagnostic /e:false)

echo  !B_BLACK!Configuration Device manager...
devmanview.exe /disable "PCI Data Acquisition and Signal Processing Controller"
devmanview.exe /disable "PCI Encryption/Decryption Controller"
devmanview.exe /disable "PCI Simple Communications Controller"
devmanview.exe /disable "PCI Memory Controller"
devmanview.exe /disable "PCI standard RAM Controller"
devmanview.exe /disable "AMD PSP"
devmanview.exe /disable "AMD SMBus"
devmanview.exe /disable "AURA LED Controller"
devmanview.exe /disable "Fax"
devmanview.exe /disable "Microsoft Print to PDF"
devmanview.exe /disable "Microsoft XPS Document Writer"
devmanview.exe /disable "Root Print Queue"
devmanview.exe /disable "Base System Device"
devmanview.exe /disable "Composite Bus Enumerator"
devmanview.exe /disable "UMBus Root Bus Enumerator"
devmanview.exe /disable "Direct memory access controller"
devmanview.exe /disable "Generic Bluetooth Adapter"
devmanview.exe /disable "Intel SMBus"
devmanview.exe /disable "System Speaker"
devmanview.exe /disable "Intel(R) Display Audio"
devmanview.exe /disable "Programmable Interrupt Controller"
devmanview.exe /disable "Legacy device"
devmanview.exe /disable "Microsoft Device Association Root Enumerator"
devmanview.exe /disable "Microsoft GS Wavetable Synth"
devmanview.exe /disable "Microsoft Hyper-V Virtualization Infrastructure Driver"
devmanview.exe /disable "Microsoft Kernel Debug Network Adapter"
devmanview.exe /disable "Microsoft Radio Device Enumeration Bus"
devmanview.exe /disable "Microsoft RRAS Root Enumerator"
devmanview.exe /disable "Microsoft Virtual Drive Enumerator"
devmanview.exe /disable "Microsoft RRAS Root Enumerator"
devmanview.exe /disable "Remote Desktop Device Redirector Bus"
devmanview.exe /disable "Numeric Data Processor"
devmanview.exe /uninstall "File as Volume Driver"

for /f "delims=:{}" %%a in ('wmic path Win32_SystemEnclosure get ChassisTypes ^| findstr [0-9]') do set "CHASSIS=%%j"
set "DEVICE_TYPE=PC"
for %%j in (8 9 10 11 12 13 14 18 21 30 31 32) do if "%CHASSIS%" == "%%j" (set "DEVICE_TYPE=LAPTOP")

if "%DEVICE_TYPE%" == "LAPTOP" (
    Reg.exe add "HKLM\System\CurrentControlSet\Services\wmiacpi" /v "Start" /t REG_DWORD /d "2" /f >nul
    Reg.exe add "HKLM\System\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "0" /f >nul
    powercfg /setactive 381b4222-f694-41f0-9685-ff5bb260df2e
)
) else (
    Reg.exe add "HKLM\System\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f >nul
)

echo  !S_GRAY!Configuration Latency Tolerance...
@rem Creator couwthynokap
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "MonitorLatencyTolerance" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "MonitorRefreshLatencyTolerance" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "ExitLatency" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "ExitLatencyCheckEnabled" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "Latency" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceDefault" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceFSVP" /t REG_DWORD /d "1" /f  >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyTolerancePerfOverride" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceScreenOffIR" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceVSyncEnabled" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "RtlCapabilityCheckLatency" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\GraphicsDrivers" /v "TdrLevel" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\GraphicsDrivers" /v "TdrDelay" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\GraphicsDrivers" /v "TdrDdiDelay" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\GraphicsDrivers" /v "TdrDebugMode" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\GraphicsDrivers" /v "TdrLimitTime" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\GraphicsDrivers" /v "TdrLimitCount" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\GraphicsDrivers" /v "DisableBadDriverCheckForHwProtection" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyActivelyUsed" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleLongTime" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleMonitorOff" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleNoContext" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleShortTime" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleVeryLongTime" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceIdle0" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceIdle0MonitorOff" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceIdle1" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceIdle1MonitorOff" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceMemory" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceNoContext" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceNoContextMonitorOff" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceOther" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceTimerPeriod" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultMemoryRefreshLatencyToleranceActivelyUsed" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultMemoryRefreshLatencyToleranceMonitorOff" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultMemoryRefreshLatencyToleranceNoContext" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "Latency" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "MaxIAverageGraphicsLatencyInOneBucket" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "MiracastPerfTrackGraphicsLatency" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "MonitorLatencyTolerance" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "MonitorRefreshLatencyTolerance" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "TransitionLatency" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "EnablePreemption" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "D3PCLatency" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "F1TransitionLatency" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "Node3DLowLatency" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PciLatencyTimerControl" /t REG_DWORD /d "20" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMDeepL1EntryLatencyUsec" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RmGspcMaxFtuS" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RmGspcMinFtuS" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RmGspcPerioduS" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMLpwrEiIdleThresholdUs" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMLpwrGrIdleThresholdUs" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMLpwrGrRgIdleThresholdUs" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMLpwrMsIdleThresholdUs" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "VRDirectFlipDPCDelayUs" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "VRDirectFlipTimingMarginUs" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "VRDirectJITFlipMsHybridFlipDelayUs" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "vrrCursorMarginUs" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "vrrDeflickerMarginUs" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "vrrDeflickerMaxUs" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMHdcpKeyglobZero" /t REG_DWORD /d "1" /f >nul

echo  !B_BLACK!Configuration Internet Tweaks....
@rem Creator couwthynokap
ipconfig /flushdns
ipconfig /registerdns
ipconfig /release
ipconfig /renew
netsh winsock reset
netsh winsock set autotuning on >nul
netsh interface tcp set global hystart=disabled >nul
netsh interface tcp set global fastopen=enabled >nul
netsh int tcp set global prr=disabled >nul
netsh int tcp set global pacingprofile=off >nul
netsh int ip set global neighborcachelimit=4096 >nul
netsh int ip set global routecachelimit=4096 >nul
netsh int ip set global sourceroutingbehavior=drop >nul
netsh int ip set global taskoffload=enabled >nul
netsh int ip set global dhcpmediasense=disabled >nul
netsh int ip set global mediasenseeventlog=disabled >nul
netsh int ip set global mldlevel=none >nul
netsh int tcp set supplemental Internet congestionprovider=ctcp >nul
netsh int tcp set global dca=enabled >nul
netsh int tcp set global netdma=disabled >nul
netsh int isatap set state disable >nul
netsh int teredo set state disable >nul
netsh interface teredo set state disabled >nul
netsh interface isatap set state disabled >nul
netsh int ipv6 isatap set state disabled >nul
netsh int ipv6 6to4 set state disabled >nul
netsh interface IPV6 set global randomizeidentifier=disabled >nul
netsh interface IPV6 set privacy state=disabled >nul
for /f "tokens=1" %%i in ('netsh int ip show interfaces ^| findstr [0-9]') do set INTERFACE=%%i >nul
netsh int ip set interface %INTERFACE% basereachable=3600000 dadtransmits=0 otherstateful=disabled routerdiscovery=disabled store=persistent >nul
netsh int tcp set global rss=enabled >nul
netsh int tcp set global rsc=disabled >nul
netsh int tcp set global initialRto=2000 >nul
netsh int tcp set security mpp=disabled >nul
netsh int tcp set security profiles=disabled >nul
netsh int tcp set global ecncapability=disabled >nul
netsh int tcp set global timestamps=disabled >nul
netsh int ip set global icmpredirects=disabled >nul
netsh int ipv4 set dynamicport tcp start=1025 num=64511 >nul
netsh int ipv4 set dynamicport udp start=1025 num=64511 >nul
powershell Set-NetTCPSetting -SettingName "*" -ForceWS Disabled >nul

powershell Set-NetAdapterAdvancedProperty -Name "*" -RegistryKeyword "*EEE" -RegistryValue "0" >nul
powershell Set-NetAdapterAdvancedProperty -Name "*" -RegistryKeyword "*FlowControl" -RegistryValue "0" >nul
powershell Set-NetAdapterAdvancedProperty -Name "*" -RegistryKeyword "*IPChecksumOffloadIPv4" -RegistryValue "0" >nul
powershell Set-NetAdapterAdvancedProperty -Name "*" -RegistryKeyword "*InterruptModeration" -RegistryValue "0" >nul
powershell Set-NetAdapterAdvancedProperty -Name "*" -RegistryKeyword "*LsoV2IPv4" -RegistryValue "0" >nul
powershell Set-NetAdapterAdvancedProperty -Name "*" -RegistryKeyword "*LsoV2IPv6" -RegistryValue "0" >nul
powershell Set-NetAdapterAdvancedProperty -Name "*" -RegistryKeyword "*NumRssQueues" -RegistryValue "2" >nul
powershell Set-NetAdapterAdvancedProperty -Name "*" -RegistryKeyword "*PMARPOffload" -RegistryValue "0" >nul
powershell Set-NetAdapterAdvancedProperty -Name "*" -RegistryKeyword "*PMNSOffload" -RegistryValue "0" >nul
powershell Set-NetAdapterAdvancedProperty -Name "*" -RegistryKeyword "*PriorityVLANTag" -RegistryValue "1" >nul
powershell Set-NetAdapterAdvancedProperty -Name "*" -RegistryKeyword "*RSS" -RegistryValue "1" >nul
powershell Set-NetAdapterAdvancedProperty -Name "*" -RegistryKeyword "*WakeOnMagicPacket" -RegistryValue "0" >nul
powershell Set-NetAdapterAdvancedProperty -Name "*" -RegistryKeyword "*WakeOnPattern" -RegistryValue "0" >nul
powershell Set-NetAdapterAdvancedProperty -Name "*" -RegistryKeyword "*ReceiveBuffers" -RegistryValue "2048" >nul
powershell Set-NetAdapterAdvancedProperty -Name "*" -RegistryKeyword "*TransmitBuffers" -RegistryValue "2048" >nul
powershell Set-NetAdapterAdvancedProperty -Name "*" -RegistryKeyword "*TCPChecksumOffloadIPv4" -RegistryValue "0" >nul
powershell Set-NetAdapterAdvancedProperty -Name "*" -RegistryKeyword "*TCPChecksumOffloadIPv6" -RegistryValue "0" >nul
powershell Set-NetAdapterAdvancedProperty -Name "*" -RegistryKeyword "*UDPChecksumOffloadIPv4" -RegistryValue "0" >nul
powershell Set-NetAdapterAdvancedProperty -Name "*" -RegistryKeyword "*UDPChecksumOffloadIPv6" -RegistryValue "0" >nul
powershell Set-NetAdapterAdvancedProperty -Name "*" -RegistryKeyword "DMACoalescing" -RegistryValue "0" >nul
powershell Set-NetAdapterAdvancedProperty -Name "*" -RegistryKeyword "EEELinkAdvertisement" -RegistryValue "0" >nul
powershell Set-NetAdapterAdvancedProperty -Name "*" -RegistryKeyword "ITR" -RegistryValue "0" >nul
powershell Set-NetAdapterAdvancedProperty -Name "*" -RegistryKeyword "ReduceSpeedOnPowerDown" -RegistryValue "0" >nul
powershell Set-NetAdapterAdvancedProperty -Name "*" -RegistryKeyword "WaitAutoNegComplete" -RegistryValue "0" >nul
powershell Set-NetAdapterAdvancedProperty -Name "*" -RegistryKeyword "WakeOnLink" -RegistryValue "0" >nul
powershell Set-NetAdapterAdvancedProperty -Name "*" -RegistryKeyword "AdvancedEEE" -RegistryValue "0" >nul
powershell Set-NetAdapterAdvancedProperty -Name "*" -RegistryKeyword "EnableGreenEthernet" -RegistryValue "0" >nul
powershell Set-NetAdapterAdvancedProperty -Name "*" -RegistryKeyword "GigaLite" -RegistryValue "0" >nul
powershell Set-NetAdapterAdvancedProperty -Name "*" -RegistryKeyword "PowerSavingMode" -RegistryValue "0" >nul
powershell Set-NetAdapterAdvancedProperty -Name "*" -RegistryKeyword "S5WakeOnLan" -RegistryValue "0" >nul
powershell Set-NetAdapterAdvancedProperty -Name "*" -RegistryKeyword "WolShutdownLinkSpeed" -RegistryValue "2" >nul
powershell Set-NetAdapterAdvancedProperty -Name "*" -RegistryKeyword "LogLinkStateEvent" -RegistryValue "16" >nul
powershell Set-NetAdapterAdvancedProperty -Name "*" -RegistryKeyword "WakeOnMagicPacketFromS5" -RegistryValue "0" >nul
powershell Set-NetAdapterAdvancedProperty -Name "*" -DisplayName "Ultra Low Power Mode" -DisplayValue "Disabled" >nul
powershell Set-NetAdapterAdvancedProperty -Name "*" -DisplayName "System Idle Power Saver" -DisplayValue "Disabled" >nul
powershell Set-NetAdapterAdvancedProperty -Name "*" -DisplayName "Selective Suspend" -DisplayValue "Disabled" >nul
powershell Set-NetAdapterAdvancedProperty -Name "*" -DisplayName "Selective Suspend Idle Timeout" -DisplayValue "60" >nul
powershell Set-NetAdapterAdvancedProperty -Name "*" -DisplayName "Link Speed Battery Saver" -DisplayValue "Disabled" >nul
powershell Set-NetAdapterAdvancedProperty -AllProperties -Name "*" -RegistryKeyword "*SelectiveSuspend" -RegistryValue "0" >nul 
powershell Set-NetAdapterAdvancedProperty -AllProperties -Name "*" -RegistryKeyword "EnablePME" -RegistryValue "0" >nul
powershell Set-NetAdapterAdvancedProperty -AllProperties -Name "*" -RegistryKeyword "TxIntDelay" -RegistryValue "0" >nul
powershell Set-NetAdapterAdvancedProperty -AllProperties -Name "*" -RegistryKeyword "TxDelay" -RegistryValue "0" >nul
powershell Set-NetAdapterAdvancedProperty -AllProperties -Name "*" -RegistryKeyword "EnableModernStandby" -RegistryValue "0" >nul
powershell Set-NetAdapterAdvancedProperty -AllProperties -Name "*" -RegistryKeyword "*ModernStandbyWoLMagicPacket" -RegistryValue "0" >nul
powershell Set-NetAdapterAdvancedProperty -AllProperties -Name "*" -RegistryKeyword "EnableLLI" -RegistryValue "1" >nul
powershell Set-NetAdapterAdvancedProperty -AllProperties -Name "*" -RegistryKeyword "*SSIdleTimeout" -RegistryValue "60" >nul

echo  !B_BLACK!Storage Tweaks apply..
for %%z in (EnableHIPM EnableDIPM EnableHDDParking) do for /f "delims=" %%z in ('reg query "HKLM\System\CurrentControlSet\Services" /s /f "%%z" ^| findstr "HKEY"') do Reg.exe add "%%z" /v "%%z" /t REG_DWORD /d "0" /f >nul
cls

echo  !S_GRAY!Disabling NetBIOS over TCP/UPD...
    for /f "delims=" %%u in ('reg query "HKLM\System\CurrentControlSet\Services\NetBT\Parameters\Interfaces" /s /f "NetbiosOptions" ^| findstr "HKEY"') do (
        Reg.exe add "%%u" /v "NetbiosOptions" /t REG_DWORD /d "2" /f
    )
)

echo  !B_BLACK!Disabling Exclusive Mode On Audio Devices...
for /f "delims=" %%e in ('reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Capture') do Reg.exe add "%%e\Properties" /v "{b3f8fa53-0004-438e-9003-51a46e139bfc},3" /t REG_DWORD /d "0" /f >nul
for /f "delims=" %%e in ('reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Capture') do Reg.exe add "%%e\Properties" /v "{b3f8fa53-0004-438e-9003-51a46e139bfc},4" /t REG_DWORD /d "0" /f >nul
for /f "delims=" %%e in ('reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Render') do Reg.exe add "%%e\Properties" /v "{b3f8fa53-0004-438e-9003-51a46e139bfc},3" /t REG_DWORD /d "0" /f >nul
for /f "delims=" %%e in ('reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Render') do Reg.exe add "%%e\Properties" /v "{b3f8fa53-0004-438e-9003-51a46e139bfc},4" /t REG_DWORD /d "0" /f >nul

echo  !S_GRAY!Clean Regedit / DirectX Shader Cache
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\HotStart" /f >nul
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Sidebar" /f >nul
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Telephony" /f >nul
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Screensavers" /f >nul
reg delete "HKCU\Printers" /f >nul
reg delete "HKLM\SYSTEM\ControlSet001\Control\Print" /f >nul
reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Font Drivers" /v "Adobe Type Manager" /f >nul
reg delete "HKLM\System\ControlSet001\Control\Terminal Server\Wds" /v "StartupPrograms" /f >nul
DISM /Online /Remove-Capability /CapabilityName:Browser.InternetExplorer~~0.0.11.0 /norestart /quiet >nul
DISM /Online /Remove-Capability /CapabilityName:MathRecognizer0.0.1.0 /norestart /quiet >nul
DISM /Online /Remove-Capability /CapabilityName:Microsoft.Windows.PowerShell.ISE0.0.1.0 /norestart /quiet >nul
DISM /Online /Remove-Capability /CapabilityName:OneCoreUAP.OneSync~~0.0.1.0 /norestart /quiet >nul
cleanmgr /sageset:0
shutdown -r -t 70 -с "70 sec for reboot pc"

:Colors
:: Credits to Artanis for colors
set "CMDLINE=RED=[31m,S_GRAY=[90m,S_RED=[91m,S_GREEN=[92m,S_YELLOW=[93m,S_MAGENTA=[95m,S_WHITE=[97m,B_BLACK=[40m,B_YELLOW=[43m,UNDERLINE=[4m,_UNDERLINE=[24m"
set "%CMDLINE:,=" & set "%"
