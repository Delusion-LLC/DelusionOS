@echo off && SetLocal EnableDelayedExpansion && title System Setup... && mode con: cols=90 lines=20

:: request administrator privileges
DISM >nul || (
    PowerShell Start -Verb RunAs '%0' 2> nul || (
        echo error: right-click on the "%~f0" script and select "Run as administrator"
        pause
    )
    exit /b 1
)

:: Delusion LLC
:: license Attribution-NonCommercial 4.0 International

call :colors
timeout /t 3 /nobreak >nul

taskkill /f /im explorer.exe 

echo  !B_BLACK!Execution Policy To Unrestricted...
powershell Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope LocalMachine -Force
powershell Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser -Force
PowerShell -NonInteractive -NoLogo -Command "Disable-MMAgent -mc"
PowerShell -NonInteractive -NoLogo -Command "Disable-WindowsErrorReporting"

setx DOTNET_CLI_TELEMETRY_OPTOUT 1 & setx POWERSHELL_TELEMETRY_OPTOUT 1 >nul

:: disable driver power saving
powershell.exe -command "Get-WmiObject MSPower_DeviceEnable -Namespace root\wmi | ForEach-Object { $_.enable = $false; $_.psbase.put(); }"

powershell Set-Processmitigation -System -Disable DEP, EmulateAtlThunks, SEHOP, ForceRelocateImages, RequireInfo, BottomUp, HighEntropy, StrictHandle, DisableWin32kSystemCalls, AuditSystemCall, DisableExtensionPoints, BlockDynamicCode, AllowThreadsToOptOut, AuditDynamicCode, SuppressExports, MicrosoftSignedOnly, AllowStoreSignedBinaries, AuditMicrosoftSigned, AuditStoreSigned, EnforceModuleDependencySigning, DisableNonSystemFonts, AuditFont, BlockRemoteImageLoads, BlockLowLabelImageLoads, PreferSystem32, AuditRemoteImageLoads, AuditLowLabelImageLoads, AuditPreferSystem32, EnableExportAddressFilter, AuditEnableExportAddressFilter, EnableExportAddressFilterPlus, AuditEnableExportAddressFilterPlus, EnableImportAddressFilter, AuditEnableImportAddressFilter, EnableRopStackPivot, AuditEnableRopStackPivot, EnableRopCallerCheck, AuditEnableRopCallerCheck, EnableRopSimExec, AuditEnableRopSimExec, AuditSEHOP, SEHOPTelemetry, TerminateOnError, DisallowChildProcessCreation, AuditChildProcess, UserShadowStack, UserShadowStackStrictMode, AuditUserShadowStack

echo  !B_BLACK!Setting up personalization
reg add "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" /f /ve
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\DelegateFolders\{F5FB2C77-0E2F-4A16-A381-3E560C68BC83}" /f
PowerRun.exe reg add "HKCR\CLSID\{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}\ShellFolder" /v "Attributes" /t REG_DWORD /d "2962489444" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{f874310e-b6b7-47dc-bc84-b9e6b38f5903}" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LaunchTo" /t REG_DWORD /d "1" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d "1" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowFrequent" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowRecent" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSyncProviderNotifications" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "EnableTransparency" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "ColorPrevalence" /t REG_DWORD /d "1" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "AppsUseLightTheme" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "SystemUsesLightTheme" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Accent" /v "AccentPalette" /t REG_BINARY /d "6b6b6bff595959ff4c4c4cff3f3f3fff333333ff262626ff141414ff88179800" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Accent" /v "StartColorMenu" /t REG_DWORD /d "4281545523" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Accent" /v "AccentColorMenu" /t REG_DWORD /d "4675079" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "Wallpaper" /t REG_SZ /d "C:\%windir%\deluos.jpg" /f >nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\DWM" /v "ColorizationColor" /t REG_DWORD /d "3292479295" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\DWM" /v "ColorizationAfterglow" /t REG_DWORD /d "3292479295" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\DWM" /v "AccentColor" /t REG_DWORD /d "4675079" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v "VisualFXSetting" /t REG_DWORD /d "3" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewAlphaSelect" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewShadow" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAnimations" /t REG_DWORD /d "0" /f
reg add "HKCU\Control Panel\Desktop" /v "UserPreferencesMask" /t REG_BINARY /d "9012038010000000" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\DWM" /v "EnableAeroPeek" /t REG_DWORD /d "0" /f
reg add "HKCU\Control Panel\Desktop" /v "ForegroundLockTimeout" /t REG_DWORD /d "0" /f
reg add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\DWM" /v "AlwaysHibernateThumbnails" /t REG_DWORD /d "0" /f
reg add "HKCU\Control Panel\Desktop\WindowMetrics" /v "MinAnimate" /t REG_SZ /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Dsh" /v "AllowNewsAndInterests" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowTaskViewButton" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Start" /v "AllowPinnedFolderSettings" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Start" /v "AllowPinnedFolderSettings_ProviderSet" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Start" /v "AllowPinnedFolderFileExplorer" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Start" /v "AllowPinnedFolderFileExplorer_ProviderSet" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "HideRecentlyAddedApps" /t REG_DWORD /d "1" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackDocs" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_Layout" /t REG_DWORD /d "1" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_IrisRecommendations" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_AccountNotifications" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAl" /t REG_DWORD /d "0" /f
bcdedit /set description "DelusionOS"
label C:DelusionOS
net accounts /maxpwage:unlimited
cls

echo  !B_BLACK!Delete Windows Defender
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Microsoft Antimalware\Real-Time Protection" /v "DisableScanOnRealtimeEnable" /t REG_DWORD /d "1" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Microsoft Antimalware\Real-Time Protection" /v "DisableOnAccessProtection" /t REG_DWORD /d "1" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableScanOnRealtimeEnable" /t REG_DWORD /d "1" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d "1" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Spynet" /v "SpyNetReporting" /t REG_DWORD /d "0" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d "0" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WTDS\Components" /v "ServiceEnabled" /t REG_DWORD /d "0" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CI\Policy" /v "VerifiedAndReputablePolicyState" /t REG_DWORD /d "0" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "SecurityHealth" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "WindowsDefender" /f

for %%a in (
	WinDefend
	MsSecCore
	MsSecWfp
	MsSecFlt
	MDCoreSvc
	wscsvc
	WdFilter
	WdBoot
	WdNisSvc
	WdNisDrv
	webthreatdefsvc
	webthreatdefusersvc
	wtd
	SecurityHealthService
	Sense
) do reg add "HKLM\SYSTEM\CurrentControlSet\Services\%%a" /v "Start" /t REG_DWORD /d "4" /f

for %%e in (
	"Windows Defender Cache Maintenance"
	"Windows Defender Cleanup"
	"Windows Defender Scheduled Scan"
	"Windows Defender Verification"
) do schtasks /delete /tn "\Microsoft\Windows\Windows Defender\%%~e" /f

reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v SettingsPageVisibility /t REG_SZ /d "hide:windowsdefender:update" /f
cls

echo  !B_BLACK!Delete Security Warn
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorUser" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableInstallerDetection" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableSecureUIAPaths" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableUIADesktopToggle" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableVirtualization" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "FilterAdministratorToken" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "PromptOnSecureDesktop" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ValidateAdminCodeSignatures" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\luafv" /v "Start" /t REG_DWORD /d "4" /f

reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1806" /t REG_DWORD /d "0" /f
cls

echo  !B_BLACK!Disabling SmartScreen
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "SmartScreenEnabled" /t REG_SZ /d "Off" /f
taskkill /f /im smartscreen.exe & ren %windir%\System32\smartscreen.exe smartscreen.exee
cls

echo  !B_BLACK!Disabling mobsync & delete
del "%windir%\System32\mobsync.exe"
del "%windir%\SysWOW64\mobsync.exe"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\OneSyncSvc" /v "Start" /t REG_DWORD /d "4" /f
cls

echo  !B_BLACK!Delete Onedrive
"%windir%\System32\OneDriveSetup.exe" /uninstall
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f
cls

echo  !B_BLACK!Disabling Auto Installing App
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "ContentDeliveryAllowed" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "OemPreInstalledAppsEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEverEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d "0" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsStore" /v "AutoDownload" /t REG_DWORD /d "2" /f
cls

echo  !B_BLACK!Edge Debload
for %%z in (MicrosoftEdgeUpdate WidgetService Widgets msedge msedgewebview2) do taskkill /f /im %%z.exe

reg add "HKLM\SOFTWARE\Microsoft\EdgeUpdate" /v "DoNotUpdateToEdgeWithChromium" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdateDev" /v "AllowUninstall" /t REG_SZ /f

rd /s /q "%programfiles(x86)%\Microsoft\EdgeUpdate"
cls

echo  !B_BLACK!Deletion Of All Telemetry
schtasks /change /tn "Microsoft\Windows\Maintenance\WinSAT" /disable
schtasks /change /tn "Microsoft\Windows\Autochk\Proxy" /disable
schtasks /change /tn "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /disable
schtasks /change /tn "Microsoft\Windows\Application Experience\ProgramDataUpdater" /disable
schtasks /change /tn "Microsoft\Windows\Application Experience\StartupAppTask" /disable
schtasks /change /tn "Microsoft\Windows\PI\Sqm-Tasks" /disable
schtasks /change /tn "Microsoft\Windows\NetTrace\GatherNetworkInfo" /disable
schtasks /change /tn "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /disable
schtasks /change /tn "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /disable
schtasks /change /tn "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver" /disable
schtasks /change /tn "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /disable
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v "EnableActivityFeed" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d "1" /f

sc stop dmwappushservice
net stop dmwappushservice 
sc config dmwappushservice start= disabled
net stop diagnosticshub.standardcollector.service > NUL 2>&1
sc config diagnosticshub.standardcollector.service start= disabled

reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Visibility" /v "DiagnosticErrorText" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Strings" /v "DiagnosticErrorText" /t REG_SZ /d "" /f
reg add "HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Strings" /v "DiagnosticLinkText" /t REG_SZ /d "" /f
reg add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /v "PreventHandwritingDataSharing" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" /v "PreventHandwritingErrorReports" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableInventory" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v "NoLockScreenCamera" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\System" /v "AllowExperimentation" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Bluetooth" /v "AllowAdvertising" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Messaging" /v "AllowMessageSync" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Biometrics" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications" /v "ToastEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Control Panel\International\User Profile" /v "HttpAcceptLanguageOptOut" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{C1D23ACC-752B-43E5-8448-8D0E519CD6D6}" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackProgs" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSyncProviderNotifications" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2297E4E2-5DBE-466D-A12B-0F8286F0D9CA}" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E5323777-F976-4f5b-9B55-B94699C46E44}" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2EEF81BE-33FA-4800-9670-1CD474972C3F}" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{52079E78-A92B-413F-B213-E8FE35712E72}" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{7D7E8402-7C54-4821-A34E-AEEFD62DED93}" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{D89823BA-7180-4B81-B50C-7E471E6121A3}" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{8BC668CF-7728-45BD-93F8-CF2B3B41D7AB}" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{9231CB4C-BF57-4AF3-8C55-FDA7BFCC04C5}" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E390DF20-07DF-446D-B962-F5C953062741}" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{992AFA70-6F47-4148-B3E9-3003349C1548}" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\ControlSet001\Services\DiagTrack" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\ControlSet001\Services\dmwappushservice" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\ControlSet001\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\WMDRM" /v "DisableOnline" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{A8804298-2D5F-42E3-9531-9C8C39EB29CE}" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredUI" /v "DisablePasswordReveal" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Main" /v "DoNotTrack" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Main" /v "OptimizeWindowsSearchResultsForScreenReaders" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\FlipAhead" /v "FPEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\User\Default\SearchScopes" /v "ShowSearchSuggestionsGlobal" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Browser" /v "AllowAddressBarDropdown" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Privacy" /v "EnableEncryptedMediaExtensions" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync" /v "SyncPolicy" /t REG_DWORD /d "5" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCloudSearch" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Speech_OneCore\Preferences" /v "ModelDownloadAllowed" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableWindowsLocationProvider" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocationScripting" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "SensorPermissionState" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /v "DODownloadMode" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization" /v "SystemSettingsDownloadMode" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Speech" /v "AllowSpeechModelUpdate" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DeferUpgrade" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DeferUpgradePeriod" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DeferUpdatePeriod" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v "PreventDeviceMetadataFromNetwork" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate" /v "AutoDownload" /t REG_DWORD /d "2" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoUpdate" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\ControlSet001\Services\wuauserv" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Services\7971f918-a847-4430-9279-4a52d1efe18d" /v "RegisteredWithAU" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\OneDrive" /v "PreventNetworkTrafficPreUserSignIn" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SpyNetReporting" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d "2" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d "0" /f
schtasks /end /tn "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator"

schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /disable

schtasks /end /tn "\Microsoft\Windows\Customer Experience Improvement Program\BthSQM"

schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\BthSQM" /disable

schtasks /end /tn "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask"

schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /disable

schtasks /end /tn "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip"

schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /disable

schtasks /end /tn "\Microsoft\Windows\Customer Experience Improvement Program\Uploader"

schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\Uploader" /disable

schtasks /end /tn "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser"

schtasks /change /tn "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /disable

schtasks /end /tn "\Microsoft\Windows\Application Experience\ProgramDataUpdater"

schtasks /change /tn "\Microsoft\Windows\Application Experience\ProgramDataUpdater" /disable

schtasks /end /tn "\Microsoft\Windows\Application Experience\StartupAppTask"

schtasks /change /tn "\Microsoft\Windows\Application Experience\StartupAppTask" /disable"

schtasks /end /tn "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector"

schtasks /change /tn "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /disable

schtasks /end /tn "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver"

schtasks /change /tn "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver" /disable

schtasks /end /tn "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem"

schtasks /change /tn "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /disable

schtasks /end /tn "\Microsoft\Windows\Shell\FamilySafetyMonitor"

schtasks /change /tn "\Microsoft\Windows\Shell\FamilySafetyMonitor" /disable

schtasks /end /tn "\Microsoft\Windows\Shell\FamilySafetyRefresh"

schtasks /change /tn "\Microsoft\Windows\Shell\FamilySafetyRefresh" /disable

schtasks /end /tn "\Microsoft\Windows\Shell\FamilySafetyUpload"

schtasks /change /tn "\Microsoft\Windows\Shell\FamilySafetyUpload" /disable

schtasks /end /tn "\Microsoft\Windows\Autochk\Proxy"

schtasks /change /tn "\Microsoft\Windows\Autochk\Proxy" /disable

schtasks /end /tn "\Microsoft\Windows\Maintenance\WinSAT"

schtasks /change /tn "\Microsoft\Windows\Maintenance\WinSAT" /disable

schtasks /end /tn "\Microsoft\Windows\Application Experience\AitAgent"

schtasks /change /tn "\Microsoft\Windows\Application Experience\AitAgent" /disable

schtasks /end /tn "\Microsoft\Windows\Windows Error Reporting\QueueReporting"

schtasks /change /tn "\Microsoft\Windows\Windows Error Reporting\QueueReporting" /disable

schtasks /end /tn "\Microsoft\Windows\CloudExperienceHost\CreateObjectTask"

schtasks /change /tn "\Microsoft\Windows\CloudExperienceHost\CreateObjectTask" /disable

schtasks /end /tn "\Microsoft\Windows\DiskFootprint\Diagnostics"

schtasks /change /tn "\Microsoft\Windows\DiskFootprint\Diagnostics" /disable

schtasks /end /tn "\Microsoft\Windows\FileHistory\File History (maintenance mode)"

schtasks /change /tn "\Microsoft\Windows\FileHistory\File History (maintenance mode)" /disable

schtasks /end /tn "\Microsoft\Windows\PI\Sqm-Tasks"

schtasks /change /tn "\Microsoft\Windows\PI\Sqm-Tasks" /disable

schtasks /end /tn "\Microsoft\Windows\NetTrace\GatherNetworkInfo"

schtasks /change /tn "\Microsoft\Windows\NetTrace\GatherNetworkInfo" /disable

schtasks /end /tn "\Microsoft\Windows\AppID\SmartScreenSpecific"

schtasks /change /tn "\Microsoft\Windows\AppID\SmartScreenSpecific" /disable

schtasks /Change /TN "Microsoft\Windows\SettingSync\BackgroundUploadTask" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 64" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 64 Critical" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 Critical" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\AppID\SmartScreenSpecific" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\ApplicationData\CleanupTemporaryState" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\ApplicationData\DsSvcCleanup" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Application Experience\AitAgent" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\CloudExperienceHost\CreateObjectTask" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\BthSQM" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\HypervisorFlightingTask" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Diagnosis\Scheduled" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\DiskFootprint\Diagnostics" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\DiskFootprint\StorageSense" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\ErrorDetails\EnableErrorDetailsUpdate" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClient" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\File Classification Infrastructure\Property Definition Sync" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Management\Provisioning\Logon" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Maintenance\WinSAT" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Maps\MapsToastTask" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Maps\MapsUpdateTask" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Mobile Broadband Accounts\MNO Metadata Parser" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Multimedia\SystemSoundsService" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\NlaSvc\WiFiTask" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\NetCfg\BindingWorkItemQueueHandler" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\NetTrace\GatherNetworkInfo" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Offline Files\Background Synchronization" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Offline Files\Logon Synchronization" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\PI\Sqm-Tasks" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Ras\MobilityManager" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\RemoteAssistance\RemoteAssistanceTask" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Servicing\StartComponentCleanup" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\SettingSync\BackupTask" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\SettingSync\NetworkStateChangeTask" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyMonitor" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyRefresh" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\SpacePort\SpaceAgentTask" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\SpacePort\SpaceManagerTask" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Speech\SpeechModelDownloadTask" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\User Profile Service\HiveUploadTask" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\WCM\WiFiTask" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Verification" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Filtering Platform\BfeOnServiceStartTypeChange" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Media Sharing\UpdateLibrary" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Wininet\CacheTask" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Work Folders\Work Folders Logon Synchronization" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Work Folders\Work Folders Maintenance Work" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Workplace Join\Automatic-Device-Join" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\XblGameSave\XblGameSaveTask" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\XblGameSave\XblGameSaveTaskLogon" /Disable > NUL 2>&1
schtasks /Change /TN "Driver Easy Scheduled Scan" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Office\OfficeTelemetryAgentFallBack2016" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Office\OfficeTelemetryAgentLogOn2016" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Office\Office ClickToRun Service Monitor" /Disable > NUL 2>&1

sc stop DiagTrack > NUL 2>&1
sc config DiagTrack start= disabled > NUL 2>&1
sc delete DiagTrack > NUL 2>&1

sc stop dmwappushservice > NUL 2>&1
sc config dmwappushservice start= disabled > NUL 2>&1
sc delete dmwappushservice > NUL 2>&1

set F=%TEMP%\al.reg
set F2=%TEMP%\al2.reg
regedit /e "%F%" "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener" > NUL 2>&1
powershell -Command "Select-String -Pattern "\"Enabled\"", "\[HKEY", "Windows\sRegistry" -Path \"%F%\" | ForEach-Object {$_.Line} | Foreach-Object {$_ -replace '\"Enabled\"=dword:00000001', '\"Enabled\"=dword:00000000'} | Out-File \"%F2%\"" > NUL 2>&1
regedit /s "%F2%" > NUL 2>&1
del "%F%" "%F2%" > NUL 2>&1
del "%ProgramData%\Microsoft\Diagnosis\ETLLogs\AutoLogger\*.etl" "%ProgramData%\Microsoft\Diagnosis\ETLLogs\ShutdownLogger\*.etl" > NUL 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d "0" /f > NUL 2>&1

sc config diagnosticshub.standardcollector.service start= disabled > NUL 2>&1

schtasks /change /TN "Microsoft\Windows\Autochk\Proxy" /DISABLE > NUL 2>&1
schtasks /change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /DISABLE > NUL 2>&1
schtasks /change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /DISABLE > NUL 2>&1
schtasks /change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /DISABLE > NUL 2>&1
schtasks /change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /DISABLE > NUL 2>&1
schtasks /change /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /DISABLE > NUL 2>&1
schtasks /change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /DISABLE > NUL 2>&1
schtasks /change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver" /DISABLE > NUL 2>&1
schtasks /change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /DISABLE > NUL 2>&1
schtasks /change /TN "Microsoft\Windows\Maintenance\WinSAT" /DISABLE > NUL 2>&1
schtasks /change /TN "Microsoft\Windows\NetTrace\GatherNetworkInfo" /DISABLE > NUL 2>&1
schtasks /change /TN "Microsoft\Windows\PI\Sqm-Tasks" /DISABLE > NUL 2>&1

:: editing the registry
reg add "HKCU\Control Panel\Mouse" /v "MouseSpeed" /t REG_SZ /d "0" /f
reg add "HKCU\Control Panel\Mouse" /v "MouseThreshold1" /t REG_SZ /d "0" /f
reg add "HKCU\Control Panel\Mouse" /v "MouseThreshold2" /t REG_SZ /d "0" /f

reg add "HKCU\Control Panel\Keyboard" /v "KeyboardDelay" /t REG_SZ /d "0" /f
reg add "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d "506" /f
reg add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Flags" /t REG_SZ /d "122" /f
reg add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "AutoRepeatDelay" /t REG_SZ /d "0" /f
reg add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "AutoRepeatRate" /t REG_SZ /d "0" /f
reg add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "BounceTime" /t REG_SZ /d "0" /f
reg add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "DelayBeforeAcceptance" /t REG_SZ /d "0" /f
reg add "HKCU\Control Panel\Accessibility\ToggleKeys" /v "Flags" /t REG_SZ /d "58" /f
reg add "HKCU\Control Panel\Mouse" /v "MouseHoverTime" /t REG_SZ /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorSpeed" /v "CursorUpdateInterval" /t REG_DWORD /d "1" /f

reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCall" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary" /v "Value" /t REG_SZ /d "Deny" /f

reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackProgs" /t REG_DWORD /d "0" /f

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338393Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353694Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353696Enabled" /t REG_DWORD /d "0" /f

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CPSS\Store\InkingAndTypingPersonalization" /v "Value" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Input\Settings" /v "InsightsEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\TabletTip\1.7" /v "EnableAutocorrection" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\TabletTip\1.7" /v "EnableSpellchecking" /t REG_DWORD /d "0" /f

reg add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d "0" /f

reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" /v "SafeSearchMode" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" /v "IsMSACloudSearchEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" /v "IsAADCloudSearchEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" /v "IsDeviceSearchHistoryEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" /v "IsDynamicSearchBoxEnabled" /t REG_DWORD /d "0" /f

reg add "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v "fAllowToGetHelp" /t REG_DWORD /d "0" /f

reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v "AutoReboot" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v "CrashDumpEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v "EnableLogFile" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v "LogEvent" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v "Overwrite" /t REG_DWORD /d "0" /f
cls

echo  !B_BLACK!Fast AltTab
reg add "HKCU\System\GameConfigStore" /v "GameDVR_DXGIHonorFSEWindowsCompatible" /t REG_DWORD /d "0" /f
reg add "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehaviorMode" /t REG_DWORD /d "2" /f
reg delete "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehavior" /f
reg add "HKCU\System\GameConfigStore" /v "GameDVR_HonorUserFSEBehaviorMode" /t REG_DWORD /d "0" /f
cls

echo  !B_BLACK!Device Manager
devmanview.exe /disable "PCI Data Acquisition and Signal Processing Controller"
devmanview.exe /disable "PCI Encryption/Decryption Controller"
devmanview.exe /disable "PCI Simple Communications Controller"
devmanview.exe /disable "PCI Memory Controller"
devmanview.exe /disable "PCI standard RAM Controller"
devmanview.exe /disable "AURA LED Controller"
devmanview.exe /disable "Communications Port (COM1)"
devmanview.exe /disable "Intel SMBus"
devmanview.exe /disable "NVIDIA Virtual Audio Device (Wave Extensible) (WDM)"
devmanview.exe /disable "AMD PSP"
devmanview.exe /disable "AMD SMBus"
devmanview.exe /disable "AMD Crash Defender Service"
devmanview.exe /disable "AMD External Events Utility"
devmanview.exe /disable "Micosoft GS Wavetable Synth"
devmanview.exe /disable "Microsoft Hyper-V Virtualization Infrastructure Driver"
devmanview.exe /disable "Microsoft Virtual Drive Enumerator Driver"
devmanview.exe /disable "Enumerator of virtual network adapters NIC"
devmanview.exe /disable "Remote Desktop Device Redirector Bus"
devmanview.exe /disable "Base System Device"
devmanview.exe /disable "Legacy device"
devmanview.exe /disable "Microsoft Kernel Debug Network Adapter"
devmanview.exe /disable "Performance Monitor"
devmanview.exe /disable "SM Bus Controller"
devmanview.exe /disable "System Speaker"
devmanview.exe /disable "Microsoft Radio Device Enumeration Bus"
devmanview.exe /disable "Direct memory access controller"
devmanview.exe /disable "Programmable Interrupt Controller"
devmanview.exe /disable "Microsoft RRAS Root Enumerator"
devmanview.exe /disable "Microsoft Device Association Root Enumerator"
devmanview.exe /disable "Amdlog"
:: devmanview.exe /uninstall "Composite Bus Enumerator"
:: devmanview.exe /uninstall "NDIS Virtual Network Adapter Enumerator"
:: devmanview.exe /uninstall "UMBus Root Bus Enumerator"
:: sc delete CompositeBus
:: sc delete NdisVirtualBus
:: sc delete umbus
cls

echo  !B_BLACK!Shutting Down Unnecessary Services
sc config AxInstSV start= disabled
sc config tzautoupdate start= disabled
sc config bthserv start= disabled
sc config dmwappushservice start= disabled
sc config MapsBroker start= disabled
sc config lfsvc start= disabled
sc config SharedAccess start= disabled
sc config lltdsvc start= disabled
sc config AppVClient start= disabled
sc config NetTcpPortSharing start= disabled
sc config CscService start= disabled
sc config PhoneSvc start= disabled
sc config Spooler start= disabled
sc config PrintNotify start= disabled
sc config QWAVE start= disabled
sc config RmSvc start= disabled
sc config RemoteAccess start= disabled
sc config SensorDataService start= disabled
sc config SensrSvc start= disabled
sc config SensorService start= disabled
sc config ShellHWDetection start= disabled
sc config SCardSvr start= disabled
sc config ScDeviceEnum start= disabled
sc config SSDPSRV start= disabled
sc config WiaRpc start= disabled
sc config TabletInputService start= disabled
sc config upnphost start= disabled
sc config UserDataSvc start= disabled
sc config UevAgentService start= disabled
sc config WalletService start= disabled
sc config FrameServer start= disabled
sc config stisvc start= disabled
sc config wisvc start= disabled
sc config icssvc start= disabled
sc config WSearch start= disabled
sc config XblAuthManager start= disabled
sc config XblGameSave start= disabled
sc config SEMgrSvc start= disabled
sc config DiagTrack start= disabled
sc config MMCSS start= disabled
sc config MMCSS start= auto
sc config SysMain start= disabled
sc config WSearch start= disabled
sc config NetBT start= disabled
sc config wercplsupport start= disabled

echo Making Important Registry Settings
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "3" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "3" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\kdnic" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NdisVirtualBus" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Vid" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" /v "MaintenanceDisabled" /t REG_DWORD /d "1" /f
reg add "HKCU\Control Panel\Accessibility\MouseKeys" /v "Flags" /t REG_SZ /d "0" /f
reg add "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d "0" /f
reg add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Flags" /t REG_SZ /d "0" /f
reg add "HKCU\Control Panel\Accessibility\ToggleKeys" /v "Flags" /t REG_SZ /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "10" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "10" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableVirtualization" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableInstallerDetection" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "PromptOnSecureDesktop" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableSecureUIAPaths" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ValidateAdminCodeSignatures" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableUIADesktopToggle" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorUser" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "FilterAdministratorToken" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /v "AllowInputPersonalization" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d "0" /f
reg add "HKCU\Control Panel\Desktop" /v "CursorBlinkRate" /t REG_SZ /d "-1" /f
reg add "HKLM\SYSTEM\ControlSet001\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "24" /f
reg add "HKLM\SYSTEM\CurrentControlSet\services\NDIS\Parameters" /v "TrackNblOwner" /t REG_DWORD /d "2" /f
reg add "HKCU\SYSTEM\GameConfigStore" /v "GameDVR_DXGIHonorFSEWindowsCompatible" /t REG_DWORD /d "1" /f
reg add "HKCU\SYSTEM\GameConfigStore" /v "GameDVR_FSEBehavior" /t REG_DWORD /d "2" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\Dwm" /v "OverlayTestMode" /t REG_DWORD /d "5" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0000" /v "*RssBaseProcNumber" /t REG_SZ /d "6" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\NetCache" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v "AutoApproveOSDumps" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v "LoggingDisabled" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "DontShowUI" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\Software\Microsoft\Windows\Windows Error Reporting\Consent" /v "DefaultConsent" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\Software\Microsoft\Windows\Windows Error Reporting\Consent" /v "DefaultOverrideBehavior" /t REG_DWORD /d "1" /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD" /v "EnableRspndr" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD" /v "AllowRspndrOnDomain" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD" /v "AllowRspndrOnPublicNet" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD" /v "ProhibitRspndrOnPrivateNet" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\LLTD" /v "EnableRspndr" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\LLTD" /v "AllowRspndrOnDomain" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\LLTD" /v "AllowRspndrOnPublicNet" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\LLTD" /v "ProhibitRspndrOnPrivateNet" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD" /v "EnableLLTDIO" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD" /v "AllowLLTDIOOnDomain" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD" /v "AllowLLTDIOOnPublicNet" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD" /v "ProhibitLLTDIOOnPrivateNet" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\HotspotAuthentication" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\HotspotAuthentication" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableFontProviders" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\System" /v "EnableFontProviders" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\PeerDist\Service" /v "Enable" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\PeerDist\Service" /v "Enable" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\BITS" /v "EnablePeercaching" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Valve\Steam" /v "SmoothScrollWebViews" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Valve\Steam" /v "DWriteEnable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Valve\Steam" /v "StartupMode" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Valve\Steam" /v "H264HWAccel" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Valve\Steam" /v "DPIScaling" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Valve\Steam" /v "GPUAccelWebViews" /t REG_DWORD /d "0" /f >nul

SETLOCAL EnableDelayedExpansion
for /f "tokens=1,2*" %%i in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}" /s /v "*IfType"^| findstr /i "HKEY 0x6"') do if /i "%%i" neq "*IfType" (set REGPATH_ETHERNET=%%i) else (
    reg add "!REGPATH_ETHERNET!" /v "*DeviceSleepOnDisconnect" /t REG_SZ /d "0" /f 
    reg add "!REGPATH_ETHERNET!" /v "*FlowControl" /t REG_SZ /d "0" /f 
    reg add "!REGPATH_ETHERNET!" /v "*InterruptModeration" /t REG_SZ /d "1" /f 
    reg add "!REGPATH_ETHERNET!" /v "*IPChecksumOffloadIPv4" /t REG_SZ /d "3" /f 
    reg add "!REGPATH_ETHERNET!" /v "*JumboPacket" /t REG_SZ /d "1514" /f 
    reg add "!REGPATH_ETHERNET!" /v "*LsoV1IPv4" /t REG_SZ /d "0" /f 
    reg add "!REGPATH_ETHERNET!" /v "*LsoV2IPv4" /t REG_SZ /d "0" /f 
    reg add "!REGPATH_ETHERNET!" /v "*LsoV2IPv6" /t REG_SZ /d "0" /f 
    reg add "!REGPATH_ETHERNET!" /v "*ModernStandbyWoLMagicPacket" /t REG_SZ /d "0" /f 
    reg add "!REGPATH_ETHERNET!" /v "*PriorityVLANTag" /t REG_SZ /d "0" /f 
    reg add "!REGPATH_ETHERNET!" /v "*RSS" /t REG_SZ /d "1" /f 
    reg add "!REGPATH_ETHERNET!" /v "*RssBaseProcNumber" /t REG_SZ /d "1" /f 
    reg add "!REGPATH_ETHERNET!" /v "*RssMaxProcNumber" /t REG_SZ /d "1" /f 
    reg add "!REGPATH_ETHERNET!" /v "*SpeedDuplex" /t REG_SZ /d "0" /f 
    reg add "!REGPATH_ETHERNET!" /v "*TCPChecksumOffloadIPv4" /t REG_SZ /d "3" /f 
    reg add "!REGPATH_ETHERNET!" /v "*TCPChecksumOffloadIPv6" /t REG_SZ /d "3" /f 
    reg add "!REGPATH_ETHERNET!" /v "*UDPChecksumOffloadIPv4" /t REG_SZ /d "3" /f 
    reg add "!REGPATH_ETHERNET!" /v "*UDPChecksumOffloadIPv6" /t REG_SZ /d "3" /f 
    reg add "!REGPATH_ETHERNET!" /v "*WakeOnMagicPacket" /t REG_SZ /d "0" /f 
    reg add "!REGPATH_ETHERNET!" /v "*WakeOnPattern" /t REG_SZ /d "0" /f 
    reg add "!REGPATH_ETHERNET!" /v "ITR" /t REG_SZ /d "65535" /f 
    reg add "!REGPATH_ETHERNET!" /v "TxIntDelay" /t REG_SZ /d "5" /f 

    reg query "!REGPATH_ETHERNET!" /v "ProviderName" | findstr "Intel" 
    if !ERRORLEVEL! equ 0 (
        reg add "!REGPATH_ETHERNET!" /v "AdaptiveIFS" /t REG_SZ /d "0" /f 
        reg add "!REGPATH_ETHERNET!" /v "AutoPowerSaveModeEnabled" /t REG_SZ /d "0" /f 
        reg add "!REGPATH_ETHERNET!" /v "EEELinkAdvertisement" /t REG_SZ /d "0" /f 
        reg add "!REGPATH_ETHERNET!" /v "EnablePME" /t REG_SZ /d "0" /f 
        reg add "!REGPATH_ETHERNET!" /v "EnableTss" /t REG_SZ /d "0" /f 
        reg add "!REGPATH_ETHERNET!" /v "LinkNegotiationProcess" /t REG_SZ /d "1" /f 
        reg add "!REGPATH_ETHERNET!" /v "LogLinkStateEvent" /t REG_SZ /d "16" /f 
        reg add "!REGPATH_ETHERNET!" /v "MasterSlave" /t REG_SZ /d "0" /f 
        reg add "!REGPATH_ETHERNET!" /v "ULPMode" /t REG_SZ /d "0" /f 
        reg add "!REGPATH_ETHERNET!" /v "ReduceSpeedOnPowerDown" /t REG_SZ /d "0" /f 
        reg add "!REGPATH_ETHERNET!" /v "SavePowerNowEnabled" /t REG_SZ /d "0" /f 
        reg add "!REGPATH_ETHERNET!" /v "SipsEnabled" /t REG_SZ /d "0" /f 
        reg add "!REGPATH_ETHERNET!" /v "WaitAutoNegComplete" /t REG_SZ /d "0" /f 
        reg add "!REGPATH_ETHERNET!" /v "WakeOnLink" /t REG_SZ /d "0" /f 
        reg add "!REGPATH_ETHERNET!" /v "WakeOnSlot" /t REG_SZ /d "0" /f 
    )
    reg query "!REGPATH_ETHERNET!" /v "ProviderName" | findstr "Realtek" 
    if !ERRORLEVEL! equ 0 (
        reg add "!REGPATH_ETHERNET!" /v "*EEE" /t REG_SZ /d "0" /f 
        reg add "!REGPATH_ETHERNET!" /v "AdvancedEEE" /t REG_SZ /d "0" /f 
        reg add "!REGPATH_ETHERNET!" /v "AutoDisableGigabit" /t REG_SZ /d "0" /f 
        reg add "!REGPATH_ETHERNET!" /v "EnableGreenEthernet" /t REG_SZ /d "0" /f 
        reg add "!REGPATH_ETHERNET!" /v "GigaLite" /t REG_SZ /d "0" /f 
        reg add "!REGPATH_ETHERNET!" /v "PowerSavingMode" /t REG_SZ /d "0" /f 
        reg add "!REGPATH_ETHERNET!" /v "S5WakeOnLan" /t REG_SZ /d "0" /f 
        reg add "!REGPATH_ETHERNET!" /v "WolShutdownLinkSpeed" /t REG_SZ /d "2" /f 
    )
)
call:POWERSHELL "$NetAdapters = Get-NetAdapterHardwareInfo | Get-NetAdapter | Where-Object {$_.Status -eq 'Up'};foreach ($NetAdapter in $NetAdapters) {$MaxNumRssQueues = [int](($NetAdapter | Get-NetAdapterAdvancedProperty -RegistryKeyword '*NumRssQueues').ValidRegistryValues | Measure-Object -Maximum).Maximum;$NetAdapter | Set-NetAdapterAdvancedProperty -RegistryKeyword '*NumRssQueues' -RegistryValue $MaxNumRssQueues}"
call:POWERSHELL "$NetAdapters = Get-NetAdapterHardwareInfo | Get-NetAdapter | Where-Object {$_.Status -eq 'Up'};foreach ($NetAdapter in $NetAdapters) {$iReceiveBuffers = [int]($NetAdapter | Get-NetAdapterAdvancedProperty -RegistryKeyword '*ReceiveBuffers').NumericParameterMaxValue;$iTransmitBuffers = [int]($NetAdapter | Get-NetAdapterAdvancedProperty -RegistryKeyword '*TransmitBuffers').NumericParameterMaxValue;$NetAdapter | Set-NetAdapterAdvancedProperty -RegistryKeyword '*ReceiveBuffers' -RegistryValue $iReceiveBuffers;$NetAdapter | Set-NetAdapterAdvancedProperty -RegistryKeyword '*TransmitBuffers' -RegistryValue $iTransmitBuffers}"
for /f "tokens=1,2*" %%i in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}" /s /v "*IfType"^| findstr /i "HKEY 0x47"') do if /i "%%i" neq "*IfType" (set REGPATH_WIFI=%%i) else (
    reg add "!REGPATH_WIFI!" /v "*DeviceSleepOnDisconnect" /t REG_SZ /d "0" /f 
    reg add "!REGPATH_WIFI!" /v "*PacketCoalescing" /t REG_SZ /d "0" /f 
    reg add "!REGPATH_WIFI!" /v "*PMARPOffload" /t REG_SZ /d "0" /f 
    reg add "!REGPATH_WIFI!" /v "*PMNSOffload" /t REG_SZ /d "0" /f 
    reg add "!REGPATH_WIFI!" /v "*PMWiFiRekeyOffload" /t REG_SZ /d "0" /f 
    reg add "!REGPATH_WIFI!" /v "*PriorityVLANTag" /t REG_SZ /d "0" /f 
    reg add "!REGPATH_WIFI!" /v "*WakeOnMagicPacket" /t REG_SZ /d "0" /f 
    reg add "!REGPATH_WIFI!" /v "*WakeOnPattern" /t REG_SZ /d "0" /f 
    reg add "!REGPATH_WIFI!" /v "WirelessMode" /t REG_SZ /d "34" /f
    reg add "!REGPATH_WIFI!" /v "ScanWhenAssociated" /t REG_DWORD /d "0" /f 
    reg add "!REGPATH_WIFI!" /v "ScanDisableOnLowTraffic" /t REG_DWORD /d "1" /f
    reg add "!REGPATH_WIFI!" /v "ScanDisableOnMediumTraffic" /t REG_DWORD /d "1" /f 
    reg add "!REGPATH_WIFI!" /v "ScanDisableOnHighOrMulticast" /t REG_DWORD /d "1" /f 
    reg add "!REGPATH_WIFI!" /v "ScanDisableOnLowLatencyOrQos" /t REG_DWORD /d "1" /f 

    reg query "!REGPATH_WIFI!" /v "ProviderName" | findstr "Intel" 
    if !ERRORLEVEL! equ 0 (
        reg add "!REGPATH_WIFI!" /v "BgScanGlobalBlocking" /t REG_SZ /d "2" /f 
        reg add "!REGPATH_WIFI!" /v "CtsToItself" /t REG_SZ /d "1" /f 
        reg add "!REGPATH_WIFI!" /v "FatChannelIntolerant" /t REG_SZ /d "0" /f 
        reg add "!REGPATH_WIFI!" /v "IbssQosEnabled" /t REG_SZ /d "0" /f 
        reg add "!REGPATH_WIFI!" /v "IbssTxPower" /t REG_SZ /d "100" /f 
        reg add "!REGPATH_WIFI!" /v "MIMOPowerSaveMode" /t REG_SZ /d "3" /f 
        reg add "!REGPATH_WIFI!" /v "RoamAggressiveness" /t REG_SZ /d "0" /f
        reg add "!REGPATH_WIFI!" /v "ThroughputBoosterEnabled" /t REG_SZ /d "1" /f 
        reg add "!REGPATH_WIFI!" /v "PropPacketBurstEnabled" /t REG_SZ /d "1" /f 
        reg add "!REGPATH_WIFI!" /v "uAPSDSupport" /t REG_SZ /d "0" /f
    )
    reg query "!REGPATH_WIFI!" /v "ProviderName" | findstr "Realtek"
    if !ERRORLEVEL! equ 0 (
        reg add "!REGPATH_WIFI!" /v "ARPOffloadEnable" /t REG_SZ /d "0" /f 
        reg add "!REGPATH_WIFI!" /v "b40Intolerant" /t REG_SZ /d "0" /f 
        reg add "!REGPATH_WIFI!" /v "bLeisurePs" /t REG_SZ /d "0" /f 
        reg add "!REGPATH_WIFI!" /v "GTKOffloadEnable" /t REG_SZ /d "0" /f 
        reg add "!REGPATH_WIFI!" /v "InactivePs" /t REG_SZ /d "0" /f 
        reg add "!REGPATH_WIFI!" /v "NSOffloadEnable" /t REG_SZ /d "0" /f 
        reg add "!REGPATH_WIFI!" /v "ProtectionMode" /t REG_SZ /d "1" /f 
        reg add "!REGPATH_WIFI!" /v "RegROAMSensitiveLevel" /t REG_SZ /d "127" /f 
        reg add "!REGPATH_WIFI!" /v "RTD3Enable" /t REG_SZ /d "0" /f 
        reg add "!REGPATH_WIFI!" /v "TxPwrLevel" /t REG_SZ /d "0" /f 
        reg add "!REGPATH_WIFI!" /v "WakeOnDisconnect" /t REG_SZ /d "1" /f 
        reg add "!REGPATH_WIFI!" /v "WoWLANLPSLevel" /t REG_SZ /d "0" /f 
        reg add "!REGPATH_WIFI!" /v "WoWLANS5Support" /t REG_SZ /d "0" /f 
    )
)

echo  !B_BLACK!Disabling NetBIOS over TCP/UPD...
    for /f "delims=" %%u in ('reg query "HKLM\System\CurrentControlSet\Services\NetBT\Parameters\Interfaces" /s /f "NetbiosOptions" ^| findstr "HKEY"') do (
        Reg.exe add "%%u" /v "NetbiosOptions" /t REG_DWORD /d "2" /f
    )
)

echo  !B_BLACK!Clean Regedit / DirectX Shader Cache
reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Font Drivers" /v "Adobe Type Manager" /f >nul
reg delete "HKLM\System\ControlSet001\Control\Terminal Server\Wds" /v "StartupPrograms" /f >nul
DISM /Online /Remove-Capability /CapabilityName:MathRecognizer0.0.1.0 /norestart /quiet >nul
DISM /Online /Remove-Capability /CapabilityName:Microsoft.Windows.PowerShell.ISE0.0.1.0 /norestart /quiet >nul
cleanmgr /sageset:0

echo  !B_BLACK!Rebooting...
shutdown /r -t 5 >NUL 2>&1

:colors
set "CMDLINE=S_GRAY=[90m,S_GREEN=[92m,S_YELLOW=[93m,S_WHITE=[97m,B_BLACK=[40m,UNDERLINE=[4m,_UNDERLINE=[24m"
set "%CMDLINE:,=" & set "%"