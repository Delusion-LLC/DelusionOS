@echo off
title DraganOS W11 23H2 Post Setup
SETLOCAL EnableDelayedExpansion

Echo Setting "Execution Policy To Unrestricted"
powershell set-executionpolicy unrestricted -force >nul
cls

:: Hello,
:: If somehow this script popped in front of you, you are obviously a curious fellow.
:: The setup script you see is the "sweet spot" settings that I have been tweaking for 3 years, through thousands of trials and errors.
:: Feel free to take a look at it to educate yourself, and if you want to pull anything from it, please contact me or the people I give credit to. If you copy the whole script and put your own name to it, I will consider it as plagiarism and expose you as soon as I discover it.
:: I may have missed some lines while quoting, I gave credit to the ones I remembered where I got them from.
:: Before I start, I would like to thank the following peoplers who helped me develop this project.
:: Sharing your experiences and results github, twitter, discord
:: couwthynokap
:: clqwnless
:: imribiy
:: HickerDicker
:: djdallmann
:: CatGamerOP
:: AMITXV

:: Disabling task manager to prevent random access
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\taskmgr.exe" /v "Debugger" /t REG_SZ /d "." /f >nul
cls

call :draganLogo
echo Welcome to DraganOS 11 23H2
echo Don't touch anything, system will reboot itself after a while. DraganOS is a not free operating system, ask for refund if you paid for it. Discord: e1uen_
timeout /t 20 /nobreak > NUL
cls

call :draganLogo
echo Configuration for start...
slmgr /ipk W269N-WFGWX-YVC9B-4J6C9-T83GX
slmgr /skms kms8.msguides.com
slmgr /ato
powershell -ExecutionPolicy Bypass -File "C:\Windows\modules\appx.ps1"
powershell -ExecutionPolicy Bypass -File "C:\Windows\modules\powersaving.ps1"
net accounts /maxpwage:unlimited >nul
call "C:\Windows\APIs\packages-dragan\runtimebroker_mgmt.bat" >nul
call "C:\Windows\APIs\packages-dragan\smartscreen_mgmt.bat" >nul
call "C:\Windows\APIs\packages-dragan\ctfmon_mgmt.bat" >nul
Reg.exe add "HKCU\Control Panel\Desktop" /v "Wallpaper" /t REG_SZ /d "C:\Windows\System32\dragan.png" /f >nul
timeout /t 1 /nobreak > NUL
cls

:: --- PACKAGES DRAGANOS ---

call :draganLogo
echo Installing Packages DraganOS...
start /b /wait "" "C:\Windows\APIs\packages-dragan\VisualC\install_all.bat" >nul
cls

call :draganLogo
echo Installing DirectX...
timeout /t 2 >nul
curl -g -k -L -# -o "C:\dxwebsetup.exe" "https://download.microsoft.com/download/1/7/1/1718CCC4-6315-4D8E-9543-8E28A4E18C4C/dxwebsetup.exe"
start /wait C:\dxwebsetup.exe /Q
del /F /Q C:\dxwebsetup.exe
cls

:: --- SCHEDULED TASKS ---

call :draganLogo
echo Configuring Scheduled Tasks...
powershell DISM /Online /Set-ReservedStorageState /State:Disabled
powershell disable-netadapterbinding -Name "*" -componentid "vmware_brige, ms_lldp, ms_lltdio, ms_implat, ms_tcpip6, ms_rspndr, ms_server, ms_msclient"
powershell Remove-AutologgerConfig -Name "autologger-diagtrack-listener", "cellcore", "cloudexperiencehostoobe", "lwtnetlog", "melanos-Kernel", "microsoft-windows-assignedacces-trace", "microsoft-windows-rdp-graphics-rdpidd-trace", "microsoft-windows-setup", "netcore", "ntfslog", "peauthlog", "radiomgr", "readyboot", "refslog", "setupplatform", "setupplatformtel", "spoolerlogger", "tcpiplogger", "wifisession", "wifidriverhvsessionrepro", "wifidriverihvsession", "wfp-ipsec-trace", "ubpm", "tilestore"
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\SharedAcces\Parameters\FirewallPolicy\FirewallRules" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAcces\Parameters\FirewallPolicy\FirewallRules" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Tpm" /v "Start" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WinPhoneCritical" /v "Start" /t REG_DWORD /d "0" /f >nul

schtasks /Change /TN "Microsoft\Office\OfficeTelemetryAgentLogOn" /Disable
schtasks /Change /TN "Microsoft\Office\OfficeTelemetryAgentFallBack" /Disable
schtasks /Change /TN "Microsoft\Office\Office 15 Subscription Heartbeat" /Disable
schtasks /Change /TN "\Microsoft\Office\OfficeTelemetryAgentLogOn" /Disable
schtasks /Change /TN "\Microsoft\Office\OfficeTelemetryAgentFallBack" /Disable
schtasks /Change /TN "\Microsoft\Office\Office 15 Subscription Heartbeat" /Disable
Reg.exe add "HKCU\Software\Microsoft\Office\Common\ClientTelemetry" /v "DisableTelemetry" /t REG_DWORD /d "1" /f

for %%x in ("Application Experience\Microsoft Compatibility Appraiser" "Application Experience\ProgramDataUpdater"
    "Application Experience\StartupAppTask" "Customer Experience Improvement Program\Consolidator"
	"Customer Experience Improvement Program\KernelCeipTask" "Customer Experience Improvement Program\UsbCeip"
    "Customer Experience Improvement Program\Uploader" "Autochk\Proxy" "CloudExperienceHost\CreateObjectTask"
    "DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" "DiskFootprint\Diagnostics"
    "UpdateOrchestrator\Schedule Scan" "WindowsUpdate\Scheduled Start" "Servicing\StartComponentCleanup" 
    "Recovery Environment\VerifyWinRE" "EDP\StorageCardEncryption Task" "BitLocker\BitLocker Encrypt All Drives" 
    "BitLocker\BitLocker MDM policy Refresh" "ApplicationData\DsSvcCleanup" "International\Synchronize Language Settings") do schtasks /change /tn "\Microsoft\Windows\%%~i" /disable
for %%p in ("InstallService\ScanForUpdates" "InstallService\ScanForUpdatesAsUser" "InstallService\SmartRetry" "\Microsoft\Windows\Defrag\ScheduledDefrag") do schtasks /change /tn "\Microsoft\Windows\%%~p" /disable

schtasks /delete /tn "\Microsoft\Windows\Application Experience\AitAgent" /f
powershell -Command "Disable-ScheduledTask -TaskPath '\\Microsoft\\Windows\\AppxDeploymentClient' -TaskName 'UCPD velocity'"
cls

:: --- SERVICES ---

call :draganLogo
echo Configuring Services...
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Perflib" /v "Disable Perfomance Counters" /t REG_DWORD /d "1" /f >nul
PowerRun.exe /SW:0 Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dhcp" /v "DependOnService" /t REG_MULTI_SZ /d "NSI\0Afd" /f >nul
PowerRun.exe /SW:0 Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache" /v "DependOnService" /t REG_MULTI_SZ /d "nsi" /f >nul
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\ssh-agent" /f >nul
Reg.exe add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\InstallAgent.exe" /v "Debugger" /d "/" /f >nul
Reg.exe add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MusNotification.exe" /v "Debugger" /d "/" /f >nul
Reg.exe add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MusNotificationUx.exe" /v "Debugger" /d "/" /f >nul
Reg.exe add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\remsh.exe" /v "Debugger" /d "/" /f >nul
Reg.exe add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SihClient.exe" /v "Debugger" /d "/" /f >nul
Reg.exe add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\UpdateAssistant.exe" /v "Debugger" /d "/" /f >nul
Reg.exe add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\upfc.exe" /v "Debugger" /d "/" /f >nul
Reg.exe add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\UsoClient.exe" /v "Debugger" /d "/" /f >nul
Reg.exe add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\WaaSMedic.exe" /v "Debugger" /d "/" /f >nul
Reg.exe add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\WaasMedicAgent.exe" /v "Debugger" /d "/" /f >nul
Reg.exe add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoWindowsUpdate" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate" /v "OSUpgrade" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate" /v "ReservationsAllowed" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKEY_LOCAL_MACHINE\Software\Microsoft\WindowsUpdate\UX\Settings" /v "TrayIconVisibility" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v "DisableWindowsUpdateAccess" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoUpdate" /t REG_DWORD /d "1" /f >nul

setlocal
set "classes=HKLM\SYSTEM\CurrentControlSet\Control\Class"
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Dhcp" /v "DependOnService" /t REG_MULTI_SZ /d "NSI\0Afd" /f
Reg.exe add "HKLM\System\CurrentControlSet\Services\Dnscache" /v "DependOnService" /t REG_MULTI_SZ /d "nsi" /f >nul
Reg.exe add "HKLM\System\CurrentControlSet\Services\rdyboost" /v "DependOnService" /t REG_MULTI_SZ /d "" /f >nul

for %%y in (
    {ca3e7ab9-b4c3-4ae6-8251-579ef933890f}
    {4d36e967-e325-11ce-bfc1-08002be10318}
    {4d36e96c-e325-11ce-bfc1-08002be10318}
    {71a27cdd-812a-11d0-bec7-08002be2092f}
    {6bdd1fc6-810f-11d0-bec7-08002be2092f} ) do (
    Reg.exe add "%classes%\%%y" /v "LowerFilters" /t REG_MULTI_SZ /d "" /f
    Reg.exe add "%classes%\%%y" /v "UpperFilters" /t REG_MULTI_SZ /d "" /f
)
endlocal

@rem WSAIFabricSvc for 24H2 service for soon

for %%n in (
    wercplsupport
    MsSecCore
    MsSecFlt
    MsSecWfp
    SecurityHealthService
    WdBoot
    WdFilter
    WdNisDrv
    WdNisSvc
    afunix
    CldFlt
    ALG
    AJRouter
    ConsentUxUserSvc
    NetBIOS
    NetBT
    amdgpio2
    DevQueryBroker
    GPIOClx0101
    Appinfo
    StiSvc
    RDPDR
    Themes
    W32Time
    HvHost
    vmicguestinterface
    vmicheartbeat
    vmickvpexchange
    vmicdrv
    vmicshutdown
    vmictimesync
    vmicvmsession
    vmicvss
    bttflt
    sedsvc
    HvHost
    wudfsvc
    vmicguestinterface
    vmicheartbeat
    vmickvpexchange
    vmicdrv
    vmicshutdown
    vmictimesync
    vmicvmsession
    vmicvss
    bttflt
    gencounter
    hvservice
    hyperkbd
    WindowsTrustedRT
    WindowsTrustedRTProxy
    Wof
    HyperVideo
    storflt
    vmbus
    vmgid
    vpci
    SessionEnv
    hvservice
    hyperkbd
    HyperVideo
    storflt
    Vid
    vmbus
    vmgid
    vpci
    SessionEnv
    RdpVideoMiniport
    sppsvc
    terminpt
    TsUsbFlt
    TsUsbGD
    tsusbhub
    TermService
    UmRdpService
    rdpbus
    embeddedmode
    WinDefend
    wscsvc
    MDCoreSvc
    SgrmAgent
    SgrmBroker
    FontCache
    FontCache3.0.0.0
    DPS
    WbioSrvc
    SysMain
    wlidsvc
    cnghwassitst
    cdfs
    cdrom
    Telemetry
    WdiServiceHost
    WdiSystemHost
    SENS
    SensrSvc
    Sense
    SSDPSRV
    webthreatdefsvc
    webthreatusersvc
    NdisVirtualBus
    SensorDataService
    SensorService
    scardsvr
    scdeviceenum
    scpolicysvc
    diagsvc
    diagnosticshub.standardcollector.service
    dmwappushservice
    DiagTrack
    AppReadiness
    bam
    dam
    rdyboost
    NetTcpPortSharing
    SEMgrSvc
    UCPD
    installservice
    RasMan
    autotimesvc
    BDESVC
    gencounter
    DusmSvc
    DsSvc
    RmSvc
    Dnscache
    BFE
    EFS
    mpssvc
    mpsdrv
    DispBrokerDesktopSvc
    Eaphost
    EntAppSvc
    WebClient
    shpamsvc
    Beep
    luafv
    appvclient
    GoogleChromeElevationService
    edgeupdate
    edgeupdatem
    gupdate
    gupdatem
    lfsvc
    SDRSVC
    MixedRealityOpenXRSvc
    MapsBroker
    Ndu
    P9RdrService
    ShellHWDetection
    PenService
    GraphicsPerfSvc
    GpuEnergyDrv
    NcbService
    OneSyncSvc
    PcaSvc
    printworkflowusersvc
    UevAgentService
    UevAgentDriver
    PrintNotify
    PhoneSvc
    RetailDemo
    VSS
    TroubleshootingSvc
    SharedRealitySvc
    spooler
    smphost
    TrkWks
    LxpSvc
    tzautoupdate
    WerSvc
    WSearch
    wuauserv
    wisvc
    wscsvc
    Vid
    RemoteAccess
    RemoteRegistry
    p2pimsvc
    p2psvc
    AxInstSV
    TapiSrv
    WpnService
    cbdhsvc
    WpnUserService
    PolicyAgent
    CSC
    CscService
    WEPHOSTSVC
    spectrum
    perceptionsimulation
    QWAVE
    QWAVEdrv
    BITS
    tabletinputservice
    DmEnrollmentSvc
    Wecsvc
    UsoSvc
    EventLog
    iphlpsvc
    IKEEXT
    WmanSvc
    AppXSvc
    PushToInstall
    ClipSVC
    StorSvc
    XblAuthManager
    GameInputSvc
    XblGameSave
    xboxgip
    XboxGipSvc
    XboxNetApiSvc
    xinputhid
    dosvc
    wmiApSrv
    OneSyncSvc
    SstpSvc
    acpiex
    acpipagr
    acpipmi
    acpitime
) do ( PowerRun.exe /SW:0 Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\%%n" /v "Start" /t REG_DWORD /d "4" /f )
cls

for %%c in (
    AppIDSvc
    BDESVC
    DiagTrack
    PimIndexMaintenanceSvc
    DoSvc
    MapsBroker
    PhoneSvc
    SCardSvr
    ScDeviceEnum
    SCPolicySvc
    SysMain
    TapiSrv
    WalletService
    WinDefend
    XblAuthManager
    XblGameSave
    xboxgip
    XboxGipSvc
    XboxNetApiSvc
    Sense
    SENS
    SensorDataService
    SensorService
    SensrSvc
    TabletInputService
    InstallService
    CDPSvc
    CDPUserSvc
    DeviceAssociationService
    DevicesFlowUserSvc
    WaaSMedicSvc
    VSS
    SDRSVC
    UsoSvc
    PeerDistSvc
    WdNisSvc
    wisvc
    WpnService
    WpnUserService
    icssvc
    Fax
    wcncsvc
    OneSyncSvc
    fhsvc
    lfsvc
    RemoteRegistry
    RetailDemo
    WerSvc
    stisvc
    BthAvctpSvc
    AxInstSV
    BcardDVRUserService
    ALG
    AssignedAccessManagerSvc
    tzautoupdate
    AJRouter
    BITS
    wbengine
    CaptureService
    CertPropSvc
    EventSystem
    COMSysApp
    ConsentUxUserSvc
    VaultSvc
    DsSvc
    DusmSvc
    dmwappushservice
    DevQueryBroker
    diagsvc
    DPS
    WdiServiceHost
    WdiSystemHost
    SENS
    DsmSvc
    SgrmBroker
    SecurityHealthService
    TrkWks
    MSDTC
    embeddedmode
    fdPHost
    BcastDVRUserService
    GraphicsPerfSvc
    hidserv
    IKEEXT
    lltdsvc
    diagnosticshub.standardcollector.service
    MSiSCSI
    smphost
    NaturalAuthentication
    Netlogon
    NcdAutoSetup
    NcbService
    NcaSvc
    CscService
    ssh-agent
    defragsvc
    SEMgrSvc
    wercplsupport
    pcasvc
    QWAVE
    shpamsvc
    ShellHWDetection
    SNMPTRAP
    SharedRealitySvc
    SSDPSRV
    TieringEngineService
    upnphost
    UserDataSvc
    UnistoreSvc
    UevAgentService
    VacSvc
    WarpJITSvc
    WebClient
    WEPHOSTSVC
    FontCache
    WMPNetworkSvc
    spectrum
    perceptionsimulation
    PushToInstall
    RasAuto
    RasMan
    SessionEnv
    TermService
    UmRdpService
    RpcLocator
    RemoteAccess
    WinRM
    AppID
    applockerfltr
    AppVClient
    bindflt
    bowser
    cbdhsvc
    CSC
    fvevol
    gencounter
    HdAudAddService
    lltdio
    luafv
    NdisCap
    NdisImPlatform
    NetTcpPortSharing
    PerfHost
    pla
    QWAVEdrv
    RasAgileVpn
    rdbss
    rdpbus
    RdpVideoMiniport
    rdyboost
    scfilter
    SgrmAgent
    WdBoot
    WdFilter
    WdNisDrv
) do ( PowerRun.exe /SW:0 Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\%%c" /f )
cls

:: --- TWEAKS REGEDIT/GPEDIT ---

echo Configuring tweaks regedit...
NetSh Advfirewall set allprofiles state off
Reg.exe add "HKLM\SOFTWARE\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f > nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableRoutinelyTakingAction" /t REG_DWORD /d "1" /f > nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "ServiceKeepAlive" /t REG_DWORD /d "0" /f > nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d "1" /f > nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d "1" /f > nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableOnAccessProtection" /t REG_DWORD /d "1" /f > nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d "1" /f > nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /t REG_DWORD /d "1" /f > nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v "DontReportInfectionInformation" /t REG_DWORD /d "0" /f > nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "LocalSettingOverrideSpynetReporting" /t REG_DWORD /d "0" /f > nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SpynetReporting" /t REG_DWORD /d "0" /f > nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d "2" /f > nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Threats" /v "Threats_ThreatSeverityDefaultAction" /t REG_DWORD /d "1" /f > nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction" /v "1" /t REG_SZ /d "6" /f > nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction" /v "2" /t REG_SZ /d "6" /f > nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction" /v "4" /t REG_SZ /d "6" /f > nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction" /v "5" /t REG_SZ /d "6" /f > nul
Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoToastApplicationNotification" /t REG_DWORD /d "1" /f > nul
Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoToastApplicationNotificationOnLockScreen" /t REG_DWORD /d "1" /f > nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\UX Configuration" /v "Notification_Suppress" /t REG_DWORD /d "0" /f > nul
Reg.exe delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f > nul 2>&1
Reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\UpdateHealthTools" /f >NUL 2>nul
Reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\rempl" /f >NUL 2>nul
Reg.exe delete "HKLM\SOFTWARE\Microsoft\CloudManagedUpdate" /f >NUL 2>nul
Reg.exe delete "HKLM\SOFTWARE\Classes\*\shellex\ContextMenuHandlers\EPP" /f >nul
Reg.exe delete "HKLM\SOFTWARE\Classes\ID\{09A47860-11B0-4DA5-AFA5-26D86198A780}" /f >nul
Reg.exe delete "HKLM\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers\EPP" /f >nul
Reg.exe delete "HKLM\SOFTWARE\Classes\Drive\shellex\ContextMenuHandlers\EPP" /f >nul
Reg.exe delete "HKLM\SOFTWARE\Classes\*\shellex\ContextMenuHandlers\Sharing" /f >nul
Reg.exe delete "HKLM\SOFTWARE\Classes\Directory\Background\shellex\ContextMenuHandlers\Sharing" /f >nul
Reg.exe delete "HKLM\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers\Sharing" /f >nul
Reg.exe delete "HKLM\SOFTWARE\Classes\Drive\shellex\ContextMenuHandlers\Sharing" /f >nul
Reg.exe delete "HKLM\SOFTWARE\Classes\LibraryFolder\background\shellex\ContextMenuHandlers\Sharing" /f >nul
Reg.exe delete "HKLM\SOFTWARE\Classes\UserLibraryFolder\shellex\ContextMenuHandlers\Sharing" /f >nul
Reg.exe delete "HKCU\CompressedFolder\ShellEx\ContextMenuHandlers\{b8cdcb65-b1bf-4b42-9428-1dfdb7ee92af}" /f >nul
Reg.exe delete "HKCU\SystemFileAssociations\.zip\ShellEx\ContextMenuHandlers\{b8cdcb65-b1bf-4b42-9428-1dfdb7ee92af}" /f >nul
Reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" /f >nul
Reg.exe delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" /f >nul
Reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows\Coplilot" /f >nul
Reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentControlSet\Fends" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v "AllowGameDVR" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\GameBar" /v "AllowAutoGameMode" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\GameBar" /v "AutoGameModeEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\GameBar" /v "GamePanelStartupTipIndex" /t REG_DWORD /d "3" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\GameBar" /v "ShowStartupPanel" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\GameBar" /v "UseNexusForGameBarEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_DSEBehavior" /t REG_DWORD /d "2" /f >nul
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_DXGIHonorFSEWindowsCompatible" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_EFSEFeatureFlags" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehavior" /t REG_DWORD /d "2" /f >nul
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehaviorMode" /t REG_DWORD /d "2" /f >nul
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_HonorUserFSEBehaviorMode" /t REG_DWORD /d "1" /f >nul
Reg.exe delete "HKCU\System\GameConfigStore" /v "Win32_AutoGameModeDefaultProfile" /f >nul
Reg.exe delete "HKCU\System\GameConfigStore" /v "Win32_GameModeRelatedProcesses" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoDriveTypeAutoRun" /t REG_DWORD /d "ff" /f >nul
Reg.exe add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoDriveTypeAutoRun" /t REG_DWORD /d "ff" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Biometrics" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\CI\Policy" /v "VerifiedAndReputablePolicyState" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\Software\Microsoft\Windows Defender" /v "PUAProtection" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\CI\Config" /v "VulnerableDriverBlocklistEnable" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Policies\Microsoft\Windows\WindowsAI" /f >nul
Reg.exe add "HKCU\Software\Policies\Microsoft\Windows\WindowsAI" /v "DisableAIDataAnalysis" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\Software\Policies\Microsoft\Windows\Windows AI" /v "TurnOffSavingSnapshots" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Tracing" /v "EnableConsoleTracing" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\DmaGuard\DeviceEnumerationPolicy" /v "value" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\System\CurrentControlSet\Services\pci\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\pci\Parameters" /v "DmaRemappingOnHiberPath" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\System\CurrentControlSet\Services\storahci\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\storahci\Parameters" /v "DmaRemappingOnHiberPath" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\System\CurrentControlSet\Services\stornvme\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters" /v "DmaRemappingOnHiberPath" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\System\CurrentControlSet\Services\USBXHCI\Parameters" /v "DmaRemappingCompatibleSelfhost" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\System\CurrentControlSet\Services\USBXHCI\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Control Panel\Desktop" /v "FontSmoothing" /t REG_SZ /d "2" /f >nul
Reg.exe add "HKCU\Control Panel\Desktop" /v "DragFullWindows" /t REG_SZ /d "0" /f >nul
Reg.exe add "HKCU\Control Panel\Desktop\WindowMetrics" /v "MinAnimate" /t REG_SZ /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v "VisualFXSetting" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\DWM" /v "EnableAeroPeek" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\DWM" /v "AlwaysHibernateThumbnails" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Control Panel\Desktop" /v "UserPreferencesMask" /t REG_BINARY /d "9012038010000000" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewShadow" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewAlphaSelect" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v "VisualFXSetting" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAnimations" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\DWM" /v "Blur" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\DWM" /v "TelemetryFramesSequenceMaximumPeriodMilliseconds" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\DWM" /v "TelemetryFramesSequenceIdleIntervalMilliseconds" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\DWM" /v "TelemetryFramesReportPeriodMilliseconds" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\DWM" /v "Animations" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\DWM" /v "BackdropBlurCachingThrottleMs" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DWM" /v "DWMA_TRANSITTIONS_FORCEDISABLED" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DWM" /v "DisallowAnimations" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "UseOLEDTaskbarTransparency" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Control Panel\Desktop\WindowMetrics" /v "MinAnimate" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "IconsOnly" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "SystemUsesLightTheme" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "AppsUseLightTheme" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows\Win32kWPP\Parameters" /v "LogPages" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\Software\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows\Win32kWPP\Parameters" /v "LogPages" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows\Win32knsWPP\Parameters" /v "LogPages" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\Software\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows\Win32knsWPP\Parameters" /v "LogPages" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\System\CurrentControlSet\Services\USBHUB3\Parameters" /v "LogPages" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\System\CurrentControlSet\Services\USBHUB3\Parameters\Wdf" /v "LogPages" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule" /v "DisableRpcOverTcp" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "RestrictAnonymousSAM" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "RestrictAnonymous" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control" /v "DisableRemoteScmEndpoints" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "fDisableCdm" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "fAllowToGetHelp" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v "TSEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" /v "DisableNotifications" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" /v "EnableFirewall" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" /v "DisableNotifications" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" /v "EnableFirewall" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Dsh" /v "AllowNewsAndInterests" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowTaskViewButton" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarDa" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "PlatformSupportMiracast" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "ForceDirectFlip" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "TdrLevel" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "TdrDelay" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "TdrDdiDelay" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "TdrDebugMode" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "TdrLimitTime" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "TdrLimitCount" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "DisableBadDriverCheckForHwProtection" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\System\CurrentControlSet\Control\GraphicsDrivers" /v "IOMMUFlags" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing" /v "EnableLog" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing" /v "EnableDpxLog" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Ole" /v "EnableDCOM" /t REG_SZ /d "N" /f >nul
Reg.exe add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Ole" /v "EnableDCOM" /t REG_SZ /d "N" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing" /v "EnableLog" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing" /v "EnableDpxLog" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Component Based Servicing" /v "EnableLog" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Component Based Servicing" /v "EnableDpxLog" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "10" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NoLazyMode" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "10" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SchedulerTimerResolution" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMax" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "Attributes" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb" /v "Attributes" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\5d76a2ca-e8c0-402f-a133-2158492d58ad" /v "Attributes" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\a55612aa-f624-42c6-a443-7397d064c04f" /v "Attributes" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\ea062031-0e34-4ff1-9b6d-eb1059334028" /v "Attributes" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "PowerOffFrozenProcessors" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "EnableWerUserReporting" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationAuditOptions" /t REG_BINARY /d "222222222222222222222222222222222222222222222222" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationOptions" /t REG_BINARY /d "222222222222222222222222222222222222222222222222" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "SleepStudyDisabled" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "IdleScanInterval" /t REG_DWORD /d "12c" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MSDisabled" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "PerfCalculateActualUtilization" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DisableVsyncLatencyUpdate" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "EnergyEstimationEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "FxAccountingTelemetryDisabled" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "CoalescingFlushInterval" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WTDS\Components" /v "ServiceEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Wow6432Node\Microsoft\VSCommon\15.0\SQM" /v "OptIn" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" /v "DisableAutoplay" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "NoAutoplayfornonVolume" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\EventHandlersDefaultSelection\CameraAlternate\ShowPicturesOnArrival" /v /t REG_SZ /d "MSTakeNoAction" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\EventHandlersDefaultSelection\StorageOnArrival" /v /t REG_SZ /d "MSTakeNoAction" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\UserChosenExecuteHandlers\CameraAlternate\ShowPicturesOnArrival" /v /t REG_SZ /d "MSTakeNoAction" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\UserChosenExecuteHandlers\StorageOnArrival" /v /t REG_SZ /d "MSTakeNoAction" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "AllowOnlineTips" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\input\Settings" /v "InsightsEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Narrator\NoRoam" /v "DuckAudio" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Narrator\NoRoam" /v "WinEnterLaunchEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Narrator\NoRoam" /v "ScriptingEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Narrator\NoRoam" /v "OnlineServicesEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Narrator" /v "NarratorCursorHighlight" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Narrator" /v "CoupleNarratorCursorKeyboard" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" /v "{e2bf9676-5f8f-435c-97eb-11607a5bedf7}" /t REG_SZ /d "" /f >nul
Reg.exe add "HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" /v "{e2bf9676-5f8f-435c-97eb-11607a5bedf7}" /t REG_SZ /d "" /f >nul
Reg.exe add "HKLM\SOFTWARE\Classes\ID\{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}\ShellFolder" /v "Attributes" /t REG_DWORD /d "2962489444" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsRunInBackground" /t REG_DWORD /d "2" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "BackgroundAppGlobalToggle" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoNetConnectDisconnect" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoNetConnectDisconnect" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" /v "{e2bf9676-5f8f-435c-97eb-11607a5bedf7}" /t REG_SZ /d "" /f >nul
Reg.exe add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" /v "{e2bf9676-5f8f-435c-97eb-11607a5bedf7}" /t REG_SZ /d "" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" /v "{1d27f844-3a1f-4410-85ac-14651078412d}" /t REG_SZ /d "" /f >nul
Reg.exe add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" /v "{1d27f844-3a1f-4410-85ac-14651078412d}" /t REG_SZ /d "" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v "AutoReboot" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v "CrashDumpEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v "LogEvent" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v "DisplayParameters" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\CabinetState" /v "FullPath" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "MultipleInvokePromptMinimum" /t REG_DWORD /d "100" /f >nul
Reg.exe add "HKCU\Control Panel\Sound" /v "Beep" /t REG_SZ /d "no" /f >nul
Reg.exe add "HKCU\Control Panel\Desktop" /v "JPEGImportQuality" /t REG_DWORD /d "64" /f >nul
Reg.exe add "HKCU\Software\Classes\ID\{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DisallowShaking" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSyncProviderNotifications" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAppsVisibleInTabletMode" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LaunchTo" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "ClearRecentDocsOnExit" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "DisableGraphRecentItems" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoLowDiskSpaceChecks" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInstrumentation" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseHoverTime" /t REG_SZ /d "30" /f >nul
Reg.exe add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "0" /f >nul
Reg.exe add "HKCU\Control Panel\Desktop" /v "ActiveWndTrkTimeout" /t REG_DWORD /d "10" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "LinkResolveIgnoreLinkInfo" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveSearch" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveTrack" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f >nul
Reg.exe add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "1200" /f >nul
Reg.exe add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "1200" /f >nul
Reg.exe add "HKCU\Control Panel\Desktop" /v "LowLevelHooksTimeout" /t REG_SZ /d "1200" /f >nul
Reg.exe add "HKU\.DEFAULT\Control Panel\Desktop" /v "LowLevelHooksTimeout" /t REG_SZ /d "1200" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "1200" /f >nul
Reg.exe add "HKCU\Software\Policies\Microsoft\Windows\Explorer" /v "DisableSearchBoxSuggestions" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" /v "EnableFeeds" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Dsh" /v "AllowNewsAndInterests" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "SmartScreenEnabled" /t REG_SZ /d "Off" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "HubMode" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Associations" /v "DefaultFileTypeRisk" /t REG_DWORD /d "1808" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "SaveZoneInformation" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Associations" /v "ModRiskFileTypes" /t REG_SZ /d ".bat;.exe;.reg;.vbs;.chm;.msi;.js;.cmd" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "ScanWithAntiVirus" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags\AllFolders\Shell" /v "FolderType" /t REG_SZ /d "NotSpecified" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "DisableGraphRecentItems" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{2cc5ca98-6485-489a-920e-b3e88a6ccce3}" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\Control Panel\Keyboard" /v "InitialKeyboardIndicators" /t REG_SZ /d "0" /f >nul
Reg.exe add "HKCU\Control Panel\Keyboard" /v "KeyboardDelay" /t REG_SZ /d "0" /f >nul
Reg.exe add "HKCU\Control Panel\Keyboard" /v "KeyboardSpeed" /t REG_SZ /d "31" /f >nul
Reg.exe add "HKCU\Software\Microsoft\TabletTip\1.7" /v "EnableAutocorrection" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\TabletTip\1.7" /v "EnableAutoShiftEngage" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\TabletTip\1.7" /v "EnableKeyAudioFeedback" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\TabletTip\1.7" /v "EnableShiftLock" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseSpeed" /t REG_SZ /d "0" /f >nul
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseThreshold1" /t REG_SZ /d "0" /f >nul
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseThreshold2" /t REG_SZ /d "0" /f >nul
Reg.exe add "HKCU\Control Panel\Accessibility\MouseKeys" /v "MaximumSpeed" /t REG_SZ /d "-" /f >nul
Reg.exe add "HKCU\Control Panel\Accessibility\MouseKeys" /v "TimeToMaximumSpeed" /t REG_SZ /d "-" /f >nul
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\System" /v "HiberbootEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" /v "ShowHibernateOption" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" /v "ShowSleepOption" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HibernateEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableSoftLanding" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v "ConfigureWindowsSpotlight" /t REG_DWORD /d "2" /f >nul
Reg.exe add "HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v "IncludeEnterpriseSpotlight" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableThirdPartySuggestions" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableTailoredExperiencesWithDiagnosticData" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsSpotlightFeatures" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsSpotlightOnActionCenter" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsSpotlightOnSettings" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "AutoApproveOSDumps" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "LoggingDisabled" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableCloudOptimizedContent" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Consent" /v "DefaultConsent" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Consent" /v "DefaultOverrideBehavior" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "DontShowUI" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\DeviceHealthAttestationService" /v "EnableDeviceHealthAttestationService" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}" /v "ScenarioExecutionEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\AdvertisingInfo" /v "DisabledByGroupPolicy" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "AllowOnlineTips" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" /v "EnableConfigFlighting" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowBuildPreview" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Speech_OneCore\Preferences" /v "ModelDownloadAllowed" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "ContentDeliveryAllowed" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContentEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "ContentDeliveryManagement" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Tips" /v "DisableWindowsTips" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCloudSearch" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortanaAboveLock" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortanaInAAD" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortanaInAADPathOOBE" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWebOverMeteredConnections" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchSafeSearch" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchPrivacy" /t REG_DWORD /d "3" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "CortanaConsent" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Speech_OneCore\Preferences" /v "ModelDownloadAllowed" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Speech_OneCore\Preferences" /v "VoiceActivationEnableAboveLockscreen" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\Software\Microsoft\Windows Search\Gather\Windows\SystemIndex" /v "RespectPowerModes" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "PreventIndexOnBattery" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Search\Preferences" /v "WholeFileSystem" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Search\Preferences" /v "SystemFolders" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettings" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d "33554435" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d "3" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePagingExecutive" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePageCombining" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Family options" /v "UILockdown" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Device performance and health" /v "UILockdown" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Account protection" /v "UILockdown" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" /v "DisableGenericRePorts" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Update" /v "SignatureDisableNotification" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates" /v "RealtimeSignatureDelivery" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates" /v "ForceUpdateFromMU" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Update" /v "DisableScheduledSignatureUpdateOnBattery" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Update" /v "UpdateOnStartUp" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Update" /v "DisableUpdateOnStartupWithoutEngine" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Update" /v "DisableScanOnUpdate" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\SmartScreen" /v "ConfigureAppInstallControlEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\SmartScreen" /v "ConfigureAppInstallControl" /t REG_SZ /d "Anywhere" /f >nul
Reg.exe add "HKLM\Software\Policies\Microsoft\System" /v "EnableSmartScreen" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "3" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "3" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray" /v "HideSystray" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications" /v "DisableEnhancedNotifications" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v "RequirePlatformSecurityFeatures" /t REG_SZ /d "-" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v "HypervisorEnforcedCodeIntegrity" /t REG_SZ /d "-" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v "HVCIMATRequired" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v "LsaCfgFlags" /t REG_SZ /d "-" /f >nul
Reg.exe add "HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\DeviceGuard" /v "RequirePlatformSecurityFeatures" /t REG_SZ /d "-" /f >nul
Reg.exe add "HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\DeviceGuard" /v "HypervisorEnforcedCodeIntegrity" /t REG_SZ /d "-" /f >nul
Reg.exe add "HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\DeviceGuard" /v "HVCIMATRequired" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\DeviceGuard" /v "LsaCfgFlags" /t REG_SZ /d "-" /f >nul
Reg.exe add "HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\DeviceGuard" /v "ConfigureSystemGuardLaunch" /t REG_SZ /d "-" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSetControl\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSetControl\DeviceGuard" /v "Locked" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSetControl\DeviceGuard" /v "RequirePlatformSecurityFeatures" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\Policies\Microsoft\Windows\DeviceGuard" /v "HVCIMATRequired" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v "HVCIMATRequired" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v "Locked" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "HideSCAHealth" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\BitLocker" /v "PreventDeviceEncryption" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "HideRecentlyAddedApps" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "HideSCAMeetNow" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "HideSCAMeetNow" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoRecentDocsHistory" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoStartMenuMFUprogramsList" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_IrisRecommendations" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_AccountNotifications" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "HidePeopleBar" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAl" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarMn" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowTaskViewButton" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Policies\Microsoft\Windows\Explorer" /v "NoAutoTrayNotify" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoSetTaskbar" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Policies\Microsoft\Windows\Explorer" /v "DisableSearchBoxSuggestions" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackDocs" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Classes\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackDocs" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoCloudApplicationNotification" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338388Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Classes\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Classes\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338388Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackProgs" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SearchSettings" /v "IsDeviceSearchHistoryEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoCloudApplicationNotification" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" /v "EnableFeeds" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications" /v "DatabaseMigrationCompleted" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications" /v "ToastEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarDeveloperSettings" /v "TaskbarEndTask" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DeferFeatureUpdates" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DeferFeatureUpdatesPeriodInDays" /t REG_DWORD /d "365" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAUAsDefaultShutdownOption" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "HideMCTLink" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "RestartNotificationsAllowed2" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "SetAutoRestartNotificationDisable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "SetUpdateNotificationLevel" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "UpdateNotificationLevel" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /v "DODownloadMode" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DisableWUfBSafeguards" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\Setup\UpgradeNotification" /v "UpgradeAvailable" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "RSoPLogging" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Task Scheduler\Maintenance" /v "WakeUp" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Update" /v "ExcludeWUDriversInQualityUpdate" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Update" /v "ExcludeWUDriversInQualityUpdate" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "ExcludeWUDriversInQualityUpdate" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "ExcludeWUDriversInQualityUpdate" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Update\ExcludeWUDriversInQualityUpdate" /v "value" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v "PreventDeviceMetadataFromNetwork" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" /v "SearchOrderConfig" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" /v "DontSearchWindowsUpdate" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" /v "DriverUpdateWizardWuSearchEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsStore" /v "AutoDownload" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Policies\Microsoft\WindowsStore" /v "DisableOSUpgrade" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsStore" /v "DisableOSUpgrade" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoUpdate" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" /v "EnableConfigFlighting" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "ManagePreviewBuilds" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "ManagePreviewBuildsPolicyValue" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuild" /v "AllowBuildPrevie" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuild" /v "EnableConfigFlighting" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuild" /v "EnableExperimentation" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Visibilit" /v "HideInsiderPage" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\Software\Classes\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-310093Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsStore" /v "DisableOSUpgrade" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DisableWUfBSafeguards" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsStore" /v "AutoDownload" /t REG_DWORD /d "2" /f >nul
Reg.exe add "HKCU\Control Panel\Accessibility\AudioDescription" /v "Flags" /t REG_SZ /d "0" /f >nul
Reg.exe add "HKCU\Control Panel\Accessibility\Blind Access" /v "Flags" /t REG_SZ /d "0" /f >nul
Reg.exe add "HKCU\Control Panel\Accessibility\HighContrast" /v "Flags" /t REG_SZ /d "0" /f >nul
Reg.exe add "HKCU\Control Panel\Accessibility\Keyboard Preference" /v Flags /t REG_SZ /d "0" /f >nul
Reg.exe add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Flags" /t REG_SZ /d "0" /f >nul
Reg.exe add "HKCU\Control Panel\Accessibility\MouseKeys" /v "Flags" /t REG_SZ /d "0" /f >nul
Reg.exe add "HKCU\Control Panel\Accessibility\On" /v "Flags" /t REG_SZ /d "0" /f >nul
Reg.exe add "HKCU\Control Panel\Accessibility\ShowSounds" /v "Flags" /t REG_SZ /d "0" /f >nul
Reg.exe add "HKCU\Control Panel\Accessibility\SlateLaunch" /v "ATapp" /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\Control Panel\Accessibility\SlateLaunch" /v "Flags" /t REG_SZ /d "0" /f >nul
Reg.exe add "HKCU\Control Panel\Accessibility\SlateLaunch" /v "LaunchAT" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Control Panel\Accessibility\SoundSentry" /v "Flags" /t REG_SZ /d "0" /f >nul
Reg.exe add "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d "0" /f >nul
Reg.exe add "HKCU\Control Panel\Accessibility\TimeOut" /v "Flags" /t REG_SZ /d "0" /f >nul
Reg.exe add "HKCU\Control Panel\Accessibility\ToggleKeys" /v "Flags" /t REG_SZ /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Ease of Access" /v "selfscan" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Ease of Access" /v "selfvoice" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Control Panel\Accessibility" /v "Warning Sounds" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Control Panel\Accessibility" /v "Sound on Activation" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Control Panel\Accessibility\SoundSentry" /v "WindowsEffect" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v "DisableWpbtExecution" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl\StorageTelemetry" /v "DeviceDumpEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableSuperfetch" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "SfTracingState" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableBootTrace" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Superfetch/Main" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Superfetch/PfApLog" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Superfetch/StoreLog" /v "Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt" /v "GroupPolicyDisallowCaches" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt" /v "AllowNewCachesByDefault" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "PromptOnSecureDesktop" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableInstallerDetection" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableSecureUIAPaths" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /v "Manufacturer" /t REG_SZ /d "DraganOS 11" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /v "Model" /t REG_SZ /d "DraganOS 23H2" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /v "SupportURL" /t REG_SZ /d "https://dsc.gg/draganos/" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /v "SupportPhone" /t REG_SZ /d "https://dsc.gg/draganos/" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\ScheduledDiagnostics" /v "EnabledExecution" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d "4294967295" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control" /v "DisableRemoteScmEndpoints" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "36" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "ConvertibleSlateMode" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\NDIS\Parameters" /v "DefaultPnPCapabilities" /t REG_DWORD /d "18" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\NDIS\Parameters" /v "DisableNDISWatchDog" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\NDIS\Parameters" /v "DisableNaps" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\NDIS\Parameters" /v "DisableWDIWatchdogForceBugcheck" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\NDIS\Parameters" /v "DisableReenumerationTimeoutBugcheck" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\NDIS\Parameters" /v "EnableNicAutoPowerSaverInSleepStudy" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\System\CurrentControlSet\Services\Tcpip\QoS" /v "Do not use NLA" /t REG_SZ /d "1" /f >nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched" /v "NonBestEffortLimit" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353694Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353696Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338393Enabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "ContentDeliveryAllowed" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContentEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEverEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "OemPreInstalledAppsEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "FeatureManagementEnabled" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\TabletTip\1.7" /v "EnableSpellchecking" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\TabletTip\1.7" /v "EnableTextPrediction" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\TabletTip\1.7" /v "EnablePredictionSpaceInsertion" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\TabletTip\1.7" /v "EnableDoubleTapSpace" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" /v "StartupDelayInMSec" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v "EnableDwmInputProcessing" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v "DwmInputUsesIoCompletionPort" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Multimedia\Audio" /v "UserDuckingPreference" /t REG_DWORD /d "3" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Multimedia\Audio\DeviceCpl" /v "ShowHiddenDevices" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Multimedia\Audio\DeviceCpl" /v "ShowDisconnectedDevices" /t REG_DWORD /d "1" /f >nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Multimedia\Audio\DeviceCpl" /v "VolumeUnits" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" /v "value" /t REG_DWORD /d "0" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes" /v /t REG_SZ /d ".None" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\.Default\.Current" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\.Default\.None" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\AppGPFault\.Current" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\AppGPFault\.None" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\CCSelect\.Current" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\CCSelect\.None" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\ChangeTheme\.Current" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\ChangeTheme\.None" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\Close\.Current" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\Close\.None" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\CriticalBatteryAlarm\.Current" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\CriticalBatteryAlarm\.None" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\DeviceConnect\.Current" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\DeviceConnect\.None" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\DeviceDisconnect\.Current" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\DeviceDisconnect\.None" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\DeviceFail\.Current" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\DeviceFail\.None" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\FaxBeep\.Current" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\FaxBeep\.None" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\LowBatteryAlarm\.Current" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\LowBatteryAlarm\.None" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\MailBeep\.Current" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\MailBeep\.None" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\Maximize\.Current" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\Maximize\.None" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\MenuCommand\.Current" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\MenuCommand\.None" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\MenuPopup\.Current" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\MenuPopup\.None" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\MessageNudge\.Current" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\MessageNudge\.None" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\Minimize\.Current" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\Minimize\.None" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\Notification.Default\.Current" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\Notification.Default\.None" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\Notification.IM\.Current" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\Notification.IM\.None" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\Notification.Mail\.Current" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\Notification.Mail\.None" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\Notification.Proximity\.Current" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\Notification.Proximity\.None" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\Notification.Reminder\.Current" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\Notification.Reminder\.None" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\Notification.SMS\.Current" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\Notification.SMS\.None" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\Open\.Current" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\Open\.None" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\PrintComplete\.Current" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\PrintComplete\.None" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\ProximityConnection\.Current" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\ProximityConnection\.None" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\RestoreDown\.Current" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\RestoreDown\.None" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\RestoreUp\.Current" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\RestoreUp\.None" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\ShowBand\.Current" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\ShowBand\.None" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\SystemAsterisk\.Current" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\SystemAsterisk\.None" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\SystemExclamation\.Current" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\SystemExclamation\.None" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\SystemHand\.Current" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\SystemHand\.None" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\SystemNotification\.Current" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\SystemNotification\.None" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\SystemQuestion\.Current" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\SystemQuestion\.None" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\WindowsUAC\.Current" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\WindowsUAC\.None" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\Explorer\ActivatingDocument\.Current" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\Explorer\ActivatingDocument\.None" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\Explorer\BlockedPopup\.current" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\Explorer\BlockedPopup\.None" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\Explorer\EmptyRecycleBin\.Current" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\Explorer\EmptyRecycleBin\.None" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\Explorer\FeedDiscovered\.current" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\Explorer\FeedDiscovered\.None" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\Explorer\MoveMenuItem\.Current" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\Explorer\MoveMenuItem\.None" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\Explorer\Navigating\.Current" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\Explorer\Navigating\.None" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\Explorer\SecurityBand\.current" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\Explorer\SecurityBand\.None" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\sapisvr\DisNumbersSound\.current" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\sapisvr\DisNumbersSound\.None" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\sapisvr\HubOffSound\.current" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\sapisvr\HubOffSound\.None" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\sapisvr\HubOnSound\.current" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\sapisvr\HubOnSound\.None" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\sapisvr\HubSleepSound\.current" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\sapisvr\HubSleepSound\.None" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\sapisvr\MisrecoSound\.current" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\sapisvr\MisrecoSound\.None" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\sapisvr\PanelSound\.current" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Apps\sapisvr\PanelSound\.None" /v /t REG_SZ /d "" /f >nul
Reg.exe add "HKCU\AppEvents\Schemes\Names\.None" /v /t REG_SZ /d "No Sounds" /f >nul
Reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\BootAnimation" /v "DisableStartupSound" /t REG_DWORD /d "1" /f >nul
cls

Echo Fix Start menu on first reboot
cmd /c "start C:\Windows\explorer.exe"
taskkill /f /im explorer.exe >nul
taskkill /f /im explorer.exe >nul
cmd /c "start C:\Windows\explorer.exe"
cls

Echo fixing languages if needed
REG ADD "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v "DoNotConnectToWindowsUpdateInternetLocations" /t REG_DWORD /d "0" /f >nul
REG ADD "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "UseWUServer" /t REG_DWORD /d "0" /f >nul
cls

if "%DEVICE_TYPE%" == "LAPTOP" (
    Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\serenum" /v "Start" /t REG_DWORD /d "3" /f >nul
    Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\sermouse" /v "Start" /t REG_DWORD /d "3" /f >nul
    Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\serial" /v "Start" /t REG_DWORD /d "3" /f >nul
    Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wmiacpi" /v "Start" /t REG_DWORD /d "2" /f >nul
    Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "0" /f
    cls
)
) else (
    Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DisplayEnhancementService" /v "Start" /t REG_DWORD /d "4" /f >nul
    Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f >nul
    Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wmiacpi" /v "Start" /t REG_DWORD /d "4" /f >nul
    cls
)

fsutil behavior set disable8dot3 1
fsutil behavior set disablelastaccess 1
fsutil behavior set disabledeletenotify 0
fsutil behavior set encryptpagingfile 0
fsutil behavior set mftzone 2
fsutil behavior set disablecompression 1
fsutil behavior set memoryusage 2
DISM /Online /Remove-Capability /CapabilityName:Browser.InternetExplorer~~0.0.11.0 /norestart /quiet
DISM /Online /Remove-Capability /CapabilityName:MathRecognizer0.0.1.0 /norestart /quiet
DISM /Online /Remove-Capability /CapabilityName:Microsoft.Windows.PowerShell.ISE0.0.1.0 /norestart /quiet
cls

echo Configuring boot windows...
bcdedit /set noumex Yes
bcdedit /set bootems No
bcdedit /set ems No
bcdedit /set bootlog No
bcdedit /set hypervisorlaunchtype No
bcdedit /set isolatedcontext No
bcdedit /set vsmlaunchtype Off
bcdedit /set vm No
bcdedit /set testsigning No
bcdedit /set allowedinmemorysettings 0
bcdedit /set perfmem 0
bcdedit /set configflags 0
bcdedit /set quietboot Yes
bcdedit /set integrityservices disable
bcdedit /set nx optin
bcdedit /set pae ForceDisable
bcdedit /set x2apicpolicy Enable
bcdedit /set bootux Disabled
bcdedit /set tpmbootentropy ForceDisable
bcdedit /set halbreakpoint No
bcdedit /set bootmenupolicy legacy
bcdedit /set tscsyncpolicy Enhanced
bcdedit /set uselegacyapicmode No
bcdedit /set configaccesspolicy Default
bcdedit /set usephysicaldestination No
bcdedit /set usefirmwarepcisettings No 
label C: DraganOS W11 23H2
bcdedit /set {current} description "DraganOS 23H2"
cls

echo Importing Power Plan...
powercfg -import "%windir%\dragan.pow" 00000000-16f6-45a6-9fcf-0fa130b83c00
powercfg -setactive 00000000-16f6-45a6-9fcf-0fa130b83c00
powercfg -delete 381b4222-f694-41f0-9685-ff5bb260df2e
powercfg -delete 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
powercfg -delete a1841308-3541-4fab-bc81-f71556f20b4a
for %l in ("SleepStudy" "Kernel-Processor-Power" "UserModePowerService") do (wevtutil sl Microsoft-Windows-%~a/Diagnostic /e:false)
cls

echo Configuration Device manager...
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
devmanview.exe /uninstall "Composite Bus Enumerator"
devmanview.exe /uninstall "NDIS Virtual Network Adapter Enumerator"
devmanview.exe /uninstall "UMBus Root Bus Enumerator"
sc delete CompositeBus
sc delete NdisVirtualBus
sc delete umbus

setx DOTNET_CLI_TELEMETRY_OPTOUT 1
setx POWERSHELL_TELEMETRY_OPTOUT 1
for %%k in (
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
	fid_D1Latency
	fid_D2Latency
	fid_D3Latency
) do for /f "delims=" %%b in ('reg query "HKLM\SYSTEM\CurrentControlSet\Enum" /s /f "%%w" ^| findstr "HKEY"') do PowerRun.exe /SW:0 "reg.exe" add "%%b" /v "%%w" /t REG_DWORD /d "0" /f >nul
PowerShell -NonInteractive -NoLogo -NoProfile -Command "Disable-MMAgent -mc | Disable-WindowsErrorReporting | Disable-MMAgent -PageCombining | Disable-MMAgent -ApplicationPreLaunch"
Powershell "Get-WmiObject MSPower_DeviceEnable -Namespace root\wmi | ForEach-Object { $_.enable = $false; $_.psbase.put(); }"
cls

echo "Configuration Latency Tolerance"
@rem Creator couwthynokap
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "MonitorLatencyTolerance" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "MonitorRefreshLatencyTolerance" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "ExitLatency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "ExitLatencyCheckEnabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "Latency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceDefault" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceFSVP" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyTolerancePerfOverride" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceScreenOffIR" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceVSyncEnabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "RtlCapabilityCheckLatency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyActivelyUsed" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleLongTime" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleMonitorOff" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleNoContext" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleShortTime" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleVeryLongTime" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceIdle0" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceIdle0MonitorOff" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceIdle1" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceIdle1MonitorOff" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceMemory" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceNoContext" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceNoContextMonitorOff" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceOther" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceTimerPeriod" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultMemoryRefreshLatencyToleranceActivelyUsed" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultMemoryRefreshLatencyToleranceMonitorOff" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultMemoryRefreshLatencyToleranceNoContext" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "Latency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "MaxIAverageGraphicsLatencyInOneBucket" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "MiracastPerfTrackGraphicsLatency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "MonitorLatencyTolerance" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "MonitorRefreshLatencyTolerance" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "TransitionLatency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "D3PCLatency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "F1TransitionLatency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "LOWLATENCY" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "Node3DLowLatency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PciLatencyTimerControl" /t REG_DWORD /d "20" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMDeepL1EntryLatencyUsec" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RmGspcMaxFtuS" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RmGspcMinFtuS" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RmGspcPerioduS" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMLpwrEiIdleThresholdUs" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMLpwrGrIdleThresholdUs" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMLpwrGrRgIdleThresholdUs" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMLpwrMsIdleThresholdUs" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "VRDirectFlipDPCDelayUs" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "VRDirectFlipTimingMarginUs" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "VRDirectJITFlipMsHybridFlipDelayUs" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "vrrCursorMarginUs" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "vrrDeflickerMarginUs" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "vrrDeflickerMaxUs" /t REG_DWORD /d "1" /f
cls

echo "Configuration Internet Tweaks"
@rem Creator couwthynokap
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
netsh int tcp set heuristics disabled >nul
netsh interface tcp set heuristics disabled >nul
netsh interface tcp set heuristics forcews=disabled >nul
netsh int tcp set heuristics wsh=disabled >nul
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
cls

echo Storage Tweaks...
	:: Disable HIPM and DIPM, HDD Parking
	FOR /F "eol=E" %%a in ('REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services" /S /F "EnableHIPM"^| FINDSTR /V "EnableHIPM"') DO (
		Reg.exe add "%%a" /F /V "EnableHIPM" /T REG_DWORD /d 0 /f
		Reg.exe add "%%a" /F /V "EnableDIPM" /T REG_DWORD /d 0 /f
		Reg.exe add "%%a" /F /V "EnableHDDParking" /T REG_DWORD /d 0 /f

		FOR /F "tokens=*" %%z IN ("%%a") DO (
			SET STR=%%z
			SET STR=!STR:HKLM\SYSTEM\CurrentControlSet\Services\=!
		)
	)
	:: Disable StorPort idle
	for /f "tokens=*" %%s in ('reg query "HKLM\System\CurrentControlSet\Enum" /S /F "StorPort" ^| findstr /e "StorPort"') do Reg.exe add "%%s" /v "EnableIdlePowerManagement" /t REG_DWORD /d "0" /f
cls

echo Disabling NetBIOS over TCP/UPD...
    for /f "delims=" %%u in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces" /s /f "NetbiosOptions" ^| findstr "HKEY"') do (
        Reg.exe add "%%u" /v "NetbiosOptions" /t REG_DWORD /d "2" /f
    )
cls

Echo "Disabling Exclusive Mode On Audio Devices"
for /f "delims=" %%e in ('reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Capture') do Reg.exe add "%%e\Properties" /v "{b3f8fa53-0004-438e-9003-51a46e139bfc},3" /t REG_DWORD /d "0" /f >nul
for /f "delims=" %%e in ('reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Capture') do Reg.exe add "%%e\Properties" /v "{b3f8fa53-0004-438e-9003-51a46e139bfc},4" /t REG_DWORD /d "0" /f >nul
for /f "delims=" %%e in ('reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Render') do Reg.exe add "%%e\Properties" /v "{b3f8fa53-0004-438e-9003-51a46e139bfc},3" /t REG_DWORD /d "0" /f >nul
for /f "delims=" %%e in ('reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Render') do Reg.exe add "%%e\Properties" /v "{b3f8fa53-0004-438e-9003-51a46e139bfc},4" /t REG_DWORD /d "0" /f >nul
cls

reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\taskmgr.exe" /v "Debugger" /f >nul

shutdown -r -t 10
msg * your pc will restart in 10 seconds from now you can run shutdown -a to cancel it if you have to install any drivers or want to set up your pc BUT DO NOT FORGET TO RESTART

Echo "Cleanup"

del /q /f /s %WINDIR%\TEMP\* >nul
del /q /f /s %WINDIR%\Prefetch* >nul
del /q /f /s %TEMP%\* >nul
del /q /f /s %WINDIR%\SystemTemp* >nul
del /q /f /s %WINDIR%\APIs\packages-dragan\* >nul
start /b "" cmd /c del "%~f0"&exit /b

Exit

:draganLogo

cls
echo.
echo ░▒▓███████▓▒░ ░▒▓███████▓▒░  ░▒▓██████▓▒░  ░▒▓██████▓▒░  ░▒▓██████▓▒░ ░▒▓███████▓▒░  ░▒▓██████▓▒░  ░▒▓███████▓▒░
echo ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░
echo ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░       ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░
echo ░▒▓█▓▒░░▒▓█▓▒░░▒▓███████▓▒░ ░▒▓████████▓▒░░▒▓█▓▒▒▓███▓▒░░▒▓████████▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ ░▒▓██████▓▒░
echo ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░       ░▒▓█▓▒░
echo ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░       ░▒▓█▓▒░
echo ░▒▓███████▓▒░ ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ ░▒▓██████▓▒░ ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ ░▒▓██████▓▒░ ░▒▓███████▓▒░
echo.
