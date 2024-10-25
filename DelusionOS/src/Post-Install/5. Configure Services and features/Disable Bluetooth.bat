@echo off

DevManView.exe /disable "Microsoft Radio Device Enumeration Bus"

Reg.exe delete "HKLM\SOFTWARE\Classes\*\shellex\ContextMenuHandlers\ModernSharing" /f

Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetoothSync" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\cellularData" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetoothSync" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\cellularData" /v "Value" /t REG_SZ /d "Deny" /f

for %%s in ("BTAGService", "BTHMODEM", "BTHPORT", "BTHUSB", "BluetoothUserService", "BthA2dp", "BthAvctpSvc", "BthEnum", "BthHFEnum", "BthLEEnum", "BthMini", "BthPan", "HidBth", "Microsoft_Bluetooth_AvrcpTransport", "NcbService", "RFCOMM", "bthserv") do (
    reg query "HKLM\SYSTEM\CurrentControlSet\Services\%%~s" /v "Start" | findstr "Start" >nul
    if !errorlevel! equ 0 (
        reg add "HKLM\SYSTEM\CurrentControlSet\Services\%%~s" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
    )
)