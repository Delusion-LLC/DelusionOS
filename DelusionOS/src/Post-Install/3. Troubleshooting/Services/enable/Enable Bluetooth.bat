@echo off

DevManView.exe /enable "Microsoft Radio Device Enumeration Bus"

Reg.exe add "HKLM\SOFTWARE\Classes\*\shellex\ContextMenuHandlers\ModernSharing" /ve /t REG_SZ /d "{e2bf9676-5f8f-435c-97eb-11607a5bedf7}" /f

Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetoothSync" /v "Value" /t REG_SZ /d "Allow" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\cellularData" /v "Value" /t REG_SZ /d "Allow" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetoothSync" /v "Value" /t REG_SZ /d "Allow" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\cellularData" /v "Value" /t REG_SZ /d "Allow" /f

for %%s in ("BTAGService", "BTHMODEM", "BTHPORT", "BTHUSB", "BluetoothUserService", "BthA2dp", "BthAvctpSvc", "BthEnum", "BthHFEnum", "BthLEEnum", "BthMini", "BthPan", "HidBth", "Microsoft_Bluetooth_AvrcpTransport", "NcbService", "RFCOMM", "bthserv") do (
    reg query "HKLM\SYSTEM\CurrentControlSet\Services\%%~s" /v "Start" | findstr "Start" >nul
    if !errorlevel! equ 0 (
        reg add "HKLM\SYSTEM\CurrentControlSet\Services\%%~s" /v "Start" /t REG_DWORD /d "3" /f >nul 2>&1
    )
)