@echo off
mode con: cols=80 lines=15

echo.
echo Disabled? = Not working GTA 5
choice /C ED /N /M "Press key to toggle the GTA5 (E - Enable , D - Disable): "

if errorlevel 2 goto :Disable
if errorlevel 1 goto :Enable

:Enable
echo.
echo SMBIOS is enabling...
:: Enabling SMBIOS driver
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\mssmbios" /v "Start" /t REG_DWORD /d "1" /f >nul 2>&1

:: Enabling SMBIOS device
DevManView.exe /enable "Microsoft System Management BIOS Driver" >nul 2>&1\
exit

:Disable
echo.
echo SMBIOS is disabling...
:: Disabling the SMBIOS driver
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\mssmbios" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1

:: Disabling the SMBIOS device
DevManView.exe /disable "Microsoft System Management BIOS Driver" >nul 2>&1
exit