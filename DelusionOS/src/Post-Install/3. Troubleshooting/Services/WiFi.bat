@echo off
mode con: cols=80 lines=15

echo.
choice /C ED /N /M "Press key to toggle the WiFi (E - Enable , D - Disable): "

if errorlevel 2 goto :Disable
if errorlevel 1 goto :Enable

:Enable
echo.
echo WiFi is enabling...
:: Enabling WiFi Driver
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\vwififlt" /v "Start" /t REG_DWORD /d "1" /f >nul 2>&1

:: Enabling WiFi service
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WlanSvc" /v "Start" /t REG_DWORD /d "2" /f >nul 2>&1
exit

:Disable
echo.
echo WiFi is disabling...
:: Disabling WiFi Driver
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\vwififlt" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1

:: Disabling WiFi Service
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WlanSvc" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
exit