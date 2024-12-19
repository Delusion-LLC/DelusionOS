@echo off
mode con: cols=80 lines=15

echo.
echo Disabled? = (disables internet icon and HWiNFO WHEA sensor)
choice /C ED /N /M "Press key to toggle the Bluetooth (E - Enable , D - Disable): "

if errorlevel 2 goto :Disable
if errorlevel 1 goto :Enable

:Enable
echo.
echo Bluetooth is enabling...
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\EventLog" /v "Start" /t REG_DWORD /d "2" /f >nul
exit

:Disable
echo.
echo Bluetooth is disabling...
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\EventLog" /v "Start" /t REG_DWORD /d "4" /f >nul
exit