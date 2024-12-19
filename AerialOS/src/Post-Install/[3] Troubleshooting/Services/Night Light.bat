@echo off
mode con: cols=80 lines=15

echo.
echo Disabled? = Not working Night Light
choice /C ED /N /M "Press key to toggle the Night Light (E - Enable , D - Disable): "

if errorlevel 2 goto :Disable
if errorlevel 1 goto :Enable

:Enable
echo.
echo Night Light is enabling...
reg add "HKLM\SYSTEM\CurrentControlSet\Services\CDPUserSvc" /v "Start" /t REG_DWORD /d "2" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\CDPSvc" /v "Start" /t REG_DWORD /d "2" /f >nul
exit

:Disable
echo.
echo Night Light is disabling...
reg add "HKLM\SYSTEM\CurrentControlSet\Services\CDPUserSvc" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\CDPSvc" /v "Start" /t REG_DWORD /d "4" /f >nul

exit