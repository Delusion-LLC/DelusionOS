@echo off
mode con: cols=80 lines=15

echo.
echo Disabled? = Not working Printer
choice /C ED /N /M "Press key to toggle the Printer (E - Enable , D - Disable): "

if errorlevel 2 goto :Disable
if errorlevel 1 goto :Enable

:Enable
echo.
echo Printer is enabling...
:: Enabling Printer Services
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Spooler" /v "Start" /t REG_DWORD /d "2" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\PrintNotify" /v "Start" /t REG_DWORD /d "3" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\PrintWorkflowUserSvc" /v "Start" /t REG_DWORD /d "3" /f >nul 2>&1

:: Turning on Printer devices
DevManView.exe /enable "Microsoft Print to PDF" >nul 2>&1
DevManView.exe /enable "Root Print Queue" >nul 2>&1
DevManView.exe /enable "Microsoft XPS Document Writer" >nul 2>&1
exit

:Disable
echo.
echo Printer is disabling...
:: Disabling Printer Services
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Spooler" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\PrintNotify" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\PrintWorkflowUserSvc" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1

:: Disabling Printer devices
DevManView.exe /disable "Microsoft Print to PDF" >nul 2>&1
DevManView.exe /disable "Root Print Queue" >nul 2>&1
DevManView.exe /disable "Microsoft XPS Document Writer" >nul 2>&1
exit