@echo off
mode con: cols=80 lines=15

echo.
choice /C ED /N /M "Press key to toggle the FACEIT AC (E - Enable , D - Disable): "

if errorlevel 2 goto :Disable
if errorlevel 1 goto :Enable

:Enable
echo.
echo FACEIT AC is enabling...
:: Включение DEP
bcdedit /deletevalue nx >nul 2>&1
bcdedit /set hypervisorlaunchtype auto >nul 2>&1

:: Enabling Vulnerable Driver Blocklist
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\CI\Config" /v "VulnerableDriverBlocklistEnable" /t REG_DWORD /d "1" /f >nul 2>&1
exit

:Disable
echo.
echo FACEIT AC is disabling...
:: Disabling DEP
bcdedit /set nx AlwaysOff >nul 2>&1
bcdedit /set hypervisorlaunchtype Off >nul 2>&1

:: Disabling Vulnerable Driver Blocklist
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\CI\Config" /v "VulnerableDriverBlocklistEnable" /t REG_DWORD /d "0" /f >nul 2>&1

exit