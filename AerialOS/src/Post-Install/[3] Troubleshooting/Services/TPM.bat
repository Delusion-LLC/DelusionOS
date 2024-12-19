@echo off
mode con: cols=80 lines=15

echo.
echo Disabled? = Not working Anti'cheats Games (CS2, VAL)
choice /C ED /N /M "Press key to toggle the TPM (E - Enable , D - Disable): "

if errorlevel 2 goto :Disable
if errorlevel 1 goto :Enable

:Enable
echo.
echo TPM is enabling...
:: Enabling the TPM driver
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\tpm" /v "Start" /t REG_DWORD /d "3" /f >nul 2>&1

:: Enabling TPM devices
DevManView.exe /enable "AMD PSP 3.0 Device" >nul 2>&1
DevManView.exe /enable "AMD PSP 10.0 Device" >nul 2>&1
DevManView.exe /enable "Trusted Platform Module 2.0" >nul 2>&1
exit

:Disable
echo.
echo TPM is disabling...
:: Disabling the TPM driver
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\tpm" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1

:: Disabling TPM devices
DevManView.exe /disable "AMD PSP 3.0 Device" >nul 2>&1
DevManView.exe /disable "AMD PSP 10.0 Device" >nul 2>&1
DevManView.exe /disable "Trusted Platform Module 2.0" >nul 2>&1
exit