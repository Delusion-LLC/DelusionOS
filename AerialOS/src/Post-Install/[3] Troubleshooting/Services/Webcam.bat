@echo off
mode con: cols=80 lines=15

echo.
echo Disabled? = Not working Webcam
choice /C ED /N /M "Press key to toggle the Webcam (E - Enable , D - Disable): "

if errorlevel 2 goto :Disable
if errorlevel 1 goto :Enable

:Enable
echo.
echo Webcam is enabling...
:: Allow Windows and apps to access Webcam in Settings
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" /v "Value" /t REG_SZ /d "Allow" /f >nul 2>&1

:: The Return of UpperFilters
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e96c-e325-11ce-bfc1-08002be10318}" /v "UpperFilters" /t REG_MULTI_SZ /d "ksthunk" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{6bdd1fc6-810f-11d0-bec7-08002be2092f}" /v "UpperFilters" /t REG_MULTI_SZ /d "ksthunk" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{ca3e7ab9-b4c3-4ae6-8251-579ef933890f}" /v "UpperFilters" /t REG_MULTI_SZ /d "ksthunk" /f >nul 2>&1

:: Enabling Webcam Drivers
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\ksthunk" /v "Start" /t REG_DWORD /d "3" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\swenum" /v "Start" /t REG_DWORD /d "3" /f >nul 2>&1

:: Enabling a Plug and Play device
DevManView.exe /enable "Plug and Play Software Device Enumerator" >nul 2>&1

:: Enabling Plug and Play service
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\PlugPlay" /v "Start" /t REG_DWORD /d "2" /f >nul 2>&1
exit

:Disable
echo.
echo Webcam is disabling...
:: Prevent Windows and applications from accessing Webcam in Settings
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" /v "Value" /t REG_SZ /d "Deny" /f >nul 2>&1

:: Disabling UpperFilters
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e96c-e325-11ce-bfc1-08002be10318}" /v "UpperFilters" /t REG_MULTI_SZ /d "" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{6bdd1fc6-810f-11d0-bec7-08002be2092f}" /v "UpperFilters" /t REG_MULTI_SZ /d "" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{ca3e7ab9-b4c3-4ae6-8251-579ef933890f}" /v "UpperFilters" /t REG_MULTI_SZ /d "" /f >nul 2>&1

:: Disabling Webcam Drivers
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\ksthunk" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\swenum" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1

:: Disabling a Plug and Play device
DevManView.exe /disable "Plug and Play Software Device Enumerator" >nul 2>&1

:: Disabling Plug and Play service
Reg.exe add "HKLM\System\CurrentControlSet\Services\PlugPlay" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
exit

