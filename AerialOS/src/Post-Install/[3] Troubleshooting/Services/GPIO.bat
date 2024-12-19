@echo off
mode con: cols=80 lines=15

echo.
echo INFO: GPIO - A general-purpose input/output is an uncommitted digital signal pin on an integrated circuit or electronic circuit board which may be used as an input or output, or both, and is controllable by software. GPIOs have no predefined purpose and are unused by default
echo What is GPIO: https://www.youtube.com/watch?v=jwWxKACHWxs
choice /C ED /N /M "Press key to toggle the GPIO (E - Enable , D - Disable): "

if errorlevel 2 goto :Disable
if errorlevel 1 goto :Enable

:Enable
echo.
echo GPIO is enabling...
reg add "HKLM\SYSTEM\CurrentControlSet\Services\GPIOClx0101" /v "Start" /t REG_DWORD /d "3" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\msgpiowin32" /v "Start" /t REG_DWORD /d "3" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\iaLPSSi_GPIO" /v "Start" /t REG_DWORD /d "3" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\iaLPSS2i_GPIO2" /v "Start" /t REG_DWORD /d "3" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\iaLPSS2i_I2C" /v "Start" /t REG_DWORD /d "3" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\iaLPSSi_I2C" /v "Start" /t REG_DWORD /d "3" /f >nul
exit

:Disable
echo.
echo GPIO is disabling...
reg add "HKLM\SYSTEM\CurrentControlSet\Services\GPIOClx0101" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\msgpiowin32" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\iaLPSSi_GPIO" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\iaLPSS2i_GPIO2" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\iaLPSS2i_I2C" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\iaLPSSi_I2C" /v "Start" /t REG_DWORD /d "4" /f >nul

exit