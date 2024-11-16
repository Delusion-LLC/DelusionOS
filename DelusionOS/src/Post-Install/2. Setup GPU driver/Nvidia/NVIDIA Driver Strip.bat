@echo off
echo.
echo                       Reinstall the driver with DDU if the driver is bugged
echo.
echo                                 Press Enter to start the script
echo.
Pause >NUL

:start

sc config NVDisplay.ContainerLocalSystem start= disabled >NUL 2>&1
sc stop NVDisplay.ContainerLocalSystem >NUL 2>&1
echo                           Do you have Geforce Experience installed? (y/n)

:choice

set /p userChoice=
if /i "%userChoice%"=="n" (
    echo                                    Removing GeForce components.
    rmdir /s /q "C:\Program Files\NVIDIA Corporation" >nul 2>&1
    cd /d "C:\Windows\System32\DriverStore\FileRepository\nv_*" >nul 2>&1
    del /f nvFBC*.dll nvIFR*.dll >nul 2>&1

    cd /d ".\Display.NvContainer\plugins\LocalSystem" >nul 2>&1
    takeown /r /d Y /f * >nul 2>&1
    icacls * /grant "%USERNAME%":F >nul 2>&1
    @REM del /f NvcDispWatchdog.dll >nul 2>&1 maybe breaks control panel

    cd /d "../Session" >nul 2>&1
    takeown /f * /r /d Y >nul 2>&1
    icacls * /grant "%USERNAME%":F >nul 2>&1
    del /f _NvGSTPlugin.dll >nul 2>&1

    cd /d "C:\Windows\System32" >nul 2>&1
    takeown /r /d Y /f "nv*.*" >nul 2>&1
    icacls "nv*.*" /grant "%USERNAME%":F /t >nul 2>&1
    del /f NvFBC64.dll NvIFR64.dll >nul 2>&1

    cd /d "C:\Windows\SysWOW64" >nul 2>&1
    takeown /r /d Y /f "nv*.*" >nul 2>&1
    del /f NvFBC.dll NvIFR.dll >nul 2>&1
    goto start
) else if /i "%userChoice%"=="y" (
    echo                                    Skipping GeForce components.
    goto start
) else (
    echo Invalid choice. Please type 'y' or 'n'.
    goto choice
)

:start
rmdir /s /q "C:\Windows\System32\drivers\NVIDIA Corporation" >nul 2>&1
cd /d "C:\Windows\System32\DriverStore\FileRepository\" >nul 2>&1
del /f /q NvTelemetry64.dll >nul 2>&1
reg add "HKCU\SOFTWARE\NVIDIA Corporation\NVControlPanel2\Client" /v "OptInOrOutPreference" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\Startup\SendTelemetryData" /ve /t REG_DWORD /d "0" /f >nul 2>&1

cd /d "C:\Windows\System32\DriverStore\FileRepository\nv_*" >nul 2>&1
takeown /r /d Y /f * >nul 2>&1
takeown /f NVWMI /R /D Y >nul 2>&1
icacls "NVWMI" /grant "%USERDOMAIN%\%USERNAME%":F /t >nul 2>&1
rmdir /s /q NVWMI >nul 2>&1

takeown /f NvCamera /R /D Y >nul 2>&1
icacls "NvCamera" /grant "%USERDOMAIN%\%USERNAME%":F /t >nul 2>&1
rmdir /s /q NvCamera >nul 2>&1
reg delete "HKLM\System\ControlSet001\Services\nvlddmkm\NvCamera" /f >nul 2>&1

icacls * /grant "%USERDOMAIN%\%USERNAME%":(F) /t >nul 2>&1
del /f "NvTelemetry64.dll" >nul 2>&1

del /f nvptxJitCompiler32.dll nvptxJitCompiler64.dll >nul 2>&1
del /f nvsmartmax*.* nvinfo.pb >nul 2>&1
del /f nvIccAdvancedColorIdentity.icm nvEncMFT*.dll nvDevMFT*.dll >nul 2>&1

cd /d "./Display.NvContainer" >nul 2>&1
takeown /f * /R /D Y >nul 2>&1
icacls * /grant "%USERNAME%":F >nul 2>&1
del /f "nvtopps.db3" >nul 2>&1

cd /d "./plugins/LocalSystem/" >nul 2>&1
takeown /f _DisplayDriverR*.dll /R /D Y >nul 2>&1
icacls "_DisplayDriverRAS.dll" /grant "%USERNAME%":F >nul 2>&1
del /f _DisplayDriverRAS.dll >nul 2>&1
del /f _nvtopps.dll >nul 2>&1

cd /d "../Session" >nul 2>&1
takeown /f * /R /D Y >nul 2>&1
icacls * /grant "%USERNAME%":F >nul 2>&1
del /f nvprofileupdaterplugin.dll >nul 2>&1

cd /d "C:\Windows\System32" >nul 2>&1
del /f nvinfo.pb >nul 2>&1
rmdir /s /q lxss >nul 2>&1
del /f MCU.exe nvcudadebugger.dll nvdebugdump.exe >nul 2>&1

sc config NVDisplay.ContainerLocalSystem start= auto >NUL 2>&1
sc start NVDisplay.ContainerLocalSystem >NUL 2>&1

echo.
echo                                The driver was stripped successfully.
