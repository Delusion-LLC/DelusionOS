@echo off
:: Ensure admin privileges
fltmc >nul 2>&1 || (
    echo Administrator privileges are required.
    PowerShell Start -Verb RunAs '%0' 2> nul || (
        echo Right-click on the script and select "Run as administrator".
        pause & exit 1
    )
    exit 0
)
:: Initialize environment
setlocal EnableExtensions DisableDelayedExpansion

devmanview.exe /disable "Remote Desktop Device Redirector Bus"
sc config termservice start=disabled
sc config umrdpservice start=disabled
sc config winrm start=disabled
sc config rdpbus start=disabled
sc config rdpdr start=disabled
sc config rdpvideominiport start=disabled
sc config terminpt start=disabled
sc config tsusbflt start=disabled
sc config tsusbgd start=disabled
sc config tsusbhub start=disabled
cls
echo Remote Desktop disabled. Please reboot.
:: Pause the script to view the final state
pause
:: Restore previous environment settings
endlocal
:: Exit the script successfully
exit /b 0