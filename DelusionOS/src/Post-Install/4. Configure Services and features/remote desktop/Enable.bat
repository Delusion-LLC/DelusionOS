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

devmanview.exe /enable "Remote Desktop Device Redirector Bus"
sc config termservice start=demand
sc config umrdpservice start=demand
sc config winrm start=demand
sc config rdpbus start=demand
sc config rdpdr start=demand
sc config rdpvideominiport start=demand
sc config terminpt start=demand
sc config tsusbflt start=demand
sc config tsusbgd start=demand
sc config tsusbhub start=demand
cls
echo Remote Desktop enabled. Please reboot.
:: Pause the script to view the final state
pause
:: Restore previous environment settings
endlocal
:: Exit the script successfully
exit /b 0