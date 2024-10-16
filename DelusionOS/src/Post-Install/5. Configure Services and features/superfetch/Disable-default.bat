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

sc config SysMain start=disabled
powerrun "schtasks.exe" /change /disable /TN "\Microsoft\Windows\Sysmain\ResPriStaticDbSync" >nul 2>&1
powerrun "schtasks.exe" /change /disable /TN "\Microsoft\Windows\Sysmain\WsSwapAssessmentTask" >nul 2>&1
cls
echo Superfetch disabled, please reboot.
:: Pause the script to view the final state
pause
:: Restore previous environment settings
endlocal
:: Exit the script successfully
exit /b 0