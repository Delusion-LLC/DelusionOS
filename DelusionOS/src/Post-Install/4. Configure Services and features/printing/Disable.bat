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

sc config PrintNotify start=disabled
sc config Spooler start=disabled
sc config PrintWorkFlowUserSvc start=disabled
sc config StiSvc start=disabled
sc stop Spooler
sc stop PrintWorkFlowUserSvc
sc stop StiSvc
sc stop PrintNotify
powerrun "schtasks.exe" /change /disable /TN "\Microsoft\Windows\Printing\PrintJobCleanupTask" >nul 2>&1
powerrun "schtasks.exe" /change /disable /TN "\Microsoft\Windows\Printing\PrinterCleanupTask" >nul 2>&1
powerrun "schtasks.exe" /change /disable /TN "\Microsoft\Windows\Printing\EduPrintProv" >nul 2>&1
cls
echo Printing disabled. Please reboot
:: Pause the script to view the final state
pause
:: Restore previous environment settings
endlocal
:: Exit the script successfully
exit /b 0
