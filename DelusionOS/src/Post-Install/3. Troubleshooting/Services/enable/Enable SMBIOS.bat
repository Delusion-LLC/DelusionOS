@echo off

Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\mssmbios" /v "Start" /t REG_DWORD /d "1" /f >nul 2>&1
DevManView.exe /enable "Microsoft System Management BIOS Driver" >nul 2>&1

exit