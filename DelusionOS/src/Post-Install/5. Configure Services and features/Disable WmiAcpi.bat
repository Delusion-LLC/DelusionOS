@echo off

Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\WmiAcpi" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
DevManView.exe /disable "Microsoft Windows Management Interface for ACPI" >nul 2>&1

exit