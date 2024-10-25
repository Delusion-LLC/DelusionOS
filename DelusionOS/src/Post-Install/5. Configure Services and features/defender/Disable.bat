@echo off
title Disabling Defender

"%ProgramFiles%\Windows Defender\MpCmdRun.exe" -DisableService
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Features" /v "TamperProtection" /t REG_DWORD /d "0" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WdNisSvc" /v "Start" /t REG_DWORD /d "4" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\MDCoreSvc" /v "Start" /t REG_DWORD /d "4" /f >nul
sc config wscsvc start=disabled & sc stop wscsvc
