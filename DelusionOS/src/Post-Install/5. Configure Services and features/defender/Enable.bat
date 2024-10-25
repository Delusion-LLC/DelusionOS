@echo off
title Enabling Defender

"%ProgramFiles%\Windows Defender\MpCmdRun.exe" -EnableService
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Features" /v "TamperProtection" /t REG_DWORD /d "1" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WdNisSvc" /v "Start" /t REG_DWORD /d "2" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\MDCoreSvc" /v "Start" /t REG_DWORD /d "2" /f >nul
sc config wscsvc start=auto & sc start wscsvc
