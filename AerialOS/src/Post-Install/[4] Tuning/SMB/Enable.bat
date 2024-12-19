@echo off
title Enabling security Protocol SMB1...

:: Enable components Protocol SMB1
powershell -Command "Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue" >nul

:: Enable Protocol SMB1 client
powershell -Command "Set-SmbClientonfiguration -EnableSMB1Protocol $true -Force -Confirm:$true -ErrorAction SilentlyContinue" >nul

:: Enable Protocol SMB1 server
powershell -Command "Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force -Confirm:$true -ErrorAction SilentlyContinue" >nul
sc config lanmanworkstation depend= bowser/mrxsmb10/mrxsmb20/nsi >nul
sc config mrxsmb10 start= auto >nul

shutdown /r /t 3