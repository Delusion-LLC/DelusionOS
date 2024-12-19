@echo off
title Disabling security Protocol SMB1...

:: Disable components Protocol SMB1
powershell -Command "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue" >nul

:: Disable Protocol SMB1 client
powershell -Command "Set-SmbClientonfiguration -EnableSMB1Protocol $false -Force -Confirm:$false -ErrorAction SilentlyContinue" >nul

:: Disable Protocol SMB1 server
powershell -Command "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -Confirm:$false -ErrorAction SilentlyContinue" >nul
sc config lanmanworkstation depend= bowser/mrxsmb20/nsi >nul
sc config mrxsmb10 start= disabled >nul

shutdown /r /t 3