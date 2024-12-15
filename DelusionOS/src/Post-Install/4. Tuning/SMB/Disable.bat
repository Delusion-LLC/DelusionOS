@echo off
title Disabling security Protocol SMB1...

echo Please write for A (to ALL apply)
powershell -Command "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol" -NoRestart

echo Please write for A (to ALL apply)
powershell -Command "Set-SmbServerConfiguration -EnableSMB1Protocol $false"
sc.exe config lanmanworkstation depend= bowser/mrxsmb20/nsi
sc.exe config mrxsmb10 start= disabled

shutdown /r /t 3
