@echo off
title Improving security with SMB...

echo Please write for A (to ALL apply)
powershell -Command "Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol" -NoRestart

echo Please write for A (to ALL apply)
powershell -Command "Set-SmbServerConfiguration -EnableSMB1Protocol $true"
@echo off
title Disabling security Protocol SMB1...

echo Please write for A (to ALL apply)
powershell -Command "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol"

echo Please write for A (to ALL apply)
powershell -Command "Set-SmbServerConfiguration -EnableSMB1Protocol $false"
sc.exe config lanmanworkstation depend= bowser/mrxsmb10/mrxsmb20/nsi
sc.exe config mrxsmb10 start= auto

shutdown /r /t 3
