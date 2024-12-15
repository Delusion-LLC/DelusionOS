@echo off
title Improving security with SMB...

echo Please write for A (to ALL apply)
powershell -Command "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol"

echo Please write for A (to ALL apply)
powershell -Command "Set-SmbServerConfiguration -EnableSMB1Protocol $false"

shutdown /r /t 3
