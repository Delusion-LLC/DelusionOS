@echo off
title Idle PowerPlan

echo. Disabling idle states forces C-State 0, which can be seen in HWiNFO, and is in Microsoft's recommendations for configuring devices for real-time performance (1). Forcing C-State 0 mitigates the undesirable delay to execute new instructions on a CPU that has entered a deeper power-saving state at the expense of higher temperatures and power consumption. Therefore, I would recommend keeping idle states enabled for the majority of readers as other problems can occur due to these side effects (e.g. throttling, power issues).
echo. Are you sure to disable Idle Powerplan?
echo.
echo.	Press [1] to Disable Idle
echo.	Press [2] to Enable Idle
echo.
set /p c="What is your choice? "
if /i %c% equ 1 goto :disable
if /i %c% equ 2 goto :enable

:disable
powercfg /setacvalueindex scheme_current sub_processor 00000000-16f6-45a6-9fcf-0fa130b83c01 1 && powercfg /setactive scheme_current
pause
exit

:enable
powercfg /setacvalueindex scheme_current sub_processor 00000000-16f6-45a6-9fcf-0fa130b83c01 0 && powercfg /setactive scheme_current
pause
exit
