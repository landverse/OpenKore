@echo off
powershell -Command "Start-Process powershell -Verb RunAs -ArgumentList '-NoExit','-Command','cd ''%~dp0''; perl .\openkore.pl'"
exit