@echo off
setlocal
powershell.exe -NoLogo -NoProfile -File "%~dp0install.ps1" %*
exit /b %ERRORLEVEL%
