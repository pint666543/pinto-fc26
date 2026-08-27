@echo off
cd /d "%~dp0"
set "APP=%CD%\index.html"
set "EDGE=%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe"
if not exist "%EDGE%" set "EDGE=%ProgramFiles%\Microsoft\Edge\Application\msedge.exe"
if not exist "%EDGE%" (
 echo Edge no encontrado.
 pause
 exit /b
)
start "" "%EDGE%" --app="file:///%APP:\=/%" --new-window
timeout /t 1 >nul
start "" "%EDGE%" --app="file:///%APP:\=/%" --new-window
timeout /t 1 >nul
start "" "%EDGE%" --app="file:///%APP:\=/%" --new-window
