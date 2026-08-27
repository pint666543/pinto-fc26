@echo off
cd /d "%~dp0"
where node >nul 2>nul
if errorlevel 1 (
 echo Node.js no esta instalado.
 echo Instala Node.js LTS desde https://nodejs.org/
 pause
 exit /b
)
if not exist node_modules (
 echo Instalando dependencias...
 call npm install
)
start "PINTO FC26 V10 SERVER" /min cmd /c "npm start"
timeout /t 2 /nobreak >nul
start "" "http://localhost:8787/"
