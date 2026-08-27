@echo off
cd /d "%~dp0desktop"
where node >nul 2>nul || (echo Instala Node.js LTS primero.&pause&exit /b 1)
call npm install
if errorlevel 1 pause & exit /b 1
call npm run dist
echo.
echo LISTO. El Setup.exe esta en desktop\dist\
pause
