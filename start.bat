@echo off
title Remote Archive Inspector
cd /d "%~dp0"

set "GITHUB_USER=medoomem"
set "GITHUB_REPO=ZipInspector"
set "EXE_NAME=ZipInspector.exe"

echo [*] Checking for updates from GitHub Releases...

:: Download latest release binary directly using GitHub's /releases/latest/download/ redirect
curl -s -f -L -o "%EXE_NAME%.tmp" "https://github.com%" >nul 2>&1

if %ERRORLEVEL% equ 0 (
    if exist "%EXE_NAME%.tmp" (
        move /y "%EXE_NAME%.tmp" "%EXE_NAME%" >nul 2>&1
        echo [*] Updated to latest release!
    )
) else (
    del /f /q "%EXE_NAME%.tmp" >nul 2>&1
    echo [*] Running local version.
)

echo [*] Starting %EXE_NAME%...
start "" cmd /c "timeout /t 2 /nobreak >nul & start http://127.0.0.1:7860"
"%EXE_NAME%"
pause
