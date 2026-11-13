@echo off
setlocal
title ZipInspector Updater
cd /d "%~dp0"

set "GITHUB_USER=medoomem"
set "GITHUB_REPO=ZipInspector"
set "BRANCH=main"
set "RAW_BASE=https://raw.githubusercontent.com/%GITHUB_USER%/%GITHUB_REPO%/%BRANCH%"

echo [*] Checking for updates...

for %%F in (requirements.txt fileex2.py) do (
    curl -s -f -L -o "%%F.tmp" "%RAW_BASE%/%%F"
    if errorlevel 1 (
        if exist "%%F.tmp" del /q "%%F.tmp" >nul 2>&1
        echo [!] Failed to check %%F - offline or not found on GitHub.
    ) else if not exist "%%F" (
        move /y "%%F.tmp" "%%F" >nul 2>&1
        echo [+] %%F downloaded!
    ) else (
        fc /b "%%F" "%%F.tmp" >nul 2>&1
        if errorlevel 1 (
            move /y "%%F.tmp" "%%F" >nul 2>&1
            echo [+] %%F was updated!
        ) else (
            del /q "%%F.tmp" >nul 2>&1
            echo [*] %%F is already up to date.
        )
    )
)

echo [*] Done!
pause