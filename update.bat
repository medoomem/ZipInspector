@echo off
setlocal
title ZipInspector Updater
cd /d "%~dp0"

set "GITHUB_USER=medoomem"
set "GITHUB_REPO=ZipInspector"
set "BRANCH=main"
set "RAW_BASE=https://raw.githubusercontent.com/%GITHUB_USER%/%GITHUB_REPO%/%BRANCH%"

echo [*] Checking for updates...

:: Loop through all files to update only if newer
for %%F in (requirements.txt fileex2.py ZipInspector.exe) do (
    if not exist "%%F" (
        echo [*] Downloading %%F...
        curl -s -f -L -R -o "%%F" "%RAW_BASE%/%%F"
        echo [*] %%F downloaded!
    ) else (
        curl -s -f -L -R -z "%%F" -o "%%F.tmp" "%RAW_BASE%/%%F"
        if exist "%%F.tmp" (
            move /y "%%F.tmp" "%%F" >nul 2>&1
            echo [*] %%F was updated!
        ) else (
            echo [*] %%F is already up to date.
        )
    )
)

echo [*] Done!
pause