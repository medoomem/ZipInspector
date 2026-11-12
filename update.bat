@echo off
setlocal enabledelayedexpansion
title ZipInspector Updater
cd /d "%~dp0"

set "GITHUB_USER=medoomem"
set "GITHUB_REPO=ZipInspector"
set "BRANCH=main"

:: Cache dir in %TEMP%
set "CACHE_DIR=%TEMP%\ZipInspector_cache"
if not exist "%CACHE_DIR%" mkdir "%CACHE_DIR%"

:: Clean up old etag files
del /f /q .*.etag *.etag >nul 2>&1

echo [*] Checking for updates on GitHub...

:: 1. Fetch latest commit SHA from GitHub API (Instant, never cached by CDN)
set "LATEST_SHA="
for /f "tokens=2 delims=:, " %%A in ('curl -s -H "User-Agent: curl" "https://api.github.com/repos/%GITHUB_USER%/%GITHUB_REPO%/commits/%BRANCH%" ^| findstr /i "\"sha\""') do (
    set "LATEST_SHA=%%~A"
    goto :got_sha
)
:got_sha

if not defined LATEST_SHA (
    echo [!] Could not reach GitHub API. Check your connection.
    goto :done
)

:: 2. Read locally saved commit SHA
set "CURRENT_SHA="
if exist "%CACHE_DIR%\commit.txt" (
    set /p CURRENT_SHA=<"%CACHE_DIR%\commit.txt"
)

:: 3. Check if any file is missing locally
set "NEEDS_UPDATE=0"
for %%F in (requirements.txt fileex2.py ZipInspector.exe) do (
    if not exist "%%F" set "NEEDS_UPDATE=1"
)

:: 4. Compare
if "%LATEST_SHA%"=="%CURRENT_SHA%" if "!NEEDS_UPDATE!"=="0" (
    echo [*] All files are already up to date! (Commit: %LATEST_SHA:~0,7%)
    goto :done
)

echo [*] New version detected (Commit: %LATEST_SHA:~0,7%)!
echo [*] Downloading fresh files...

:: Using the commit SHA directly in the URL completely bypasses the 5-minute CDN cache
set "COMMIT_URL=https://raw.githubusercontent.com/%GITHUB_USER%/%GITHUB_REPO%/%LATEST_SHA%"

for %%F in (requirements.txt fileex2.py ZipInspector.exe) do (
    echo [*] Fetching %%F...
    curl -s -f -L -o "%%F.tmp" "%COMMIT_URL%/%%F"
    if exist "%%F.tmp" (
        move /y "%%F.tmp" "%%F" >nul 2>&1
        echo [*] %%F updated!
    ) else (
        echo [!] Failed to download %%F
    )
)

:: Save new commit hash
echo %LATEST_SHA%>"%CACHE_DIR%\commit.txt"

:done
echo [*] Done!
pause