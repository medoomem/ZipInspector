@echo off
setlocal
title Remote Archive Inspector
cd /d "%~dp0"

set "GITHUB_USER=medoomem"
set "GITHUB_REPO=ZipInspector"
set "BRANCH=main"
set "EXE_NAME=ZipInspector.exe"
set "PY_NAME=fileex2.py"

set "RAW_BASE=https://raw.githubusercontent.com/%GITHUB_USER%/%GITHUB_REPO%/%BRANCH%"

echo [*] Checking for updates...

:: ==========================================
:: 1. Update fileex2.py (Only if newer)
:: ==========================================
if not exist "%PY_NAME%" (
    echo [*] Downloading %PY_NAME%...
    curl -s -f -L -R -o "%PY_NAME%" "%RAW_BASE%/%PY_NAME%"
) else (
    curl -s -f -L -R -z "%PY_NAME%" -o "%PY_NAME%.tmp" "%RAW_BASE%/%PY_NAME%"
    if exist "%PY_NAME%.tmp" (
        move /y "%PY_NAME%.tmp" "%PY_NAME%" >nul 2>&1
        echo [*] %PY_NAME% was updated!
    ) else (
        echo [*] %PY_NAME% is up to date.
    )
)

:: ==========================================
:: 2. Update ZipInspector.exe (Only if newer)
:: ==========================================
if not exist "%EXE_NAME%" (
    echo [*] Downloading %EXE_NAME%...
    curl -s -f -L -R -o "%EXE_NAME%" "%RAW_BASE%/%EXE_NAME%"
) else (
    curl -s -f -L -R -z "%EXE_NAME%" -o "%EXE_NAME%.tmp" "%RAW_BASE%/%EXE_NAME%"
    if exist "%EXE_NAME%.tmp" (
        move /y "%EXE_NAME%.tmp" "%EXE_NAME%" >nul 2>&1
        echo [*] %EXE_NAME% was updated!
    ) else (
        echo [*] %EXE_NAME% is up to date.
    )
)

:: ==========================================
:: 3. Launch Application
:: ==========================================
echo [*] Starting %EXE_NAME%...
start "" cmd /c "timeout /t 2 /nobreak >nul & start http://127.0.0.1:7860"

if exist "%EXE_NAME%" (
    "%EXE_NAME%"
) else if exist "%PY_NAME%" (
    python "%PY_NAME%"
)

pause