@echo off
title Remote Archive Inspector
cd /d "%~dp0"

:: ===================================================
:: CONFIGURATION: SET YOUR GITHUB DETAILS HERE
:: ===================================================
set "GITHUB_USER=medoomem"
set "GITHUB_REPO=ZipInspector"
set "GITHUB_BRANCH=main"
:: ===================================================

echo ===================================================
echo     Remote ZIP and RAR Inspector and Explorer
echo ===================================================
echo.


REM 1. AUTO-UPDATE FROM GITHUB BEFORE LAUNCHING
if not "%GITHUB_USER%"=="YOUR_GITHUB_USERNAME" (
    echo [*] Checking for updates from GitHub...

    REM Method A: If repo was cloned using Git
    if exist ".git" (
        where git >nul 2>&1
        if %ERRORLEVEL% equ 0 (
            git pull --quiet
            echo [*] Git sync complete.
        )
    ) else (
        REM Method B: If downloaded as ZIP (No Git installed) - Uses Windows native curl
        where curl >nul 2>&1
        if %ERRORLEVEL% equ 0 (
            REM Determine if main file is named app.py or fileex2.py
            set "TARGET_FILE=app.py"
            if exist "fileex2.py" set "TARGET_FILE=fileex2.py"

            REM Try to download the latest python script to a temp file
            curl -s -f -L -o "%TARGET_FILE%.tmp" "https://raw.githubusercontent.com/%GITHUB_USER%/%GITHUB_REPO%/%GITHUB_BRANCH%/%TARGET_FILE%" >nul 2>&1
            if %ERRORLEVEL% equ 0 (
                if exist "%TARGET_FILE%.tmp" (
                    move /y "%TARGET_FILE%.tmp" "%TARGET_FILE%" >nul 2>&1
                    echo [*] Successfully updated %TARGET_FILE% to latest version!
                )
            ) else (
                del /f /q "%TARGET_FILE%.tmp" >nul 2>&1
            )

            REM Also update requirements.txt if changed
            curl -s -f -L -o "requirements.txt.tmp" "https://raw.githubusercontent.com/%GITHUB_USER%/%GITHUB_REPO%/%GITHUB_BRANCH%/requirements.txt" >nul 2>&1
            if %ERRORLEVEL% equ 0 (
                if exist "requirements.txt.tmp" (
                    move /y "requirements.txt.tmp" "requirements.txt" >nul 2>&1
                )
            ) else (
                del /f /q "requirements.txt.tmp" >nul 2>&1
            )
        )
    )
)
echo.

REM 2. DETECT PYTHON COMMAND
set "PY_CMD="
py --version >nul 2>&1 && set "PY_CMD=py -3"
if not defined PY_CMD (
    python --version >nul 2>&1 && set "PY_CMD=python"
)

if not defined PY_CMD (
    echo [ERROR] Python is not installed or not in your system PATH!
    echo Opening https://www.python.org/downloads/ ...
    start https://www.python.org/downloads/
    echo Please install Python and ensure you check the Add to PATH box.
    pause
    exit /b 1
)

REM 3. CHECK FOR 7-ZIP OR WINRAR
set "ARCHIVE_TOOL_FOUND=0"
if exist "C:\Program Files\7-Zip\7z.exe" set "ARCHIVE_TOOL_FOUND=1"
if exist "C:\Program Files (x86)\7-Zip\7z.exe" set "ARCHIVE_TOOL_FOUND=1"
if exist "%LOCALAPPDATA%\Programs\7-Zip\7z.exe" set "ARCHIVE_TOOL_FOUND=1"
if exist "C:\Program Files\WinRAR\UnRAR.exe" set "ARCHIVE_TOOL_FOUND=1"
if exist "C:\Program Files (x86)\WinRAR\UnRAR.exe" set "ARCHIVE_TOOL_FOUND=1"
where 7z.exe >nul 2>&1 && set "ARCHIVE_TOOL_FOUND=1"
where unrar.exe >nul 2>&1 && set "ARCHIVE_TOOL_FOUND=1"

if "%ARCHIVE_TOOL_FOUND%"=="0" (
    echo [NOTICE] Neither 7-Zip nor WinRAR was found on this PC!
    echo 7-Zip is recommended to preview and stream compressed files from RAR archives.
    echo Opening https://www.7-zip.org/ in your browser...
    start https://www.7-zip.org/
    echo Please install 7-Zip and press any key to continue...
    pause
    echo.
)

REM 4. SETUP ENVIRONMENT (AUTO-HEALING VENV WITH FALLBACK)
set "RUNNER="

if exist "venv" if not exist "venv\Scripts\python.exe" (
    echo [*] Cleaning up corrupted venv folder...
    rmdir /s /q "venv" >nul 2>&1
)

if not exist "venv\Scripts\python.exe" (
    echo [*] Creating Python virtual environment...
    %PY_CMD% -m venv venv
    
    if exist "venv\Scripts\python.exe" (
        echo [*] Virtual environment created successfully.
        set "RUNNER=venv\Scripts\python.exe"
        call venv\Scripts\python.exe -m pip install --upgrade pip --quiet
        call venv\Scripts\pip.exe install -r requirements.txt
    ) else (
        echo.
        echo [WARNING] Could not create venv on this system.
        echo [*] Falling back to system Python automatically...
        set "RUNNER=%PY_CMD%"
        %PY_CMD% -m pip install -r requirements.txt
    )
) else (
    echo [*] Virtual environment found. Verifying dependencies...
    set "RUNNER=venv\Scripts\python.exe"
    call venv\Scripts\pip.exe install -r requirements.txt --quiet
)

REM 5. LAUNCH BROWSER AND RUN SERVER
echo.
echo [*] Starting server at http://127.0.0.1:7860 ...
echo [INFO] Press CTRL + C in this window to stop the server.
echo.

start "" cmd /c "timeout /t 2 /nobreak >nul & start http://127.0.0.1:7860"

if exist "app.py" (
    %RUNNER% app.py
) else if exist "fileex2.py" (
    %RUNNER% fileex2.py
) else (
    echo [ERROR] Neither app.py nor fileex2.py was found!
    pause
)

if %ERRORLEVEL% neq 0 (
    echo.
    echo [CRASH] Application stopped with an error code.
    pause
)