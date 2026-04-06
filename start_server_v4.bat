@echo off
title WiFi Sniffer Web Control Panel v4
color 0A

REM ============================================================
REM PORT settings - change here to use a different port (default 5000)
REM ============================================================
set FLASK_PORT=5000

echo.
echo ============================================================
echo         WiFi Sniffer Web Control Panel v4.0
echo ============================================================
echo.
echo  Improvements in v4:
echo  - No paramiko dependency (native OpenSSH only)
echo  - SSH availability pre-check at startup
echo  - Semaphore-based SSH concurrency (4 concurrent)
echo  - Persistent config (channel, file-split settings)
echo  - Real file-size monitoring
echo  - Input validation on all API endpoints
echo  - Localhost-only by default (127.0.0.1)
echo.
echo [INFO] Starting web server on port %FLASK_PORT%...
echo [INFO] Please wait for the browser to open automatically...
echo.

REM Change to script directory
cd /d "%~dp0"

REM Check if Python is available
where python >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Python is not installed or not in PATH!
    echo Please install Python first: https://www.python.org/downloads/
    pause
    exit /b 1
)

REM Check if SSH is available
where ssh >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [WARNING] OpenSSH not found in PATH!
    echo Install via: Settings -^> Apps -^> Optional Features -^> Add OpenSSH Client
    echo The server will start but capture will not work until SSH is installed.
    echo.
)

REM Check if dependencies are installed
python -c "import flask; import flask_socketio" >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [INFO] Installing dependencies...
    pip install -r requirements_v4.txt
    echo.
)

REM Wait a moment then open browser
start "" cmd /c "timeout /t 3 >nul & start http://127.0.0.1:%FLASK_PORT%"

REM Start the server
echo [INFO] Server running at http://127.0.0.1:%FLASK_PORT%
echo [INFO] Press Ctrl+C to stop the server
echo.
python wifi_sniffer_web_control_v4.py

pause
