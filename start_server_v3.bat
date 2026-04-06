@echo off
title WiFi Sniffer Web Control Panel v3
color 0A

REM ============================================================
REM PORT settings - change here to use a different port (default 5000)
REM ============================================================
set FLASK_PORT=5000

echo.
echo ============================================================
echo         WiFi Sniffer Web Control Panel v3.0
echo ============================================================
echo.
echo  Improvements in v3:
echo  - Service-oriented architecture (5 focused services)
echo  - Python logging with configurable levels
echo  - Thread-safe SSH client
echo  - Input validation on all API endpoints
echo  - 37 smoke tests for self-verification
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

REM Check if dependencies are installed
python -c "import flask; import flask_socketio" >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [INFO] Installing dependencies...
    pip install -r requirements.txt
    echo.
)

REM Wait a moment then open browser
start "" cmd /c "timeout /t 3 >nul & start http://127.0.0.1:%FLASK_PORT%"

REM Start the server
echo [INFO] Server running at http://127.0.0.1:%FLASK_PORT%
echo [INFO] Press Ctrl+C to stop the server
echo.
python wifi_sniffer_web_control_v3.py

pause
