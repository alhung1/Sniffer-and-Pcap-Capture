@echo off
title WiFi Sniffer - Installation Script
color 0B
setlocal EnableDelayedExpansion

echo.
echo ============================================================
echo     WiFi Sniffer Web Control Panel - Installation
echo     Supports v1 / v2 / v3 / v4 (Latest)
echo ============================================================
echo.

REM ========== Check Administrator ==========
net session >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [WARN] This script may require administrator privileges.
    echo [WARN] If installation fails, please right-click and "Run as administrator"
    echo.
)

REM ========== Check Python ==========
echo [1/7] Checking Python installation...
where python >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Python is NOT installed!
    echo.
    echo Please install Python manually:
    echo   1. Download from: https://www.python.org/downloads/
    echo   2. During installation, CHECK "Add Python to PATH"
    echo   3. Run this script again after installation
    echo.
    echo Opening Python download page...
    start "" "https://www.python.org/downloads/"
    pause
    exit /b 1
) else (
    for /f "tokens=*" %%i in ('python --version 2^>^&1') do set PYVER=%%i
    echo [OK] !PYVER! is installed
)

REM ========== Check pip ==========
echo.
echo [2/7] Checking pip installation...
python -m pip --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [INFO] Installing pip...
    python -m ensurepip --upgrade
) else (
    echo [OK] pip is installed
)

REM ========== Upgrade pip ==========
echo.
echo [3/7] Upgrading pip to latest version...
python -m pip install --upgrade pip --quiet

REM ========== Check SSH ==========
echo.
echo [4/7] Checking OpenSSH availability...
where ssh >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [WARN] OpenSSH is NOT found in PATH!
    echo [INFO] v4 requires native Windows OpenSSH (no paramiko).
    echo [INFO] Install via: Settings -^> Apps -^> Optional Features -^> Add OpenSSH Client
    echo.
) else (
    for /f "tokens=*" %%i in ('ssh -V 2^>^&1') do set SSHVER=%%i
    echo [OK] !SSHVER!
)

REM ========== Install v4 Dependencies ==========
echo.
echo [5/7] Installing v4 dependencies...
echo      - Flask (Web framework)
echo      - Flask-SocketIO (Real-time updates)
echo      - Eventlet (Async support)
echo.
echo      NOTE: v4 does NOT require paramiko (uses native SSH)
echo.

python -m pip install flask flask-socketio eventlet --quiet
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Failed to install dependencies!
    echo Please try running: pip install flask flask-socketio eventlet
    pause
    exit /b 1
)
echo [OK] v4 dependencies installed

REM ========== Check Wireshark ==========
echo.
echo [6/7] Checking Wireshark installation...
where wireshark >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [WARN] Wireshark is NOT found in PATH
    echo [INFO] Wireshark is recommended for viewing .pcap files
    echo.
    set /p INSTALL_WS="Do you want to open Wireshark download page? (Y/N): "
    if /i "!INSTALL_WS!"=="Y" (
        echo Opening Wireshark download page...
        start "" "https://www.wireshark.org/download.html"
    )
) else (
    echo [OK] Wireshark is installed
)

REM ========== SSH Key Setup Info ==========
echo.
echo ============================================================
echo     SSH Configuration for OpenWrt (192.168.1.1)
echo ============================================================
echo.
echo v4 uses Windows native SSH which works automatically
echo with OpenWrt's default configuration (publickey auth).
echo.
echo If SSH fails, ensure:
echo   1. OpenSSH Client is installed (Windows Optional Features)
echo   2. SSH key is set up: ssh-keygen -t rsa
echo   3. Key is copied to router: ssh root@192.168.1.1
echo.

REM ========== Test Connection ==========
echo.
echo [7/7] Testing SSH connection...
set /p TEST_SSH="Test SSH connection to 192.168.1.1? (Y/N): "
if /i "%TEST_SSH%"=="Y" (
    echo.
    echo [INFO] Testing SSH connection...
    ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o HostKeyAlgorithms=+ssh-rsa root@192.168.1.1 "echo 'SSH connection successful!'" 2>nul
    if %ERRORLEVEL% NEQ 0 (
        echo [WARN] SSH connection failed. Please check:
        echo        - OpenWrt is powered on
        echo        - IP address is 192.168.1.1
        echo        - SSH service is enabled on OpenWrt
        echo        - Correct authentication configured
    ) else (
        echo [OK] SSH connection successful!
    )
)

REM ========== Complete ==========
echo.
echo ============================================================
echo                 Installation Complete!
echo ============================================================
echo.
echo Available versions:
echo.
echo   v4 (Latest - Recommended):
echo      - Run: start_server_v4.bat
echo      - Or:  python wifi_sniffer_web_control_v4.py
echo      - Features: No paramiko, semaphore SSH, persistent config,
echo                   real file-size monitoring, input validation
echo.
echo   v3 (Service Architecture):
echo      - Run: start_server_v3.bat
echo      - Or:  python wifi_sniffer_web_control_v3.py
echo.
echo   v2 (Performance):
echo      - Run: start_server_v2.bat
echo      - Or:  python wifi_sniffer_web_control_v2.py
echo.
echo   Standalone EXE (No Python needed):
echo      - v4: build\dist\WiFi_Sniffer_Control_Panel_v4.exe
echo      - v2: build\dist\WiFi_Sniffer_Control_Panel_v2.exe
echo.
echo Files saved to: %USERPROFILE%\Downloads
echo.
pause
