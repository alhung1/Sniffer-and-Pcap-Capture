@echo off
title WiFi Sniffer - Installation Script
color 0B
setlocal EnableDelayedExpansion

echo.
echo ============================================================
echo     WiFi Sniffer Web Control Panel - Installation
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
echo [1/5] Checking Python installation...
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
echo [2/5] Checking pip installation...
python -m pip --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [INFO] Installing pip...
    python -m ensurepip --upgrade
) else (
    echo [OK] pip is installed
)

REM ========== Upgrade pip ==========
echo.
echo [3/5] Upgrading pip to latest version...
python -m pip install --upgrade pip --quiet

REM ========== Install Dependencies ==========
echo.
echo [4/5] Installing Python dependencies...
echo      - Flask (Web framework)
echo      - Paramiko (SSH library)
echo.

python -m pip install flask paramiko --quiet
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Failed to install dependencies!
    echo Please try running: pip install flask paramiko scapy
    pause
    exit /b 1
)
echo [OK] All dependencies installed successfully

REM ========== Check Wireshark ==========
echo.
echo [5/5] Checking Wireshark installation...
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
echo To ensure SSH connection works, you may need to:
echo.
echo Option 1: Password Authentication
echo   - Edit wifi_sniffer_web_control.py
echo   - Set: OPENWRT_PASSWORD = "your_password"
echo.
echo Option 2: SSH Key Authentication (Recommended)
echo   - Generate key: ssh-keygen -t rsa
echo   - Copy to router: ssh-copy-id root@192.168.1.1
echo   - Or manually add public key to router
echo.

REM ========== Test Connection ==========
echo.
set /p TEST_SSH="Test SSH connection to 192.168.1.1? (Y/N): "
if /i "%TEST_SSH%"=="Y" (
    echo.
    echo [INFO] Testing SSH connection...
    ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no -oHostKeyAlgorithms=+ssh-rsa root@192.168.1.1 "echo 'SSH connection successful!'" 2>nul
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
echo Next steps:
echo   1. Double-click "start_server.bat" to launch
echo   2. Browser will open to http://127.0.0.1:5000
echo   3. Click Start/Stop buttons to capture WiFi packets
echo.
echo Files saved to: %USERPROFILE%\Downloads
echo.
pause
