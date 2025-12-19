@echo off
title WiFi Sniffer - SSH Setup Helper
color 0E

echo.
echo ============================================================
echo     SSH Connection Setup for OpenWrt
echo ============================================================
echo.

REM ========== Menu ==========
:MENU
echo Please select an option:
echo.
echo   [1] Generate new SSH key pair
echo   [2] Copy SSH key to OpenWrt router
echo   [3] Test SSH connection
echo   [4] Clear known_hosts entry for 192.168.1.1
echo   [5] Show SSH public key
echo   [6] Exit
echo.
set /p CHOICE="Enter choice (1-6): "

if "%CHOICE%"=="1" goto GENERATE_KEY
if "%CHOICE%"=="2" goto COPY_KEY
if "%CHOICE%"=="3" goto TEST_CONNECTION
if "%CHOICE%"=="4" goto CLEAR_HOST
if "%CHOICE%"=="5" goto SHOW_KEY
if "%CHOICE%"=="6" goto END
echo Invalid choice. Please try again.
echo.
goto MENU

:GENERATE_KEY
echo.
echo [INFO] Generating new SSH key pair...
echo [INFO] Press Enter to accept defaults, or enter custom values.
echo.
ssh-keygen -t rsa -b 4096
echo.
echo [OK] SSH key generated!
echo [INFO] Public key location: %USERPROFILE%\.ssh\id_rsa.pub
echo.
pause
goto MENU

:COPY_KEY
echo.
echo [INFO] This will copy your SSH public key to the OpenWrt router.
echo [INFO] You will be prompted for the root password.
echo.
set /p ROUTER_IP="Enter router IP [192.168.1.1]: "
if "%ROUTER_IP%"=="" set ROUTER_IP=192.168.1.1

REM Windows doesn't have ssh-copy-id, so we do it manually
echo.
echo [INFO] Copying key to root@%ROUTER_IP%...
type %USERPROFILE%\.ssh\id_rsa.pub | ssh -oHostKeyAlgorithms=+ssh-rsa root@%ROUTER_IP% "mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
if %ERRORLEVEL% EQU 0 (
    echo [OK] SSH key copied successfully!
) else (
    echo [ERROR] Failed to copy SSH key. Please try manually.
)
echo.
pause
goto MENU

:TEST_CONNECTION
echo.
set /p ROUTER_IP="Enter router IP [192.168.1.1]: "
if "%ROUTER_IP%"=="" set ROUTER_IP=192.168.1.1

echo [INFO] Testing SSH connection to %ROUTER_IP%...
ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no -oHostKeyAlgorithms=+ssh-rsa root@%ROUTER_IP% "echo 'Connection successful!' && uname -a"
echo.
pause
goto MENU

:CLEAR_HOST
echo.
echo [INFO] Removing known_hosts entry for 192.168.1.1...
ssh-keygen -R 192.168.1.1
echo [OK] Entry removed. You can now reconnect with a new host key.
echo.
pause
goto MENU

:SHOW_KEY
echo.
echo [INFO] Your SSH public key:
echo ============================================================
type %USERPROFILE%\.ssh\id_rsa.pub 2>nul || echo [ERROR] No SSH key found. Please generate one first (Option 1).
echo.
echo ============================================================
echo.
echo [TIP] Copy this key to OpenWrt's /root/.ssh/authorized_keys
echo.
pause
goto MENU

:END
echo.
echo Goodbye!
exit /b 0
