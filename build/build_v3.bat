@echo off
setlocal

title Build WiFi Sniffer Control Panel v3
color 0B

cd /d "%~dp0\.."

echo.
echo ============================================================
echo   Building WiFi Sniffer Control Panel v3
echo ============================================================
echo.

where python >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Python is not installed or not in PATH.
    exit /b 1
)

echo [1/4] Installing runtime dependencies...
python -m pip install -r requirements.txt
if %ERRORLEVEL% NEQ 0 exit /b 1

echo [2/4] Installing build dependencies...
python -m pip install -r build\requirements_build.txt
if %ERRORLEVEL% NEQ 0 exit /b 1

echo [3/4] Running PyInstaller...
python -m PyInstaller --noconfirm --clean --distpath build\dist --workpath build\build build\wifi_sniffer_v3.spec
if %ERRORLEVEL% NEQ 0 exit /b 1

echo [4/4] Copying deployment helper files...
copy /Y .env.example build\dist\.env.example >nul
copy /Y README.md build\dist\README.md >nul
copy /Y build\BUILD_README.md build\dist\BUILD_README.md >nul

echo.
echo Build complete.
echo Output:
echo   %CD%\build\dist\WiFi_Sniffer_Control_Panel_v3.exe
echo.

endlocal
