@echo off
setlocal enabledelayedexpansion
title WiFi Sniffer v4 - Build System
color 0A

echo.
echo ============================================================
echo    WiFi Sniffer Control Panel v4 - Build System
echo ============================================================
echo.

REM Change to script directory
cd /d "%~dp0"

REM Check Python
echo [1/7] Checking Python installation...
where python >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Python is not installed or not in PATH!
    echo         Please install Python 3.8+ from https://www.python.org/downloads/
    goto :error
)
python --version
echo [OK] Python found
echo.

REM Install build dependencies
echo [2/7] Installing build dependencies...
pip install -r requirements_build_v4.txt --quiet
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Failed to install dependencies!
    goto :error
)
echo [OK] Dependencies installed
echo.

REM Generate icon
echo [3/7] Generating application icon...
python create_icon.py
if %ERRORLEVEL% NEQ 0 (
    echo [WARNING] Icon generation failed. Using default icon.
)
echo.

REM Create version info for v4
echo [4/7] Creating version information...
if not exist "assets" mkdir assets
(
echo VSVersionInfo(
echo   ffi=FixedFileInfo(
echo     filevers=(4, 0, 0, 0^),
echo     prodvers=(4, 0, 0, 0^),
echo     mask=0x3f,
echo     flags=0x0,
echo     OS=0x40004,
echo     fileType=0x1,
echo     subtype=0x0,
echo     date=(0, 0^)
echo   ^),
echo   kids=[
echo     StringFileInfo(
echo       [
echo         StringTable(
echo           u'040904B0',
echo           [StringStruct(u'CompanyName', u'WiFi Sniffer'^),
echo           StringStruct(u'FileDescription', u'WiFi Sniffer Control Panel v4'^),
echo           StringStruct(u'FileVersion', u'4.0.0.0'^),
echo           StringStruct(u'InternalName', u'WiFi_Sniffer_v4'^),
echo           StringStruct(u'LegalCopyright', u'Copyright 2024-2026'^),
echo           StringStruct(u'OriginalFilename', u'WiFi_Sniffer_Control_Panel_v4.exe'^),
echo           StringStruct(u'ProductName', u'WiFi Sniffer Control Panel'^),
echo           StringStruct(u'ProductVersion', u'4.0.0.0'^)]
echo         ^)
echo       ]
echo     ^),
echo     VarFileInfo([VarStruct(u'Translation', [1033, 1200]^)^]^)
echo   ]
echo ^)
) > assets\version_info_v4.txt
echo [OK] Version info created
echo.

REM Copy wifi_sniffer_v4 package to build directory
echo [5/7] Preparing source files...
if exist "wifi_sniffer_v4" rmdir /s /q "wifi_sniffer_v4"
xcopy /E /I /Y "..\wifi_sniffer_v4" "wifi_sniffer_v4" >nul
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Cannot copy wifi_sniffer_v4 package!
    goto :error
)
if exist "templates" rmdir /s /q "templates"
xcopy /E /I /Y "..\templates" "templates" >nul
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Cannot copy templates!
    goto :error
)
echo [OK] Source files prepared
echo.

REM Build with PyInstaller
echo [6/7] Building executable with PyInstaller...
echo       This may take a few minutes...
echo.
python -m PyInstaller --clean --noconfirm wifi_sniffer_v4.spec
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] PyInstaller build failed!
    goto :error
)
echo.
echo [OK] Build completed successfully!
echo.

REM Create output directory
if not exist "output" mkdir output

REM Check output
echo [7/7] Verifying build output...
if exist "dist\WiFi_Sniffer_Control_Panel_v4.exe" (
    echo [OK] Executable created successfully!

    REM Get file size
    for %%A in ("dist\WiFi_Sniffer_Control_Panel_v4.exe") do set SIZE=%%~zA
    set /a SIZE_MB=!SIZE!/1048576
    echo       Size: !SIZE_MB! MB
) else (
    echo [ERROR] Executable not found!
    goto :error
)

echo.
echo ============================================================
echo    BUILD COMPLETED!
echo ============================================================
echo.
echo    Executable: dist\WiFi_Sniffer_Control_Panel_v4.exe
echo.
echo    You can now:
echo    1. Run the EXE directly from dist\ folder
echo    2. Copy the EXE to any Windows 10/11 computer
echo.
echo    v4 improvements:
echo    - No paramiko (native OpenSSH only)
echo    - Semaphore SSH (4 concurrent)
echo    - Persistent config
echo    - Real file-size monitoring
echo    - Input validation + security fixes
echo.
echo ============================================================
goto :end

:error
echo.
echo ============================================================
echo    BUILD FAILED!
echo ============================================================
echo    Please check the error messages above.
echo ============================================================
pause
exit /b 1

:end
pause
exit /b 0
