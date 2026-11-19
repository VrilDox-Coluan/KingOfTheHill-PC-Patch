@echo off
setlocal
title King of the Hill (2000) PC Modern Patcher

echo ============================================================
echo   King of the Hill (2000) PC Modern Patcher
echo   Supports: Hootenanny + Texas Huntin'
echo ============================================================
echo.
echo NOTE: This patcher does NOT include any game files or assets.
echo       You must provide your own CD-ROM drive or extracted ISO.
echo.

where python >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python 3 was not found on PATH.
    echo Please install Python 3 from https://www.python.org/downloads/
    pause
    exit /b 1
)

set "SRC_DIR=%~1"
if "%SRC_DIR%"=="" (
    set /p "SRC_DIR=Enter path to CD-ROM drive or extracted ISO folder (e.g. D:\ or C:\Games\KOTH): "
)

set "OUT_DIR=%~2"
if "%OUT_DIR%"=="" (
    echo.
    echo Leave output folder blank to patch in-place (if writable)
    echo or automatically copy to "%~dp0KOTH_Patched" (if read-only CD/ISO).
    set /p "OUT_DIR=Optional output folder: "
)

echo.
if "%OUT_DIR%"=="" (
    python "%~dp0patch_koth.py" "%SRC_DIR%"
) else (
    python "%~dp0patch_koth.py" "%SRC_DIR%" --out "%OUT_DIR%"
)

echo.
pause
