@echo off
title Build AV-EDR-Analyzer.exe
echo ============================================================
echo   Building standalone .exe for AV/EDR Log Analyzer
echo ============================================================
echo.

where python >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Python was not found on this system.
    echo Please install Python 3.9+ from https://www.python.org/downloads/windows/
    echo and make sure to check "Add python.exe to PATH" during setup.
    pause
    exit /b 1
)

echo [1/3] Installing/upgrading PyInstaller ...
python -m pip install --upgrade pip >nul 2>nul
python -m pip install pyinstaller
if errorlevel 1 (
    echo [ERROR] Failed to install PyInstaller.
    pause
    exit /b 1
)

echo.
echo [2/3] Building the executable ...
python -m PyInstaller --onefile --windowed --name AV-EDR-Analyzer main.py

echo.
if exist "dist\AV-EDR-Analyzer.exe" (
    echo [3/3] Build succeeded!
    echo.
    echo Your executable is here:
    echo   %cd%\dist\AV-EDR-Analyzer.exe
    echo.
    echo You can copy this single .exe file to any other Windows machine
    echo and run it there without installing Python.
) else (
    echo [ERROR] The .exe file was not created. Check the messages above for details.
)

echo.
pause
