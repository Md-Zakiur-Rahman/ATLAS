@echo off
echo ============================================
echo   BLUE TEAM SYSTEM - BUILD FOR WINDOWS
echo ============================================
echo.

REM Check if PyInstaller is installed
py -3.10 -m pip list | findstr pyinstaller >nul
if errorlevel 1 (
    echo [1] Installing PyInstaller...
    py -3.10 -m pip install pyinstaller
)

echo [2] Building executable...
py -3.10 -m PyInstaller build.spec

echo.
echo [3] Build complete!
echo.
echo Output: dist/BlueTeamSystem.exe
echo.
pause