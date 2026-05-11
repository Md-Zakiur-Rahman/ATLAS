Write-Host "==========================================" -ForegroundColor Green
Write-Host "  BLUE TEAM SYSTEM - BUILD FOR WINDOWS" -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Green
Write-Host ""

# Check PyInstaller
Write-Host "[1] Checking PyInstaller..." -ForegroundColor Yellow
py -3.10 -m pip list | Select-String "pyinstaller" | Out-Null
if ($?) {
    Write-Host "    ✓ PyInstaller found" -ForegroundColor Green
} else {
    Write-Host "    Installing PyInstaller..." -ForegroundColor Yellow
    py -3.10 -m pip install pyinstaller
}

# Build
Write-Host "[2] Building executable..." -ForegroundColor Yellow
py -3.10 -m PyInstaller build.spec

Write-Host ""
Write-Host "==========================================" -ForegroundColor Green
Write-Host "  ✅ BUILD COMPLETE!" -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Output: dist/BlueTeamSystem.exe" -ForegroundColor Cyan
Write-Host ""