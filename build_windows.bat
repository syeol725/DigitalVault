@echo off
setlocal
cd /d "%~dp0"

py -m pip install --upgrade pip
if errorlevel 1 goto error

py -m pip install -r requirements.txt pyinstaller
if errorlevel 1 goto error

py -m PyInstaller --clean --noconfirm --onefile --console --name DigitalVault digital_vault.py
if errorlevel 1 goto error

echo.
echo Build complete: dist\DigitalVault.exe
pause
exit /b 0

:error
echo.
echo Build failed. Check the error messages above.
pause
exit /b 1
