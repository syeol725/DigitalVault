@echo off
setlocal
py -m pip install --upgrade pip
py -m pip install -r requirements.txt pyinstaller
py -m PyInstaller --clean --noconfirm --onefile --console --name DigitalVault digital_vault.py
echo.
echo Build complete: dist\DigitalVault.exe
pause
