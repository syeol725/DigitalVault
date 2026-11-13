#!/usr/bin/env bash
set -euo pipefail
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt pyinstaller
python3 -m PyInstaller --clean --noconfirm --onefile --console --name DigitalVault digital_vault.py
echo "Build complete: dist/DigitalVault"
