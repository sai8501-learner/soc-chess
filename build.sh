#!/usr/bin/env bash
# ==============================================================================
# RENDER NATIVE PYTHON BUILD SCRIPT
# ==============================================================================
set -o errexit

echo "[1/3] Upgrading pip..."
pip install --upgrade pip

echo "[2/3] Installing backend dependencies..."
pip install -r backend/requirements.txt

echo "[3/3] Preparing frontend distribution..."
if command -v npm &> /dev/null; then
    echo "Node.js detected. Building frontend bundle..."
    cd frontend
    npm install
    npm run build
    cd ..
else
    echo "Using pre-compiled frontend distribution in frontend/dist."
fi

echo "[✔] Build completed successfully."
