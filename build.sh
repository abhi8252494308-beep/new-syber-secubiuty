#!/usr/bin/env bash
# Build script for Render deployment

set -e  # Exit on error

echo "=== Starting build process ==="

# Ensure only binary wheels are used (no Rust compilation)
export PIP_ONLY_BINARY=:all:

# Upgrade pip
pip install --upgrade pip

# Install Python dependencies - only use pre-built wheels
echo "=== Installing Python dependencies ==="
pip install --no-cache-dir --only-binary=:all: -r backend/requirements.txt

# Create reports directory
mkdir -p backend/reports

echo "=== Build completed successfully ==="