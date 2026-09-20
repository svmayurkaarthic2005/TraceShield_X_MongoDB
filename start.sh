#!/bin/bash

# Get the directory where this script lives
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Starting TraceShield X++ backend..."
cd "$SCRIPT_DIR/backend"
"$SCRIPT_DIR/backend/venv/bin/uvicorn" main:app --reload --port 8000 &

echo "Starting frontend..."
cd "$SCRIPT_DIR/frontend"
"$SCRIPT_DIR/frontend/node_modules/.bin/vite"
