#!/bin/bash

# Get the directory where this script lives
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Starting TraceShield X++ backend..."
cd "$SCRIPT_DIR/backend"
"$SCRIPT_DIR/backend/venv/bin/uvicorn" main:app --reload --port 8000 &

echo "Checking MongoDB..."
if command -v mongosh &> /dev/null; then
  if mongosh --quiet --eval "db.runCommand({ ping: 1 })" "mongodb://127.0.0.1:27017" &> /dev/null; then
    echo "MongoDB reachable on 127.0.0.1:27017"
  else
    echo "WARNING: MongoDB not reachable — report saving will be disabled (server degrades gracefully)"
  fi
else
  echo "WARNING: mongosh not found — skipping MongoDB check"
fi

echo "Starting Express server..."
cd "$SCRIPT_DIR/server"
npm run dev &

echo "Starting frontend..."
cd "$SCRIPT_DIR/frontend"
"$SCRIPT_DIR/frontend/node_modules/.bin/vite"
