#!/bin/bash
set -e

# Clean up Xvfb lock if needed
if [ -e /tmp/.X99-lock ]; then
  echo "Removing stale Xvfb lock..."
  rm -f /tmp/.X99-lock
fi

# Start Xvfb
echo "Starting Xvfb on :99..."
Xvfb :99 -screen 0 1024x768x16 &

# Start the app
exec node /app/index.js

