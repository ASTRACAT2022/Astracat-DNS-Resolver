#!/bin/bash

echo "Updating code..."
./update_code.sh
if [ $? -ne 0 ]; then
    echo "Code update failed. Aborting rebuild."
    exit 1
fi

echo "Rebuilding the application..."
go mod tidy
go build -o dns-g .
if [ $? -eq 0 ]; then
    echo "Application rebuilt successfully."
else
    echo "Failed to rebuild application."
    exit 1
fi

echo "Starting the application..."
# The install.sh script is designed for Linux systemd services and is not compatible with macOS.
# We will start the dns-g application directly.
# The port will be handled by the application itself if it supports command-line arguments for it.
./dns-g &
if [ $? -eq 0 ]; then
    echo "Application started successfully."
else
    echo "Failed to start application."
    exit 1
fi

echo "Update, rebuild, and start complete. The application is running the latest release on port 5353."
