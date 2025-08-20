#!/bin/bash

echo "Updating code from GitHub..."
git pull origin main
if [ $? -eq 0 ]; then
    echo "Code updated successfully."
else
    echo "Failed to update code."
    exit 1
fi
