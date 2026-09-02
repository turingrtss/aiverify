#!/bin/bash
set -e

echo "Installing AIVerify..."

# Download the main script
curl -fsSL https://raw.githubusercontent.com/turingrtss/aiverify/main/src/aiverify.py -o /usr/local/bin/aiverify
chmod +x /usr/local/bin/aiverify

echo "✅ AIVerify installed successfully!"
echo ""
echo "Usage:"
echo "  aiverify <path>          # Scan a file or directory"
echo "  aiverify init            # Set up pre-commit hook"
echo ""
