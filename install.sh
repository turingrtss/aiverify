#!/bin/bash
set -e

echo "🔧 Installing AIVerify..."

# Detect OS
if [[ "$OSTYPE" == "linux-gnu"* ]] || [[ "$OSTYPE" == "darwin"* ]]; then
    INSTALL_DIR="/usr/local/bin"
else
    echo "❌ Unsupported OS. Please install manually."
    exit 1
fi

# Download
echo "📥 Downloading latest version..."
curl -fsSL https://raw.githubusercontent.com/turingrtss/aiverify/master/src/aiverify.py -o /tmp/aiverify

# Install
echo "📦 Installing to $INSTALL_DIR..."
sudo mv /tmp/aiverify "$INSTALL_DIR/aiverify"
sudo chmod +x "$INSTALL_DIR/aiverify"

echo ""
echo "✅ AIVerify installed successfully!"
echo ""
echo "Quick start:"
echo "  aiverify .              # Scan current directory"
echo "  aiverify --init         # Set up git hook"
echo "  aiverify --help         # Show all options"
echo ""
echo "⭐ Star us: https://github.com/turingrtss/aiverify"
