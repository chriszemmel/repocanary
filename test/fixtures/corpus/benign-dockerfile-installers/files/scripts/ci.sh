#!/usr/bin/env bash
set -euo pipefail
# Toolchain bootstrap for CI runners.
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" "" --unattended
LATEST=$(curl -s https://api.github.com/repos/cli/cli/releases/latest | jq -r .tag_name)
echo "latest gh: $LATEST"
npm ci
npm test
