#!/bin/bash

set -euo pipefail

# Move to this demo project directory so relative paths are stable.
cd "$(dirname "$0")"

# Uninstall the package without confirmation.
pip3 uninstall -y snake-guard || true

# Install the local repo package in editable mode.
pip3 install -e ../..
