#!/bin/sh
set -e

# Quint Install Script
# Usage:
#   curl -fsSL https://get.quintai.dev | sudo sh -s -- --token <token>
#   curl -fsSL https://get.quintai.dev | sudo sh              (local mode)
#
# One command installs the binary, generates CA certs, trusts them in the
# system keychain, configures your shell, and starts the daemon.

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
TOKEN=""
API_URL=""
PORT=""
API_PORT=""
NO_DAEMON=""
DRY_RUN=""

# ---------------------------------------------------------------------------
# Parse arguments (pass-through to quint setup)
# ---------------------------------------------------------------------------
SETUP_ARGS=""
while [ $# -gt 0 ]; do
  case "$1" in
    --token)
      TOKEN="$2"
      SETUP_ARGS="$SETUP_ARGS --token $2"
      shift 2
      ;;
    --api-url)
      API_URL="$2"
      SETUP_ARGS="$SETUP_ARGS --api-url $2"
      shift 2
      ;;
    --port)
      PORT="$2"
      SETUP_ARGS="$SETUP_ARGS --port $2"
      shift 2
      ;;
    --api-port)
      API_PORT="$2"
      SETUP_ARGS="$SETUP_ARGS --api-port $2"
      shift 2
      ;;
    --no-daemon)
      NO_DAEMON="1"
      SETUP_ARGS="$SETUP_ARGS --no-daemon"
      shift
      ;;
    --dry-run)
      DRY_RUN="1"
      shift
      ;;
    *)
      echo "Unknown option: $1"
      shift
      ;;
  esac
done

# Require root
if [ "$(id -u)" -ne 0 ]; then
  echo "Error: this script must be run as root."
  echo "Usage: curl -fsSL https://get.quintai.dev | sudo sh -s -- --token <token>"
  exit 1
fi

# ---------------------------------------------------------------------------
# Detect OS and architecture
# ---------------------------------------------------------------------------
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$ARCH" in
  x86_64)  ARCH="amd64" ;;
  aarch64) ARCH="arm64" ;;
  arm64)   ARCH="arm64" ;;
  *)
    echo "Error: unsupported architecture: $ARCH"
    exit 1
    ;;
esac

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------
for cmd in curl chmod; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "  Error: required command '$cmd' not found"
    exit 1
  fi
done

if [ "$OS" = "darwin" ]; then
  MACOS_VERSION="$(sw_vers -productVersion 2>/dev/null || echo "unknown")"
  MACOS_MAJOR="$(echo "$MACOS_VERSION" | cut -d. -f1)"
  if [ "$MACOS_MAJOR" != "unknown" ] && [ "$MACOS_MAJOR" -lt 13 ]; then
    echo "  Warning: macOS $MACOS_VERSION detected. Quint requires macOS 13+ for full functionality."
  fi
fi

# Stop existing daemon before upgrade
if [ -f /Library/LaunchDaemons/dev.quintai.agent.plist ]; then
  echo "  Stopping existing Quint daemon..."
  launchctl unload /Library/LaunchDaemons/dev.quintai.agent.plist 2>/dev/null || true
fi

# Check for stale binary
if [ -f /usr/local/bin/quint ]; then
  OLD_VERSION="$(/usr/local/bin/quint version 2>/dev/null || echo "unknown")"
  echo "  Existing install detected: $OLD_VERSION (upgrading)"
fi

# Check for Homebrew shadow
if [ -f /opt/homebrew/bin/quint ]; then
  echo "  Warning: /opt/homebrew/bin/quint may shadow /usr/local/bin/quint"
  echo "  Consider: brew uninstall quint"
fi

echo ""
echo "  Installing Quint (${OS}/${ARCH})"
echo ""

# ---------------------------------------------------------------------------
# Fetch latest version
# ---------------------------------------------------------------------------
FETCH_URL="${API_URL:-https://api.quintai.dev}"
VERSION="$(curl -fsSL "${FETCH_URL}/agent/latest-version" 2>/dev/null || echo "")"
if [ -z "$VERSION" ]; then
  # Fallback: check GitHub releases API
  VERSION="$(curl -fsSL "https://api.github.com/repos/Quint-Security/quint-proxy/releases/latest" 2>/dev/null | grep '"tag_name"' | head -1 | sed 's/.*"v\([^"]*\)".*/\1/' || echo "")"
fi
if [ -z "$VERSION" ]; then
  VERSION="0.9.9"
fi
echo "  Version: v${VERSION}"

# ---------------------------------------------------------------------------
# Download binary
# ---------------------------------------------------------------------------
DOWNLOAD_URL="https://github.com/Quint-Security/quint-proxy/releases/download/v${VERSION}/quint-proxy-${OS}-${ARCH}"
INSTALL_PATH="/usr/local/bin/quint"

if [ "$DRY_RUN" = "1" ]; then
  echo ""
  echo "  [dry-run] Would download: $DOWNLOAD_URL"
  echo "  [dry-run] Would install to: $INSTALL_PATH"
  echo "  [dry-run] Would run: quint setup $SETUP_ARGS"
  exit 0
fi

echo "  Downloading ${DOWNLOAD_URL} ..."
if ! curl -fsSL -o "$INSTALL_PATH" "$DOWNLOAD_URL"; then
  echo ""
  echo "  Error: download failed. Check your network connection."
  echo "  URL: $DOWNLOAD_URL"
  exit 1
fi
chmod +x "$INSTALL_PATH"
echo "  [ok] Installed ${INSTALL_PATH}"

# Verify binary works
if ! "$INSTALL_PATH" version >/dev/null 2>&1; then
  echo "  Error: binary verification failed"
  exit 1
fi
echo "  [ok] Binary verified: $($INSTALL_PATH version)"

# ---------------------------------------------------------------------------
# Run setup (does everything: CA, keychain, env.sh, shell profile, daemon)
# ---------------------------------------------------------------------------
echo ""
"$INSTALL_PATH" setup $SETUP_ARGS
SETUP_EXIT=$?

if [ $SETUP_EXIT -ne 0 ]; then
  echo ""
  echo "  Error: setup failed (exit $SETUP_EXIT)"
  echo "  Try: sudo quint setup $SETUP_ARGS"
  exit $SETUP_EXIT
fi

# Verify daemon is running
sleep 2
if curl -sf http://localhost:9090/health >/dev/null 2>&1; then
  echo "  [ok] Quint daemon is running"
else
  echo "  Warning: daemon health check failed (may still be starting)"
  echo "  Check: sudo launchctl list | grep quintai"
fi

echo ""
echo "  Quint installed successfully!"
