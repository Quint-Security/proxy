#!/bin/sh
set -e

# Quint Agent install script
# Usage: curl -fsSL https://get.quintai.dev | sh -s -- --token <token>

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
TOKEN=""
API_URL="https://api.quintai.dev"

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
while [ $# -gt 0 ]; do
  case "$1" in
    --token)
      TOKEN="$2"
      shift 2
      ;;
    --api-url)
      API_URL="$2"
      shift 2
      ;;
    *)
      echo "Unknown option: $1"
      shift
      ;;
  esac
done

if [ -z "$TOKEN" ]; then
  echo "Usage: curl -fsSL https://get.quintai.dev | sh -s -- --token <token> [--api-url <url>]"
  echo ""
  echo "Options:"
  echo "  --token    (required) Agent enrollment token"
  echo "  --api-url  API endpoint (default: https://api.quintai.dev)"
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

echo "Detected OS=${OS} ARCH=${ARCH}"

# ---------------------------------------------------------------------------
# Fetch latest version (fallback to 0.5.0)
# ---------------------------------------------------------------------------
VERSION="$(curl -fsSL "${API_URL}/agent/latest-version" 2>/dev/null || echo "0.5.0")"
if [ -z "$VERSION" ]; then
  VERSION="0.5.0"
fi
echo "Installing Quint Agent v${VERSION} ..."

# ---------------------------------------------------------------------------
# Download binary
# ---------------------------------------------------------------------------
DOWNLOAD_URL="https://github.com/Quint-Security/quint-proxy/releases/download/v${VERSION}/quint-proxy-${OS}-${ARCH}"
echo "Downloading ${DOWNLOAD_URL} ..."
curl -fsSL -o /usr/local/bin/quint "$DOWNLOAD_URL"
chmod +x /usr/local/bin/quint

# ---------------------------------------------------------------------------
# Create directories
# ---------------------------------------------------------------------------
mkdir -p /etc/quint
mkdir -p /var/log/quint

# ---------------------------------------------------------------------------
# Write config
# ---------------------------------------------------------------------------
cat > /etc/quint/config.yaml <<YAML
token: "${TOKEN}"
api_url: "${API_URL}"
log_level: "info"
YAML
chmod 600 /etc/quint/config.yaml
echo "Wrote /etc/quint/config.yaml"

# ---------------------------------------------------------------------------
# Install system service
# ---------------------------------------------------------------------------
case "$OS" in
  darwin)
    cat > /Library/LaunchDaemons/dev.quintai.agent.plist <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>dev.quintai.agent</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/quint</string>
    <string>daemon</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>/var/log/quint/agent.log</string>
  <key>StandardErrorPath</key><string>/var/log/quint/agent.err</string>
</dict>
</plist>
PLIST
    launchctl load /Library/LaunchDaemons/dev.quintai.agent.plist
    echo "Installed macOS LaunchDaemon: dev.quintai.agent"
    ;;

  linux)
    cat > /etc/systemd/system/quint-agent.service <<'UNIT'
[Unit]
Description=Quint Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/quint daemon
Restart=always
RestartSec=5
User=root
StandardOutput=append:/var/log/quint/agent.log
StandardError=append:/var/log/quint/agent.err

[Install]
WantedBy=multi-user.target
UNIT
    systemctl daemon-reload
    systemctl enable quint-agent
    systemctl start quint-agent
    echo "Installed and started systemd service: quint-agent"
    ;;

  *)
    echo "Warning: unsupported OS for service installation: $OS"
    echo "Binary installed to /usr/local/bin/quint — start manually with: quint daemon"
    ;;
esac

# ---------------------------------------------------------------------------
# Wait for daemon to generate CA cert, then trust it
# ---------------------------------------------------------------------------
DATA_DIR="/var/lib/quint"
CA_CERT="${DATA_DIR}/ca/quint-ca.crt"

echo "Waiting for CA certificate..."
for i in 1 2 3 4 5 6 7 8 9 10; do
  if [ -f "$CA_CERT" ]; then
    break
  fi
  sleep 1
done

if [ "$OS" = "darwin" ] && [ -f "$CA_CERT" ]; then
  security add-trusted-cert -d -r trustRoot \
    -k /Library/Keychains/System.keychain "$CA_CERT" 2>/dev/null && \
    echo "Trusted CA certificate in macOS Keychain" || \
    echo "Warning: could not add CA to Keychain (may need manual trust)"
fi

# ---------------------------------------------------------------------------
# Shell profile injection — auto-set proxy env vars for new terminals
# ---------------------------------------------------------------------------
REAL_USER="${SUDO_USER:-$(whoami)}"
REAL_HOME="$(eval echo "~${REAL_USER}")"

# Write env.sh that quint env would output
QUINT_ENV="${REAL_HOME}/.quint/env.sh"
mkdir -p "${REAL_HOME}/.quint"

BUNDLE_PATH="${DATA_DIR}/ca/quint-ca-bundle.pem"
CERT_PATH="${DATA_DIR}/ca/quint-ca.crt"

cat > "$QUINT_ENV" <<ENVSH
# Quint proxy environment — auto-generated
# Routes AI agent traffic through the Quint security proxy
export SSL_CERT_FILE=${BUNDLE_PATH}
export NODE_EXTRA_CA_CERTS=${CERT_PATH}
export HTTP_PROXY=http://localhost:9090
export HTTPS_PROXY=http://localhost:9090
ENVSH
chown "${REAL_USER}" "$QUINT_ENV" 2>/dev/null || true
echo "Wrote ${QUINT_ENV}"

# Add to shell profiles (idempotent — won't add twice)
SHELL_LINE='[ -f ~/.quint/env.sh ] && source ~/.quint/env.sh'
for profile in "${REAL_HOME}/.zshrc" "${REAL_HOME}/.bashrc"; do
  if [ -f "$profile" ] || [ "$(basename "$profile")" = ".zshrc" ]; then
    if ! grep -qF "quint/env.sh" "$profile" 2>/dev/null; then
      echo "" >> "$profile"
      echo "# Quint agent proxy" >> "$profile"
      echo "$SHELL_LINE" >> "$profile"
      chown "${REAL_USER}" "$profile" 2>/dev/null || true
      echo "Added to $(basename "$profile")"
    fi
  fi
done

# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------
sleep 2
if quint version >/dev/null 2>&1; then
  echo ""
  echo "Quint Agent v${VERSION} installed successfully!"
  echo "  Binary:  /usr/local/bin/quint"
  echo "  Config:  /etc/quint/config.yaml"
  echo "  Proxy:   eval \$(quint env)  or open a new terminal"
  echo "  Logs:    /var/log/quint/agent.log"
  echo ""
  echo "  Every new terminal session will auto-route AI agent traffic"
  echo "  through Quint. To use immediately: eval \$(quint env)"
else
  echo ""
  echo "Warning: 'quint version' check failed, but the binary was installed."
  echo "Check logs at /var/log/quint/agent.err for details."
  exit 1
fi
