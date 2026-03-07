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
# macOS: Trust CA + set system proxy (zero-config interception)
# ---------------------------------------------------------------------------
if [ "$OS" = "darwin" ]; then
  DATA_DIR="/var/lib/quint"
  CA_CERT="${DATA_DIR}/ca/quint-ca.crt"

  # Wait for daemon to generate CA cert (up to 10s)
  echo "Waiting for CA certificate..."
  for i in 1 2 3 4 5 6 7 8 9 10; do
    if [ -f "$CA_CERT" ]; then
      break
    fi
    sleep 1
  done

  if [ -f "$CA_CERT" ]; then
    # Trust CA in macOS system keychain
    security add-trusted-cert -d -r trustRoot \
      -k /Library/Keychains/System.keychain "$CA_CERT" 2>/dev/null && \
      echo "Trusted CA certificate in macOS Keychain" || \
      echo "Warning: could not add CA to Keychain (may need manual trust)"

    # Detect active network service (Wi-Fi, Ethernet, etc.)
    NETWORK_SERVICE=""
    for svc in "Wi-Fi" "Ethernet" "USB 10/100/1000 LAN"; do
      if networksetup -getinfo "$svc" 2>/dev/null | grep -q "IP address"; then
        NETWORK_SERVICE="$svc"
        break
      fi
    done

    if [ -n "$NETWORK_SERVICE" ]; then
      # Set system-wide HTTP and HTTPS proxy
      networksetup -setwebproxy "$NETWORK_SERVICE" localhost 9090 2>/dev/null
      networksetup -setsecurewebproxy "$NETWORK_SERVICE" localhost 9090 2>/dev/null
      echo "Set system proxy on ${NETWORK_SERVICE} → localhost:9090"
    else
      echo "Warning: could not detect active network — set proxy manually"
      echo "  networksetup -setwebproxy \"Wi-Fi\" localhost 9090"
      echo "  networksetup -setsecurewebproxy \"Wi-Fi\" localhost 9090"
    fi
  else
    echo "Warning: CA cert not found at ${CA_CERT} — daemon may still be starting"
    echo "  You can trust it manually later:"
    echo "  sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ${CA_CERT}"
  fi
fi

# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------
sleep 2
if quint version >/dev/null 2>&1; then
  echo ""
  echo "Quint Agent v${VERSION} installed successfully!"
  echo "  Binary:  /usr/local/bin/quint"
  echo "  Config:  /etc/quint/config.yaml"
  echo "  Logs:    /var/log/quint/agent.log"
  echo "           /var/log/quint/agent.err"
  if [ "$OS" = "darwin" ] && [ -n "$NETWORK_SERVICE" ]; then
    echo ""
    echo "  All traffic on ${NETWORK_SERVICE} now routes through Quint."
    echo "  To disable: networksetup -setwebproxystate \"${NETWORK_SERVICE}\" off"
    echo "              networksetup -setsecurewebproxystate \"${NETWORK_SERVICE}\" off"
  fi
else
  echo ""
  echo "Warning: 'quint version' check failed, but the binary was installed."
  echo "Check logs at /var/log/quint/agent.err for details."
  exit 1
fi
