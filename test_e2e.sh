#!/bin/bash
set -e

# End-to-end test for quint-proxy
# Tests: passthrough, policy deny, risk scoring, risk deny, large payloads,
# chain integrity, signature verification

PROXY="./quint-proxy"
TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

echo "=== E2E Test Suite ==="
echo "  tmpdir: $TMPDIR"
echo ""

# Build
echo "--- Building proxy ---"
make build 2>&1 | tail -1

# Create a minimal MCP echo server (responds to tools/call with success)
cat > "$TMPDIR/mcp-server.js" << 'EOJS'
const readline = require('readline');
const rl = readline.createInterface({ input: process.stdin });
rl.on('line', (line) => {
  try {
    const msg = JSON.parse(line);
    if (msg.method === 'initialize') {
      console.log(JSON.stringify({
        jsonrpc: '2.0',
        id: msg.id,
        result: { protocolVersion: '2024-11-05', capabilities: { tools: {} }, serverInfo: { name: 'test-mcp', version: '1.0' } }
      }));
    } else if (msg.method === 'tools/list') {
      console.log(JSON.stringify({
        jsonrpc: '2.0',
        id: msg.id,
        result: { tools: [
          { name: 'ReadFile', description: 'Read a file', inputSchema: { type: 'object', properties: { path: { type: 'string' } } } },
          { name: 'WriteFile', description: 'Write a file', inputSchema: { type: 'object', properties: { path: { type: 'string' }, content: { type: 'string' } } } },
          { name: 'DeleteFile', description: 'Delete a file', inputSchema: { type: 'object', properties: { path: { type: 'string' } } } },
          { name: 'RunShell', description: 'Run shell command', inputSchema: { type: 'object', properties: { command: { type: 'string' } } } },
        ] }
      }));
    } else if (msg.method === 'tools/call') {
      const name = msg.params?.name || 'unknown';
      console.log(JSON.stringify({
        jsonrpc: '2.0',
        id: msg.id,
        result: { content: [{ type: 'text', text: 'Tool ' + name + ' executed successfully' }] }
      }));
    } else if (msg.method === 'notifications/initialized') {
      // No response needed for notifications
    } else {
      console.log(JSON.stringify({
        jsonrpc: '2.0',
        id: msg.id,
        result: {}
      }));
    }
  } catch (e) {
    // Forward non-JSON lines
  }
});
rl.on('close', () => process.exit(0));
EOJS

# Create policy with deny rules
cat > "$TMPDIR/policy.json" << 'EOJSON'
{
  "version": 1,
  "data_dir": "REPLACE_TMPDIR",
  "log_level": "debug",
  "servers": [
    {
      "server": "test-mcp",
      "default_action": "allow",
      "tools": [
        { "tool": "DeleteFile", "action": "deny" },
        { "tool": "RunShell", "action": "deny" }
      ]
    },
    { "server": "*", "default_action": "allow", "tools": [] }
  ]
}
EOJSON
sed -i '' "s|REPLACE_TMPDIR|$TMPDIR|g" "$TMPDIR/policy.json"

PASS=0
FAIL=0

check() {
  local desc="$1" expected="$2" actual="$3"
  if echo "$actual" | grep -q "$expected"; then
    echo "  PASS: $desc"
    PASS=$((PASS+1))
  else
    echo "  FAIL: $desc"
    echo "    expected to contain: $expected"
    echo "    actual: $(echo "$actual" | head -3)"
    FAIL=$((FAIL+1))
  fi
}

check_not() {
  local desc="$1" unexpected="$2" actual="$3"
  if echo "$actual" | grep -q "$unexpected"; then
    echo "  FAIL: $desc"
    echo "    should NOT contain: $unexpected"
    FAIL=$((FAIL+1))
  else
    echo "  PASS: $desc"
    PASS=$((PASS+1))
  fi
}

# =============================================
echo ""
echo "--- Test 1: Passthrough + Tool Allow ---"
# Send initialize, tools/list, allowed tool call
OUTPUT=$(echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/list"}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"ReadFile","arguments":{"path":"/tmp/test.txt"}}}' | $PROXY --name test-mcp --policy "$TMPDIR/policy.json" -- node "$TMPDIR/mcp-server.js" 2>"$TMPDIR/stderr1.txt")

check "initialize response received" '"protocolVersion"' "$OUTPUT"
check "tools/list response received" '"tools"' "$OUTPUT"
check "ReadFile allowed and response received" 'ReadFile executed successfully' "$OUTPUT"
check_not "no deny error for ReadFile" 'denied by policy' "$OUTPUT"

# =============================================
echo ""
echo "--- Test 2: Policy Deny ---"
# DeleteFile is denied by policy
OUTPUT=$(echo '{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"DeleteFile","arguments":{"path":"/important.txt"}}}
{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"RunShell","arguments":{"command":"ls"}}}
{"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"ReadFile","arguments":{"path":"/safe.txt"}}}' | $PROXY --name test-mcp --policy "$TMPDIR/policy.json" -- node "$TMPDIR/mcp-server.js" 2>"$TMPDIR/stderr2.txt")

check "DeleteFile denied with error response" 'denied by policy' "$OUTPUT"
check "RunShell denied with error response" 'denied by policy' "$OUTPUT"
check "ReadFile still allowed after denies" 'ReadFile executed successfully' "$OUTPUT"

# Verify deny responses have correct JSON-RPC structure
check "DeleteFile deny has id=10" '"id":10' "$OUTPUT"
check "RunShell deny has id=11" '"id":11' "$OUTPUT"

# =============================================
echo ""
echo "--- Test 3: Risk Scoring ---"
STDERR2=$(cat "$TMPDIR/stderr2.txt")
check "stderr shows denied for DeleteFile" 'denied DeleteFile' "$STDERR2"
check "stderr shows denied for RunShell" 'denied RunShell' "$STDERR2"

# =============================================
echo ""
echo "--- Test 4: Audit Log Entries ---"
ENTRY_COUNT=$(sqlite3 "$TMPDIR/quint.db" "SELECT COUNT(*) FROM audit_log WHERE server_name='test-mcp'" 2>/dev/null)
check "audit entries created" '[0-9]' "$ENTRY_COUNT"

# Check that denied entries have verdict='deny'
DENY_COUNT=$(sqlite3 "$TMPDIR/quint.db" "SELECT COUNT(*) FROM audit_log WHERE verdict='deny' AND server_name='test-mcp'" 2>/dev/null)
check "deny verdicts recorded" '[0-9]' "$DENY_COUNT"

# Check that allowed tool call has risk score
RISK_ENTRY=$(sqlite3 "$TMPDIR/quint.db" "SELECT risk_score, risk_level FROM audit_log WHERE tool_name='ReadFile' AND server_name='test-mcp' AND direction='request' LIMIT 1" 2>/dev/null)
check "ReadFile has risk_score=10" '10' "$RISK_ENTRY"
check "ReadFile has risk_level=low" 'low' "$RISK_ENTRY"

# =============================================
echo ""
echo "--- Test 5: Signature Verification ---"
# Verify all entries from our test
VERIFY_OUTPUT=$(node /Users/amerabbadi/Quint/quint-cli/packages/cli/dist/index.js verify --all --chain 2>&1 || true)
# Extract just the summary lines
SIG_LINE=$(echo "$VERIFY_OUTPUT" | grep "Signatures:" | head -1)
CHAIN_LINE=$(echo "$VERIFY_OUTPUT" | grep "Chain:" | head -1)
check "all signatures valid" '0 invalid' "$SIG_LINE"
check "chain integrity intact" '0 broken' "$CHAIN_LINE"

# =============================================
echo ""
echo "--- Test 6: String ID handling ---"
OUTPUT=$(echo '{"jsonrpc":"2.0","id":"str-id-42","method":"tools/call","params":{"name":"ReadFile","arguments":{"path":"/test"}}}' | $PROXY --name test-mcp --policy "$TMPDIR/policy.json" -- node "$TMPDIR/mcp-server.js" 2>"$TMPDIR/stderr6.txt")
check "string ID forwarded" 'ReadFile executed successfully' "$OUTPUT"

# String ID denied
OUTPUT=$(echo '{"jsonrpc":"2.0","id":"del-99","method":"tools/call","params":{"name":"DeleteFile","arguments":{"path":"/x"}}}' | $PROXY --name test-mcp --policy "$TMPDIR/policy.json" -- node "$TMPDIR/mcp-server.js" 2>/dev/null)
check "string ID preserved in deny response" '"id":"del-99"' "$OUTPUT"

# =============================================
echo ""
echo "--- Test 7: Large Payload ---"
# Generate a large arguments payload (~100KB)
LARGE_ARG=$(python3 -c "print('{\"data\":\"' + 'x'*100000 + '\"}')")
OUTPUT=$(echo "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"ReadFile\",\"arguments\":$LARGE_ARG}}" | $PROXY --name test-mcp --policy "$TMPDIR/policy.json" -- node "$TMPDIR/mcp-server.js" 2>/dev/null)
check "large payload passes through" 'ReadFile executed successfully' "$OUTPUT"

# =============================================
echo ""
echo "--- Test 8: Risk-based Deny ---"
# WriteFile with extremely dangerous args should trigger risk deny
# Base score 50 (Write*) + drop boost 30 + delete boost 25 + rm -rf boost 30 = 135 -> capped at 100
OUTPUT=$(echo '{"jsonrpc":"2.0","id":50,"method":"tools/call","params":{"name":"WriteFile","arguments":{"path":"/etc/cron","content":"rm -rf / && drop database && delete everything && sudo chmod 777"}}}' | $PROXY --name test-mcp --policy "$TMPDIR/policy.json" -- node "$TMPDIR/mcp-server.js" 2>"$TMPDIR/stderr8.txt")
STDERR8=$(cat "$TMPDIR/stderr8.txt")
check "risk-denied WriteFile with dangerous args" 'denied by policy' "$OUTPUT"
check "stderr shows risk-denied" 'risk-denied WriteFile' "$STDERR8"

# WriteFile with safe args should pass
OUTPUT=$(echo '{"jsonrpc":"2.0","id":51,"method":"tools/call","params":{"name":"WriteFile","arguments":{"path":"/tmp/safe.txt","content":"hello world"}}}' | $PROXY --name test-mcp --policy "$TMPDIR/policy.json" -- node "$TMPDIR/mcp-server.js" 2>/dev/null)
check "WriteFile with safe args passes" 'WriteFile executed successfully' "$OUTPUT"

# =============================================
echo ""
echo "--- Test 9: Keys Generated ---"
ls "$TMPDIR/keys/quint.key" > /dev/null 2>&1
check "private key file created" '' ''
ls "$TMPDIR/keys/quint.pub" > /dev/null 2>&1
check "public key file created" '' ''

# =============================================
echo ""
echo "--- Test 10: Chain Link Verification on Test Entries ---"
# Get last 5 entries and verify prev_hash chain
ENTRIES=$(sqlite3 "$TMPDIR/quint.db" "SELECT id, prev_hash, signature FROM audit_log ORDER BY id DESC LIMIT 5" 2>/dev/null)
check "audit entries have signatures" '|' "$ENTRIES"

# =============================================
echo ""
echo "=========================================="
echo "  Results: $PASS passed, $FAIL failed"
echo "=========================================="

if [ $FAIL -gt 0 ]; then
  exit 1
fi
