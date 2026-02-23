#!/bin/bash
set -e

# Full end-to-end test: proxy → audit → verify → sync → API
# Tests the entire Quint pipeline from tool call to control plane.

PROXY="/Users/amerabbadi/Quint/quint-proxy/quint-proxy"
QUINT_CLI="node /Users/amerabbadi/Quint/quint-cli/packages/cli/dist/index.js"
API_URL="http://localhost:8080"
API_KEY="qk_c11cf33a7dbeb27591e73eadeb0d6433e56b4b98564dac43c14f04e12aec4edd"
TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

echo "============================================"
echo "  Quint Full E2E Test"
echo "============================================"
echo ""

# Create test MCP server
cat > "$TMPDIR/mcp-server.js" << 'EOJS'
const readline = require('readline');
const rl = readline.createInterface({ input: process.stdin });
rl.on('line', (line) => {
  try {
    const msg = JSON.parse(line);
    if (msg.method === 'initialize') {
      console.log(JSON.stringify({ jsonrpc:'2.0', id:msg.id, result:{ protocolVersion:'2024-11-05', capabilities:{tools:{}}, serverInfo:{name:'e2e-mcp',version:'1.0'}} }));
    } else if (msg.method === 'tools/list') {
      console.log(JSON.stringify({ jsonrpc:'2.0', id:msg.id, result:{ tools:[
        {name:'read_file',inputSchema:{type:'object'}},
        {name:'write_file',inputSchema:{type:'object'}},
        {name:'delete_file',inputSchema:{type:'object'}},
        {name:'run_shell',inputSchema:{type:'object'}}
      ]}}));
    } else if (msg.method === 'tools/call') {
      console.log(JSON.stringify({ jsonrpc:'2.0', id:msg.id, result:{ content:[{type:'text',text:'OK: '+msg.params.name}]} }));
    }
  } catch {}
});
rl.on('close', () => process.exit(0));
EOJS

# Create policy with all features
cat > "$TMPDIR/policy.json" << EOJSON
{
  "version": 1,
  "data_dir": "$TMPDIR",
  "log_level": "info",
  "fail_mode": "closed",
  "servers": [
    {
      "server": "e2e-server",
      "default_action": "allow",
      "tools": [
        { "tool": "delete_file", "action": "deny" },
        { "tool": "run_shell", "action": "deny" }
      ]
    },
    { "server": "*", "default_action": "allow", "tools": [] }
  ],
  "risk": {
    "flag": 50,
    "deny": 80,
    "patterns": [
      { "tool": "write_file", "base_score": 55 }
    ],
    "keywords": [
      { "pattern": "\\\\b/etc/\\\\b", "boost": 30 }
    ]
  }
}
EOJSON

# Record the starting count in the shared DB
START_COUNT=$(sqlite3 ~/.quint/quint.db "SELECT COUNT(*) FROM audit_log" 2>/dev/null || echo 0)

echo "Step 1: Send tool calls through the Go proxy"
echo "  - initialize, tools/list (passthrough)"
echo "  - read_file (allowed, low risk)"
echo "  - write_file (allowed, medium risk — custom pattern)"
echo "  - delete_file (policy denied)"
echo "  - run_shell (policy denied)"
echo "  - write_file with /etc/ path (risk denied — custom keyword boost)"
echo ""

(
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"e2e","version":"1.0"}}}'
echo '{"jsonrpc":"2.0","method":"notifications/initialized"}'
echo '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
echo '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/safe.txt"}}}'
echo '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"/tmp/out.txt","content":"hello"}}}'
echo '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"delete_file","arguments":{"path":"/important.dat"}}}'
echo '{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"run_shell","arguments":{"command":"ls"}}}'
echo '{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"/etc/passwd","content":"hacked"}}}'
) | $PROXY --name e2e-server --policy "$TMPDIR/policy.json" -- node "$TMPDIR/mcp-server.js" 2>"$TMPDIR/proxy-stderr.txt" | while read -r line; do
  echo "  > $line" | head -c 120
  echo ""
done

echo ""
echo "Step 2: Check proxy logs"
echo "---"
cat "$TMPDIR/proxy-stderr.txt"
echo "---"

echo ""
echo "Step 3: Verify audit log entries"
echo ""
ENTRIES=$(sqlite3 "$TMPDIR/quint.db" "SELECT id, direction, tool_name, verdict, risk_score, risk_level FROM audit_log ORDER BY id" 2>/dev/null)
echo "$ENTRIES" | while read -r line; do
  echo "  $line"
done
TOTAL=$(sqlite3 "$TMPDIR/quint.db" "SELECT COUNT(*) FROM audit_log" 2>/dev/null)
echo ""
echo "  Total entries: $TOTAL"

echo ""
echo "Step 4: Verify signatures (Go-signed entries verified by TS CLI)"
echo ""
QUINT_DATA_DIR="$TMPDIR" $QUINT_CLI verify --all 2>&1 | head -5

echo ""
echo "Step 5: Verify chain integrity"
echo ""
QUINT_DATA_DIR="$TMPDIR" $QUINT_CLI verify --all --chain 2>&1 | grep -E "Signatures|Chain"

echo ""
echo "Step 6: Sync to API server"
echo ""
QUINT_DATA_DIR="$TMPDIR" $QUINT_CLI sync --api-url "$API_URL" --api-key "$API_KEY" --verbose 2>&1

echo ""
echo "Step 7: Query API to confirm entries arrived"
echo ""
STATS=$(curl -s -H "Authorization: Bearer $API_KEY" "$API_URL/v1/stats")
echo "  API Stats: $STATS" | python3 -m json.tool 2>/dev/null || echo "  $STATS"

echo ""
echo "============================================"
echo "  Full E2E Complete"
echo "============================================"
