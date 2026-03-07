package intercept

import (
	"encoding/json"
	"fmt"
	"testing"
)

// --- Benchmark: ClassifyAction ---

func BenchmarkClassifyAction_ToolsCall(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ClassifyAction("github", "list_repos", "tools/call")
	}
}

func BenchmarkClassifyAction_ResourceRead(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ClassifyAction("github", "", "resources/read")
	}
}

func BenchmarkClassifyAction_Dirty(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ClassifyAction("my-server:name", "my-tool:name", "tools/call")
	}
}

func BenchmarkClassifyHTTPAction(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ClassifyHTTPAction("POST", "api.github.com:443", "/v1/repos/owner/name/pulls")
	}
}

// --- Benchmark: sanitizeSegment ---

func BenchmarkSanitizeSegment_Clean(b *testing.B) {
	for i := 0; i < b.N; i++ {
		sanitizeSegment("already_clean")
	}
}

func BenchmarkSanitizeSegment_Dirty(b *testing.B) {
	for i := 0; i < b.N; i++ {
		sanitizeSegment("My-Server:Name/Path")
	}
}

// --- Benchmark: inferVerb ---

func BenchmarkInferVerb_Known(b *testing.B) {
	for i := 0; i < b.N; i++ {
		inferVerb("list_repos")
	}
}

func BenchmarkInferVerb_Unknown(b *testing.B) {
	for i := 0; i < b.N; i++ {
		inferVerb("do_something")
	}
}

// --- Benchmark: ParseJsonRpc ---

func BenchmarkParseJsonRpc_ToolCall(b *testing.B) {
	line := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_repos","arguments":{"org":"test"}}}`
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ParseJsonRpc(line)
	}
}

func BenchmarkParseJsonRpc_Response(b *testing.B) {
	line := `{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ParseJsonRpc(line)
	}
}

func BenchmarkParseJsonRpc_LargePayload(b *testing.B) {
	args := map[string]any{
		"query":    "SELECT * FROM users WHERE email = 'test@test.com'",
		"database": "production",
		"options": map[string]any{
			"limit": 100, "offset": 0, "timeout": 30,
		},
	}
	argsJSON, _ := json.Marshal(args)
	line := fmt.Sprintf(`{"jsonrpc":"2.0","id":42,"method":"tools/call","params":{"name":"execute_query","arguments":%s}}`, argsJSON)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ParseJsonRpc(line)
	}
}

// --- Benchmark: InspectRequest ---

func BenchmarkInspectRequest_ToolCall(b *testing.B) {
	line := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_repos","arguments":{"org":"test"}}}`
	policy := PolicyConfig{}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		InspectRequest(line, "github", policy)
	}
}

func BenchmarkInspectRequest_WithPolicy(b *testing.B) {
	line := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_file","arguments":{"path":"/important"}}}`
	policy := PolicyConfig{
		Servers: []ServerPolicy{
			{Server: "filesystem", DefaultAction: ActionDeny, Tools: []ToolRule{{Tool: "delete_*", Action: ActionDeny}}},
		},
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		InspectRequest(line, "filesystem", policy)
	}
}

// --- Benchmark: ExtractToolInfo ---

func BenchmarkExtractToolInfo(b *testing.B) {
	line := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_repos","arguments":{"org":"test"}}}`
	req, _ := ParseJsonRpc(line)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ExtractToolInfo(req)
	}
}

// --- Benchmark: GlobMatch ---

func BenchmarkGlobMatch_Exact(b *testing.B) {
	for i := 0; i < b.N; i++ {
		GlobMatch("ReadFile", "ReadFile")
	}
}

func BenchmarkGlobMatch_Prefix(b *testing.B) {
	for i := 0; i < b.N; i++ {
		GlobMatch("Read*", "ReadFile")
	}
}

func BenchmarkGlobMatch_Contains(b *testing.B) {
	for i := 0; i < b.N; i++ {
		GlobMatch("*Sql*", "ExecuteSqlQuery")
	}
}

func BenchmarkGlobMatch_NoMatch(b *testing.B) {
	for i := 0; i < b.N; i++ {
		GlobMatch("Delete*", "ReadFile")
	}
}

// --- Benchmark: Parallel InspectRequest ---

func BenchmarkInspectRequest_Parallel(b *testing.B) {
	line := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_repos","arguments":{"org":"test"}}}`
	policy := PolicyConfig{}
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			InspectRequest(line, "github", policy)
		}
	})
}
