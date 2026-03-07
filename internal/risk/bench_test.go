package risk

import (
	"encoding/json"
	"fmt"
	"testing"
)

// --- Benchmark: ScoreToolCall ---

func BenchmarkScoreToolCall_ReadFile(b *testing.B) {
	e := NewEngine(nil)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.ScoreToolCall("ReadFile", "", "bench-agent")
	}
}

func BenchmarkScoreToolCall_DeleteFile(b *testing.B) {
	e := NewEngine(nil)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.ScoreToolCall("DeleteFile", "", "bench-agent")
	}
}

func BenchmarkScoreToolCall_WithArgs(b *testing.B) {
	e := NewEngine(nil)
	args := `{"path":"/etc/passwd","content":"password=secret123","query":"DROP TABLE users"}`
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.ScoreToolCall("WriteFile", args, "bench-agent")
	}
}

func BenchmarkScoreToolCall_UnknownTool(b *testing.B) {
	e := NewEngine(nil)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.ScoreToolCall("CompletelyUnknownTool", "", "bench-agent")
	}
}

func BenchmarkScoreToolCall_WithHTTPPatterns(b *testing.B) {
	e := NewEngine(&EngineOpts{IncludeHTTP: true})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.ScoreToolCall("http:api.github.com:post.repos", "", "bench-agent")
	}
}

// --- Benchmark: ScoreWithContext ---

func BenchmarkScoreWithContext(b *testing.B) {
	e := NewEngine(nil)
	st := NewSessionTracker(20, 0)
	ctx := &EventContext{
		AgentID:    "test-agent",
		ServerName: "github",
		Transport:  "http",
		ToolName:   "list_repos",
		Depth:      2,
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.ScoreWithContext("list_repos", `{"org":"test"}`, "bench-agent", ctx, st)
	}
}

// --- Benchmark: ExtractFields ---

func BenchmarkExtractFields_Empty(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ExtractFields("{}")
	}
}

func BenchmarkExtractFields_Simple(b *testing.B) {
	args := `{"email":"user@example.com","name":"John","path":"/tmp/test"}`
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ExtractFields(args)
	}
}

func BenchmarkExtractFields_Sensitive(b *testing.B) {
	args := `{"password":"secret","api_key":"sk-123","ssn":"123-45-6789","credit_card":"4111-1111-1111-1111","email":"user@test.com","phone":"555-123-4567"}`
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ExtractFields(args)
	}
}

func BenchmarkExtractFields_LargePayload(b *testing.B) {
	// Simulate a large tool call payload
	args := `{"query":"SELECT * FROM users WHERE email = 'admin@test.com' AND password = 'secret'","database":"production","table":"users","options":{"limit":100,"offset":0,"sort":"created_at","include_deleted":true},"metadata":{"source":"api","version":"2.0","request_id":"abc-123"}}`
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ExtractFields(args)
	}
}

// --- Benchmark: ExtractTarget ---

func BenchmarkExtractTarget(b *testing.B) {
	fields := []ClassifiedField{
		{Field: "email", Classification: "pii"},
		{Field: "password", Classification: "auth"},
	}
	args := `{"path":"/etc/passwd","database":"users"}`
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ExtractTarget("postgres", "execute_query", args, fields)
	}
}

// --- Benchmark: SessionTracker ---

func BenchmarkSessionTracker_Record(b *testing.B) {
	st := NewSessionTracker(20, 0)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		st.Record("bench-agent", fmt.Sprintf("mcp:github:list_repos.list.%d", i%20))
	}
}

func BenchmarkSessionTracker_Recent(b *testing.B) {
	st := NewSessionTracker(20, 0)
	for i := 0; i < 20; i++ {
		st.Record("bench-agent", fmt.Sprintf("mcp:github:tool_%d.invoke", i))
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		st.Recent("bench-agent")
	}
}

func BenchmarkSessionTracker_RecordAndRecent(b *testing.B) {
	st := NewSessionTracker(20, 0)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		st.Record("bench-agent", "mcp:github:list_repos.list")
		st.Recent("bench-agent")
	}
}

func BenchmarkSessionTracker_DetectBurst(b *testing.B) {
	st := NewSessionTracker(20, 0)
	for i := 0; i < 10; i++ {
		st.Record("bench-agent", fmt.Sprintf("mcp:github:tool_%d.invoke", i))
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		st.DetectDelegationBurst("bench-agent")
	}
}

// --- Benchmark: BehaviorTracker (in-memory) ---

func BenchmarkBehaviorTracker_Record(b *testing.B) {
	bt := NewBehaviorTracker(5*60*1000, nil)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bt.Record("bench-agent")
	}
}

func BenchmarkBehaviorTracker_Count(b *testing.B) {
	bt := NewBehaviorTracker(5*60*1000, nil)
	for i := 0; i < 10; i++ {
		bt.Record("bench-agent")
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bt.Count("bench-agent")
	}
}

// --- Benchmark: RemoteScorer payload construction ---

func BenchmarkBuildRemotePayload(b *testing.B) {
	// Benchmark just the payload construction part of EnhanceScore
	args := `{"path":"/etc/passwd","content":"password=secret"}`
	ctx := &EventContext{
		AgentID:          "test-agent",
		AgentType:        "claude",
		ServerName:       "filesystem",
		Transport:        "stdio",
		IsVerified:       true,
		ToolName:         "write_file",
		PrecedingActions: []string{"mcp:filesystem:read_file.read", "mcp:filesystem:list_files.list"},
		SessionID:        "session-123",
		CanonicalAction:  "mcp:filesystem:write_file.write",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		classifiedFields := ExtractFields(args)
		target := ExtractTarget("filesystem", "write_file", args, classifiedFields)

		req := eventRequest{
			EventID:    fmt.Sprintf("%s:%s:%d", ctx.ServerName, ctx.ToolName, 1234567890),
			CustomerID: "test-customer",
			AgentID:    ctx.AgentID,
			Action:     ctx.CanonicalAction,
			Timestamp:  "2024-01-01T00:00:00Z",
			Metadata: map[string]any{
				"local_score": 50,
				"local_level": "medium",
			},
			Parameters:         json.RawMessage(args),
			DataFieldsAccessed: classifiedFields,
			PrecedingActions:   ctx.PrecedingActions,
		}

		if target != nil {
			req.Target = &TargetInfoPayload{
				ResourceType:     target.ResourceType,
				ResourceID:       target.ResourceID,
				SensitivityLevel: target.SensitivityLevel,
			}
		}

		req.Agent = &AgentInfoPayload{
			AgentID:   ctx.AgentID,
			AgentType: ctx.AgentType,
			Framework: "quint-proxy",
		}
		req.Session = &SessionInfoPayload{SessionID: ctx.SessionID}
		req.MCPContext = &MCPContextPayload{
			ServerName: ctx.ServerName,
			Transport:  ctx.Transport,
			IsVerified: ctx.IsVerified,
			ToolName:   ctx.ToolName,
		}

		json.Marshal(req)
	}
}

// --- Benchmark: sanitize ---

func BenchmarkSanitize(b *testing.B) {
	inputs := []string{
		"simple",
		"my-server-name",
		"my:server:name",
		"My Server Name/Path",
		"already_clean",
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sanitize(inputs[i%len(inputs)])
	}
}

// --- Benchmark: Full pipeline (ScoreToolCall + ExtractFields + ExtractTarget) ---

func BenchmarkFullScoringPipeline(b *testing.B) {
	e := NewEngine(nil)
	st := NewSessionTracker(20, 0)
	args := `{"path":"/etc/passwd","content":"password=secret123","query":"SELECT * FROM users"}`
	ctx := &EventContext{
		AgentID:    "test-agent",
		ServerName: "filesystem",
		Transport:  "stdio",
		ToolName:   "write_file",
		Depth:      1,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// This is the full hot path that happens on every tool call
		score := e.ScoreWithContext("write_file", args, "bench-agent", ctx, st)
		_ = ExtractFields(args)
		_ = ExtractTarget("filesystem", "write_file", args, nil)
		st.Record("bench-agent", "mcp:filesystem:write_file.write")
		_ = st.Recent("bench-agent")
		_ = score
	}
}

// --- Benchmark: Parallel scoring (simulating concurrent gateway requests) ---

func BenchmarkScoreToolCall_Parallel(b *testing.B) {
	e := NewEngine(nil)
	args := `{"path":"/tmp/test.txt","content":"hello world"}`
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			e.ScoreToolCall("WriteFile", args, fmt.Sprintf("agent-%d", i%100))
			i++
		}
	})
}

func BenchmarkSessionTracker_Parallel(b *testing.B) {
	st := NewSessionTracker(20, 0)
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			key := fmt.Sprintf("agent-%d", i%50)
			st.Record(key, "mcp:github:list_repos.list")
			st.Recent(key)
			i++
		}
	})
}
