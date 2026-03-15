# PLAN: Expand LLM Parsers to Cover All Major AI Providers

## Overview

Expand `internal/llmparse/` to handle ALL major AI providers: OpenAI Responses API, Google Gemini, Azure OpenAI, Bedrock Converse, and a generic fallback parser for unknown providers. Add streaming support for tool call detection.

### Current State
- `types.go` — `AgentEvent` and `ParseResult` structs (no `Provider` field)
- `parser.go` — `Parse()` router: matches host to Anthropic, Bedrock (reuses Anthropic), or OpenAI
- `anthropic.go` — Anthropic Messages API (snake_case `tool_use`/`tool_result`) + SSE streaming
- `openai.go` — OpenAI Chat Completions API (`tool_calls`/`tool` role messages)

The router signature is `Parse(host string, reqBody []byte, userAgent string) *ParseResult`. The call site in `proxy.go` passes domain, body, and User-Agent but **not** `req.URL.Path`.

---

## 1. Files to Create

| File | Purpose |
|------|---------|
| `internal/llmparse/openai_responses.go` | OpenAI Responses API parser (`/v1/responses`) |
| `internal/llmparse/openai_responses_test.go` | Tests with real-world payloads |
| `internal/llmparse/gemini.go` | Google Gemini API parser (`functionCall`/`functionResponse`) |
| `internal/llmparse/gemini_test.go` | Tests with real-world payloads |
| `internal/llmparse/bedrock_converse.go` | Bedrock Converse API parser (camelCase `toolUse`/`toolResult`) |
| `internal/llmparse/bedrock_converse_test.go` | Tests with real-world payloads |
| `internal/llmparse/generic.go` | Generic fallback parser for unknown providers |
| `internal/llmparse/generic_test.go` | Tests including conservative false-positive avoidance |
| `internal/llmparse/streaming.go` | Shared streaming buffer/accumulator types + SSE utilities |
| `internal/llmparse/streaming_test.go` | Tests for streaming utilities |
| `internal/llmparse/openai_stream.go` | OpenAI streaming response parser (tool_calls deltas) |
| `internal/llmparse/openai_stream_test.go` | Tests |
| `internal/llmparse/gemini_stream.go` | Gemini streaming response parser |
| `internal/llmparse/gemini_stream_test.go` | Tests |

## 2. Files to Modify

| File | Changes |
|------|---------|
| `internal/llmparse/types.go` | Add `Provider` field to `ParseResult` |
| `internal/llmparse/parser.go` | Rewrite router with path → host → body → generic fallback; accept `path` param |
| `internal/llmparse/anthropic.go` | Set `Provider` on `ParseResult` |
| `internal/llmparse/openai.go` | Set `Provider` on `ParseResult` |
| `internal/forwardproxy/passthrough.go` | Add `*.openai.azure.com` to `llmProviderDomains` |
| `internal/forwardproxy/proxy.go` | Pass `req.URL.Path` to new `Parse()` signature (line ~1249) |
| Existing test files | Update `Parse()` calls with new `path` argument |

---

## 3. Step-by-Step Implementation Order

### Phase 1: Foundation (types, router signature, no breaking changes)

#### Step 1.1: Extend `types.go`

Add `Provider` field to `ParseResult`:
```go
type ParseResult struct {
    Events   []AgentEvent
    Model    string
    Agent    string
    Provider string // "anthropic", "openai", "openai-responses", "google-gemini",
                    // "aws-bedrock-converse", "azure-openai", "generic"
}
```

#### Step 1.2: Update `parser.go` router signature

Change `Parse` to:
```go
func Parse(host, path string, reqBody []byte, userAgent string) *ParseResult
```

Only one call site (`proxy.go` line ~1249), so direct signature change is clean.

#### Step 1.3: Update call site in `proxy.go`

Change:
```go
llmparse.Parse(domain, llmBodyBytes, req.Header.Get("User-Agent"))
```
to:
```go
llmparse.Parse(domain, req.URL.Path, llmBodyBytes, req.Header.Get("User-Agent"))
```

#### Step 1.4: Set `Provider` on existing parsers

- `anthropic.go` → `result.Provider = "anthropic"`
- `openai.go` → `result.Provider = "openai"`

#### Step 1.5: Update existing tests

Update router tests to pass new `path` argument.

---

### Phase 2: New Parsers (one at a time, each with tests)

#### Step 2.1: OpenAI Responses API (`openai_responses.go`)

**Detection:** Path contains `/v1/responses` OR body has `"input"` field and no `"messages"` field.

**Request format:**
```json
{
    "model": "gpt-4.1",
    "input": "delete the temp files",
    "tools": [{"type": "function", "name": "shell", ...}]
}
```

**Response format:**
```json
{
    "output": [
        {"type": "function_call", "id": "fc_01", "name": "shell", "arguments": "{\"command\": \"rm -rf /tmp/*\"}"},
        {"type": "function_call_output", "call_id": "fc_01", "output": "deleted 47 files"}
    ]
}
```

**Parser logic:**
1. Unmarshal body. If `Input` empty or body also has `"messages"`, return nil.
2. Try `Input` as string (simple prompt, no tool calls — return empty).
3. Try `Input` as `[]responsesOutput`.
4. Collect `function_call` items, pair with `function_call_output` by `call_id`/`id`.
5. Return last function_call + output as event.
6. Set `Provider = "openai-responses"`.

**Tests:** Single function_call with output, multiple (return last), without output (pending), string input, mixed types, malformed JSON, empty body, router detection via path and body sniffing.

#### Step 2.2: Google Gemini API (`gemini.go`)

**Detection:** Host contains `googleapis.com` OR body has `"contents"` field OR path contains `:generateContent`.

**Request format:**
```json
{
    "contents": [
        {"role": "user", "parts": [{"text": "list files"}]},
        {"role": "model", "parts": [{"functionCall": {"name": "bash", "args": {"command": "ls"}}}]},
        {"role": "user", "parts": [{"functionResponse": {"name": "bash", "response": {"result": "file1.txt"}}}]}
    ]
}
```

**Parser logic:**
1. Unmarshal as `geminiRequest`.
2. Walk `Contents` in order. Track last `functionCall` in `"model"` role.
3. Check `"user"` messages for matching `functionResponse` by name.
4. Return last pair as event.
5. Model: try body `model` field, fall back to path extraction (`/models/{model}:generateContent`).
6. Set `Provider = "google-gemini"`.

**Tests:** Single call+response, multiple (return last), text-only, pending call, model extraction, router detection via host/path/body.

#### Step 2.3: Bedrock Converse API (`bedrock_converse.go`)

**Detection:** Body has `"toolUse"` (camelCase) — distinguishes from Anthropic's `"tool_use"` (snake_case). Host is Bedrock + camelCase body.

**Request format:**
```json
{
    "messages": [
        {"role": "assistant", "content": [{"toolUse": {"toolUseId": "tu_01", "name": "Bash", "input": {"command": "ls"}}}]},
        {"role": "user", "content": [{"toolResult": {"toolUseId": "tu_01", "content": [{"text": "file.txt"}]}}]}
    ]
}
```

**Parser logic:** Mirrors Anthropic but reads camelCase fields. Set `Provider = "aws-bedrock-converse"`.

**Tests:** Single toolUse+toolResult, multiple, camelCase detection, router disambiguation from Anthropic, malformed JSON.

#### Step 2.4: Generic Parser (`generic.go`)

**Conservative heuristic for unknown providers.**

Strategy:
1. Unmarshal body as `map[string]interface{}`.
2. Recursive key scan for: `"tool_use"`, `"tool_calls"`, `"function_call"`, `"functionCall"`, `"tool_result"`, `"function_call_output"`, `"functionResponse"`, `"toolResult"`.
3. If found, extract `name` + `arguments`/`input`/`args`.
4. Require at least a tool name to emit an event.
5. Return nil if nothing looks like a tool call.
6. Set `Provider = "generic"`.

**Design:** Conservative — better to miss a tool call than false-positive.

**Tests:** Body with `tool_calls`, `function_call`, `functionCall`, no patterns (nil), deeply nested (nil), non-JSON (nil), empty JSON (nil).

#### Step 2.5: Azure OpenAI routing

No new parser file. Azure uses same format as OpenAI.

Changes:
- `passthrough.go`: Add `*.openai.azure.com` to `llmProviderDomains` via suffix match:
  ```go
  if strings.HasSuffix(domain, ".openai.azure.com") { return true }
  ```
- `parser.go` router: Case for `openai.azure.com` → `ParseOpenAIRequest` with `Provider = "azure-openai"`

---

### Phase 3: Router Decision Tree

#### Step 3.1: Implement new router in `parser.go`

**Detection priority (path → host → body → generic):**

```
Parse(host, path, body, userAgent)
  │
  ├─ body empty? → nil
  │
  ├─ PATH MATCH (highest priority, unambiguous):
  │   ├─ /v1/responses                          → OpenAI Responses
  │   ├─ :generateContent / :streamGenerateContent → Gemini
  │   └─ /converse + bedrock host                → Bedrock Converse
  │
  ├─ HOST MATCH (current behavior, preserved):
  │   ├─ anthropic.com                           → Anthropic
  │   ├─ bedrock.*.amazonaws.com
  │   │   ├─ body has "toolUse" (camelCase)      → Bedrock Converse
  │   │   └─ else                                → Anthropic (raw passthrough)
  │   ├─ *.openai.azure.com                      → OpenAI (Provider="azure-openai")
  │   ├─ openai.com                              → OpenAI
  │   ├─ googleapis.com                          → Gemini
  │   └─ mistral.ai                              → OpenAI (compatible format)
  │
  ├─ BODY SNIFF (content detection for unknown hosts):
  │   ├─ has "contents" key                      → Gemini
  │   ├─ has "input" AND no "messages"           → OpenAI Responses
  │   └─ has "toolUse" substring                 → Bedrock Converse
  │
  └─ GENERIC FALLBACK                            → Generic (conservative)
```

Implementation: `detectFormat(host, path string, body []byte) string` returns format ID. Switch dispatches to correct parser. Body sniffing uses `bytes.Contains` (cheaper than full unmarshal).

```go
func Parse(host, path string, reqBody []byte, userAgent string) *ParseResult {
    if len(reqBody) == 0 { return nil }
    host = strings.ToLower(host)
    path = strings.ToLower(path)

    format := detectFormat(host, path, reqBody)

    var result *ParseResult
    switch format {
    case "anthropic":
        result, _ = ParseAnthropicRequest(reqBody, userAgent)
    case "openai":
        result, _ = ParseOpenAIRequest(reqBody, userAgent)
    case "openai-responses":
        result, _ = ParseOpenAIResponsesRequest(reqBody, userAgent)
    case "azure-openai":
        result, _ = ParseOpenAIRequest(reqBody, userAgent)
        if result != nil { result.Provider = "azure-openai" }
    case "gemini":
        result, _ = ParseGeminiRequest(reqBody, path, userAgent)
    case "bedrock-converse":
        result, _ = ParseConverseRequest(reqBody, userAgent)
    case "generic":
        result, _ = ParseGenericRequest(reqBody, userAgent)
    default:
        return nil
    }
    return result
}
```

---

### Phase 4: Streaming Support

#### Step 4.1: Streaming architecture

Create `internal/llmparse/streaming.go` with shared utilities:

```go
type StreamAccumulator struct {
    provider string
    pending  map[int]*pendingToolCall
    complete []AgentEvent
}

type pendingToolCall struct {
    id        string
    name      string
    argChunks []string
}

func (a *StreamAccumulator) ParseSSELine(line []byte) bool
func (a *StreamAccumulator) Events() []AgentEvent
```

#### Step 4.2: Provider-specific streaming

**Anthropic** (refactor existing `ParseAnthropicStreamResponse` to use `StreamAccumulator`).

**OpenAI** (`openai_stream.go`): Accumulate `tool_calls` delta chunks per index. Emit on `[DONE]` or new tool index.

**Gemini** (`gemini_stream.go`): Each SSE `data:` line with `functionCall` is complete (no delta assembly).

#### Step 4.3: Proxy wiring (deferred)

Implement streaming parsers now, defer proxy wiring to follow-up. Parsers tested independently. Proxy can be wired later by detecting SSE responses and routing to stream parsers.

---

## 4. Streaming Buffering Strategy

**For SSE streams (`Content-Type: text/event-stream`):**
1. `TeeReader` copies bytes to buffer while forwarding to client (non-blocking)
2. After response fully streamed, parse buffered SSE data
3. Cap buffer at 10MB to prevent OOM

**Chunk assembly for tool call deltas (OpenAI/Anthropic):**
- `StreamAccumulator` with per-index pending slots
- Accumulate `arguments` string fragments
- Emit on `content_block_stop` (Anthropic) or `[DONE]`/new index (OpenAI)

---

## 5. Test Strategy

### Per-parser test files with real-world payloads:

**OpenAI Responses** (`openai_responses_test.go`):
- Single function_call with output
- Multiple function_calls, return last
- function_call without output (pending)
- String input (no tool calls)
- Array input with mixed types
- Malformed JSON, empty body
- Router detection via path (`/v1/responses`) and body sniffing

**Gemini** (`gemini_test.go`):
- Single functionCall with functionResponse
- Multiple functionCalls, return last pair
- Text-only (no tool calls)
- functionCall without functionResponse
- Model from path (`/models/gemini-2.0-flash:generateContent`)
- Router detection via host, path, body

**Bedrock Converse** (`bedrock_converse_test.go`):
- Single toolUse with toolResult
- Multiple toolUse blocks
- camelCase vs snake_case disambiguation
- Malformed JSON, empty messages

**Generic** (`generic_test.go`):
- Body with `tool_calls`, `function_call`, `functionCall` patterns
- No tool call patterns → nil
- Deeply nested → nil (conservative)
- Non-JSON → nil, empty JSON → nil

**Router** (new `router_test.go` or in existing files):
- All host-based routes
- All path-based routes
- Body sniffing routes
- Generic fallback
- Azure OpenAI, Mistral routing
- Priority: path > host > body > generic

**Streaming** (`openai_stream_test.go`, `gemini_stream_test.go`):
- Complete SSE stream with tool call deltas
- No tool calls in stream
- Partial/incomplete stream
- Multiple tool calls in one stream

---

## 6. Edge Cases

| Edge Case | Handling |
|-----------|----------|
| Empty response body | Return nil |
| Malformed JSON | Return nil, no panic (wrap `json.Unmarshal` errors) |
| Partial tool call (no arguments) | Emit with `ToolArgs = "{}"` |
| Tool call without result | Emit with empty `ToolResult` |
| Mixed content (text + tool_use) | Extract only tool call blocks |
| Very large body (>10MB) | Already capped by proxy |
| Very large tool result | Truncate to 10KB using existing `truncate()` helper |
| Unknown JSON structure | Generic returns nil (conservative) |
| Bedrock ambiguity | `bytes.Contains` for `"toolUse"` to disambiguate |
| Azure OpenAI path variations | Suffix match `*.openai.azure.com`; body format identical to OpenAI |
| Responses API with `"messages"` | If both `"input"` and `"messages"`, prefer Chat Completions |
| Gemini model in path vs body | Try body first, fall back to path segment |
| Concurrent parsing | All parsers are stateless functions; `StreamAccumulator` is per-response |

---

## 7. Dependencies and Sequencing

```
Phase 1 (Foundation)        Phase 2 (Parsers)            Phase 3 (Router)      Phase 4 (Streaming)
  types.go changes     ──→   openai_responses.go    ──→   parser.go rewrite ──→  streaming.go
  parser.go signature  ──→   gemini.go              ──→   router tests          openai_stream.go
  proxy.go call site   ──→   bedrock_converse.go                                gemini_stream.go
  passthrough.go azure ──→   generic.go                                          (proxy wiring deferred)
  existing parser fixes──→   all _test.go files
```

Phase 1 must be done first (signature change). Phase 2 parsers are independent of each other (parallelizable). Phase 3 depends on all parsers. Phase 4 is an independent enhancement.

---

## 8. Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| Breaking existing parsers | Preserve existing tests verbatim; run full suite after each change |
| Body sniffing false positives | Path/host checks take priority; generic is conservative |
| Performance of body scanning | `bytes.Contains` on 10MB is O(n) but runs once per request; negligible vs network |
| `detectFormat` maintenance burden | Pure function with clear priority; well-tested |
| Streaming parser complexity | Defer proxy wiring; implement and test parsers independently |
