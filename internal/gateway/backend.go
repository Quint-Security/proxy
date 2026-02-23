package gateway

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/Quint-Security/quint-proxy/internal/credential"
	qlog "github.com/Quint-Security/quint-proxy/internal/log"
)

const maxLineSize = 10 * 1024 * 1024

// Tool represents a tool from a downstream server, namespaced.
type Tool struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	InputSchema map[string]any `json:"inputSchema,omitempty"`
}

// Backend is a connection to a downstream MCP server.
type Backend interface {
	// Name returns the server name (namespace prefix).
	Name() string
	// Start starts the backend connection.
	Start() error
	// Stop stops the backend.
	Stop()
	// Tools returns the tools this backend provides.
	Tools() []Tool
	// Call sends a tools/call and returns the JSON-RPC response.
	Call(id json.RawMessage, toolName string, arguments json.RawMessage) (json.RawMessage, error)
	// Forward sends a raw JSON-RPC message and returns the response.
	Forward(msg json.RawMessage) (json.RawMessage, error)
}

// --- Stdio Backend ---

// StdioBackend manages a child MCP server process via stdio.
type StdioBackend struct {
	name    string
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	stdout  *bufio.Scanner
	tools   []Tool
	mu      sync.Mutex
	pending map[string]chan json.RawMessage
	nextID  int64
	config  ServerConfig
}

// NewStdioBackend creates a new stdio backend.
func NewStdioBackend(name string, cfg ServerConfig) *StdioBackend {
	return &StdioBackend{
		name:    name,
		config:  cfg,
		pending: make(map[string]chan json.RawMessage),
	}
}

func (b *StdioBackend) Name() string { return b.name }

func (b *StdioBackend) Start() error {
	b.cmd = exec.Command(b.config.Command, b.config.Args...)
	b.cmd.Stderr = os.Stderr

	// Merge env
	env := os.Environ()
	for k, v := range b.config.Env {
		env = append(env, fmt.Sprintf("%s=%s", k, v))
	}
	b.cmd.Env = env

	var err error
	b.stdin, err = b.cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("stdin pipe: %w", err)
	}

	stdoutPipe, err := b.cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}

	if err := b.cmd.Start(); err != nil {
		return fmt.Errorf("start %s: %w", b.config.Command, err)
	}

	b.stdout = bufio.NewScanner(stdoutPipe)
	b.stdout.Buffer(make([]byte, 0, 64*1024), maxLineSize)

	// Read responses in background
	go b.readLoop()

	// Initialize the MCP session
	if err := b.initialize(); err != nil {
		b.Stop()
		return fmt.Errorf("initialize %s: %w", b.name, err)
	}

	// Enumerate tools
	if err := b.listTools(); err != nil {
		qlog.Error("failed to list tools for %s: %v", b.name, err)
	}

	return nil
}

func (b *StdioBackend) Stop() {
	if b.stdin != nil {
		b.stdin.Close()
	}
	if b.cmd != nil && b.cmd.Process != nil {
		b.cmd.Process.Kill()
	}
}

func (b *StdioBackend) Tools() []Tool { return b.tools }

func (b *StdioBackend) Call(id json.RawMessage, toolName string, arguments json.RawMessage) (json.RawMessage, error) {
	req := map[string]any{
		"jsonrpc": "2.0",
		"id":      json.RawMessage(b.allocID()),
		"method":  "tools/call",
		"params": map[string]any{
			"name":      toolName,
			"arguments": json.RawMessage(arguments),
		},
	}
	return b.sendAndWait(req)
}

func (b *StdioBackend) Forward(msg json.RawMessage) (json.RawMessage, error) {
	return b.sendRaw(msg)
}

func (b *StdioBackend) readLoop() {
	for b.stdout.Scan() {
		line := b.stdout.Text()
		if line == "" {
			continue
		}

		// Parse to find the ID
		var msg map[string]json.RawMessage
		if err := json.Unmarshal([]byte(line), &msg); err != nil {
			continue
		}

		idRaw, hasID := msg["id"]
		if !hasID {
			continue // notification, skip
		}

		idStr := strings.Trim(string(idRaw), `"`)

		b.mu.Lock()
		ch, ok := b.pending[idStr]
		if ok {
			delete(b.pending, idStr)
		}
		b.mu.Unlock()

		if ok {
			ch <- json.RawMessage(line)
		}
	}
}

func (b *StdioBackend) allocID() string {
	b.mu.Lock()
	b.nextID++
	id := fmt.Sprintf("q_%s_%d", b.name, b.nextID)
	b.mu.Unlock()
	return `"` + id + `"`
}

func (b *StdioBackend) sendAndWait(req map[string]any) (json.RawMessage, error) {
	data, _ := json.Marshal(req)

	// Extract the ID for matching
	idRaw, _ := req["id"]
	idBytes, _ := json.Marshal(idRaw)
	idStr := strings.Trim(string(idBytes), `"`)

	ch := make(chan json.RawMessage, 1)
	b.mu.Lock()
	b.pending[idStr] = ch
	b.mu.Unlock()

	b.mu.Lock()
	_, err := fmt.Fprintf(b.stdin, "%s\n", data)
	b.mu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("write to %s: %w", b.name, err)
	}

	select {
	case resp := <-ch:
		return resp, nil
	case <-time.After(30 * time.Second):
		b.mu.Lock()
		delete(b.pending, idStr)
		b.mu.Unlock()
		return nil, fmt.Errorf("timeout waiting for response from %s", b.name)
	}
}

func (b *StdioBackend) sendRaw(msg json.RawMessage) (json.RawMessage, error) {
	var parsed map[string]any
	json.Unmarshal(msg, &parsed)
	return b.sendAndWait(parsed)
}

func (b *StdioBackend) initialize() error {
	req := map[string]any{
		"jsonrpc": "2.0",
		"id":      json.RawMessage(b.allocID()),
		"method":  "initialize",
		"params": map[string]any{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]any{},
			"clientInfo": map[string]any{
				"name":    "quint-gateway",
				"version": "1.0.0",
			},
		},
	}

	resp, err := b.sendAndWait(req)
	if err != nil {
		return err
	}

	// Send initialized notification
	notif, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"method":  "notifications/initialized",
	})
	b.mu.Lock()
	fmt.Fprintf(b.stdin, "%s\n", notif)
	b.mu.Unlock()

	_ = resp
	return nil
}

func (b *StdioBackend) listTools() error {
	req := map[string]any{
		"jsonrpc": "2.0",
		"id":      json.RawMessage(b.allocID()),
		"method":  "tools/list",
	}

	resp, err := b.sendAndWait(req)
	if err != nil {
		return err
	}

	var parsed struct {
		Result struct {
			Tools []Tool `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(resp, &parsed); err != nil {
		return fmt.Errorf("parse tools/list response: %w", err)
	}

	b.tools = parsed.Result.Tools
	qlog.Info("  %s: %d tools", b.name, len(b.tools))
	return nil
}

// --- HTTP Backend ---

// HTTPBackend connects to a remote HTTP MCP server.
type HTTPBackend struct {
	name      string
	config    ServerConfig
	tools     []Tool
	client    *http.Client
	session   string // Mcp-Session header
	credStore *credential.Store
}

// NewHTTPBackend creates a new HTTP backend.
func NewHTTPBackend(name string, cfg ServerConfig, credStore *credential.Store) *HTTPBackend {
	return &HTTPBackend{
		name:      name,
		config:    cfg,
		client:    &http.Client{Timeout: 60 * time.Second},
		credStore: credStore,
	}
}

func (b *HTTPBackend) Name() string { return b.name }

func (b *HTTPBackend) Start() error {
	// Initialize the MCP session
	initReq := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]any{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]any{},
			"clientInfo": map[string]any{
				"name":    "quint-gateway",
				"version": "1.0.0",
			},
		},
	}

	resp, err := b.post(initReq)
	if err != nil {
		return fmt.Errorf("initialize %s: %w", b.name, err)
	}
	_ = resp

	// Send initialized notification
	notif := map[string]any{
		"jsonrpc": "2.0",
		"method":  "notifications/initialized",
	}
	b.post(notif)

	// List tools
	toolsReq := map[string]any{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/list",
	}
	toolsResp, err := b.post(toolsReq)
	if err != nil {
		qlog.Error("failed to list tools for %s: %v", b.name, err)
		return nil
	}

	var parsed struct {
		Result struct {
			Tools []Tool `json:"tools"`
		} `json:"result"`
	}
	json.Unmarshal(toolsResp, &parsed)
	b.tools = parsed.Result.Tools
	qlog.Info("  %s: %d tools (HTTP)", b.name, len(b.tools))

	return nil
}

func (b *HTTPBackend) Stop() {}

func (b *HTTPBackend) Tools() []Tool { return b.tools }

func (b *HTTPBackend) Call(id json.RawMessage, toolName string, arguments json.RawMessage) (json.RawMessage, error) {
	req := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      toolName,
			"arguments": json.RawMessage(arguments),
		},
	}
	return b.post(req)
}

func (b *HTTPBackend) Forward(msg json.RawMessage) (json.RawMessage, error) {
	var req map[string]any
	json.Unmarshal(msg, &req)
	return b.post(req)
}

func (b *HTTPBackend) post(body any) (json.RawMessage, error) {
	data, _ := json.Marshal(body)

	req, _ := http.NewRequest("POST", b.config.URL, bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")

	// Add configured headers (auth tokens, etc.)
	for k, v := range b.config.Headers {
		req.Header.Set(k, v)
	}

	// Pull token from credential store if available
	if b.credStore != nil && req.Header.Get("Authorization") == "" {
		if token, err := b.credStore.GetAccessToken(b.name); err == nil && token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
	}

	// Include session header if we have one
	if b.session != "" {
		req.Header.Set("Mcp-Session", b.session)
	}

	resp, err := b.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Capture session header
	if s := resp.Header.Get("Mcp-Session"); s != "" {
		b.session = s
	}

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 && resp.StatusCode != 202 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody[:min(200, len(respBody))]))
	}

	return json.RawMessage(respBody), nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
