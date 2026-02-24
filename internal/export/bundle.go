package export

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/Quint-Security/quint-proxy/internal/audit"
	"github.com/Quint-Security/quint-proxy/internal/crypto"
)

// Bundle is the top-level export format.
type Bundle struct {
	Version           int               `json:"version"`
	Format            string            `json:"format"`
	ExportedAt        string            `json:"exported_at"`
	Range             BundleRange       `json:"range"`
	Summary           BundleSummary     `json:"summary"`
	ChainVerification ChainVerification `json:"chain_verification"`
	Entries           []BundleEntry     `json:"entries"`
	PublicKey         string            `json:"public_key"`
	BundleSignature   string            `json:"bundle_signature"`
}

// BundleRange describes the time window of the export.
type BundleRange struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// BundleSummary holds aggregate statistics.
type BundleSummary struct {
	TotalEntries     int            `json:"total_entries"`
	ToolCalls        int            `json:"tool_calls"`
	Denied           int            `json:"denied"`
	Flagged          int            `json:"flagged"`
	UniqueTools      int            `json:"unique_tools"`
	UniqueServers    int            `json:"unique_servers"`
	RiskDistribution map[string]int `json:"risk_distribution"`
}

// ChainVerification holds chain integrity results.
type ChainVerification struct {
	Valid          bool     `json:"valid"`
	EntriesChecked int     `json:"entries_checked"`
	FirstID        int64   `json:"first_id"`
	LastID         int64   `json:"last_id"`
	Breaks         []int64 `json:"breaks"`
}

// BundleEntry is a single audit entry in the bundle.
type BundleEntry struct {
	ID            int64   `json:"id"`
	Timestamp     string  `json:"timestamp"`
	ServerName    string  `json:"server_name"`
	Direction     string  `json:"direction"`
	Method        string  `json:"method"`
	MessageID     *string `json:"message_id"`
	ToolName      *string `json:"tool_name"`
	ArgumentsJSON *string `json:"arguments_json"`
	ResponseJSON  *string `json:"response_json"`
	Verdict       string  `json:"verdict"`
	RiskScore     *int    `json:"risk_score"`
	RiskLevel     *string `json:"risk_level"`
	PolicyHash    string  `json:"policy_hash"`
	PrevHash      string  `json:"prev_hash"`
	Nonce         string  `json:"nonce"`
	Signature     string  `json:"signature"`
	PublicKey     string  `json:"public_key"`
	AgentID       *string `json:"agent_id"`
	AgentName     *string `json:"agent_name"`
}

// BundleVerifyResult holds the result of verifying an export bundle.
type BundleVerifyResult struct {
	BundleSignatureValid bool
	SignaturesChecked    int
	SignaturesValid      int
	SignaturesInvalid    int
	ChainValid           bool
	ChainLinksChecked    int
	ChainBreaks          int
	Errors               []string
}

// BuildBundle creates a signed export bundle from audit entries.
func BuildBundle(entries []audit.Entry, publicKey, privateKey string) (*Bundle, error) {
	now := time.Now().UTC().Format("2006-01-02T15:04:05Z")

	bundle := &Bundle{
		Version:    1,
		Format:     "quint-audit-bundle",
		ExportedAt: now,
		PublicKey:  publicKey,
	}

	// Convert entries
	bundleEntries := make([]BundleEntry, len(entries))
	for i, e := range entries {
		bundleEntries[i] = entryToBundleEntry(e)
	}
	bundle.Entries = bundleEntries

	// Compute range
	if len(entries) > 0 {
		bundle.Range = BundleRange{
			From: entries[0].Timestamp,
			To:   entries[len(entries)-1].Timestamp,
		}
	}

	// Compute summary
	bundle.Summary = computeSummary(entries)

	// Verify chain
	bundle.ChainVerification = verifyChain(entries)

	// Sign the bundle
	if err := signBundle(bundle, privateKey); err != nil {
		return nil, fmt.Errorf("sign bundle: %w", err)
	}

	return bundle, nil
}

// ParseBundle parses a JSON bundle from bytes.
func ParseBundle(data []byte) (*Bundle, error) {
	var b Bundle
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("parse bundle: %w", err)
	}
	if b.Format != "quint-audit-bundle" {
		return nil, fmt.Errorf("unknown bundle format: %q", b.Format)
	}
	return &b, nil
}

// VerifyBundle verifies a bundle's integrity entirely offline.
// Checks: bundle signature, individual entry signatures, hash chain.
func VerifyBundle(b *Bundle) *BundleVerifyResult {
	result := &BundleVerifyResult{}

	// 1. Verify bundle signature
	payload := bundlePayload{
		Version:           b.Version,
		Format:            b.Format,
		ExportedAt:        b.ExportedAt,
		Range:             b.Range,
		Summary:           b.Summary,
		ChainVerification: b.ChainVerification,
		Entries:           b.Entries,
		PublicKey:         b.PublicKey,
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("failed to marshal bundle payload: %v", err))
		return result
	}
	ok, err := crypto.VerifySignature(string(payloadBytes), b.BundleSignature, b.PublicKey)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("bundle signature verification error: %v", err))
	} else {
		result.BundleSignatureValid = ok
		if !ok {
			result.Errors = append(result.Errors, "INVALID bundle signature")
		}
	}

	// 2. Verify individual entry signatures
	for _, be := range b.Entries {
		result.SignaturesChecked++
		e := bundleEntryToEntry(be)
		if audit.VerifyEntry(&e) {
			result.SignaturesValid++
		} else {
			result.SignaturesInvalid++
			result.Errors = append(result.Errors, fmt.Sprintf("INVALID signature on entry #%d (%s)", be.ID, be.Timestamp))
		}
	}

	// 3. Verify hash chain
	result.ChainValid = true
	if len(b.Entries) > 1 {
		for i := 1; i < len(b.Entries); i++ {
			prev := b.Entries[i-1]
			curr := b.Entries[i]

			if curr.PrevHash == "" && prev.PrevHash == "" {
				continue // legacy entries
			}

			result.ChainLinksChecked++
			expected := crypto.SHA256Hex(prev.Signature)
			if curr.PrevHash != expected {
				result.ChainBreaks++
				result.ChainValid = false
				result.Errors = append(result.Errors, fmt.Sprintf("BROKEN chain at entry #%d — prev_hash doesn't match entry #%d", curr.ID, prev.ID))
			}
		}
	}

	return result
}

// ToJSON marshals the bundle as indented JSON.
func ToJSON(b *Bundle) ([]byte, error) {
	return json.MarshalIndent(b, "", "  ")
}

// WriteCSV writes entries as CSV to the given writer.
func WriteCSV(w io.Writer, b *Bundle) error {
	cw := csv.NewWriter(w)
	defer cw.Flush()

	// Header
	if err := cw.Write([]string{
		"timestamp", "server", "tool", "verdict", "risk_score", "risk_level", "signature_valid",
	}); err != nil {
		return err
	}

	for _, e := range b.Entries {
		tool := ""
		if e.ToolName != nil {
			tool = *e.ToolName
		}
		riskScore := ""
		if e.RiskScore != nil {
			riskScore = fmt.Sprintf("%d", *e.RiskScore)
		}
		riskLevel := ""
		if e.RiskLevel != nil {
			riskLevel = *e.RiskLevel
		}

		entry := bundleEntryToEntry(e)
		sigValid := "true"
		if !audit.VerifyEntry(&entry) {
			sigValid = "false"
		}

		if err := cw.Write([]string{
			e.Timestamp, e.ServerName, tool, e.Verdict, riskScore, riskLevel, sigValid,
		}); err != nil {
			return err
		}
	}
	return nil
}

// --- internal helpers ---

// bundlePayload is the bundle without BundleSignature, used for signing.
// Field order must match Bundle exactly (minus BundleSignature) for deterministic marshaling.
type bundlePayload struct {
	Version           int               `json:"version"`
	Format            string            `json:"format"`
	ExportedAt        string            `json:"exported_at"`
	Range             BundleRange       `json:"range"`
	Summary           BundleSummary     `json:"summary"`
	ChainVerification ChainVerification `json:"chain_verification"`
	Entries           []BundleEntry     `json:"entries"`
	PublicKey         string            `json:"public_key"`
}

func signBundle(b *Bundle, privateKey string) error {
	payload := bundlePayload{
		Version:           b.Version,
		Format:            b.Format,
		ExportedAt:        b.ExportedAt,
		Range:             b.Range,
		Summary:           b.Summary,
		ChainVerification: b.ChainVerification,
		Entries:           b.Entries,
		PublicKey:         b.PublicKey,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}
	sig, err := crypto.SignData(string(data), privateKey)
	if err != nil {
		return fmt.Errorf("sign: %w", err)
	}
	b.BundleSignature = sig
	return nil
}

func entryToBundleEntry(e audit.Entry) BundleEntry {
	return BundleEntry{
		ID:            e.ID,
		Timestamp:     e.Timestamp,
		ServerName:    e.ServerName,
		Direction:     e.Direction,
		Method:        e.Method,
		MessageID:     e.MessageID,
		ToolName:      e.ToolName,
		ArgumentsJSON: e.ArgumentsJSON,
		ResponseJSON:  e.ResponseJSON,
		Verdict:       e.Verdict,
		RiskScore:     e.RiskScore,
		RiskLevel:     e.RiskLevel,
		PolicyHash:    e.PolicyHash,
		PrevHash:      e.PrevHash,
		Nonce:         e.Nonce,
		Signature:     e.Signature,
		PublicKey:     e.PublicKey,
		AgentID:       e.AgentID,
		AgentName:     e.AgentName,
	}
}

func bundleEntryToEntry(be BundleEntry) audit.Entry {
	return audit.Entry{
		ID:            be.ID,
		Timestamp:     be.Timestamp,
		ServerName:    be.ServerName,
		Direction:     be.Direction,
		Method:        be.Method,
		MessageID:     be.MessageID,
		ToolName:      be.ToolName,
		ArgumentsJSON: be.ArgumentsJSON,
		ResponseJSON:  be.ResponseJSON,
		Verdict:       be.Verdict,
		RiskScore:     be.RiskScore,
		RiskLevel:     be.RiskLevel,
		PolicyHash:    be.PolicyHash,
		PrevHash:      be.PrevHash,
		Nonce:         be.Nonce,
		Signature:     be.Signature,
		PublicKey:     be.PublicKey,
		AgentID:       be.AgentID,
		AgentName:     be.AgentName,
	}
}

func computeSummary(entries []audit.Entry) BundleSummary {
	s := BundleSummary{
		RiskDistribution: map[string]int{"low": 0, "medium": 0, "high": 0, "critical": 0},
	}

	tools := map[string]struct{}{}
	servers := map[string]struct{}{}

	for _, e := range entries {
		s.TotalEntries++

		if e.ToolName != nil && *e.ToolName != "" && e.Direction == "request" {
			s.ToolCalls++
			tools[*e.ToolName] = struct{}{}
		}

		servers[e.ServerName] = struct{}{}

		switch e.Verdict {
		case "deny", "scope_denied", "flag_denied":
			s.Denied++
		}

		if e.RiskLevel != nil {
			level := strings.ToLower(*e.RiskLevel)
			if level == "high" || level == "critical" {
				s.Flagged++
			}
			if _, ok := s.RiskDistribution[level]; ok {
				s.RiskDistribution[level]++
			}
		}
	}

	s.UniqueTools = len(tools)
	s.UniqueServers = len(servers)
	return s
}

func verifyChain(entries []audit.Entry) ChainVerification {
	cv := ChainVerification{
		Valid:  true,
		Breaks: []int64{},
	}

	if len(entries) == 0 {
		return cv
	}

	cv.EntriesChecked = len(entries)
	cv.FirstID = entries[0].ID
	cv.LastID = entries[len(entries)-1].ID

	for i := 1; i < len(entries); i++ {
		prev := entries[i-1]
		curr := entries[i]

		if curr.PrevHash == "" && prev.PrevHash == "" {
			continue // legacy entries
		}

		expected := crypto.SHA256Hex(prev.Signature)
		if curr.PrevHash != expected {
			cv.Valid = false
			cv.Breaks = append(cv.Breaks, curr.ID)
		}
	}

	return cv
}
