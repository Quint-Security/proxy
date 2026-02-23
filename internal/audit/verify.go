package audit

import (
	"fmt"

	"github.com/Quint-Security/quint-proxy/internal/crypto"
)

// VerifyResult holds the result of a verification run.
type VerifyResult struct {
	Checked      int
	SigValid     int
	SigInvalid   int
	ChainValid   int
	ChainBroken  int
	Errors       []string
}

// GetAll returns all audit entries in ascending order.
func (d *DB) GetAll() ([]Entry, error) {
	rows, err := d.db.Query(
		`SELECT id, timestamp, server_name, direction, method, message_id, tool_name,
		        arguments_json, response_json, verdict, risk_score, risk_level,
		        policy_hash, prev_hash, nonce, signature, public_key, agent_id, agent_name
		 FROM audit_log ORDER BY id ASC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []Entry
	for rows.Next() {
		var e Entry
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.ServerName, &e.Direction, &e.Method,
			&e.MessageID, &e.ToolName, &e.ArgumentsJSON, &e.ResponseJSON, &e.Verdict,
			&e.RiskScore, &e.RiskLevel, &e.PolicyHash, &e.PrevHash, &e.Nonce,
			&e.Signature, &e.PublicKey, &e.AgentID, &e.AgentName); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// GetLast returns the last N entries in ascending order (oldest first).
func (d *DB) GetLast(n int) ([]Entry, error) {
	rows, err := d.db.Query(
		`SELECT id, timestamp, server_name, direction, method, message_id, tool_name,
		        arguments_json, response_json, verdict, risk_score, risk_level,
		        policy_hash, prev_hash, nonce, signature, public_key, agent_id, agent_name
		 FROM audit_log ORDER BY id DESC LIMIT ?`, n,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []Entry
	for rows.Next() {
		var e Entry
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.ServerName, &e.Direction, &e.Method,
			&e.MessageID, &e.ToolName, &e.ArgumentsJSON, &e.ResponseJSON, &e.Verdict,
			&e.RiskScore, &e.RiskLevel, &e.PolicyHash, &e.PrevHash, &e.Nonce,
			&e.Signature, &e.PublicKey, &e.AgentID, &e.AgentName); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	// Reverse to ascending
	for i, j := 0, len(entries)-1; i < j; i, j = i+1, j-1 {
		entries[i], entries[j] = entries[j], entries[i]
	}
	return entries, nil
}

// GetByID returns a single entry by ID.
func (d *DB) GetByID(id int64) (*Entry, error) {
	var e Entry
	err := d.db.QueryRow(
		`SELECT id, timestamp, server_name, direction, method, message_id, tool_name,
		        arguments_json, response_json, verdict, risk_score, risk_level,
		        policy_hash, prev_hash, nonce, signature, public_key, agent_id, agent_name
		 FROM audit_log WHERE id = ?`, id,
	).Scan(&e.ID, &e.Timestamp, &e.ServerName, &e.Direction, &e.Method,
		&e.MessageID, &e.ToolName, &e.ArgumentsJSON, &e.ResponseJSON, &e.Verdict,
		&e.RiskScore, &e.RiskLevel, &e.PolicyHash, &e.PrevHash, &e.Nonce,
		&e.Signature, &e.PublicKey, &e.AgentID, &e.AgentName)
	if err != nil {
		return nil, err
	}
	return &e, nil
}

// Count returns the total number of audit entries.
func (d *DB) Count() int {
	var n int
	d.db.QueryRow("SELECT COUNT(*) FROM audit_log").Scan(&n)
	return n
}

// GetAfterID returns entries with ID > afterID, limited to n entries.
func (d *DB) GetAfterID(afterID int64, limit int) ([]Entry, error) {
	rows, err := d.db.Query(
		`SELECT id, timestamp, server_name, direction, method, message_id, tool_name,
		        arguments_json, response_json, verdict, risk_score, risk_level,
		        policy_hash, prev_hash, nonce, signature, public_key, agent_id, agent_name
		 FROM audit_log WHERE id > ? ORDER BY id ASC LIMIT ?`, afterID, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []Entry
	for rows.Next() {
		var e Entry
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.ServerName, &e.Direction, &e.Method,
			&e.MessageID, &e.ToolName, &e.ArgumentsJSON, &e.ResponseJSON, &e.Verdict,
			&e.RiskScore, &e.RiskLevel, &e.PolicyHash, &e.PrevHash, &e.Nonce,
			&e.Signature, &e.PublicKey, &e.AgentID, &e.AgentName); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// VerifyEntry verifies the Ed25519 signature on a single audit entry.
// Tries with agent fields first, then with risk fields only, then without risk fields (legacy).
func VerifyEntry(e *Entry) bool {
	// Try with agent fields (current format)
	obj := crypto.BuildSignableObject(
		e.Timestamp, e.ServerName, e.Direction, e.Method,
		e.MessageID, e.ToolName, e.ArgumentsJSON, e.ResponseJSON,
		e.Verdict, e.PolicyHash, e.PrevHash, e.Nonce, e.PublicKey,
		e.RiskScore, e.RiskLevel,
		e.AgentID, e.AgentName,
	)
	canonical, err := crypto.Canonicalize(obj)
	if err == nil {
		if ok, err := crypto.VerifySignature(canonical, e.Signature, e.PublicKey); err == nil && ok {
			return true
		}
	}

	// Try without agent fields (pre-agent entries)
	objNoAgent := crypto.BuildSignableObject(
		e.Timestamp, e.ServerName, e.Direction, e.Method,
		e.MessageID, e.ToolName, e.ArgumentsJSON, e.ResponseJSON,
		e.Verdict, e.PolicyHash, e.PrevHash, e.Nonce, e.PublicKey,
		e.RiskScore, e.RiskLevel,
		nil, nil,
	)
	canonicalNoAgent, err := crypto.Canonicalize(objNoAgent)
	if err == nil {
		if ok, err := crypto.VerifySignature(canonicalNoAgent, e.Signature, e.PublicKey); err == nil && ok {
			return true
		}
	}

	return false
}

// VerifyAll verifies signatures and optionally the hash chain on entries.
func VerifyAll(entries []Entry, checkChain bool) VerifyResult {
	result := VerifyResult{}

	for i := range entries {
		result.Checked++
		if VerifyEntry(&entries[i]) {
			result.SigValid++
		} else {
			result.SigInvalid++
			result.Errors = append(result.Errors, fmt.Sprintf("INVALID signature on entry #%d (%s)", entries[i].ID, entries[i].Timestamp))
		}
	}

	if checkChain && len(entries) > 1 {
		for i := 1; i < len(entries); i++ {
			prev := entries[i-1]
			curr := entries[i]

			if curr.PrevHash == "" && prev.PrevHash == "" {
				continue // legacy entries
			}

			expectedHash := crypto.SHA256Hex(prev.Signature)
			if curr.PrevHash == expectedHash {
				result.ChainValid++
			} else {
				result.ChainBroken++
				result.Errors = append(result.Errors, fmt.Sprintf("BROKEN chain at entry #%d — prev_hash doesn't match entry #%d", curr.ID, prev.ID))
			}
		}
	}

	return result
}
