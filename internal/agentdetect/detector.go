package agentdetect

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"sync"
)

// Detection holds the result of agent platform identification.
type Detection struct {
	Platform    string   `json:"platform"`              // "claude-code", "cursor", "copilot", etc.
	Confidence  float64  `json:"confidence"`            // 0.0 - 1.0
	Sources     []string `json:"sources"`               // which layers contributed
	ProcessPath string   `json:"process_path,omitempty"`
	PID         int      `json:"pid,omitempty"`
}

// DetectParams holds the input signals for platform detection.
type DetectParams struct {
	UserAgent   string
	Headers     http.Header
	BodyPreview string // raw API request body (for system prompt extraction)
	ProcessName string // from pidlookup (already resolved to agent name if known)
	ProcessPath string
	PID         int
}

// Detector combines multiple identification layers to determine which
// AI coding platform originated a proxied request.
type Detector struct {
	cache sync.Map // agentID → Detection
}

// NewDetector creates a new agent platform detector.
func NewDetector() *Detector {
	return &Detector{}
}

// Detect runs all identification layers and returns the best result.
func (d *Detector) Detect(params DetectParams) Detection {
	var candidates []Detection

	// Layer 1: Process tree (hard identifier — OS-level truth)
	if platform := identifyFromProcess(params.ProcessName, params.ProcessPath); platform != "" {
		return Detection{
			Platform:    platform,
			Confidence:  1.0,
			Sources:     []string{"process-tree"},
			ProcessPath: params.ProcessPath,
			PID:         params.PID,
		}
	}

	// Layer 2: HTTP headers (hard identifier for agents with custom headers)
	if platform, conf := identifyFromHeaders(params.Headers); platform != "" {
		candidates = append(candidates, Detection{
			Platform:   platform,
			Confidence: conf,
			Sources:    []string{"headers"},
		})
	}

	// Layer 3: System prompt fingerprinting (highest-value soft identifier)
	if params.BodyPreview != "" {
		if systemPrompt := ExtractSystemPrompt(params.BodyPreview); systemPrompt != "" {
			// Try hash match first (exact version identification)
			promptHash := sha256Hex(systemPrompt)
			if platform := matchPromptHash(promptHash); platform != "" {
				candidates = append(candidates, Detection{
					Platform:   platform,
					Confidence: 0.95,
					Sources:    []string{"system-prompt-hash"},
				})
			} else if platform, conf := identifyFromSystemPrompt(systemPrompt); platform != "" {
				// Fall back to substring pattern matching (resilient across versions)
				candidates = append(candidates, Detection{
					Platform:   platform,
					Confidence: conf,
					Sources:    []string{"system-prompt"},
				})
			}
		}
	}

	// Layer 4: User-Agent
	if platform, conf := identifyFromUA(params.UserAgent); platform != "" {
		candidates = append(candidates, Detection{
			Platform:   platform,
			Confidence: conf,
			Sources:    []string{"user-agent"},
		})
	}

	if len(candidates) == 0 {
		return Detection{
			Platform:    "unknown",
			ProcessPath: params.ProcessPath,
			PID:         params.PID,
		}
	}

	// Merge: highest confidence wins. Same platform from multiple layers boosts confidence.
	best := candidates[0]
	for _, c := range candidates[1:] {
		if c.Platform == best.Platform && c.Platform != "" {
			best.Confidence = clamp(best.Confidence+0.05, 0, 1)
			best.Sources = append(best.Sources, c.Sources...)
		} else if c.Confidence > best.Confidence {
			best = c
		}
	}

	best.ProcessPath = params.ProcessPath
	best.PID = params.PID
	return best
}

// DetectCached returns a cached detection for the given agentID, or runs
// detection and caches the result. Cached high-confidence results are
// returned immediately without re-running detection.
func (d *Detector) DetectCached(agentID string, params DetectParams) Detection {
	if agentID != "" {
		if cached, ok := d.cache.Load(agentID); ok {
			det := cached.(Detection)
			if det.Confidence >= 0.9 {
				return det
			}
		}
	}

	result := d.Detect(params)
	if agentID != "" && result.Platform != "unknown" {
		d.cache.Store(agentID, result)
	}
	return result
}

// IsSpecificPlatform returns true if the platform name represents a known
// AI coding agent (not a generic SDK like "python-httpx").
func IsSpecificPlatform(platform string) bool {
	switch platform {
	case "claude-code", "cursor", "copilot", "windsurf", "kiro",
		"codex", "aider", "cline", "continue", "zed", "goose",
		"roo-code", "augment", "opencode", "gemini-cli", "pearai",
		"trae", "void", "antigravity", "devin", "amp":
		return true
	}
	return false
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func containsFold(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}
