package crypto

import (
	"crypto/sha256"
	"encoding/hex"
)

// SHA256Hex returns the hex-encoded SHA-256 hash of data.
// Matches TypeScript: createHash("sha256").update(data, "utf-8").digest("hex")
func SHA256Hex(data string) string {
	h := sha256.Sum256([]byte(data))
	return hex.EncodeToString(h[:])
}
