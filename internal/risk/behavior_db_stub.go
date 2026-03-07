//go:build nosqlite

package risk

import "errors"

// BehaviorDB is a stub when compiled without SQLite.
type BehaviorDB struct{}

func OpenBehaviorDB(dataDir string) (*BehaviorDB, error) {
	return nil, errors.New("sqlite support not compiled in")
}

func (b *BehaviorDB) Record(subjectID string, ts int64) {}

func (b *BehaviorDB) Count(subjectID string, cutoff int64) int { return 0 }

func (b *BehaviorDB) Close() error { return nil }
