package log

import (
	"fmt"
	"os"
	"strings"
	"sync"
)

// Level represents a log severity level.
type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

var (
	currentLevel = LevelInfo
	mu           sync.Mutex
)

// SetLevel sets the minimum log level from a string ("debug", "info", "warn", "error").
func SetLevel(s string) {
	mu.Lock()
	defer mu.Unlock()
	switch strings.ToLower(s) {
	case "debug":
		currentLevel = LevelDebug
	case "info":
		currentLevel = LevelInfo
	case "warn":
		currentLevel = LevelWarn
	case "error":
		currentLevel = LevelError
	default:
		currentLevel = LevelInfo
	}
}

func log(level Level, prefix, format string, args ...any) {
	mu.Lock()
	l := currentLevel
	mu.Unlock()
	if level < l {
		return
	}
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(os.Stderr, "quint:%s %s\n", prefix, msg)
}

func Debug(format string, args ...any) { log(LevelDebug, "debug", format, args...) }
func Info(format string, args ...any)  { log(LevelInfo, "info", format, args...) }
func Warn(format string, args ...any)  { log(LevelWarn, "warn", format, args...) }
func Error(format string, args ...any) { log(LevelError, "error", format, args...) }
