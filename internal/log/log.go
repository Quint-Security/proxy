package log

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"gopkg.in/natefinch/lumberjack.v2"
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
	output       io.Writer = os.Stderr
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

// SetOutput sets the log output writer. If w is nil, logs go to stderr.
func SetOutput(w io.Writer) {
	mu.Lock()
	defer mu.Unlock()
	if w == nil {
		output = os.Stderr
	} else {
		output = w
	}
}

// SetupFileLogging configures log rotation using lumberjack.
// Logs are written to the specified file with automatic rotation.
// If logFile is empty, logging stays on stderr.
func SetupFileLogging(logFile string) {
	if logFile == "" {
		return
	}

	writer := &lumberjack.Logger{
		Filename:   logFile,
		MaxSize:    50, // megabytes
		MaxBackups: 3,
		MaxAge:     14, // days
		Compress:   true,
	}

	mu.Lock()
	defer mu.Unlock()
	// Write to both file and stderr so daemon logs are captured and
	// interactive users still see output.
	output = io.MultiWriter(os.Stderr, writer)
}

func log(level Level, prefix, format string, args ...any) {
	mu.Lock()
	l := currentLevel
	w := output
	mu.Unlock()
	if level < l {
		return
	}
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(w, "quint:%s %s\n", prefix, msg)
}

func Debug(format string, args ...any) { log(LevelDebug, "debug", format, args...) }
func Info(format string, args ...any)  { log(LevelInfo, "info", format, args...) }
func Warn(format string, args ...any)  { log(LevelWarn, "warn", format, args...) }
func Error(format string, args ...any) { log(LevelError, "error", format, args...) }
