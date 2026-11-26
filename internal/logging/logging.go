// Package logging sets up structured logs to stdout (for docker logs) and
// to a rotated JSON file in the log directory.
package logging

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/natefinch/lumberjack.v2"
)

// Setup returns a logger writing to stdout (text or json) and, when logDir is
// writable, to <logDir>/leazone.log (json, rotated at 20 MB, 5 files kept).
func Setup(level, format, logDir string) (*slog.Logger, io.Closer) {
	var lvl slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn", "warning":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: lvl}
	var stdout slog.Handler
	if format == "json" {
		stdout = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		stdout = slog.NewTextHandler(os.Stdout, opts)
	}
	handlers := []slog.Handler{stdout}
	var closer io.Closer = nopCloser{}
	if logDir != "" {
		if err := os.MkdirAll(logDir, 0o750); err == nil {
			lj := &lumberjack.Logger{
				Filename:   filepath.Join(logDir, "leazone.log"),
				MaxSize:    20,
				MaxBackups: 5,
				Compress:   true,
			}
			// Probe write access once so a read-only /logs only costs a warning.
			if _, err := lj.Write(nil); err == nil {
				handlers = append(handlers, slog.NewJSONHandler(lj, opts))
				closer = lj
			}
		}
	}
	return slog.New(multi(handlers)), closer
}

type nopCloser struct{}

func (nopCloser) Close() error { return nil }
