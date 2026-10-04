package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// LogEntry is one structured line, both printed to stdout and pushed to the
// web panel (both the history buffer and the live SSE stream).
type LogEntry struct {
	Time    string `json:"time"`
	Level   string `json:"level"`
	Message string `json:"message"`
}

const (
	levelDebug = iota
	levelInfo
	levelWarn
	levelError
)

func levelName(l int) string {
	switch l {
	case levelDebug:
		return "DEBUG"
	case levelWarn:
		return "WARN"
	case levelError:
		return "ERROR"
	default:
		return "INFO"
	}
}

// Logger writes timestamped lines to stdout and keeps a bounded ring buffer
// that the panel serves to browsers.
type Logger struct {
	mu       sync.Mutex
	history  []LogEntry
	capacity int
	level    int
	out      io.Writer

	subsMu sync.Mutex
	subs   map[int]chan LogEntry
	nextID int
}

// NewLogger builds a logger with a history ring of `capacity` entries.
func NewLogger(capacity int, verbose bool) *Logger {
	if capacity < 1 {
		capacity = 1
	}
	lvl := levelInfo
	if verbose {
		lvl = levelDebug
	}
	return &Logger{
		history:  make([]LogEntry, 0, capacity),
		capacity: capacity,
		level:    lvl,
		out:      os.Stdout,
		subs:     make(map[int]chan LogEntry),
	}
}

// SetOutput redirects the log sink (used by tests).
func (l *Logger) SetOutput(w io.Writer) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.out = w
}

func (l *Logger) logf(level int, format string, args ...any) {
	l.mu.Lock()
	if level < l.level {
		l.mu.Unlock()
		return
	}
	msg := sanitize(format, args...)
	entry := LogEntry{
		Time:    time.Now().Format("15:04:05"),
		Level:   levelName(level),
		Message: msg,
	}
	if len(l.history) >= l.capacity {
		copy(l.history, l.history[1:])
		l.history[len(l.history)-1] = entry
	} else {
		l.history = append(l.history, entry)
	}
	out := l.out
	l.mu.Unlock()

	if out != nil {
		fmt.Fprintf(out, "[%s] %-5s %s\n", entry.Time, entry.Level, msg)
	}
	l.broadcast(entry)
}

func sanitize(format string, args ...any) string {
	msg := format
	if len(args) > 0 {
		msg = fmt.Sprintf(format, args...)
	}
	msg = strings.ReplaceAll(msg, "\n", " ")
	msg = strings.ReplaceAll(msg, "\r", "")
	if len(msg) > 2000 {
		msg = msg[:2000] + "…"
	}
	return msg
}

func (l *Logger) broadcast(e LogEntry) {
	l.subsMu.Lock()
	defer l.subsMu.Unlock()
	for _, ch := range l.subs {
		select {
		case ch <- e:
		default: // slow browser: drop instead of blocking the server
		}
	}
}

// Debugf logs at DEBUG level.
func (l *Logger) Debugf(format string, args ...any) { l.logf(levelDebug, format, args...) }

// Infof logs at INFO level.
func (l *Logger) Infof(format string, args ...any) { l.logf(levelInfo, format, args...) }

// Warnf logs at WARN level.
func (l *Logger) Warnf(format string, args ...any) { l.logf(levelWarn, format, args...) }

// Errorf logs at ERROR level.
func (l *Logger) Errorf(format string, args ...any) { l.logf(levelError, format, args...) }

// History returns a copy of the buffered log lines.
func (l *Logger) History() []LogEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]LogEntry, len(l.history))
	copy(out, l.history)
	return out
}

// Subscribe registers a live log consumer. The returned function unsubscribes.
func (l *Logger) Subscribe() (<-chan LogEntry, func()) {
	ch := make(chan LogEntry, 128)
	l.subsMu.Lock()
	id := l.nextID
	l.nextID++
	l.subs[id] = ch
	l.subsMu.Unlock()

	return ch, func() {
		l.subsMu.Lock()
		if c, ok := l.subs[id]; ok {
			delete(l.subs, id)
			close(c)
		}
		l.subsMu.Unlock()
	}
}
