package main

import "os"

// ANSI SGR codes for the palette.
const (
	ansiReset  = "\033[0m"
	ansiBold   = "\033[1m"
	ansiDim    = "\033[2m"
	ansiRed    = "\033[31m"
	ansiGreen  = "\033[32m"
	ansiCyan   = "\033[36m"
	ansiYellow = "\033[33m"
)

// errPal colors status and error messages on stderr; set once in main.
var errPal palette

// isTerminal reports whether f is an interactive terminal (not a pipe/file).
func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// colorEnabled reports whether ANSI color should be emitted to f: only when f
// is a terminal and NO_COLOR is unset (https://no-color.org).
func colorEnabled(f *os.File) bool {
	return os.Getenv("NO_COLOR") == "" && isTerminal(f)
}

// palette wraps ANSI colors, becoming a no-op when disabled so the same writer
// code serves both the colored console and the plain report file. It still backs
// the stderr status lines (errPal) and the --help screen (usage); the scan
// dashboard and report tables use lipgloss (tui.go, report.go).
type palette struct {
	enabled bool
}

func (p palette) paint(code, s string) string {
	if !p.enabled {
		return s
	}
	return code + s + ansiReset
}

func (p palette) title(s string) string  { return p.paint(ansiBold, s) }
func (p palette) ok(s string) string     { return p.paint(ansiGreen, s) }
func (p palette) fail(s string) string   { return p.paint(ansiRed, s) }
func (p palette) dim(s string) string    { return p.paint(ansiDim, s) }
func (p palette) warn(s string) string   { return p.paint(ansiYellow, s) }
func (p palette) accent(s string) string { return p.paint(ansiCyan, s) }
func (p palette) addr(s string) string   { return p.paint(ansiBold, s) }
