package main

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

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
// code serves both the colored console and the plain report file.
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

// spinnerFrames is a Braille spinner cycle.
var spinnerFrames = []rune("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")

const progressBarWidth = 24

// progress renders a live spinner + bar on stderr for a phase of `total` steps.
// On a non-terminal stderr it degrades to a single start line and a single
// summary line (no carriage-return animation, no ANSI), matching the old
// plain output for pipes and redirects.
type progress struct {
	label string
	total int
	pal   palette
	tty   bool
	done  int64 // atomic

	stopCh chan struct{}
	wg     sync.WaitGroup
}

func newProgress(label string, total int, pal palette) *progress {
	p := &progress{label: label, total: total, pal: pal, tty: isTerminal(os.Stderr)}
	if !p.tty {
		fmt.Fprintf(os.Stderr, "%s: %d...\n", label, total)
		return p
	}
	p.stopCh = make(chan struct{})
	p.wg.Add(1)
	go p.animate()
	return p
}

func (p *progress) inc() { atomic.AddInt64(&p.done, 1) }

func (p *progress) animate() {
	defer p.wg.Done()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	frame := 0
	for {
		select {
		case <-p.stopCh:
			return
		case <-ticker.C:
			p.render(spinnerFrames[frame%len(spinnerFrames)])
			frame++
		}
	}
}

func (p *progress) render(spin rune) {
	done := atomic.LoadInt64(&p.done)
	pct := 0
	if p.total > 0 {
		pct = int(done * 100 / int64(p.total))
	}
	filled := pct * progressBarWidth / 100
	bar := strings.Repeat("█", filled) + strings.Repeat("░", progressBarWidth-filled)
	line := fmt.Sprintf("%s %s [%s] %3d%% %d/%d",
		p.pal.accent(string(spin)), p.pal.title(p.label), bar, pct, done, p.total)
	fmt.Fprintf(os.Stderr, "\r\033[K%s", line)
}

// stop ends the animation and prints a final summary line for the phase.
func (p *progress) stop(summary string) {
	if !p.tty {
		fmt.Fprintf(os.Stderr, "%s: %s\n", p.label, summary)
		return
	}
	close(p.stopCh)
	p.wg.Wait()
	fmt.Fprintf(os.Stderr, "\r\033[K%s %s: %s\n", p.pal.ok("✔"), p.pal.title(p.label), summary)
}
