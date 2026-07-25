package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"
)

const findJunkSample = 3

type junkCandidate struct {
	jc, jmin, jmax int
	working, total int
	i1, i1Label    string
}

func (c junkCandidate) String() string {
	return fmt.Sprintf("jc=%d jmin=%d jmax=%d  %d/%d working", c.jc, c.jmin, c.jmax, c.working, c.total)
}

func runFindJunk(ctx context.Context, opts options, runs []protoRun, timeout time.Duration) error {
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt)
	defer stop()

	fmt.Fprintln(os.Stderr, errPal.dim(fmt.Sprintf(
		"Searching AmneziaWG junk params (%d addresses per subnet, %s). Press Ctrl+C to stop and keep the best set.",
		opts.perSubnet, i1Note())))
	fmt.Fprintln(os.Stderr)

	var best junkCandidate
	for attempt := 1; ctx.Err() == nil; attempt++ {
		genJunkParams()
		if opts.genI1 != "" {
			if err := regenI1(opts); err != nil {
				return err
			}
		}
		fmt.Fprintln(os.Stderr, errPal.dim(fmt.Sprintf(
			"Attempt %d: jc=%d jmin=%d jmax=%d, %s", attempt, awgJc, awgJmin, awgJmax, i1Note())))

		// ponytail: full runScan per candidate (incl. colo resolution) - one extra
		// lookup per attempt buys zero new orchestration code.
		phases, err := runScan(ctx, opts, runs, expandPools(opts.perSubnet), timeout, plainEmit)
		if ctx.Err() != nil {
			break
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, errPal.fail(fmt.Sprintf("Attempt %d: %v", attempt, err)))
			continue
		}

		c := scoreJunk(phases)
		fmt.Fprintln(os.Stderr, errPal.dim("Attempt "+fmt.Sprint(attempt)+": "+c.String()))
		fmt.Fprintln(os.Stderr)
		if c.working > best.working {
			best = c
		}
		if c.total > 0 && c.working == c.total {
			return reportJunk(c, true)
		}
	}

	if best.total == 0 {
		fmt.Fprintln(os.Stderr, errPal.dim("Stopped before any junk set finished a scan - nothing to report."))
		return nil
	}
	return reportJunk(best, false)
}

func scoreJunk(phases []phaseResult) junkCandidate {
	c := junkCandidate{jc: awgJc, jmin: awgJmin, jmax: awgJmax, i1: awgI1, i1Label: genI1Label}
	if len(phases) == 0 {
		return c
	}
	for _, r := range phases[0].results {
		c.total++
		if r.working() {
			c.working++
		}
	}
	return c
}

func reportJunk(c junkCandidate, complete bool) error {
	fmt.Fprintln(os.Stderr)
	note := i1NoteFor(c.i1, c.i1Label)
	if complete {
		fmt.Fprintln(os.Stderr, errPal.ok(fmt.Sprintf("Every sampled endpoint came up with %s (%s)", c, note)))
	} else {
		fmt.Fprintln(os.Stderr, errPal.dim(fmt.Sprintf("Stopped. Best set: %s (%s)", c, note)))
	}
	fmt.Fprintln(os.Stdout, junkCommand(c))
	return nil
}

func i1Note() string {
	return i1NoteFor(awgI1, genI1Label)
}

func i1NoteFor(i1, label string) string {
	if label != "" {
		return "generated " + label + " I1"
	}
	switch i1 {
	case "":
		return "no I1"
	case i1Default:
		return "default iCloud I1"
	}
	return "custom I1"
}

func junkCommand(c junkCandidate) string {
	parts := []string{filepath.Base(os.Args[0]), "-proto", protoAWG,
		fmt.Sprintf("-jc %d", c.jc), fmt.Sprintf("-jmin %d", c.jmin), fmt.Sprintf("-jmax %d", c.jmax)}
	if c.i1 == "" {
		parts = append(parts, "-i1 none")
	} else if c.i1 != i1Default {
		parts = append(parts, fmt.Sprintf("-i1 %q", c.i1))
	}
	return strings.Join(parts, " ")
}
