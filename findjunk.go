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
		fmt.Fprintln(os.Stderr, errPal.dim(fmt.Sprintf("Attempt %d: jc=%d jmin=%d jmax=%d", attempt, awgJc, awgJmin, awgJmax)))

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
	c := junkCandidate{jc: awgJc, jmin: awgJmin, jmax: awgJmax}
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
	if complete {
		fmt.Fprintln(os.Stderr, errPal.ok(fmt.Sprintf("Every sampled endpoint came up with %s (%s)", c, i1Note())))
	} else {
		fmt.Fprintln(os.Stderr, errPal.dim(fmt.Sprintf("Stopped. Best set: %s (%s)", c, i1Note())))
	}
	fmt.Fprintln(os.Stdout, junkCommand(c))
	return nil
}

func i1Note() string {
	switch awgI1 {
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
	if awgI1 == "" {
		parts = append(parts, "-i1 none")
	} else if awgI1 != i1Default {
		parts = append(parts, fmt.Sprintf("-i1 %q", awgI1))
	}
	return strings.Join(parts, " ")
}
