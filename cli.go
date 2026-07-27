package main

import (
	"context"
	"flag"
	"fmt"
	"os"
)

type command struct {
	name   string
	brief  string
	intro  []string
	groups []flagGroup
	setup  func(*flag.FlagSet, *options)
	run    func(context.Context, options) error
}

var commands = []command{
	{
		name:  "scan",
		brief: "scan WARP endpoint pools for working, low-latency endpoints",
		intro: []string{
			"Two-phase scan:",
			"  - Phase 1 finds which WARP ports get through this network",
			"  - Phase 2 verifies each endpoint's real exit colo through a WARP tunnel",
			"",
			"Working endpoints are reported grouped per subnet.",
			"Needs a WARP account: run \"warpscout register\" first.",
		},
		groups: []flagGroup{scanGroup, protoGroup, awgGroup, outputGroup},
		setup:  setupScanFlags,
		run:    runScanCmd,
	},
	{
		name:  "register",
		brief: "register a WARP account and save it",
		intro: []string{
			"Registers a fresh WARP account and writes it to the account file,",
			"overwriting any existing one.",
			"",
			"Falls back to registering through a WARP tunnel when the Cloudflare API",
			"is unreachable directly; -proxy skips that fallback.",
		},
		groups: []flagGroup{registerGroup, protoGroup, awgGroup, plainGroup},
		setup:  setupRegisterFlags,
		run:    runRegisterCmd,
	},
	{
		name:  "find-junk",
		brief: "search AmneziaWG junk params that unblock every endpoint",
		intro: []string{
			"Rescans with a fresh random junk set (and a fresh I1 when -gen-i1 is set)",
			"until one set brings up every sampled endpoint, then prints the scan",
			"command to reuse it. Ctrl+C keeps the best set so far.",
			"",
			"Verifies by handshake and in-tunnel ping only - no exit colo is resolved.",
		},
		groups: []flagGroup{findJunkGroup, findJunkI1Group, plainGroup},
		setup:  setupFindJunkFlags,
		run:    runFindJunkCmd,
	},
}

func main() {
	errPal = palette{enabled: colorEnabled(os.Stderr)}

	if len(os.Args) < 2 {
		rootUsage(os.Stderr)
		os.Exit(2)
	}
	cmd := lookupCommand(os.Args[1])
	if cmd == nil {
		fmt.Fprintln(os.Stderr, errPal.fail(fmt.Sprintf("unknown command %q", os.Args[1])))
		fmt.Fprintln(os.Stderr)
		rootUsage(os.Stderr)
		os.Exit(2)
	}

	var opts options
	fs := flag.NewFlagSet(cmd.name, flag.ExitOnError)
	fs.Usage = func() { commandUsage(fs.Output(), *cmd, fs) }
	cmd.setup(fs, &opts)
	fs.Parse(os.Args[2:])
	applyCommonFlags(fs, &opts)

	noEmoji = opts.noEmoji || usePlainOutput(opts)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := cmd.run(ctx, opts); err != nil {
		fmt.Fprintln(os.Stderr, errPal.fail(err.Error()))
		os.Exit(1)
	}
}

func lookupCommand(name string) *command {
	for i, c := range commands {
		if c.name == name {
			return &commands[i]
		}
	}
	return nil
}
