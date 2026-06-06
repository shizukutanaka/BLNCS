package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"blrcs/doctor"
)

const version = "1.0.0"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run — testable entry point. Returns the process exit code.
// os.Exit is confined to main(); all logic here is unit-testable.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) < 1 {
		usage(stderr)
		return 1
	}
	switch args[0] {
	case "doctor":
		return cmdDoctor(args[1:], stdout)
	case "version":
		fmt.Fprintf(stdout, "blrcs %s\n", version)
		return 0
	case "completion":
		return cmdCompletion(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown: %s\n", args[0])
		usage(stderr)
		return 1
	}
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "Usage: blrcs <doctor|version|completion>")
}

func cmdDoctor(args []string, stdout io.Writer) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(stdout)
	jsonOut := fs.Bool("json", false, "JSON output")
	timeout := fs.Int("timeout", 30, "timeout seconds")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(*timeout)*time.Second)
	defer cancel()
	report := doctor.Run(ctx, doctor.DefaultChecks())
	if *jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{"passed": report.Passed, "failed": report.Failed})
	} else {
		report.PrintTo(stdout)
	}
	if report.HasFailures() {
		return 1
	}
	return 0
}

func cmdCompletion(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: completion [bash|zsh|fish]")
		return 1
	}
	switch args[0] {
	case "bash":
		fmt.Fprint(stdout, "# blrcs bash completion\ncomplete -W 'doctor version completion' blrcs\n")
	case "zsh":
		fmt.Fprint(stdout, "#compdef blrcs\n_blrcs() { local cmds=(doctor version completion); _describe cmd cmds }\n_blrcs \"$@\"\n")
	case "fish":
		fmt.Fprint(stdout, "complete -c blrcs -a 'doctor version completion'\n")
	default:
		fmt.Fprintf(stderr, "unknown shell: %s\n", args[0])
		return 1
	}
	return 0
}
