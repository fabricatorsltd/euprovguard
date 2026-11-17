package main

import (
	"flag"
	"os"
	"testing"
)

func TestParseFlagsFindingGate(t *testing.T) {
	oldArgs, oldFlags := os.Args, flag.CommandLine
	t.Cleanup(func() { os.Args, flag.CommandLine = oldArgs, oldFlags })
	flag.CommandLine = flag.NewFlagSet("test", flag.ContinueOnError)
	os.Args = []string{"euprovguard", "-fail-on-findings", "-baseline", "accepted.json", "-path", "."}
	cfg := parseFlags()
	if !cfg.FailOnFindings || cfg.BaselinePath != "accepted.json" {
		t.Fatalf("configuration %+v", cfg)
	}
}
