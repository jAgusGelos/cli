// Command webapp-verify checks a Web App session evidence bundle offline against the recording key fingerprint the
// customer recorded out of band. Exit codes: 0 Verified, 1 Tampered, 2 usage error, 3 Incomplete.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/Infisical/infisical-merge/packages/pam/webapp/verifier"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("webapp-verify", flag.ContinueOnError)
	flags.SetOutput(stderr)
	bundleDir := flags.String("bundle", "", "evidence bundle directory (replay.json, session-key.b64, objects/)")
	fingerprint := flags.String("fingerprint", "", "recording key fingerprint recorded out of band, SHA256:...")
	asJSON := flags.Bool("json", false, "print the report as JSON")
	version := flags.Bool("version", false, "print the SHA-256 of this binary and exit")
	if err := flags.Parse(args); err != nil {
		return verifier.ExitUsage
	}
	if *version {
		return printVersion(stdout, stderr)
	}
	if *bundleDir == "" || *fingerprint == "" || flags.NArg() > 0 {
		fmt.Fprintln(stderr, "usage: webapp-verify --bundle <dir> --fingerprint SHA256:... [--json]")
		return verifier.ExitUsage
	}
	bundle, err := verifier.LoadBundle(*bundleDir)
	if errors.Is(err, verifier.ErrMalformedBundle) {
		fmt.Fprintf(stdout, "%s\n  %v\n", verifier.VerdictTampered, err)
		return verifier.ExitTampered
	}
	if err != nil {
		fmt.Fprintf(stderr, "webapp-verify: %v\n", err)
		return verifier.ExitUsage
	}
	report := verifier.Verify(bundle, *fingerprint)
	if err := writeReport(stdout, report, *asJSON); err != nil {
		fmt.Fprintf(stderr, "webapp-verify: write report: %v\n", err)
		return verifier.ExitUsage
	}
	return report.ExitCode()
}

func writeReport(w io.Writer, report *verifier.Report, asJSON bool) error {
	if !asJSON {
		return report.WriteText(w)
	}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

// printVersion prints the binary's own digest so auditors can compare it with the pinned value.
func printVersion(stdout, stderr io.Writer) int {
	path, err := os.Executable()
	if err == nil {
		var raw []byte
		if raw, err = os.ReadFile(path); err == nil {
			sum := sha256.Sum256(raw)
			fmt.Fprintf(stdout, "webapp-verify sha256:%s\n", hex.EncodeToString(sum[:]))
			return verifier.ExitVerified
		}
	}
	fmt.Fprintf(stderr, "webapp-verify: hash own binary: %v\n", err)
	return verifier.ExitUsage
}
