package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Infisical/infisical-merge/packages/pam/webapp/verifier"
	"github.com/stretchr/testify/require"
)

const (
	fixtureBundle    = "../../testdata/bundle-verified"
	otherFingerprint = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
)

var fixtureFingerprint = func() string {
	b, err := verifier.LoadBundle(fixtureBundle)
	if err != nil {
		panic(err)
	}
	return b.Replay.RecordingKey.Fingerprint
}()

func runCLI(args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestVerifiedBundle(t *testing.T) {
	code, out, _ := runCLI("--bundle", fixtureBundle, "--fingerprint", fixtureFingerprint)
	require.Equal(t, verifier.ExitVerified, code)
	require.True(t, strings.HasPrefix(out, "Verified\n"), out)
}

func TestJSONReport(t *testing.T) {
	code, out, _ := runCLI("--bundle", fixtureBundle, "--fingerprint", fixtureFingerprint, "--json")
	require.Equal(t, verifier.ExitVerified, code)
	var report verifier.Report
	require.NoError(t, json.Unmarshal([]byte(out), &report))
	require.Equal(t, verifier.VerdictVerified, report.Verdict)
	require.Equal(t, 3, report.VideoObjects)
}

func TestWrongFingerprintIsTampered(t *testing.T) {
	code, out, _ := runCLI("--bundle", fixtureBundle, "--fingerprint", otherFingerprint)
	require.Equal(t, verifier.ExitTampered, code)
	require.Contains(t, out, "does not match the trusted fingerprint")
}

func TestUsageErrors(t *testing.T) {
	for name, args := range map[string][]string{
		"no flags":         {},
		"no fingerprint":   {"--bundle", fixtureBundle},
		"unknown flag":     {"--nope"},
		"missing bundle":   {"--bundle", t.TempDir(), "--fingerprint", fixtureFingerprint},
		"extra positional": {"--bundle", fixtureBundle, "--fingerprint", fixtureFingerprint, "extra"},
	} {
		t.Run(name, func(t *testing.T) {
			code, _, _ := runCLI(args...)
			require.Equal(t, verifier.ExitUsage, code)
		})
	}
}

func TestMalformedBundleIsTampered(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, verifier.ReplayFile), []byte("{not json"), 0o644))
	code, out, _ := runCLI("--bundle", dir, "--fingerprint", fixtureFingerprint)
	require.Equal(t, verifier.ExitTampered, code)
	require.True(t, strings.HasPrefix(out, "Tampered\n"), out)
}
