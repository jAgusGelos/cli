package supervisor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

const (
	NetworkName   = "iwa-runners"
	NetworkSubnet = "172.28.0.0/24"
	BridgeName    = "iwa-runners0"
	SessionLabel  = "infisical.webapp.session"
)

// dockerRunner runs one docker CLI command. env holds extra NAME=value pairs for the docker client process, so
// secrets reach the container through "-e NAME" and never appear in argv or logs.
type dockerRunner interface {
	Run(ctx context.Context, args ...string) (string, error)
	RunEnv(ctx context.Context, env []string, args ...string) (string, error)
}

type execDocker struct {
	bin    string
	logger *log.Logger
}

func newExecDocker(logger *log.Logger) *execDocker {
	return &execDocker{bin: "docker", logger: logger}
}

func (d *execDocker) Run(ctx context.Context, args ...string) (string, error) {
	return d.RunEnv(ctx, nil, args...)
}

func (d *execDocker) RunEnv(ctx context.Context, env []string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, d.bin, args...)
	if len(env) > 0 {
		cmd.Env = append(os.Environ(), env...)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	start := time.Now()
	err := cmd.Run()
	took := time.Since(start).Round(time.Millisecond)
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		d.logger.Printf("docker %s failed in %s: %v: %s", strings.Join(args, " "), took, err, msg)
		return stdout.String(), &dockerError{args: args, msg: msg, err: err}
	}
	d.logger.Printf("docker %s ok in %s", strings.Join(args, " "), took)
	return stdout.String(), nil
}

type dockerError struct {
	args []string
	msg  string
	err  error
}

func (e *dockerError) Error() string {
	sub := ""
	if len(e.args) > 0 {
		sub = e.args[0]
	}
	return fmt.Sprintf("docker %s: %v: %s", sub, e.err, e.msg)
}

func (e *dockerError) Unwrap() error { return e.err }

func isNoSuchContainer(err error) bool {
	var de *dockerError
	return errors.As(err, &de) && strings.Contains(strings.ToLower(de.msg), "no such container")
}

// ensureNetwork creates iwa-runners if missing and checks an existing one has the contract shape.
func ensureNetwork(ctx context.Context, d dockerRunner) error {
	check := func() (bool, error) {
		out, err := d.Run(ctx, "network", "inspect", "--format",
			`{{.Internal}} {{range .IPAM.Config}}{{.Subnet}}{{end}} {{index .Options "com.docker.network.bridge.name"}}`, NetworkName)
		if err != nil {
			return false, nil
		}
		want := fmt.Sprintf("true %s %s", NetworkSubnet, BridgeName)
		if got := strings.TrimSpace(out); got != want {
			return true, fmt.Errorf("network %s exists as %q, want %q", NetworkName, got, want)
		}
		return true, nil
	}
	if ok, err := check(); ok || err != nil {
		return err
	}
	_, createErr := d.Run(ctx, "network", "create", "--driver", "bridge", "--internal",
		"--subnet", NetworkSubnet, "--gateway", HostAddress,
		"-o", "com.docker.network.bridge.name="+BridgeName, NetworkName)
	// A concurrent create (another supervisor) is fine as long as the network now looks right.
	if ok, err := check(); ok || err != nil {
		return err
	}
	return fmt.Errorf("create network %s: %w", NetworkName, createErr)
}

var allowlistRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._/-]*(:[0-9]+)?[a-z0-9._/-]*@sha256:[0-9a-f]{64}$`)

// parseAllowlist reads INFISICAL_WEBAPP_RUNNER_IMAGES: comma-separated name@sha256:<id>.
func parseAllowlist(raw string) ([]string, error) {
	var out []string
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if !allowlistRE.MatchString(item) {
			return nil, fmt.Errorf("allowlist entry %q is not name@sha256:<64 hex>", item)
		}
		out = append(out, item)
	}
	return out, nil
}

// resolveImage maps an allowlisted name@sha256:<id> to the local image ID. Docker may resolve the digest reference
// directly; otherwise the image whose ID is sha256:<id> must exist locally. The caller always runs the ID.
func resolveImage(ctx context.Context, d dockerRunner, ref string) (string, error) {
	at := strings.LastIndex(ref, "@")
	want := ref[at+1:]
	for _, candidate := range []string{ref, want} {
		out, err := d.Run(ctx, "image", "inspect", "--format", "{{.Id}}", candidate)
		if err != nil {
			continue
		}
		if strings.TrimSpace(out) == want {
			return want, nil
		}
	}
	return "", fmt.Errorf("image %s is not present locally with ID %s", ref, want)
}
