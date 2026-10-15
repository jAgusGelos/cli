package supervisor

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

//go:embed assets/seccomp-chromium.json
var seccompProfile []byte

// runnerCapAdd is the only capability set the runner gets on top of --cap-drop ALL (CONTRACTS 3).
var runnerCapAdd = []string{"SYS_CHROOT"}

const (
	ipPoolFirst     = 10
	ipPoolLast      = 250
	pauseDNS        = "192.0.2.53"
	netnsRulesPath  = "/opt/iwa/netns-rules.sh"
	launchTimeout   = 90 * time.Second
	ipLaunchRetries = 3
)

var (
	errAlreadyExists = errors.New("session already exists")
	errCapacity      = errors.New("capacity exhausted")
	errIPExhausted   = errors.New("no free runner IP")
)

func runnerName(short string) string { return "iwa-runner-" + short }
func pauseName(short string) string  { return "iwa-netns-" + short }
func helperName(short string) string { return "iwa-nethelper-" + short }

func (s *Server) seccompPath() string    { return filepath.Join(s.cfg.StateDir, "seccomp-chromium.json") }
func (s *Server) resolvConfPath() string { return filepath.Join(s.cfg.StateDir, "resolv.conf") }

// writeStateFiles writes the empty resolv.conf and the seccomp profile the launch spec references.
func (s *Server) writeStateFiles() error {
	if err := os.MkdirAll(s.cfg.StateDir, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(s.resolvConfPath(), nil, 0o644); err != nil {
		return err
	}
	return os.WriteFile(s.seccompPath(), seccompProfile, 0o644)
}

// labeledContainer is one container carrying the session label.
type labeledContainer struct {
	name    string
	session string
}

func (s *Server) listLabeled(ctx context.Context) ([]labeledContainer, error) {
	out, err := s.docker.Run(ctx, "ps", "-a", "--filter", "label="+SessionLabel,
		"--format", `{{.Names}}	{{.Label "`+SessionLabel+`"}}`)
	if err != nil {
		return nil, err
	}
	var res []labeledContainer
	for _, line := range strings.Split(out, "\n") {
		name, sess, ok := strings.Cut(strings.TrimSpace(line), "\t")
		if ok {
			res = append(res, labeledContainer{name: name, session: sess})
		}
	}
	return res, nil
}

func activeSessions(cs []labeledContainer) map[string]bool {
	active := map[string]bool{}
	for _, c := range cs {
		active[c.session] = true
	}
	return active
}

// reserve admits a launch: 409 for a known session or name clash, 429 above capacity. Pending launches count.
func (s *Server) reserve(ctx context.Context, spec *launchSpec) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.pending[spec.SessionID]; ok {
		return errAlreadyExists
	}
	cs, err := s.listLabeled(ctx)
	if err != nil {
		return err
	}
	for _, c := range cs {
		if c.session == spec.SessionID || strings.HasSuffix(c.name, "-"+spec.Short) {
			return errAlreadyExists
		}
	}
	active := activeSessions(cs)
	for id := range s.pending {
		active[id] = true
	}
	if len(active) >= s.cfg.MaxRunners {
		return errCapacity
	}
	s.pending[spec.SessionID] = ""
	delete(s.destroyed, spec.SessionID)
	return nil
}

func (s *Server) release(sessionID string) {
	s.mu.Lock()
	delete(s.pending, sessionID)
	s.mu.Unlock()
}

// pickIP returns a free address in .10-.250 that is neither attached to iwa-runners nor reserved by a pending launch.
func (s *Server) pickIP(ctx context.Context, sessionID string, skip map[string]bool) (string, error) {
	out, err := s.docker.Run(ctx, "network", "inspect", "--format",
		`{{range .Containers}}{{.IPv4Address}}{{"\n"}}{{end}}`, NetworkName)
	if err != nil {
		return "", err
	}
	used := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		if ip, _, ok := strings.Cut(strings.TrimSpace(line), "/"); ok {
			used[ip] = true
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ip := range s.pending {
		used[ip] = true
	}
	for i := ipPoolFirst; i <= ipPoolLast; i++ {
		ip := "172.28.0." + strconv.Itoa(i)
		if !used[ip] && !skip[ip] {
			s.pending[sessionID] = ip
			return ip, nil
		}
	}
	return "", errIPExhausted
}

func pauseArgs(spec *launchSpec, ip, resolvConf, imageID string) []string {
	return []string{"run", "-d", "--name", pauseName(spec.Short),
		"--label", SessionLabel + "=" + spec.SessionID,
		"--network", NetworkName, "--ip", ip, "--dns", pauseDNS,
		"--sysctl", "net.ipv6.conf.all.disable_ipv6=1",
		"-v", resolvConf + ":/etc/resolv.conf:ro",
		"--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
		"--entrypoint", "sleep", imageID, "infinity"}
}

func helperArgs(spec *launchSpec, imageID string) []string {
	return []string{"run", "--rm", "--name", helperName(spec.Short),
		"--label", SessionLabel + "=" + spec.SessionID,
		"--network", "container:" + pauseName(spec.Short),
		"--user", "0", "--cap-drop", "ALL", "--cap-add", "NET_ADMIN", "--security-opt", "no-new-privileges",
		"--entrypoint", netnsRulesPath, imageID,
		HostAddress, strconv.Itoa(spec.AgentPort), strconv.Itoa(spec.ProxyPort)}
}

// runnerArgs is the fixed runner launch spec (m1-interface.md). Env values travel through the docker client
// environment; argv only names them.
func runnerArgs(spec *launchSpec, seccomp, imageID string, envNames []string) []string {
	args := []string{"run", "-d", "--name", runnerName(spec.Short),
		"--label", SessionLabel + "=" + spec.SessionID,
		"--network", "container:" + pauseName(spec.Short),
		"--read-only",
		"--tmpfs", "/tmp:rw,nosuid,nodev,exec,size=512m,uid=1000,gid=1000,mode=0700",
		"--tmpfs", "/home/rbi:rw,nosuid,nodev,size=512m,uid=1000,gid=1000,mode=0700",
		"--tmpfs", "/quarantine:rw,nosuid,nodev,noexec,size=256m,uid=1000,gid=1000,mode=0700",
		"--shm-size", "1g",
		"--security-opt", "seccomp=" + seccomp,
		"--security-opt", "no-new-privileges",
		"--cap-drop", "ALL"}
	for _, c := range runnerCapAdd {
		args = append(args, "--cap-add", c)
	}
	args = append(args, "--user", "1000:1000",
		"--cpus", strconv.FormatFloat(spec.Resources.CPUs, 'f', -1, 64),
		"--memory", strconv.Itoa(spec.Resources.MemoryMb)+"m",
		"--pids-limit", strconv.Itoa(spec.Resources.PidsLimit))
	for _, n := range envNames {
		args = append(args, "-e", n)
	}
	return append(args, imageID)
}

func envNames(env []string) []string {
	names := make([]string, 0, len(env))
	for _, kv := range env {
		name, _, _ := strings.Cut(kv, "=")
		names = append(names, name)
	}
	return names
}

// checkRules verifies the helper's `iptables -S` output holds the egress lockdown.
func checkRules(out string, agentPort, proxyPort int) error {
	hasDrop := false
	accepts := map[int]bool{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if strings.Join(f, " ") == "-P OUTPUT DROP" {
			hasDrop = true
		}
		if len(f) < 2 || f[0] != "-A" || f[1] != "OUTPUT" || !strings.Contains(line, "ACCEPT") ||
			!strings.Contains(line, HostAddress) || !strings.Contains(line, "tcp") {
			continue
		}
		for i := 0; i+1 < len(f); i++ {
			if f[i] == "--dport" {
				if p, err := strconv.Atoi(f[i+1]); err == nil {
					accepts[p] = true
				}
			}
		}
	}
	switch {
	case !hasDrop:
		return errors.New("netns rules: OUTPUT policy is not DROP")
	case !accepts[agentPort]:
		return fmt.Errorf("netns rules: no OUTPUT accept for %s:%d", HostAddress, agentPort)
	case !accepts[proxyPort]:
		return fmt.Errorf("netns rules: no OUTPUT accept for %s:%d", HostAddress, proxyPort)
	}
	return nil
}

func isAddressInUse(err error) bool {
	var de *dockerError
	return errors.As(err, &de) && strings.Contains(strings.ToLower(de.msg), "address already in use")
}

type launchResult struct {
	SessionID     string `json:"sessionId"`
	ContainerName string `json:"containerName"`
	IP            string `json:"ip"`
	State         string `json:"state"`
}

// launch runs pause container, netns helper and runner; any failure removes whatever was created.
func (s *Server) launch(ctx context.Context, spec *launchSpec) (res *launchResult, err error) {
	ctx, cancel := context.WithTimeout(ctx, launchTimeout)
	defer cancel()
	s.mu.Lock()
	s.cancels[spec.SessionID] = cancel
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.cancels, spec.SessionID)
		s.mu.Unlock()
	}()
	defer s.release(spec.SessionID)

	if err := ensureNetwork(ctx, s.docker); err != nil {
		return nil, err
	}
	imageID, err := resolveImage(ctx, s.docker, spec.Image)
	if err != nil {
		return nil, err
	}
	if err := s.writeStateFiles(); err != nil {
		return nil, fmt.Errorf("state files: %w", err)
	}

	defer func() {
		if err != nil {
			// Rollback with a fresh context: the launch context may be the reason we failed.
			rbCtx, rbCancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer rbCancel()
			s.removeSession(rbCtx, spec.SessionID)
		}
	}()

	var ip string
	skip := map[string]bool{}
	for attempt := 0; ; attempt++ {
		if ip, err = s.pickIP(ctx, spec.SessionID, skip); err != nil {
			return nil, err
		}
		s.logger.Printf("launch %s: pause container %s at %s", spec.SessionID, pauseName(spec.Short), ip)
		_, err = s.docker.Run(ctx, pauseArgs(spec, ip, s.resolvConfPath(), imageID)...)
		if err == nil {
			break
		}
		if !isAddressInUse(err) || attempt+1 >= ipLaunchRetries {
			return nil, err
		}
		skip[ip] = true
		_, _ = s.docker.Run(ctx, "rm", "-f", pauseName(spec.Short))
	}

	s.logger.Printf("launch %s: netns rules via %s", spec.SessionID, helperName(spec.Short))
	out, err := s.docker.Run(ctx, helperArgs(spec, imageID)...)
	if err != nil {
		return nil, err
	}
	if err = checkRules(out, spec.AgentPort, spec.ProxyPort); err != nil {
		return nil, err
	}

	env, err := spec.runnerEnv(imageID)
	if err != nil {
		return nil, err
	}
	s.logger.Printf("launch %s: runner container %s", spec.SessionID, runnerName(spec.Short))
	if _, err = s.docker.RunEnv(ctx, env, runnerArgs(spec, s.seccompPath(), imageID, envNames(env))...); err != nil {
		return nil, err
	}

	s.mu.Lock()
	if err = ctx.Err(); err != nil {
		s.mu.Unlock()
		return nil, fmt.Errorf("launch aborted: %w", err)
	}
	s.sessions[spec.SessionID] = &session{id: spec.SessionID, short: spec.Short, ip: ip, imageID: imageID}
	s.mu.Unlock()
	return &launchResult{SessionID: spec.SessionID, ContainerName: runnerName(spec.Short), IP: ip, State: "starting"}, nil
}

// removeSession force-removes the session's containers by name, then sweeps anything else carrying its label.
func (s *Server) removeSession(ctx context.Context, sessionID string) error {
	short := shortID(sessionID)
	var firstErr error
	for _, name := range []string{runnerName(short), helperName(short), pauseName(short)} {
		if _, err := s.docker.Run(ctx, "rm", "-f", name); err != nil && !isNoSuchContainer(err) && firstErr == nil {
			firstErr = err
		}
	}
	out, err := s.docker.Run(ctx, "ps", "-aq", "--filter", "label="+SessionLabel+"="+sessionID)
	if err != nil {
		if firstErr == nil {
			firstErr = err
		}
	} else if ids := strings.Fields(out); len(ids) > 0 {
		if _, err := s.docker.Run(ctx, append([]string{"rm", "-f"}, ids...)...); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

type statusResult struct {
	SessionID     string  `json:"sessionId"`
	ContainerName string  `json:"containerName"`
	IP            string  `json:"ip"`
	State         string  `json:"state"`
	StartedAt     *string `json:"startedAt"`
	ExitCode      *int    `json:"exitCode"`
	OOMKilled     bool    `json:"oomKilled"`
}

// status reports the runner container state; ok is false for a session this host never knew.
func (s *Server) status(ctx context.Context, sessionID string) (*statusResult, bool, error) {
	short := shortID(sessionID)
	res := &statusResult{SessionID: sessionID, ContainerName: runnerName(short)}
	s.mu.Lock()
	known := s.sessions[sessionID]
	_, pending := s.pending[sessionID]
	destroyed := s.destroyed[sessionID]
	s.mu.Unlock()
	if known != nil {
		res.IP = known.ip
	}

	out, err := s.docker.Run(ctx, "container", "inspect", "--format",
		`{{index .Config.Labels "`+SessionLabel+`"}}|{{.State.Status}}|{{.State.StartedAt}}|{{.State.ExitCode}}|{{.State.OOMKilled}}`,
		runnerName(short))
	if err != nil {
		if !isNoSuchContainer(err) {
			return nil, false, err
		}
		switch {
		case pending:
			res.State = "starting"
		case destroyed:
			res.State = "destroyed"
		default:
			return nil, false, nil
		}
		return res, true, nil
	}
	parts := strings.Split(strings.TrimSpace(out), "|")
	if len(parts) != 5 || parts[0] != sessionID {
		return nil, false, nil
	}
	if res.IP == "" {
		res.IP = s.pauseIP(ctx, short)
	}
	switch parts[1] {
	case "created", "restarting":
		res.State = "starting"
	case "running", "paused":
		res.State = "running"
	case "removing":
		res.State = "destroyed"
	default:
		res.State = "exited"
		if code, err := strconv.Atoi(parts[3]); err == nil {
			res.ExitCode = &code
		}
	}
	if t := parts[2]; t != "" && !strings.HasPrefix(t, "0001-") {
		res.StartedAt = &t
	}
	res.OOMKilled = parts[4] == "true"
	return res, true, nil
}

func (s *Server) pauseIP(ctx context.Context, short string) string {
	out, err := s.docker.Run(ctx, "container", "inspect", "--format",
		`{{with index .NetworkSettings.Networks "`+NetworkName+`"}}{{.IPAddress}}{{end}}`, pauseName(short))
	if err != nil {
		return ""
	}
	ip := strings.TrimSpace(out)
	if net.ParseIP(ip) == nil {
		return ""
	}
	return ip
}
