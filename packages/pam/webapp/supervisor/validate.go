package supervisor

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// HostAddress is the host side of the iwa-runners bridge; the gateway listeners must live there (CONTRACTS 2).
const HostAddress = "172.28.0.1"

// Fixed caps for caller-supplied numbers. Defaults follow CONTRACTS 3.1.
const (
	maxAllowedHosts   = 32
	maxStartURLLen    = 2048
	maxCAPemLen       = 16 * 1024
	maxWatermarkRunes = 200
	minTokenBytes     = 16
	maxTokenBytes     = 64
)

var (
	uuidRE     = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	dnsLabelRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
)

// launchSpec is a validated request with defaults applied; every field is safe to place in argv or env.
type launchSpec struct {
	SessionID    string
	Short        string // first 12 hex of the session id
	Image        string // the allowlisted reference as requested
	RunnerToken  string
	AgentAddr    string
	AgentPort    int
	ProxyAddr    string
	ProxyPort    int
	StartURL     string
	AllowedHosts []string
	CAPem        string
	Policy       Policy
	Display      Display
	Recording    Recording
	Resources    Resources
	Watermark    string
}

type validationError struct{ msg string }

func (e *validationError) Error() string { return e.msg }

func invalid(format string, args ...any) error {
	return &validationError{msg: fmt.Sprintf(format, args...)}
}

func validSessionID(id string) bool { return uuidRE.MatchString(id) }

func shortID(sessionID string) string { return strings.ReplaceAll(sessionID, "-", "")[:12] }

func validateLaunch(req *LaunchRequest) (*launchSpec, error) {
	if !validSessionID(req.SessionID) {
		return nil, invalid("sessionId must be a lowercase UUID")
	}
	spec := &launchSpec{SessionID: req.SessionID, Short: shortID(req.SessionID), Image: req.Image}
	if req.Image == "" {
		return nil, invalid("image is required")
	}

	tok, err := base64.RawURLEncoding.DecodeString(req.RunnerToken)
	if err != nil || strings.ContainsAny(req.RunnerToken, "=+/") {
		return nil, invalid("runnerToken must be b64url without padding")
	}
	if len(tok) < minTokenBytes || len(tok) > maxTokenBytes {
		return nil, invalid("runnerToken must decode to %d..%d bytes", minTokenBytes, maxTokenBytes)
	}
	spec.RunnerToken = req.RunnerToken

	if spec.AgentPort, err = bridgePort(req.GatewayAgentAddr); err != nil {
		return nil, invalid("gatewayAgentAddr: %v", err)
	}
	if spec.ProxyPort, err = bridgePort(req.EgressProxyAddr); err != nil {
		return nil, invalid("egressProxyAddr: %v", err)
	}
	if spec.AgentPort == spec.ProxyPort {
		return nil, invalid("gatewayAgentAddr and egressProxyAddr must use different ports")
	}
	spec.AgentAddr = net.JoinHostPort(HostAddress, strconv.Itoa(spec.AgentPort))
	spec.ProxyAddr = net.JoinHostPort(HostAddress, strconv.Itoa(spec.ProxyPort))

	if len(req.AllowedHosts) == 0 || len(req.AllowedHosts) > maxAllowedHosts {
		return nil, invalid("allowedHosts must have 1..%d entries", maxAllowedHosts)
	}
	for _, h := range req.AllowedHosts {
		if !validDNSName(h) {
			return nil, invalid("allowedHosts entry %q is not a lowercase DNS name", h)
		}
	}
	spec.AllowedHosts = append([]string(nil), req.AllowedHosts...)

	if err := validateStartURL(req.StartURL, spec.AllowedHosts); err != nil {
		return nil, err
	}
	spec.StartURL = req.StartURL

	if err := validateCAPem(req.CaPem); err != nil {
		return nil, err
	}
	spec.CAPem = req.CaPem

	if spec.Policy, err = validatePolicy(req.Policy); err != nil {
		return nil, err
	}
	if spec.Display, err = validateDisplay(req.Display); err != nil {
		return nil, err
	}
	if spec.Recording, err = validateRecording(req.Recording); err != nil {
		return nil, err
	}
	if spec.Resources, err = validateResources(req.Resources); err != nil {
		return nil, err
	}
	if spec.Watermark, err = validateWatermark(req.Watermark, spec.Short); err != nil {
		return nil, err
	}
	return spec, nil
}

func bridgePort(addr string) (int, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return 0, fmt.Errorf("must be %s:<port>", HostAddress)
	}
	if host != HostAddress {
		return 0, fmt.Errorf("host must be %s", HostAddress)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 || strconv.Itoa(port) != portStr {
		return 0, fmt.Errorf("invalid port %q", portStr)
	}
	return port, nil
}

func validDNSName(h string) bool {
	if len(h) == 0 || len(h) > 253 || net.ParseIP(h) != nil {
		return false
	}
	labels := strings.Split(h, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if !dnsLabelRE.MatchString(l) {
			return false
		}
	}
	// An all-numeric last label would read as an IPv4 literal to some resolvers.
	_, err := strconv.Atoi(labels[len(labels)-1])
	return err != nil
}

func validateStartURL(raw string, allowed []string) error {
	if raw == "" || len(raw) > maxStartURLLen || hasControl(raw) {
		return invalid("startUrl is required, at most %d bytes, without control characters", maxStartURLLen)
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Opaque != "" || u.User != nil {
		return invalid("startUrl must be an https URL without credentials")
	}
	if p := u.Port(); p != "" && p != "443" {
		return invalid("startUrl must use port 443")
	}
	host := u.Hostname()
	for _, h := range allowed {
		if host == h {
			return nil
		}
	}
	return invalid("startUrl host %q is not in allowedHosts", host)
}

func validateCAPem(caPem string) error {
	if caPem == "" || len(caPem) > maxCAPemLen {
		return invalid("caPem is required and at most %d bytes", maxCAPemLen)
	}
	rest := []byte(caPem)
	certs := 0
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if strings.Contains(block.Type, "PRIVATE KEY") {
			return invalid("caPem must not contain a private key")
		}
		if block.Type != "CERTIFICATE" {
			return invalid("caPem contains an unexpected %q block", block.Type)
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return invalid("caPem certificate does not parse")
		}
		certs++
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return invalid("caPem has trailing data that is not PEM")
	}
	if certs != 1 {
		return invalid("caPem must hold exactly one certificate, got %d", certs)
	}
	return nil
}

func validatePolicy(p Policy) (Policy, error) {
	out := Policy{Clipboard: "off", Downloads: "quarantine", Uploads: "block", Kiosk: true}
	if p == (Policy{}) {
		return out, nil
	}
	if !oneOf(p.Clipboard, "off", "to_remote", "from_remote", "both") {
		return out, invalid("policy.clipboard must be off|to_remote|from_remote|both")
	}
	if !oneOf(p.Downloads, "block", "quarantine", "allow") {
		return out, invalid("policy.downloads must be block|quarantine|allow")
	}
	if !oneOf(p.Uploads, "block", "allow") {
		return out, invalid("policy.uploads must be block|allow")
	}
	return p, nil
}

func validateDisplay(d Display) (Display, error) {
	out := Display{Width: 1280, Height: 720, Framerate: 30}
	if d == (Display{}) {
		return out, nil
	}
	if d.Width < 320 || d.Width > 1920 || d.Height < 240 || d.Height > 1080 || d.Width%2 != 0 || d.Height%2 != 0 {
		return out, invalid("display must be even, 320..1920 x 240..1080")
	}
	if d.Framerate < 5 || d.Framerate > 30 {
		return out, invalid("display.framerate must be 5..30")
	}
	return d, nil
}

func validateRecording(r Recording) (Recording, error) {
	out := Recording{SegmentSeconds: 10, BitrateKbps: 1500, CRF: 26}
	if r == (Recording{}) {
		return out, nil
	}
	if r.SegmentSeconds < 2 || r.SegmentSeconds > 60 {
		return out, invalid("recording.segmentSeconds must be 2..60")
	}
	if r.BitrateKbps < 200 || r.BitrateKbps > 8000 {
		return out, invalid("recording.bitrateKbps must be 200..8000")
	}
	if r.CRF < 15 || r.CRF > 40 {
		return out, invalid("recording.crf must be 15..40")
	}
	return r, nil
}

func validateResources(r Resources) (Resources, error) {
	out := Resources{CPUs: 1.5, MemoryMb: 1536, PidsLimit: 512}
	if r == (Resources{}) {
		return out, nil
	}
	if r.CPUs < 0.5 || r.CPUs > 4 {
		return out, invalid("resources.cpus must be 0.5..4")
	}
	if r.MemoryMb < 768 || r.MemoryMb > 4096 {
		return out, invalid("resources.memoryMb must be 768..4096")
	}
	if r.PidsLimit < 128 || r.PidsLimit > 2048 {
		return out, invalid("resources.pidsLimit must be 128..2048")
	}
	return r, nil
}

func validateWatermark(w Watermark, short string) (string, error) {
	if strings.TrimSpace(w.Text) == "" {
		return "session " + short, nil
	}
	if !utf8.ValidString(w.Text) || utf8.RuneCountInString(w.Text) > maxWatermarkRunes || hasControl(w.Text) {
		return "", invalid("watermark.text must be at most %d characters without control characters", maxWatermarkRunes)
	}
	return w.Text, nil
}

func hasControl(s string) bool {
	return strings.IndexFunc(s, unicode.IsControl) >= 0
}

func oneOf(v string, allowed ...string) bool {
	return slices.Contains(allowed, v)
}

// runnerEnv is the IWA_* environment of the runner container (CONTRACTS 3.1 plus IWA_IMAGE_DIGEST).
func (s *launchSpec) runnerEnv(imageID string) ([]string, error) {
	hosts, err := json.Marshal(s.AllowedHosts)
	if err != nil {
		return nil, err
	}
	policy, err := json.Marshal(s.Policy)
	if err != nil {
		return nil, err
	}
	rec, err := json.Marshal(s.Recording)
	if err != nil {
		return nil, err
	}
	return []string{
		"IWA_SESSION_ID=" + s.SessionID,
		"IWA_RUNNER_TOKEN=" + s.RunnerToken,
		"IWA_GATEWAY_AGENT_ADDR=" + s.AgentAddr,
		"IWA_PROXY_ADDR=" + s.ProxyAddr,
		"IWA_START_URL=" + s.StartURL,
		"IWA_ALLOWED_HOSTS=" + string(hosts),
		"IWA_CA_PEM=" + s.CAPem,
		"IWA_POLICY=" + string(policy),
		fmt.Sprintf("IWA_DISPLAY=%dx%d@%d", s.Display.Width, s.Display.Height, s.Display.Framerate),
		"IWA_RECORDING=" + string(rec),
		"IWA_WATERMARK=" + s.Watermark,
		"IWA_IMAGE_DIGEST=" + imageID,
	}, nil
}
