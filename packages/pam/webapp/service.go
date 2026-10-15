package webapp

import (
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Infisical/infisical-merge/packages/pam/webapp/contract"
	"github.com/Infisical/infisical-merge/packages/pam/webapp/egress"
	"github.com/Infisical/infisical-merge/packages/pam/webapp/recorder"
	"github.com/Infisical/infisical-merge/packages/pam/webapp/supervisor"
	"github.com/go-resty/resty/v2"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Defaults from CONTRACTS.md section 2.
const (
	DefaultAgentAddr = "172.28.0.1:7701"
	DefaultProxyAddr = "172.28.0.1:3128"
)

type Config struct {
	SupervisorSocket string
	RunnerImage      string
	HostsOverride    string
	AgentAddr        string // listen address of the runner-agent endpoint
	ProxyAddr        string // listen address of the egress proxy
	StateDir         string // recording key directory
	BackendURL       string // Infisical API base URL (config.INFISICAL_URL)
	GatewayID        string

	HealthInterval   time.Duration // supervisor health probe and bind retry period (2 s)
	HealthTimeout    time.Duration // give up after this long (60 s)
	AgentWaitTimeout time.Duration // AGENT_HELLO wait after launch (60 s)
	HelloTimeout     time.Duration // viewer HELLO wait (30 s)
}

// ConfigFromEnv reads the Web App environment once (documented in doc.go). defaultStateDir is the gateway's existing
// state dir, used when INFISICAL_GATEWAY_DIR is unset.
func ConfigFromEnv(defaultStateDir string) Config {
	env := func(k, def string) string {
		if v := os.Getenv(k); v != "" {
			return v
		}
		return def
	}
	return Config{
		SupervisorSocket: env("INFISICAL_WEBAPP_SUPERVISOR_SOCKET", supervisor.DefaultSocketPath),
		RunnerImage:      os.Getenv("INFISICAL_WEBAPP_RUNNER_IMAGE"),
		HostsOverride:    os.Getenv("INFISICAL_WEBAPP_HOSTS_OVERRIDE"),
		AgentAddr:        env("INFISICAL_WEBAPP_AGENT_ADDR", DefaultAgentAddr),
		ProxyAddr:        env("INFISICAL_WEBAPP_PROXY_ADDR", DefaultProxyAddr),
		StateDir:         env("INFISICAL_GATEWAY_DIR", defaultStateDir),
	}
}

func (c *Config) defaults() {
	if c.HealthInterval == 0 {
		c.HealthInterval = 2 * time.Second
	}
	if c.HealthTimeout == 0 {
		c.HealthTimeout = 60 * time.Second
	}
	if c.AgentWaitTimeout == 0 {
		c.AgentWaitTimeout = 60 * time.Second
	}
	if c.HelloTimeout == 0 {
		c.HelloTimeout = 30 * time.Second
	}
	if c.AgentAddr == "" {
		c.AgentAddr = DefaultAgentAddr
	}
	if c.ProxyAddr == "" {
		c.ProxyAddr = DefaultProxyAddr
	}
}

const (
	stateStarting int32 = iota
	stateReady
	stateDisabled
)

// Service is the gateway-wide Web App component: supervisor client, recording key, the runner-agent endpoint, the
// egress proxy and the registry of sessions waiting for their agent (plan AD-2).
type Service struct {
	cfg        Config
	sup        *supervisor.Client
	recKey     ed25519.PrivateKey
	api        *resty.Client
	proxy      *egress.Proxy
	log        zerolog.Logger
	newBackend func(sessionID, uploadToken string) recorder.Backend

	state   atomic.Int32
	settled chan struct{}

	mu       sync.Mutex
	pending  map[string]*pendingAgent
	live     map[string]*liveSession
	agentLn  net.Listener
	proxyLn  net.Listener
	stopOnce sync.Once
}

// NewService loads (or creates) the recording key and prints its fingerprint. Listeners bind in Start.
func NewService(cfg Config, apiClient *resty.Client) (*Service, error) {
	cfg.defaults()
	key, err := recorder.LoadOrCreateRecordingKey(cfg.StateDir)
	if err != nil {
		return nil, fmt.Errorf("webapp: recording key: %w", err)
	}
	policy, err := egress.NewPolicy(cfg.HostsOverride)
	if err != nil {
		return nil, fmt.Errorf("webapp: INFISICAL_WEBAPP_HOSTS_OVERRIDE: %w", err)
	}
	l := log.With().Str("component", "webapp").Logger()
	s := &Service{
		cfg:     cfg,
		sup:     supervisor.NewClient(cfg.SupervisorSocket),
		recKey:  key,
		api:     apiClient,
		proxy:   egress.NewProxy(policy, l),
		log:     l,
		settled: make(chan struct{}),
		pending: map[string]*pendingAgent{},
		live:    map[string]*liveSession{},
	}
	s.newBackend = func(sessionID, uploadToken string) recorder.Backend {
		return recorder.NewHTTPBackend(cfg.BackendURL, sessionID, uploadToken, apiClient)
	}
	l.Info().Msgf("Web App recording key fingerprint: %s", contract.Fingerprint(key.Public().(ed25519.PublicKey)))
	return s, nil
}

// SetGatewayID sets the gateway id recorded in session_open (known only after registration).
func (s *Service) SetGatewayID(id string) {
	s.mu.Lock()
	s.cfg.GatewayID = id
	s.mu.Unlock()
}

func (s *Service) gatewayID() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cfg.GatewayID
}

// RecordingPublicKey returns the gateway recording public key.
func (s *Service) RecordingPublicKey() ed25519.PublicKey {
	return s.recKey.Public().(ed25519.PublicKey)
}

// Start probes the supervisor every HealthInterval for HealthTimeout and binds the agent and proxy listeners only after
// health is ok (the runner bridge exists only then, CONTRACTS.md section 2 bind order).
func (s *Service) Start(ctx context.Context) {
	go s.run(ctx)
}

func (s *Service) run(ctx context.Context) {
	deadline := time.Now().Add(s.cfg.HealthTimeout)
	settle := func(st int32) {
		s.state.Store(st)
		close(s.settled)
	}
	healthy := false
	for {
		if !healthy {
			hctx, cancel := context.WithTimeout(ctx, healthProbeTimeout)
			_, err := s.sup.Health(hctx)
			cancel()
			healthy = err == nil
			if err != nil {
				s.log.Debug().Err(err).Msg("Web App supervisor not healthy yet")
			}
		}
		if healthy {
			err := s.bind()
			if err == nil {
				settle(stateReady)
				s.log.Info().Str("agentAddr", s.cfg.AgentAddr).Str("proxyAddr", s.cfg.ProxyAddr).Msg("Web App sessions enabled")
				go func() { <-ctx.Done(); s.Close() }()
				return
			}
			s.log.Debug().Err(err).Msg("Web App listener bind failed, retrying")
		}
		if time.Now().After(deadline) {
			settle(stateDisabled)
			s.log.Warn().Msg("Web App sessions disabled: supervisor unavailable")
			return
		}
		select {
		case <-ctx.Done():
			settle(stateDisabled)
			return
		case <-time.After(s.cfg.HealthInterval):
		}
	}
}

func (s *Service) bind() error {
	aln, err := net.Listen("tcp", s.cfg.AgentAddr)
	if err != nil {
		return err
	}
	pln, err := net.Listen("tcp", s.cfg.ProxyAddr)
	if err != nil {
		aln.Close()
		return err
	}
	s.mu.Lock()
	s.agentLn, s.proxyLn = aln, pln
	// The runner dials the bound addresses (ephemeral ports in tests).
	s.cfg.AgentAddr, s.cfg.ProxyAddr = aln.Addr().String(), pln.Addr().String()
	s.mu.Unlock()
	go s.acceptAgents(aln)
	go s.proxy.Serve(pln) //nolint:errcheck
	return nil
}

// Ready waits for the bind-order outcome (bounded by ctx) and reports whether sessions are enabled.
func (s *Service) Ready(ctx context.Context) bool {
	select {
	case <-s.settled:
	case <-ctx.Done():
		return false
	}
	return s.state.Load() == stateReady
}

// Close stops the listeners.
func (s *Service) Close() {
	s.stopOnce.Do(func() {
		s.mu.Lock()
		if s.agentLn != nil {
			s.agentLn.Close()
		}
		if s.proxyLn != nil {
			s.proxyLn.Close()
		}
		s.mu.Unlock()
	})
}

func (s *Service) addrs() (agent, proxy string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cfg.AgentAddr, s.cfg.ProxyAddr
}

// pendingAgent is a session waiting for (or holding) its runner agent link.
type pendingAgent struct {
	token   string
	mu      sync.Mutex
	ip      netip.Addr
	ipKnown chan struct{}
	links   chan *agentLink
}

func (s *Service) registerPending(sessionID, token string) (*pendingAgent, func()) {
	p := &pendingAgent{token: token, ipKnown: make(chan struct{}), links: make(chan *agentLink, 1)}
	s.mu.Lock()
	s.pending[sessionID] = p
	s.mu.Unlock()
	return p, func() {
		s.mu.Lock()
		if s.pending[sessionID] == p {
			delete(s.pending, sessionID)
		}
		s.mu.Unlock()
	}
}

func (p *pendingAgent) setIP(ip netip.Addr) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.ip.IsValid() {
		p.ip = ip.Unmap()
		close(p.ipKnown)
	}
}

func (s *Service) acceptAgents(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go s.handleAgent(c)
	}
}

// Errors carried by AGENT_WELCOME (CONTRACTS.md 1.6, 4.1).
const (
	welcomeUnauthorized     = "unauthorized"
	welcomeEncoderModeNotOK = "encoder_mode_not_allowed"
)

func writeWelcome(c net.Conn, w contract.AgentWelcome) error {
	b, _ := json.Marshal(w)
	return contract.WriteFrame(c, &contract.Frame{Type: contract.FrameAgentWelcome, Payload: b})
}

// handleAgent authenticates AGENT_HELLO (constant-time token, source IP equals the supervisor-assigned IP, encoder mode
// dual) and hands the link to its session.
func (s *Service) handleAgent(c net.Conn) {
	refuse := func(reason, why string) {
		s.log.Warn().Str("remote", c.RemoteAddr().String()).Str("reason", why).Msg("Web App agent link refused")
		_ = writeWelcome(c, contract.AgentWelcome{OK: false, Error: reason})
		c.Close()
	}
	_ = c.SetDeadline(time.Now().Add(agentHelloTimeout))
	f, err := contract.ReadFrame(c, contract.MaxAgentPayload)
	if err != nil || f.Type != contract.FrameAgentHello {
		c.Close()
		return
	}
	var hello contract.AgentHello
	if err := json.Unmarshal(f.Payload, &hello); err != nil {
		refuse(welcomeUnauthorized, "bad AGENT_HELLO")
		return
	}
	s.mu.Lock()
	p := s.pending[hello.SessionID]
	s.mu.Unlock()
	if p == nil || subtle.ConstantTimeCompare([]byte(hello.RunnerToken), []byte(p.token)) != 1 {
		refuse(welcomeUnauthorized, "unknown session or bad token")
		return
	}
	select {
	case <-p.ipKnown:
	case <-time.After(runnerIPWait):
		refuse(welcomeUnauthorized, "runner IP unknown")
		return
	}
	src, err := netip.ParseAddrPort(c.RemoteAddr().String())
	if err != nil || src.Addr().Unmap() != p.ip {
		refuse(welcomeUnauthorized, "source IP does not match the runner")
		return
	}
	if hello.EncoderMode != encoderModeDual {
		refuse(welcomeEncoderModeNotOK, "encoder mode "+hello.EncoderMode)
		return
	}
	link := newAgentLink(c, hello)
	if err := link.welcome(); err != nil {
		c.Close()
		return
	}
	_ = c.SetDeadline(time.Time{})
	select {
	case p.links <- link:
	default:
		// Reconnect handling (link replacement) is not wired yet: keep the current link.
		s.log.Warn().Str("sessionId", hello.SessionID).Msg("Web App agent reconnect while a link is pending, refused")
		c.Close()
	}
}

var errAgentTimeout = errors.New("webapp: runner agent did not connect in time")
