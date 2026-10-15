// Package egress is the gateway's forward proxy for Web App runners (INF-WEBAPP CONTRACTS.md section 2): the only
// network path out of a runner. It attributes each connection to a session by source IP, enforces the session host
// allowlist and the destination deny list, pins the resolved IP and records L1 events.
package egress

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// Block reasons recorded in l1_blocked (CONTRACTS.md 5.3).
const (
	ReasonHostNotAllowed = "host_not_allowed"
	ReasonIPDenied       = "ip_denied"
	ReasonResolveFailed  = "resolve_failed"
	ReasonSNIMismatch    = "sni_mismatch"
)

// Resolver resolves a host name; tests inject a fake (no real DNS).
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// ParseHostsOverride parses INFISICAL_WEBAPP_HOSTS_OVERRIDE ("host=ip,host=ip").
func ParseHostsOverride(s string) (map[string]netip.Addr, error) {
	out := map[string]netip.Addr{}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		host, ip, ok := strings.Cut(part, "=")
		if !ok {
			return nil, fmt.Errorf("hosts override entry %q is not host=ip", part)
		}
		addr, err := netip.ParseAddr(strings.TrimSpace(ip))
		if err != nil {
			return nil, fmt.Errorf("hosts override entry %q: %w", part, err)
		}
		out[strings.ToLower(strings.TrimSpace(host))] = addr.Unmap()
	}
	return out, nil
}

var alwaysDenied = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("169.254.0.0/16"), // link-local, includes the metadata address 169.254.169.254
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("172.28.0.0/24"), // runner subnet
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("ff00::/8"),
	netip.MustParsePrefix("::/128"),
}

// DefaultOwnAddrExempt is the demo app network: the host owns 172.27.0.1 there, and apps on it are reachable.
var DefaultOwnAddrExempt = []netip.Prefix{netip.MustParsePrefix("172.27.0.0/24")}

// Policy decides which destinations a runner may reach.
type Policy struct {
	Override map[string]netip.Addr
	Resolver Resolver
	// OwnAddrs are the gateway host's interface addresses (denied unless inside OwnAddrExempt).
	OwnAddrs      []netip.Addr
	OwnAddrExempt []netip.Prefix
	// Exempt bypasses every deny rule for the listed prefixes. Tests only; never set from configuration.
	Exempt []netip.Prefix
}

// NewPolicy builds the production policy: hosts override, system resolver, host interface addresses.
func NewPolicy(hostsOverride string) (*Policy, error) {
	ov, err := ParseHostsOverride(hostsOverride)
	if err != nil {
		return nil, err
	}
	return &Policy{Override: ov, Resolver: net.DefaultResolver, OwnAddrs: InterfaceAddrs(), OwnAddrExempt: DefaultOwnAddrExempt}, nil
}

// InterfaceAddrs lists the addresses of the host's interfaces.
func InterfaceAddrs() []netip.Addr {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []netip.Addr
	for _, a := range addrs {
		if p, err := netip.ParsePrefix(a.String()); err == nil {
			out = append(out, p.Addr().Unmap())
		}
	}
	return out
}

// Denied reports whether ip is on the deny list.
func (p *Policy) Denied(ip netip.Addr) bool {
	ip = ip.Unmap()
	for _, pre := range p.Exempt {
		if pre.Contains(ip) {
			return false
		}
	}
	if !ip.IsValid() || ip.IsUnspecified() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() {
		return true
	}
	for _, pre := range alwaysDenied {
		if pre.Contains(ip) {
			return true
		}
	}
	for _, own := range p.OwnAddrs {
		if own == ip {
			for _, ex := range p.OwnAddrExempt {
				if ex.Contains(ip) {
					return false
				}
			}
			return true
		}
	}
	return false
}

// HostAllowed checks host (lowercase, exact) against the session allowlist.
func HostAllowed(host string, allowed []string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, a := range allowed {
		if strings.ToLower(a) == host {
			return true
		}
	}
	return false
}

// ErrBlocked carries the l1_blocked reason.
type ErrBlocked struct{ Reason string }

func (e *ErrBlocked) Error() string { return "egress blocked: " + e.Reason }

// Resolve returns the pinned destination for host: the override first, then the resolver; the first resolved address
// that passes the deny list wins.
func (p *Policy) Resolve(ctx context.Context, host string) (netip.Addr, error) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	var candidates []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		candidates = []netip.Addr{ip}
	} else if ip, ok := p.Override[host]; ok {
		candidates = []netip.Addr{ip}
	} else {
		if p.Resolver == nil {
			return netip.Addr{}, &ErrBlocked{Reason: ReasonResolveFailed}
		}
		ips, err := p.Resolver.LookupNetIP(ctx, "ip", host)
		if err != nil || len(ips) == 0 {
			return netip.Addr{}, &ErrBlocked{Reason: ReasonResolveFailed}
		}
		candidates = ips
	}
	for _, ip := range candidates {
		if !p.Denied(ip) {
			return ip.Unmap(), nil
		}
	}
	return netip.Addr{}, &ErrBlocked{Reason: ReasonIPDenied}
}

func blockReason(err error) string {
	var b *ErrBlocked
	if errors.As(err, &b) {
		return b.Reason
	}
	return ReasonResolveFailed
}
