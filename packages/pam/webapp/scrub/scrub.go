// Package scrub is the single scrubber of every Web App evidence stream (INF-WEBAPP CONTRACTS.md 5.3, 5.3b). It
// replaces each vaulted secret with "***" in its raw, URL-encoded, base64 (standard and URL-safe, padded and
// unpadded, embedded at the three byte alignments) and JSON-escaped forms, and masks the values of sensitive headers
// and query parameters.
package scrub

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"sort"
	"strings"
)

// Mask is the replacement of every scrubbed value.
const Mask = "***"

// minEmbeddedCore is the shortest base64 core matched inside a longer base64 string: a shorter core would match
// random base64 text far too often.
const minEmbeddedCore = 4

// FixedMaskedHeaders are always masked, whatever the template says (CONTRACTS.md 5.3).
var FixedMaskedHeaders = []string{"authorization", "cookie", "set-cookie", "proxy-authorization"}

// Config lists what one session scrubs.
type Config struct {
	// Secrets are the vaulted values: password, token, headerValue and the "username:password" pair.
	Secrets []string
	// MaskedHeaders are added to FixedMaskedHeaders (names, case-insensitive).
	MaskedHeaders []string
	// MaskedQueryParams are query parameter names whose value is always masked (case-sensitive, as URLs are).
	MaskedQueryParams []string
}

// Scrubber is safe for concurrent use; it is immutable after New.
type Scrubber struct {
	replacer *strings.Replacer
	needles  []string
	headers  map[string]bool
	params   map[string]bool
}

// New builds the needle list of a session. A Config without secrets still masks headers and query parameters.
func New(cfg Config) *Scrubber {
	set := map[string]bool{}
	for _, s := range cfg.Secrets {
		if s == "" {
			continue
		}
		for _, f := range forms(s) {
			if f != "" {
				set[f] = true
			}
		}
	}
	needles := make([]string, 0, len(set))
	for n := range set {
		needles = append(needles, n)
	}
	// Longest first: strings.Replacer tries the old strings in argument order, so a longer form (the padded base64)
	// wins over a shorter one it contains (an embedded core).
	sort.Slice(needles, func(i, j int) bool {
		if len(needles[i]) != len(needles[j]) {
			return len(needles[i]) > len(needles[j])
		}
		return needles[i] < needles[j]
	})
	s := &Scrubber{needles: needles, headers: map[string]bool{}, params: map[string]bool{}}
	if len(needles) > 0 {
		pairs := make([]string, 0, 2*len(needles))
		for _, n := range needles {
			pairs = append(pairs, n, Mask)
		}
		s.replacer = strings.NewReplacer(pairs...)
	}
	for _, h := range FixedMaskedHeaders {
		s.headers[h] = true
	}
	for _, h := range cfg.MaskedHeaders {
		if h = strings.ToLower(strings.TrimSpace(h)); h != "" {
			s.headers[h] = true
		}
	}
	for _, p := range cfg.MaskedQueryParams {
		if p != "" {
			s.params[p] = true
		}
	}
	return s
}

// HasSecrets reports whether any secret is scrubbed.
func (s *Scrubber) HasSecrets() bool { return s != nil && s.replacer != nil }

// String scrubs every secret form in v.
func (s *Scrubber) String(v string) string {
	if !s.HasSecrets() {
		return v
	}
	return s.replacer.Replace(v)
}

// Bytes scrubs a raw payload (an HTTP body, a WebSocket payload). It returns b itself when nothing matched.
func (s *Scrubber) Bytes(b []byte) []byte {
	if !s.HasSecrets() || len(b) == 0 {
		return b
	}
	out := s.replacer.Replace(string(b))
	if len(out) == len(b) && out == string(b) {
		return b
	}
	return []byte(out)
}

// JSON scrubs the string values (and keys) of a JSON document without touching its structure: each string literal is
// decoded, scrubbed and re-encoded only when it changed. Invalid JSON falls back to Bytes, so nothing is left
// unscrubbed.
func (s *Scrubber) JSON(raw []byte) []byte {
	if !s.HasSecrets() || len(raw) == 0 {
		return raw
	}
	var out []byte
	last := 0
	for i := 0; i < len(raw); i++ {
		if raw[i] != '"' {
			continue
		}
		end := literalEnd(raw, i)
		if end < 0 {
			return s.Bytes(raw)
		}
		lit := raw[i : end+1]
		var v string
		if err := json.Unmarshal(lit, &v); err != nil {
			return s.Bytes(raw)
		}
		if sv := s.replacer.Replace(v); sv != v {
			enc, err := json.Marshal(sv)
			if err != nil {
				return s.Bytes(raw)
			}
			out = append(out, raw[last:i]...)
			out = append(out, enc...)
			last = end + 1
		}
		i = end
	}
	if out == nil {
		return raw
	}
	return append(out, raw[last:]...)
}

// literalEnd returns the index of the quote closing the JSON string literal that starts at start, or -1.
func literalEnd(raw []byte, start int) int {
	for j := start + 1; j < len(raw); j++ {
		switch raw[j] {
		case '\\':
			j++
		case '"':
			return j
		}
	}
	return -1
}

// HeaderMasked reports whether a header's value is always replaced by Mask.
func (s *Scrubber) HeaderMasked(name string) bool { return s.headers[strings.ToLower(name)] }

// Headers returns a copy of h ([[name, value], ...] in wire order) with masked header values replaced by Mask and
// every other value scrubbed.
func (s *Scrubber) Headers(h [][]string) [][]string {
	out := make([][]string, 0, len(h))
	for _, kv := range h {
		if len(kv) != 2 {
			continue
		}
		v := kv[1]
		if s.HeaderMasked(kv[0]) {
			v = Mask
		} else {
			v = s.String(v)
		}
		out = append(out, []string{kv[0], v})
	}
	return out
}

// URL masks the value of every masked query parameter (keeping the wire order of the query) and then scrubs every
// secret form in the whole URL.
func (s *Scrubber) URL(u string) string {
	if len(s.params) > 0 {
		base, frag, hasFrag := strings.Cut(u, "#")
		if path, query, ok := strings.Cut(base, "?"); ok {
			parts := strings.Split(query, "&")
			for i, part := range parts {
				name, _, hasValue := strings.Cut(part, "=")
				if dn, err := url.QueryUnescape(name); err == nil {
					name = dn
				}
				if hasValue && s.params[name] {
					parts[i] = part[:strings.IndexByte(part, '=')+1] + Mask
				}
			}
			base = path + "?" + strings.Join(parts, "&")
		}
		u = base
		if hasFrag {
			u += "#" + frag
		}
	}
	return s.String(u)
}

// forms lists every encoded form of one secret (CONTRACTS.md 5.3b).
func forms(secret string) []string {
	out := []string{secret}
	out = append(out, urlForms(secret)...)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding} {
		out = append(out, enc.EncodeToString([]byte(secret)))
		raw := enc.WithPadding(base64.NoPadding)
		out = append(out, raw.EncodeToString([]byte(secret)))
		out = append(out, embeddedCores(raw, []byte(secret))...)
	}
	for _, f := range jsonForms(secret) {
		out = append(out, f)
		// A JSON document carried inside a JSON string (an ext_event field, a logged request body) escapes twice.
		out = append(out, jsonForms(f)...)
	}
	return out
}

// urlForms covers the encoders a browser or an app uses: form encoding (space as "+"), encodeURIComponent, Go's
// QueryEscape and PathEscape, and percent-encoding of every byte, each with upper and lower case hex digits.
func urlForms(secret string) []string {
	enc := func(keep func(c byte) bool, plusSpace bool) string {
		var b strings.Builder
		for i := 0; i < len(secret); i++ {
			c := secret[i]
			switch {
			case c == ' ' && plusSpace:
				b.WriteByte('+')
			case keep(c):
				b.WriteByte(c)
			default:
				b.WriteByte('%')
				b.WriteByte("0123456789ABCDEF"[c>>4])
				b.WriteByte("0123456789ABCDEF"[c&15])
			}
		}
		return b.String()
	}
	alnum := func(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' }
	form := func(c byte) bool { return alnum(c) || strings.IndexByte("*-._", c) >= 0 }
	component := func(c byte) bool { return alnum(c) || strings.IndexByte("-_.!~*'()", c) >= 0 }
	none := func(c byte) bool { return false }
	upper := []string{
		enc(form, true), enc(component, false), url.QueryEscape(secret), url.PathEscape(secret), enc(none, false),
		enc(alnum, true), enc(alnum, false),
	}
	out := make([]string, 0, 2*len(upper))
	for _, f := range upper {
		out = append(out, f, lowerHex(f))
	}
	return out
}

// lowerHex lowers the hex digits of every %XX escape.
func lowerHex(s string) string {
	b := []byte(s)
	for i := 0; i+2 < len(b); i++ {
		if b[i] == '%' {
			b[i+1] = toLowerHex(b[i+1])
			b[i+2] = toLowerHex(b[i+2])
			i += 2
		}
	}
	return string(b)
}

func toLowerHex(c byte) byte {
	if c >= 'A' && c <= 'F' {
		return c + 'a' - 'A'
	}
	return c
}

// embeddedCores returns, for the three byte alignments a secret can have inside a longer base64 string, the run of
// base64 characters that depends on the secret bytes only.
func embeddedCores(enc *base64.Encoding, secret []byte) []string {
	var out []string
	for align := 0; align < 3; align++ {
		buf := append(make([]byte, align), secret...)
		s := enc.EncodeToString(buf)
		totalBits := 8 * len(buf)
		first := (8*align + 5) / 6  // first char whose 6 bits are all secret bits
		last := (totalBits - 6) / 6 // last char whose 6 bits are all inside the buffer
		if last >= len(s) || last < first {
			continue
		}
		if core := s[first : last+1]; len(core) >= minEmbeddedCore {
			out = append(out, core)
		}
	}
	return out
}

// jsonForms is the secret as it appears inside a JSON string written by Go (HTML escaping on) and by JavaScript's
// JSON.stringify (no HTML escaping).
func jsonForms(secret string) []string {
	var out []string
	for _, html := range []bool{true, false} {
		var buf bytes.Buffer
		e := json.NewEncoder(&buf)
		e.SetEscapeHTML(html)
		if err := e.Encode(secret); err != nil {
			continue
		}
		v := strings.TrimSuffix(buf.String(), "\n")
		out = append(out, strings.TrimSuffix(strings.TrimPrefix(v, `"`), `"`))
	}
	// JSON.stringify keeps "/" as is, but some encoders escape it.
	out = append(out, strings.ReplaceAll(out[len(out)-1], "/", `\/`))
	return out
}
