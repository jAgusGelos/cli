package scrub

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

const (
	secret   = `S3cr&t "pa/ss" w+rd<ü>\`
	username = "corp-admin"
)

func newTest() *Scrubber {
	return New(Config{
		Secrets:           []string{secret, username + ":" + secret, "tok_ABCdef123456"},
		MaskedHeaders:     []string{"X-Api-Key"},
		MaskedQueryParams: []string{"session"},
	})
}

func TestEveryFormIsScrubbed(t *testing.T) {
	s := newTest()
	pair := username + ":" + secret
	cases := map[string]string{
		"raw":                 secret,
		"query escape":        url.QueryEscape(secret),
		"path escape":         url.PathEscape(secret),
		"lower hex":           lowerHex(url.QueryEscape(secret)),
		"b64 std":             base64.StdEncoding.EncodeToString([]byte(secret)),
		"b64 std raw":         base64.RawStdEncoding.EncodeToString([]byte(secret)),
		"b64 url":             base64.URLEncoding.EncodeToString([]byte(secret)),
		"b64 url raw":         base64.RawURLEncoding.EncodeToString([]byte(secret)),
		"basic auth":          "Basic " + base64.StdEncoding.EncodeToString([]byte(pair)),
		"basic auth url safe": base64.RawURLEncoding.EncodeToString([]byte(pair)),
		"json go":             mustJSON(t, secret, true),
		"json js":             mustJSON(t, secret, false),
		"json twice":          mustJSON(t, mustJSON(t, secret, false), false),
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			doc := "before " + in + " after"
			out := s.String(doc)
			if !strings.Contains(out, Mask) {
				t.Fatalf("no mask in %q", out)
			}
			if strings.Contains(out, in) || strings.Contains(out, secret) {
				t.Fatalf("secret form survived: %q", out)
			}
			if !strings.HasPrefix(out, "before ") || !strings.HasSuffix(out, " after") {
				t.Fatalf("surrounding text changed: %q", out)
			}
		})
	}
}

func TestEmbeddedBase64AtEveryAlignment(t *testing.T) {
	s := newTest()
	for prefix := 0; prefix < 6; prefix++ {
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding} {
			blob := strings.Repeat("x", prefix) + "user=" + secret + "&tail=yes"
			encoded := enc.EncodeToString([]byte(blob))
			out := s.String(encoded)
			if !strings.Contains(out, Mask) {
				t.Fatalf("prefix %d: embedded secret not found in %q", prefix, encoded)
			}
			for _, core := range embeddedCores(enc.WithPadding(base64.NoPadding), []byte(secret)) {
				if strings.Contains(out, core) {
					t.Fatalf("prefix %d: core %q survived", prefix, core)
				}
			}
		}
	}
}

func TestJSONKeepsStructure(t *testing.T) {
	s := newTest()
	type ev struct {
		URL   string     `json:"url"`
		Text  string     `json:"text"`
		Hdrs  [][]string `json:"headers"`
		Count int        `json:"count"`
	}
	in := ev{
		URL:  "https://app.corp.internal/login?p=" + url.QueryEscape(secret) + "&next=%2F",
		Text: "typed " + secret,
		Hdrs: [][]string{{"x-note", base64.StdEncoding.EncodeToString([]byte(username + ":" + secret))}},
		// A count that only looks like a needle boundary stays a number.
		Count: 7,
	}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	out := s.JSON(raw)
	var got ev
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("scrubbed JSON is invalid: %v\n%s", err, out)
	}
	if got.URL != "https://app.corp.internal/login?p=***&next=%2F" || got.Text != "typed ***" || got.Hdrs[0][1] != "***" || got.Count != 7 {
		t.Fatalf("unexpected scrubbed value: %+v", got)
	}
	if strings.Contains(string(out), "S3cr") {
		t.Fatalf("secret survived: %s", out)
	}
	clean := []byte(`{"a":"nothing here","b":[1,2]}`)
	if got := s.JSON(clean); &got[0] != &clean[0] {
		t.Fatal("unchanged JSON must be returned as is")
	}
}

func TestHeadersAndURL(t *testing.T) {
	s := newTest()
	h := s.Headers([][]string{
		{"Authorization", "Bearer anything"}, {"cookie", "a=b"}, {"X-API-KEY", "k"}, {"accept", "text/html"},
		{"x-echo", "tok_ABCdef123456"},
	})
	want := [][]string{{"Authorization", "***"}, {"cookie", "***"}, {"X-API-KEY", "***"}, {"accept", "text/html"}, {"x-echo", "***"}}
	for i := range want {
		if h[i][0] != want[i][0] || h[i][1] != want[i][1] {
			t.Fatalf("header %d: got %v want %v", i, h[i], want[i])
		}
	}
	got := s.URL("https://app.corp.internal/a?x=1&session=abc&q=tok_ABCdef123456&session#frag")
	if got != "https://app.corp.internal/a?x=1&session=***&q=***&session#frag" {
		t.Fatalf("url: %s", got)
	}
}

func TestNoSecrets(t *testing.T) {
	s := New(Config{})
	if s.HasSecrets() {
		t.Fatal("no secrets expected")
	}
	b := []byte("body")
	if got := s.Bytes(b); &got[0] != &b[0] {
		t.Fatal("Bytes must return its input when there is nothing to scrub")
	}
	if got := s.Headers([][]string{{"Cookie", "a=b"}}); got[0][1] != Mask {
		t.Fatal("fixed masked headers apply without secrets")
	}
}

func mustJSON(t *testing.T, v string, html bool) string {
	t.Helper()
	for _, f := range jsonForms(v) {
		if html == strings.Contains(f, `<`) {
			return f
		}
	}
	t.Fatalf("no json form of %q", v)
	return ""
}
