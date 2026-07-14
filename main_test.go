package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"image/jpeg"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildPayload(t *testing.T) {
	got := buildPayload("example.com", "2014", "2026-07-14", "9f3a1c")
	want := "example.com|2014|2026-07-14|9f3a1c"
	if got != want {
		t.Errorf("buildPayload = %q, want %q", got, want)
	}
}

func TestSignPayload(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	payload := "example.com|2014|2026-07-14|9f3a1c"
	sig := signPayload(priv, payload)

	if strings.ContainsAny(sig, "+/=") {
		t.Errorf("signature %q must be base64url without padding", sig)
	}
	raw, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		t.Fatalf("signature is not valid base64url: %v", err)
	}
	if !ed25519.Verify(pub, []byte(payload), raw) {
		t.Error("signature does not verify against payload")
	}
}

func TestEncodePublicKey(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	got := encodePublicKey(pub)
	want := base64.StdEncoding.EncodeToString(pub)
	if got != want {
		t.Errorf("encodePublicKey = %q, want std base64 %q", got, want)
	}
	if !strings.HasSuffix(got, "=") {
		t.Errorf("32-byte key must have padding, got %q", got)
	}
}

func TestTXTNameAndValue(t *testing.T) {
	if got, want := txtName("suzuri", "example.com"), "suzuri._domainkey.example.com"; got != want {
		t.Errorf("txtName = %q, want %q", got, want)
	}
	if got, want := txtValue("AbC="), "v=DKIM1; k=ed25519; p=AbC="; got != want {
		t.Errorf("txtValue = %q, want %q", got, want)
	}
}

func TestNewNonce(t *testing.T) {
	n, err := newNonce()
	if err != nil {
		t.Fatal(err)
	}
	if len(n) != 6 {
		t.Errorf("nonce %q length = %d, want 6", n, len(n))
	}
	if _, err := hex.DecodeString(n); err != nil {
		t.Errorf("nonce %q is not hex: %v", n, err)
	}
	n2, _ := newNonce()
	if n == n2 {
		t.Errorf("two nonces should differ: %q", n)
	}
}

func TestYearFromStartDate(t *testing.T) {
	cases := []struct{ in, want string }{
		{"2025-01-01T00:00:00+09:00", "2025"},
		{"2014-12-31", "2014"},
		{"", "unknown"},
		{"abc", "unknown"},
	}
	for _, c := range cases {
		if got := yearFromStartDate(c.in); got != c.want {
			t.Errorf("yearFromStartDate(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestBuildVerifyURL(t *testing.T) {
	got := buildVerifyURL("https://verify.example", "example.com", "2014", "2026-07-14", "9f3a1c", "si/g+na==", "")
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("invalid URL %q: %v", got, err)
	}
	q := u.Query()
	for k, want := range map[string]string{
		"d": "example.com", "y": "2014", "t": "2026-07-14", "n": "9f3a1c", "sig": "si/g+na==",
	} {
		if q.Get(k) != want {
			t.Errorf("query %s = %q, want %q", k, q.Get(k), want)
		}
	}
	if !strings.HasPrefix(got, "https://verify.example/?") {
		t.Errorf("URL %q should start with base + /?", got)
	}
	if !strings.Contains(got, "sig=si%2Fg%2Bna%3D%3D") {
		t.Errorf("sig should be URL-encoded in %q", got)
	}
	if q.Has("item") {
		t.Errorf("item should be omitted when empty: %q", got)
	}
}

func TestBuildVerifyURLWithItem(t *testing.T) {
	got := buildVerifyURL("https://verify.example", "example.com", "2014", "2026-07-14", "9f3a1c", "sig",
		"https://suzuri.jp/example/1/t-shirt/s/white")
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("invalid URL %q: %v", got, err)
	}
	if item := u.Query().Get("item"); item != "https://suzuri.jp/example/1/t-shirt/s/white" {
		t.Errorf("item = %q", item)
	}
	if !strings.Contains(got, "item=https%3A%2F%2Fsuzuri.jp") {
		t.Errorf("item should be URL-encoded in %q", got)
	}
}

// --- loadConfig ---

func clearEnv(t *testing.T) {
	for _, k := range []string{"MUU_PAT", "MUUMUU_PAT", "SUZURI_API_KEY", "SUZURI_TOKEN",
		"MUUMUU_BASE", "SUZURI_BASE", "VERIFY_BASE", "DOMAIN", "SELECTOR"} {
		t.Setenv(k, "")
	}
}

func TestLoadConfigRequiresTokens(t *testing.T) {
	clearEnv(t)
	if _, err := loadConfig(nil); err == nil {
		t.Error("expected error when MUU_PAT is missing")
	}
	t.Setenv("MUU_PAT", "pat")
	if _, err := loadConfig(nil); err == nil {
		t.Error("expected error when SUZURI_API_KEY is missing")
	}
}

func TestLoadConfigDefaults(t *testing.T) {
	clearEnv(t)
	t.Setenv("MUU_PAT", "pat")
	t.Setenv("SUZURI_API_KEY", "key")
	cfg, err := loadConfig(nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MuuPAT != "pat" || cfg.SuzuriKey != "key" {
		t.Errorf("tokens not loaded: %+v", cfg)
	}
	if cfg.MuumuuBase != "https://muumuu-domain.com" {
		t.Errorf("MuumuuBase = %q, want production URL", cfg.MuumuuBase)
	}
	t.Setenv("MUUMUU_BASE", "https://api-sandbox.muumuu-domain.com")
	cfg, err = loadConfig(nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MuumuuBase != "https://muumuu-domain.com" {
		t.Errorf("MuumuuBase must be fixed to production, got %q", cfg.MuumuuBase)
	}
	if cfg.SuzuriBase != "https://suzuri.jp" {
		t.Errorf("SuzuriBase default = %q", cfg.SuzuriBase)
	}
	t.Setenv("VERIFY_BASE", "https://other.example")
	cfg, err = loadConfig(nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.VerifyBase != "https://dkip-site.lolipop-now.app" {
		t.Errorf("VerifyBase must be fixed to production, got %q", cfg.VerifyBase)
	}
	if cfg.Selector != "dkip" {
		t.Errorf("Selector default = %q", cfg.Selector)
	}
}

func TestLoadConfigFallbackNames(t *testing.T) {
	clearEnv(t)
	t.Setenv("MUUMUU_PAT", "pat2")
	t.Setenv("SUZURI_TOKEN", "key2")
	cfg, err := loadConfig(nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MuuPAT != "pat2" || cfg.SuzuriKey != "key2" {
		t.Errorf("fallback env names not honored: %+v", cfg)
	}
}

// --- listDomains ---

func TestListDomains(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/me/domains" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer pat" {
			t.Errorf("Authorization = %q", got)
		}
		w.Write([]byte(`{"data":[{"id":"MU00000001","fqdn":"example.com","state":"active"},
			{"id":"MU00000002","fqdn":"example.jp","state":"active"}],"meta":{"total":2}}`))
	}))
	defer srv.Close()

	ds, err := listDomains(srv.Client(), srv.URL, "pat")
	if err != nil {
		t.Fatal(err)
	}
	if len(ds) != 2 || ds[0].ID != "MU00000001" || ds[0].FQDN != "example.com" {
		t.Errorf("domains = %+v", ds)
	}
}

func TestPickDomain(t *testing.T) {
	ds := []domainInfo{{ID: "MU1", FQDN: "a.com"}, {ID: "MU2", FQDN: "b.jp"}}
	d, err := pickDomain(ds, "b.jp")
	if err != nil || d.ID != "MU2" {
		t.Errorf("pickDomain(b.jp) = %+v, %v", d, err)
	}
	d, err = pickDomain(ds, "")
	if err != nil || d.ID != "MU1" {
		t.Errorf("pickDomain(empty) should take first: %+v, %v", d, err)
	}
	if _, err := pickDomain(ds, "nope.com"); err == nil {
		t.Error("pickDomain(nope.com) should fail")
	}
	if _, err := pickDomain(nil, ""); err == nil {
		t.Error("pickDomain with no domains should fail")
	}
}

// --- getDomainYear ---

func TestGetDomainYear(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/me/domains/MU00000001" {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.Write([]byte(`{"data":{"id":"MU00000001","fqdn":"example.com",
			"contract":{"start-date":"2014-01-01T00:00:00+09:00"}}}`))
	}))
	defer srv.Close()

	year, err := getDomainYear(srv.Client(), srv.URL, "pat", "MU00000001")
	if err != nil {
		t.Fatal(err)
	}
	if year != "2014" {
		t.Errorf("year = %q, want 2014", year)
	}
}

func TestGetDomainYearMissing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"data":{"id":"MU00000001","fqdn":"example.com"}}`))
	}))
	defer srv.Close()

	year, err := getDomainYear(srv.Client(), srv.URL, "pat", "MU00000001")
	if err != nil {
		t.Fatal(err)
	}
	if year != "unknown" {
		t.Errorf("year = %q, want unknown", year)
	}
}

// --- putTXT ---

func TestPutTXT(t *testing.T) {
	var body map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v2/me/domains/MU00000001/dns-records" {
			t.Errorf("%s %s", r.Method, r.URL.Path)
		}
		if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
			t.Errorf("Content-Type = %q", ct)
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("body decode: %v", err)
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	created, err := putTXT(srv.Client(), srv.URL, "pat", "MU00000001",
		"suzuri._domainkey.example.com", "v=DKIM1; k=ed25519; p=AbC=")
	if err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Error("created = false, want true on 201")
	}
	if body["fqdn"] != "suzuri._domainkey.example.com." {
		t.Errorf("fqdn = %q, want trailing dot", body["fqdn"])
	}
	if body["type"] != "TXT" {
		t.Errorf("type = %q", body["type"])
	}
	if body["value"] != "v=DKIM1; k=ed25519; p=AbC=" {
		t.Errorf("value = %q", body["value"])
	}
}

func TestPutTXTConflict(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
	}))
	defer srv.Close()

	created, err := putTXT(srv.Client(), srv.URL, "pat", "MU1", "n.example.com", "v")
	if err != nil {
		t.Fatalf("409 should not be an error: %v", err)
	}
	if created {
		t.Error("created = true, want false on 409")
	}
}

func TestPutTXTServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		w.Write([]byte(`{"errors":[{"message":"invalid fqdn"}]}`))
	}))
	defer srv.Close()

	if _, err := putTXT(srv.Client(), srv.URL, "pat", "MU1", "n.example.com", "v"); err == nil {
		t.Error("expected error on 422")
	}
}

// --- createTee ---

func TestCreateTee(t *testing.T) {
	var body struct {
		Texture  string `json:"texture"`
		Title    string `json:"title"`
		Products []struct {
			ItemID    int  `json:"itemId"`
			Published bool `json:"published"`
		} `json:"products"`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/materials" {
			t.Errorf("%s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer key" {
			t.Errorf("Authorization = %q", got)
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("body decode: %v", err)
		}
		w.Write([]byte(`{"material":{"id":123},"products":[{"id":456,"sampleUrl":"https://suzuri.jp/x/1/t-shirt"}]}`))
	}))
	defer srv.Close()

	u, err := createTee(srv.Client(), srv.URL, "key", "data:image/jpeg;base64,xxx", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if u != "https://suzuri.jp/x/1/t-shirt" {
		t.Errorf("sampleUrl = %q", u)
	}
	if body.Texture != "data:image/jpeg;base64,xxx" || body.Title != "example.com" {
		t.Errorf("body = %+v", body)
	}
	if len(body.Products) != 1 || body.Products[0].ItemID != 1 || !body.Products[0].Published {
		t.Errorf("products = %+v", body.Products)
	}
}

// --- renderJPEG ---

func TestRenderJPEG(t *testing.T) {
	uri, err := renderJPEG("example.com", "2014",
		"https://dkip-site.lolipop-now.app/?d=example.com&n=9f3a1c&sig=xxx&t=2026-07-14&y=2014")
	if err != nil {
		t.Fatal(err)
	}
	const prefix = "data:image/jpeg;base64,"
	if !strings.HasPrefix(uri, prefix) {
		t.Fatalf("data URI prefix missing: %.40q", uri)
	}
	raw, err := base64.StdEncoding.DecodeString(uri[len(prefix):])
	if err != nil {
		t.Fatalf("not valid std base64: %v", err)
	}
	img, err := jpeg.Decode(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("not a valid JPEG: %v", err)
	}
	b := img.Bounds()
	if b.Dx() < 500 || b.Dy() < 500 {
		t.Errorf("image too small for print: %dx%d", b.Dx(), b.Dy())
	}
}

func TestQRModules(t *testing.T) {
	m, err := qrModules("https://dkip-site.lolipop-now.app/?d=example.com&n=9f3a1c&sig=" + strings.Repeat("A", 86) + "&t=2026-07-14&y=2026")
	if err != nil {
		t.Fatal(err)
	}
	if len(m) < 21 {
		t.Errorf("QR too small: %d modules", len(m))
	}
	for i, row := range m {
		if len(row) != len(m) {
			t.Fatalf("QR not square: row %d has %d cols, want %d", i, len(row), len(m))
		}
	}
	// クワイエットゾーン（外周は白）が含まれていること — スキャン可能性の要件
	for i := range m {
		if m[0][i] || m[len(m)-1][i] || m[i][0] || m[i][len(m)-1] {
			t.Fatal("QR bitmap must include a white quiet zone border")
		}
	}
}

// --- savePrivateKey ---

func TestSavePrivateKey(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "dns-signed-tee.key")
	if err := savePrivateKey(path, priv); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("perm = %o, want 600", perm)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("file is not PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := parsed.(ed25519.PrivateKey)
	if !ok || !got.Equal(priv) {
		t.Error("restored key does not equal original")
	}
}

func TestLoadConfigDomainFromArg(t *testing.T) {
	clearEnv(t)
	t.Setenv("MUU_PAT", "pat")
	t.Setenv("SUZURI_API_KEY", "key")

	cfg, err := loadConfig([]string{"arg.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Domain != "arg.example.com" {
		t.Errorf("Domain = %q, want arg.example.com", cfg.Domain)
	}

	// ドメインは CLI 引数のみで受け取る。DOMAIN 環境変数は使わない
	t.Setenv("DOMAIN", "env.example.com")
	cfg, err = loadConfig(nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Domain != "" {
		t.Errorf("DOMAIN env must be ignored, got %q", cfg.Domain)
	}
}
