package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
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
			ItemID       int  `json:"itemId"`
			Published    bool `json:"published"`
			SubMaterials []struct {
				Texture   string `json:"texture"`
				PrintSide string `json:"printSide"`
				Enabled   bool   `json:"enabled"`
			} `json:"sub_materials"`
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

	u, err := createTee(srv.Client(), srv.URL, "key", "data:image/jpeg;base64,xxx", "example.com", "")
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
	// 背面なしのときは sub_materials を付けない
	if len(body.Products[0].SubMaterials) != 0 {
		t.Errorf("sub_materials should be empty when no back texture: %+v", body.Products[0].SubMaterials)
	}
}

// --- renderJPEG ---

func TestRenderJPEG(t *testing.T) {
	uri, err := renderJPEG("example.com", "2014",
		"https://dkip-site.lolipop-now.app/?d=example.com&n=9f3a1c&sig=xxx&t=2026-07-14&y=2014", nil)
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
	if b.Dx() < 1600 || b.Dy() < 1600 {
		t.Errorf("image too small for print: %dx%d", b.Dx(), b.Dy())
	}
}

func TestQRSizeOnCanvas(t *testing.T) {
	url := "https://dkip-site.lolipop-now.app/?d=example.com&n=9f3a1c&sig=" + strings.Repeat("A", 86) + "&t=2026-07-14&y=2026"
	modules, err := qrModules(url)
	if err != nil {
		t.Fatal(err)
	}
	px := qrPixelSize(len(modules), 2000)
	// スキャン可能性のため、QR はキャンバス幅の 25% 以上を占めること
	if px < 2000*25/100 {
		t.Errorf("QR too small: %dpx on 2000px canvas (< 25%%)", px)
	}
	if px > 2000*40/100 {
		t.Errorf("QR too large: %dpx on 2000px canvas (> 40%%)", px)
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

// --- loadOrCreateKey ---

func TestLoadOrCreateKeyCreatesAndSaves(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dns-signed-tee.key")
	pub, priv, reused, err := loadOrCreateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if reused {
		t.Error("reused = true, want false when key file does not exist")
	}
	if !priv.Public().(ed25519.PublicKey).Equal(pub) {
		t.Error("returned public key does not match private key")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("key file must be saved immediately: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("perm = %o, want 600", perm)
	}
}

func TestLoadOrCreateKeyReusesExisting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dns-signed-tee.key")
	_, priv1, _, err := loadOrCreateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	pub2, priv2, reused, err := loadOrCreateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reused {
		t.Error("reused = false, want true when key file exists")
	}
	if !priv2.Equal(priv1) {
		t.Error("second call must return the same private key")
	}
	if !priv1.Public().(ed25519.PublicKey).Equal(pub2) {
		t.Error("public key does not match the original key pair")
	}
}

// --- ensureTXT ---

func TestEnsureTXTCreated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	created, err := ensureTXT(srv.Client(), srv.URL, "pat", "MU1",
		"dkip._domainkey.example.com", "v=DKIM1; k=ed25519; p=AbC=")
	if err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Error("created = false, want true on 201")
	}
}

func TestEnsureTXTConflictSameValue(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			w.WriteHeader(http.StatusConflict)
		case http.MethodGet:
			if r.URL.Path != "/api/v2/me/domains/MU1/dns-records" {
				t.Errorf("GET path = %q", r.URL.Path)
			}
			w.Write([]byte(`{"data":[
				{"fqdn":"www.example.com.","type":"A","value":"203.0.113.1"},
				{"fqdn":"dkip._domainkey.example.com.","type":"TXT","value":"v=DKIM1; k=ed25519; p=AbC="}]}`))
		}
	}))
	defer srv.Close()

	created, err := ensureTXT(srv.Client(), srv.URL, "pat", "MU1",
		"dkip._domainkey.example.com", "v=DKIM1; k=ed25519; p=AbC=")
	if err != nil {
		t.Fatalf("409 with matching value must not be an error: %v", err)
	}
	if created {
		t.Error("created = true, want false on 409")
	}
}

func TestEnsureTXTConflictDifferentValue(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			w.WriteHeader(http.StatusConflict)
		case http.MethodGet:
			w.Write([]byte(`{"data":[{"fqdn":"dkip._domainkey.example.com.","type":"TXT","value":"v=DKIM1; k=ed25519; p=OldKey="}]}`))
		}
	}))
	defer srv.Close()

	// DNS 上の公開鍵と手元の鍵が食い違うと署名が検証できないため、続行してはいけない
	if _, err := ensureTXT(srv.Client(), srv.URL, "pat", "MU1",
		"dkip._domainkey.example.com", "v=DKIM1; k=ed25519; p=NewKey="); err == nil {
		t.Error("409 with different value must be an error")
	}
}

func TestEnsureTXTConflictRecordNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			w.WriteHeader(http.StatusConflict)
		case http.MethodGet:
			w.Write([]byte(`{"data":[]}`))
		}
	}))
	defer srv.Close()

	// 409 なのに一覧に見つからない＝値の一致を確認できないので、続行してはいけない
	if _, err := ensureTXT(srv.Client(), srv.URL, "pat", "MU1",
		"dkip._domainkey.example.com", "v=DKIM1; k=ed25519; p=AbC="); err == nil {
		t.Error("409 with no matching record must be an error")
	}
}

// --- checkASCIIDomain ---

func TestCheckASCIIDomain(t *testing.T) {
	for _, d := range []string{"example.com", "xn--tckwe-1b4c.jp", "xn--wgv71a119e.jp"} {
		if err := checkASCIIDomain(d); err != nil {
			t.Errorf("checkASCIIDomain(%q) = %v, want nil (punycode must be accepted)", d, err)
		}
	}
	for _, d := range []string{"日本語.jp", "テスト.com", "ドメイン.日本"} {
		if err := checkASCIIDomain(d); err == nil {
			t.Errorf("checkASCIIDomain(%q) = nil, want error", d)
		} else if !strings.Contains(err.Error(), "punycode") {
			t.Errorf("error should suggest punycode form: %v", err)
		}
	}
}

func TestLoadConfigRejectsNonASCIIDomain(t *testing.T) {
	clearEnv(t)
	t.Setenv("MUU_PAT", "pat")
	t.Setenv("SUZURI_API_KEY", "key")

	if _, err := loadConfig([]string{"日本語.jp"}); err == nil {
		t.Error("expected error for non-ASCII domain arg")
	}
	if _, err := loadConfig([]string{"xn--wgv71a119e.jp"}); err != nil {
		t.Errorf("punycode domain arg must be accepted: %v", err)
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

// --- サイトロゴの取得 ---

// pngBytes は指定サイズの単色 PNG バイト列を返す（テスト用のダミー画像）。
func pngBytes(t *testing.T, w, h int, c color.Color) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.Set(x, y, c)
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestExtractLogoCandidatesPriority(t *testing.T) {
	base, _ := url.Parse("https://example.com/")
	htmlBody := `<html><head>
		<link rel="icon" href="/favicon-16.png">
		<meta property="og:image" content="https://cdn.example.com/og.png">
		<link rel="apple-touch-icon" href="/apple.png">
		<link rel="shortcut icon" href="/legacy.ico">
		<link rel="icon" href="/logo.svg">
	</head><body></body></html>`
	cands := extractLogoCandidates(base, strings.NewReader(htmlBody))
	sortByPriority(cands)

	if len(cands) == 0 {
		t.Fatal("no candidates extracted")
	}
	// SVG も候補に残る（ダウンロード時にラスタライズする）
	hasSVG := false
	for _, c := range cands {
		if strings.HasSuffix(c.url, ".svg") {
			hasSVG = true
		}
	}
	if !hasSVG {
		t.Error("SVG candidate must be kept (rasterized at download time)")
	}
	// 先頭は apple-touch-icon（絶対 URL に解決されている）
	if cands[0].url != "https://example.com/apple.png" {
		t.Errorf("top candidate = %q, want apple-touch-icon", cands[0].url)
	}
	// og:image が次点で、絶対 URL のまま保持される
	if cands[1].url != "https://cdn.example.com/og.png" {
		t.Errorf("second candidate = %q, want og:image", cands[1].url)
	}
}

func TestFetchSiteLogoPrefersAppleTouchIcon(t *testing.T) {
	apple := pngBytes(t, 180, 180, color.RGBA{R: 255, A: 255})
	fav := pngBytes(t, 16, 16, color.RGBA{B: 255, A: 255})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<html><head>
				<link rel="apple-touch-icon" href="/apple.png">
			</head></html>`))
		case "/apple.png":
			w.Write(apple)
		case "/favicon.ico":
			w.Write(fav)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	logo, err := fetchSiteLogoAt(srv.Client(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if logo == nil {
		t.Fatal("expected a logo, got nil")
	}
	if b := logo.Bounds(); b.Dx() != 180 || b.Dy() != 180 {
		t.Errorf("logo size = %dx%d, want 180x180 (apple-touch-icon)", b.Dx(), b.Dy())
	}
}

func TestFetchSiteLogoFallsBackToFavicon(t *testing.T) {
	fav := pngBytes(t, 32, 32, color.RGBA{G: 255, A: 255})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<html><head><title>no icons here</title></head></html>`))
		case "/favicon.ico":
			w.Write(fav)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	logo, err := fetchSiteLogoAt(srv.Client(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if logo == nil {
		t.Fatal("expected favicon fallback, got nil")
	}
	if b := logo.Bounds(); b.Dx() != 32 || b.Dy() != 32 {
		t.Errorf("logo size = %dx%d, want 32x32 (favicon)", b.Dx(), b.Dy())
	}
}

func TestFetchSiteLogoNoneReturnsNil(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Write([]byte(`<html><head></head></html>`))
		default:
			http.NotFound(w, r) // favicon.ico も無い
		}
	}))
	defer srv.Close()

	logo, err := fetchSiteLogoAt(srv.Client(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if logo != nil {
		t.Errorf("expected nil logo when nothing is set, got %v", logo.Bounds())
	}
}

func TestFetchSiteLogoRasterizesSVGIcon(t *testing.T) {
	svg := `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><rect width="100" height="100" fill="#ff0000"/></svg>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<html><head>
				<link rel="icon" href="/icon.svg?v=abc123" sizes="any" type="image/svg+xml">
			</head></html>`))
		case "/icon.svg":
			w.Header().Set("Content-Type", "image/svg+xml")
			w.Write([]byte(svg))
		default:
			http.NotFound(w, r) // /favicon.ico も無い
		}
	}))
	defer srv.Close()

	logo, err := fetchSiteLogoAt(srv.Client(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if logo == nil {
		t.Fatal("expected rasterized SVG logo, got nil")
	}
	b := logo.Bounds()
	if b.Dx() != b.Dy() {
		t.Errorf("logo aspect = %dx%d, want square (viewBox 100x100)", b.Dx(), b.Dy())
	}
	if b.Dx() < 100 {
		t.Errorf("logo width = %d, want >= 100 (rasterized at print-friendly size)", b.Dx())
	}
	// 中央付近が塗りの赤であること（ラスタライズが実際に描画している）
	r, g, _, a := logo.At(b.Dx()/2, b.Dy()/2).RGBA()
	if a == 0 || r < 0x8000 || g > 0x4000 {
		t.Errorf("center pixel = r:%#x g:%#x a:%#x, want opaque red", r, g, a)
	}
}

// icoBytes は 1 枚の PNG を埋め込んだ ICO ファイルを組み立てる。
func icoBytes(t *testing.T, w, h int, c color.Color) []byte {
	t.Helper()
	pngData := pngBytes(t, w, h, c)
	var buf bytes.Buffer
	// ICONDIR: reserved, type=1 (icon), count=1
	binary.Write(&buf, binary.LittleEndian, [3]uint16{0, 1, 1})
	// ICONDIRENTRY
	buf.WriteByte(byte(w))                                        // width
	buf.WriteByte(byte(h))                                        // height
	buf.WriteByte(0)                                              // palette colors
	buf.WriteByte(0)                                              // reserved
	binary.Write(&buf, binary.LittleEndian, uint16(1))            // planes
	binary.Write(&buf, binary.LittleEndian, uint16(32))           // bit count
	binary.Write(&buf, binary.LittleEndian, uint32(len(pngData))) // data size
	binary.Write(&buf, binary.LittleEndian, uint32(22))           // data offset (6+16)
	buf.Write(pngData)
	return buf.Bytes()
}

// icoBMPBytes は 24bpp の BMP (DIB) を 1 枚埋め込んだクラシックな ICO を組み立てる。
// DIB の高さは AND マスク分を含む 2 倍で記録する（ICO の仕様どおり）。
func icoBMPBytes(t *testing.T, w, h int, c color.RGBA) []byte {
	t.Helper()
	rowSize := (w*3 + 3) &^ 3     // 24bpp 行は 4 バイト境界に揃える
	maskRow := ((w+7)/8 + 3) &^ 3 // AND マスク行も 4 バイト境界
	var dib bytes.Buffer
	binary.Write(&dib, binary.LittleEndian, uint32(40))   // ヘッダサイズ
	binary.Write(&dib, binary.LittleEndian, int32(w))     // 幅
	binary.Write(&dib, binary.LittleEndian, int32(h*2))   // 高さ（マスク込みで 2 倍）
	binary.Write(&dib, binary.LittleEndian, uint16(1))    // planes
	binary.Write(&dib, binary.LittleEndian, uint16(24))   // bpp
	binary.Write(&dib, binary.LittleEndian, [6]uint32{0}) // 圧縮以降は全て 0
	for y := 0; y < h; y++ {                              // ピクセル（ボトムアップ、BGR）
		row := make([]byte, rowSize)
		for x := 0; x < w; x++ {
			row[x*3], row[x*3+1], row[x*3+2] = c.B, c.G, c.R
		}
		dib.Write(row)
	}
	dib.Write(make([]byte, maskRow*h)) // AND マスク（全ピクセル不透明）

	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, [3]uint16{0, 1, 1}) // ICONDIR
	buf.WriteByte(byte(w))
	buf.WriteByte(byte(h))
	buf.WriteByte(0)                                           // palette colors
	buf.WriteByte(0)                                           // reserved
	binary.Write(&buf, binary.LittleEndian, uint16(1))         // planes
	binary.Write(&buf, binary.LittleEndian, uint16(24))        // bit count
	binary.Write(&buf, binary.LittleEndian, uint32(dib.Len())) // data size
	binary.Write(&buf, binary.LittleEndian, uint32(22))        // data offset
	buf.Write(dib.Bytes())
	return buf.Bytes()
}

func TestDecodeICOClassicBMP(t *testing.T) {
	data := icoBMPBytes(t, 32, 32, color.RGBA{R: 255, A: 255})
	img, err := decodeICO(data)
	if err != nil {
		t.Fatal(err)
	}
	if b := img.Bounds(); b.Dx() != 32 || b.Dy() != 32 {
		t.Errorf("size = %dx%d, want 32x32", b.Dx(), b.Dy())
	}
	r, g, _, _ := img.At(16, 16).RGBA()
	if r < 0x8000 || g > 0x4000 {
		t.Errorf("center pixel = r:%#x g:%#x, want red", r, g)
	}
}

func TestDecodeICORejectsGarbage(t *testing.T) {
	if _, err := decodeICO([]byte("not an ico at all")); err == nil {
		t.Error("expected error for non-ICO data")
	}
	if _, err := decodeICO([]byte{0, 0, 1, 0, 9, 0}); err == nil {
		t.Error("expected error for truncated ICO directory")
	}
}

func TestFetchSiteLogoDecodesICOFavicon(t *testing.T) {
	fav := icoBytes(t, 48, 48, color.RGBA{G: 255, A: 255})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<html><head><title>no icons in html</title></head></html>`))
		case "/favicon.ico":
			w.Header().Set("Content-Type", "image/x-icon")
			w.Write(fav)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	logo, err := fetchSiteLogoAt(srv.Client(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if logo == nil {
		t.Fatal("expected ICO favicon to decode, got nil")
	}
	if b := logo.Bounds(); b.Dx() != 48 || b.Dy() != 48 {
		t.Errorf("logo size = %dx%d, want 48x48", b.Dx(), b.Dy())
	}
}

func TestFetchSiteLogoBrokenSVGReturnsNil(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<html><head><link rel="icon" href="/icon.svg"></head></html>`))
		case "/icon.svg":
			w.Header().Set("Content-Type", "image/svg+xml")
			w.Write([]byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0`)) // 途中で切れた SVG
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	logo, err := fetchSiteLogoAt(srv.Client(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if logo != nil {
		t.Errorf("expected nil logo for broken SVG, got %v", logo.Bounds())
	}
}

func TestRasterizeSVGKeepsAspectRatio(t *testing.T) {
	svg := `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 200 100"><rect width="200" height="100" fill="#00f"/></svg>`
	img, err := rasterizeSVG([]byte(svg))
	if err != nil {
		t.Fatal(err)
	}
	b := img.Bounds()
	if b.Dx() != 512 || b.Dy() != 256 {
		t.Errorf("rasterized size = %dx%d, want 512x256 (long side 512, aspect 2:1)", b.Dx(), b.Dy())
	}
}

func TestRenderJPEGWithLogo(t *testing.T) {
	logo := image.NewRGBA(image.Rect(0, 0, 200, 200))
	for y := 0; y < 200; y++ {
		for x := 0; x < 200; x++ {
			logo.Set(x, y, color.RGBA{R: 255, A: 255})
		}
	}
	uri, err := renderJPEG("example.com", "2014",
		"https://dkip-site.lolipop-now.app/?d=example.com&n=9f3a1c&sig=xxx&t=2026-07-14&y=2014", logo)
	if err != nil {
		t.Fatal(err)
	}
	const prefix = "data:image/jpeg;base64,"
	raw, err := base64.StdEncoding.DecodeString(uri[len(prefix):])
	if err != nil {
		t.Fatal(err)
	}
	img, err := jpeg.Decode(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("not a valid JPEG: %v", err)
	}
	// ロゴは上部中央（約 5% の位置）に赤で描かれているはず
	const size = 2000
	c := img.At(size/2, size/20+50)
	r, _, _, _ := c.RGBA()
	if r>>8 < 200 {
		t.Errorf("expected red logo near top-center, got %v", c)
	}
}

// --- createTee 背面プリント ---

func TestCreateTeeWithBack(t *testing.T) {
	var body struct {
		Products []struct {
			ItemID       int `json:"itemId"`
			SubMaterials []struct {
				Texture   string `json:"texture"`
				PrintSide string `json:"printSide"`
				Enabled   bool   `json:"enabled"`
			} `json:"sub_materials"`
		} `json:"products"`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&body)
		w.Write([]byte(`{"products":[{"sampleUrl":"https://suzuri.jp/x/1/t-shirt"}]}`))
	}))
	defer srv.Close()

	_, err := createTee(srv.Client(), srv.URL, "key",
		"data:image/jpeg;base64,front", "example.com", "data:image/jpeg;base64,back")
	if err != nil {
		t.Fatal(err)
	}
	if len(body.Products) != 1 || len(body.Products[0].SubMaterials) != 1 {
		t.Fatalf("expected one sub_material, got %+v", body.Products)
	}
	sm := body.Products[0].SubMaterials[0]
	if sm.Texture != "data:image/jpeg;base64,back" {
		t.Errorf("back texture = %q", sm.Texture)
	}
	if sm.PrintSide != "back" || !sm.Enabled {
		t.Errorf("printSide/enabled = %q/%v", sm.PrintSide, sm.Enabled)
	}
}

// --- サイトマップの取得 ---

func TestParseSitemapUrlset(t *testing.T) {
	xmlBody := `<?xml version="1.0"?>
	<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
		<url><loc>https://example.com/</loc></url>
		<url><loc>https://example.com/about</loc></url>
		<url><loc>https://example.com/blog/hello</loc></url>
	</urlset>`
	locs, children := parseSitemap(strings.NewReader(xmlBody))
	if len(children) != 0 {
		t.Errorf("urlset should have no child sitemaps, got %v", children)
	}
	if len(locs) != 3 || locs[1] != "https://example.com/about" {
		t.Errorf("locs = %v", locs)
	}
}

func TestParseSitemapIndex(t *testing.T) {
	xmlBody := `<?xml version="1.0"?>
	<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
		<sitemap><loc>https://example.com/sitemap-1.xml</loc></sitemap>
		<sitemap><loc>https://example.com/sitemap-2.xml</loc></sitemap>
	</sitemapindex>`
	locs, children := parseSitemap(strings.NewReader(xmlBody))
	if len(locs) != 0 {
		t.Errorf("index should yield no direct locs, got %v", locs)
	}
	if len(children) != 2 || children[0] != "https://example.com/sitemap-1.xml" {
		t.Errorf("children = %v", children)
	}
}

func TestFetchSitemapURLsUrlset(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sitemap.xml" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/xml")
		w.Write([]byte(`<urlset><url><loc>https://example.com/a</loc></url>
			<url><loc>https://example.com/b</loc></url></urlset>`))
	}))
	defer srv.Close()

	urls := fetchSitemapURLsAt(srv.Client(), srv.URL+"/sitemap.xml")
	if len(urls) != 2 || urls[0] != "https://example.com/a" {
		t.Errorf("urls = %v", urls)
	}
}

func TestFetchSitemapURLsIndexFollowsChildren(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/sitemap.xml":
			w.Write([]byte(`<sitemapindex><sitemap><loc>http://` + r.Host + `/child.xml</loc></sitemap></sitemapindex>`))
		case "/child.xml":
			w.Write([]byte(`<urlset><url><loc>https://example.com/deep</loc></url></urlset>`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	urls := fetchSitemapURLsAt(srv.Client(), srv.URL+"/sitemap.xml")
	if len(urls) != 1 || urls[0] != "https://example.com/deep" {
		t.Errorf("expected to follow child sitemap, got %v", urls)
	}
}

func TestFetchSitemapURLsNone(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()
	if urls := fetchSitemapURLsAt(srv.Client(), srv.URL+"/sitemap.xml"); urls != nil {
		t.Errorf("expected nil when no sitemap, got %v", urls)
	}
}

func TestSitemapPaths(t *testing.T) {
	in := []string{"https://example.com/", "https://example.com/about", "https://example.com/s?q=1"}
	got := sitemapPaths(in)
	want := []string{"/", "/about", "/s?q=1"}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("paths[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestLimitSitemapURLs(t *testing.T) {
	many := make([]string, maxSitemapURLs+10)
	for i := range many {
		many[i] = "https://example.com/p"
	}
	shown, total := limitSitemapURLs(many)
	if len(shown) != maxSitemapURLs {
		t.Errorf("shown = %d, want %d", len(shown), maxSitemapURLs)
	}
	if total != maxSitemapURLs+10 {
		t.Errorf("total = %d, want %d", total, maxSitemapURLs+10)
	}

	few := []string{"https://example.com/a"}
	shown, total = limitSitemapURLs(few)
	if len(shown) != 1 || total != 1 {
		t.Errorf("small set: shown=%d total=%d", len(shown), total)
	}
}

func TestRenderSitemapJPEG(t *testing.T) {
	// 空なら背面なし
	uri, err := renderSitemapJPEG("example.com", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if uri != "" {
		t.Errorf("empty paths should yield no image, got %.30q", uri)
	}

	paths := []string{"/", "/about", "/blog/hello", "/contact"}
	uri, err = renderSitemapJPEG("example.com", paths, 120) // total>len → "+N more"
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(uri[len("data:image/jpeg;base64,"):])
	if err != nil {
		t.Fatal(err)
	}
	img, err := jpeg.Decode(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("not a valid JPEG: %v", err)
	}
	if b := img.Bounds(); b.Dx() < 1600 || b.Dy() < 1600 {
		t.Errorf("back image too small: %dx%d", b.Dx(), b.Dy())
	}
}
