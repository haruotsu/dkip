package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	_ "image/gif"
	"image/jpeg"
	"image/png"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"
	"github.com/srwiley/oksvg"
	"github.com/srwiley/rasterx"
	"golang.org/x/image/bmp"
	xdraw "golang.org/x/image/draw"
	"golang.org/x/image/font"
	"golang.org/x/image/font/basicfont"
	"golang.org/x/image/math/fixed"
	"golang.org/x/net/html"
)

const keyFilePath = "dns-signed-tee.key"

// ---- 設定 ----

type config struct {
	MuuPAT     string // ムームー Personal Access Token
	SuzuriKey  string // SUZURI API キー
	MuumuuBase string // ムームー API ベース URL（本番固定）
	SuzuriBase string // SUZURI API ベース URL
	VerifyBase string // 検証サイトのベース URL（本番固定）
	Domain     string // 対象ドメイン（CLI 第 1 引数。未指定なら一覧から選択）
	Selector   string // DKIM セレクタ
}

func envOr(key, fallbackKey string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return os.Getenv(fallbackKey)
}

func envDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// loadConfig は環境変数と CLI 引数から設定を組み立てる。
// args（os.Args[1:]）の第 1 引数は対象ドメインで、DOMAIN 環境変数より優先される。
func loadConfig(args []string) (config, error) {
	cfg := config{
		MuuPAT:     envOr("MUU_PAT", "MUUMUU_PAT"),
		SuzuriKey:  envOr("SUZURI_API_KEY", "SUZURI_TOKEN"),
		MuumuuBase: "https://muumuu-domain.com",
		SuzuriBase: envDefault("SUZURI_BASE", "https://suzuri.jp"),
		VerifyBase: "https://dkip-site.lolipop-now.app",
		Selector:   envDefault("SELECTOR", "dkip"),
	}
	if len(args) > 0 && args[0] != "" {
		cfg.Domain = args[0]
	}
	if err := checkASCIIDomain(cfg.Domain); err != nil {
		return cfg, err
	}
	if cfg.MuuPAT == "" {
		return cfg, errors.New("環境変数 MUU_PAT（ムームー Personal Access Token）を設定してください")
	}
	if cfg.SuzuriKey == "" {
		return cfg, errors.New("環境変数 SUZURI_API_KEY（SUZURI API キー）を設定してください")
	}
	return cfg, nil
}

// checkASCIIDomain はドメインが ASCII のみか検査する。日本語（Unicode）ドメインは
// 未対応のため、punycode 形式（xn-- で始まる ASCII 表記）での指定を求める。
func checkASCIIDomain(domain string) error {
	for _, r := range domain {
		if r > 127 {
			return fmt.Errorf("日本語（Unicode）ドメイン %q には対応していません。punycode 形式（xn-- で始まる表記）で指定してください", domain)
		}
	}
	return nil
}

// ---- 署名まわり ----

// buildPayload は署名対象文字列 <domain>|<acquired_year>|<issued_at>|<nonce> を組み立てる。
func buildPayload(domain, year, issuedAt, nonce string) string {
	return fmt.Sprintf("%s|%s|%s|%s", domain, year, issuedAt, nonce)
}

// signPayload は payload を Ed25519 署名し base64url（パディングなし）で返す。
func signPayload(priv ed25519.PrivateKey, payload string) string {
	return base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, []byte(payload)))
}

// encodePublicKey は生 32 バイトの公開鍵を base64 標準（パディングあり）でエンコードする（DKIM の p= 形式）。
func encodePublicKey(pub ed25519.PublicKey) string {
	return base64.StdEncoding.EncodeToString(pub)
}

// txtName は TXT レコード名 <selector>._domainkey.<domain> を返す（末尾ドットなし）。
func txtName(selector, domain string) string {
	return selector + "._domainkey." + domain
}

// txtValue は TXT レコード値 v=DKIP1; k=ed25519; p=<base64公開鍵> を返す。
//
// タグの形式は DKIM (RFC 6376) から借りているが、バージョンは DKIM1 ではなく DKIP1 を名乗る。
// RFC 6376 3.6.1 は「v= があって DKIM1 以外の値ならレコードを破棄しなければならない」と定めており、
// DKIP1 にしておけば準拠した DKIM 検証器はこのレコードをメール署名鍵として解釈しない。
func txtValue(pubB64 string) string {
	return "v=DKIP1; k=ed25519; p=" + pubB64
}

// newNonce は crypto/rand によるランダム 16 進 6 文字を返す。
func newNonce() (string, error) {
	b := make([]byte, 3)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// yearFromStartDate は contract.start-date の先頭 4 文字（西暦年）を返す。取得できなければ "unknown"。
func yearFromStartDate(s string) string {
	if len(s) < 4 {
		return "unknown"
	}
	year := s[:4]
	for _, r := range year {
		if r < '0' || r > '9' {
			return "unknown"
		}
	}
	return year
}

// buildVerifyURL は検証 URL <base>/?d=&y=&t=&n=&sig= を組み立てる。各値は URL エンコードされる。
// item（SUZURI 商品 URL）は任意で、署名対象外。空なら付けない。
func buildVerifyURL(base, domain, year, issuedAt, nonce, sig, item string) string {
	q := url.Values{}
	q.Set("d", domain)
	q.Set("y", year)
	q.Set("t", issuedAt)
	q.Set("n", nonce)
	q.Set("sig", sig)
	if item != "" {
		q.Set("item", item)
	}
	return base + "/?" + q.Encode()
}

// ---- HTTP ----

func doJSON(hc *http.Client, method, url, token string, reqBody any) (int, []byte, error) {
	var body io.Reader
	if reqBody != nil {
		b, err := json.Marshal(reqBody)
		if err != nil {
			return 0, nil, err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := hc.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, respBody, nil
}

// ---- ムームー API ----

type domainInfo struct {
	ID    string `json:"id"`
	FQDN  string `json:"fqdn"`
	State string `json:"state"`
}

// listDomains は保有ドメイン一覧を取得する（GET /api/v2/me/domains）。
func listDomains(hc *http.Client, base, token string) ([]domainInfo, error) {
	status, body, err := doJSON(hc, http.MethodGet, base+"/api/v2/me/domains", token, nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("ドメイン一覧の取得に失敗しました (HTTP %d): %s", status, body)
	}
	var res struct {
		Data []domainInfo `json:"data"`
	}
	if err := json.Unmarshal(body, &res); err != nil {
		return nil, err
	}
	return res.Data, nil
}

// pickDomain は want（fqdn）指定なら一致するものを、未指定なら先頭を返す。
func pickDomain(domains []domainInfo, want string) (domainInfo, error) {
	if len(domains) == 0 {
		return domainInfo{}, errors.New("保有ドメインが 1 つも見つかりませんでした")
	}
	if want == "" {
		return domains[0], nil
	}
	for _, d := range domains {
		if d.FQDN == want {
			return d, nil
		}
	}
	return domainInfo{}, fmt.Errorf("DOMAIN=%s は保有ドメインの中に見つかりませんでした", want)
}

// getDomainYear はドメイン詳細から取得年（contract.start-date の西暦年）を返す。無ければ "unknown"。
func getDomainYear(hc *http.Client, base, token, domainID string) (string, error) {
	status, body, err := doJSON(hc, http.MethodGet, base+"/api/v2/me/domains/"+domainID, token, nil)
	if err != nil {
		return "", err
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("ドメイン詳細の取得に失敗しました (HTTP %d): %s", status, body)
	}
	var res struct {
		Data struct {
			Contract struct {
				StartDate string `json:"start-date"`
			} `json:"contract"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &res); err != nil {
		return "", err
	}
	return yearFromStartDate(res.Data.Contract.StartDate), nil
}

// putTXT は TXT レコードを作成する（POST /api/v2/me/domains/{id}/dns-records）。
// API 仕様により fqdn は末尾ドット付きで送る。201 で created=true、409（既存）は created=false で継続可。
func putTXT(hc *http.Client, base, token, domainID, name, value string) (created bool, err error) {
	reqBody := map[string]string{
		"fqdn":  name + ".",
		"type":  "TXT",
		"value": value,
	}
	status, body, err := doJSON(hc, http.MethodPost, base+"/api/v2/me/domains/"+domainID+"/dns-records", token, reqBody)
	if err != nil {
		return false, err
	}
	switch status {
	case http.StatusCreated, http.StatusOK:
		return true, nil
	case http.StatusConflict:
		return false, nil
	default:
		return false, fmt.Errorf("TXT レコードの登録に失敗しました (HTTP %d): %s", status, body)
	}
}

// getTXTValue は DNS レコード一覧（GET /api/v2/me/domains/{id}/dns-records）から
// name（末尾ドットの有無は問わない）に一致する TXT レコードの値を返す。無ければ空文字。
func getTXTValue(hc *http.Client, base, token, domainID, name string) (string, error) {
	status, body, err := doJSON(hc, http.MethodGet, base+"/api/v2/me/domains/"+domainID+"/dns-records", token, nil)
	if err != nil {
		return "", err
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("DNS レコード一覧の取得に失敗しました (HTTP %d): %s", status, body)
	}
	var res struct {
		Data []struct {
			FQDN  string `json:"fqdn"`
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &res); err != nil {
		return "", err
	}
	want := strings.TrimSuffix(name, ".")
	for _, rec := range res.Data {
		if rec.Type == "TXT" && strings.TrimSuffix(rec.FQDN, ".") == want {
			return rec.Value, nil
		}
	}
	return "", nil
}

// ensureTXT は TXT レコードを登録する。既存（409）の場合は DNS 上の値と value を照合し、
// 一致すればそのまま継続できる。不一致なら DNS 上の古い公開鍵では今回の署名を検証できないため、
// 続行せずエラーを返す。
func ensureTXT(hc *http.Client, base, token, domainID, name, value string) (created bool, err error) {
	created, err = putTXT(hc, base, token, domainID, name, value)
	if err != nil || created {
		return created, err
	}
	existing, err := getTXTValue(hc, base, token, domainID, name)
	if err != nil {
		return false, err
	}
	if existing == value {
		return false, nil
	}
	return false, fmt.Errorf(
		"TXT レコード %s は既に別の公開鍵で登録されています。このまま発行すると QR の署名が検証に失敗します。\n"+
			"   DNS 上の値: %s\n   今回の値:   %s\n"+
			"   セレクタを変えて再実行する（例: SELECTOR=dkip2）か、古い TXT レコードを削除してください",
		name, existing, value)
}

// ---- SUZURI API ----

// createTee は JPEG データ URI を素材として T シャツを生成し、商品ページ URL を返す。
// backDataURI が空でなければ背面プリント（printSide: back）として追加する。
func createTee(hc *http.Client, base, token, dataURI, title, backDataURI string) (string, error) {
	product := map[string]any{"itemId": 1, "published": true} // itemId 1 = スタンダード T シャツ
	if backDataURI != "" {
		product["sub_materials"] = []map[string]any{
			{"texture": backDataURI, "printSide": "back", "enabled": true},
		}
	}
	reqBody := map[string]any{
		"texture":  dataURI,
		"title":    title,
		"products": []map[string]any{product},
	}
	status, body, err := doJSON(hc, http.MethodPost, base+"/api/v1/materials", token, reqBody)
	if err != nil {
		return "", err
	}
	if status != http.StatusOK && status != http.StatusCreated {
		return "", fmt.Errorf("SUZURI での T シャツ生成に失敗しました (HTTP %d): %s", status, body)
	}
	var res struct {
		Products []struct {
			SampleURL string `json:"sampleUrl"`
		} `json:"products"`
	}
	if err := json.Unmarshal(body, &res); err != nil {
		return "", err
	}
	if len(res.Products) == 0 {
		return "", nil
	}
	return res.Products[0].SampleURL, nil
}

// ---- サイトロゴの取得 ----

// logoCandidate は抽出したロゴ/アイコン候補。priority が小さいほど優先（高解像度寄り）。
type logoCandidate struct {
	url      string
	priority int
}

// 優先度: apple-touch-icon(0) → og:image(1) → rel=icon(2) → /favicon.ico(3)。小さいほど優先。
const (
	prioAppleTouch = 0
	prioOGImage    = 1
	prioIcon       = 2
	prioFavicon    = 3
)

// extractLogoCandidates は HTML から候補 URL を抽出し、base で絶対 URL に解決して優先度順に返す。
func extractLogoCandidates(base *url.URL, htmlBody io.Reader) []logoCandidate {
	root, err := html.Parse(htmlBody)
	if err != nil {
		return nil
	}
	var cands []logoCandidate
	add := func(raw string, prio int) {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return
		}
		ref, err := url.Parse(raw)
		if err != nil {
			return
		}
		abs := base.ResolveReference(ref)
		if abs.Scheme != "http" && abs.Scheme != "https" {
			return
		}
		cands = append(cands, logoCandidate{url: abs.String(), priority: prio})
	}
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "link":
				rel := strings.ToLower(attr(n, "rel"))
				href := attr(n, "href")
				switch {
				case strings.Contains(rel, "apple-touch-icon"):
					add(href, prioAppleTouch)
				case strings.Contains(rel, "icon"): // "icon" / "shortcut icon"
					add(href, prioIcon)
				}
			case "meta":
				prop := strings.ToLower(attr(n, "property"))
				if prop == "" {
					prop = strings.ToLower(attr(n, "name"))
				}
				if prop == "og:image" || prop == "og:image:url" {
					add(attr(n, "content"), prioOGImage)
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(root)
	return cands
}

// attr はノードの属性値を（大文字小文字を無視して）返す。無ければ空文字。
func attr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if strings.EqualFold(a.Key, key) {
			return a.Val
		}
	}
	return ""
}

// downloadImage は URL から画像を取得してデコードする。
// ラスタ画像（PNG/JPEG/GIF）を優先し、扱えなければ SVG としてのラスタライズを試す。
func downloadImage(hc *http.Client, u string) (image.Image, error) {
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "dkip")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20)) // 上限 10MB
	if err != nil {
		return nil, err
	}
	img, _, err := image.Decode(bytes.NewReader(data))
	if err == nil {
		return img, nil
	}
	if img, icoErr := decodeICO(data); icoErr == nil {
		return img, nil
	}
	return rasterizeSVG(data)
}

// decodeICO は ICO コンテナから最大サイズのエントリを取り出してデコードする。
// エントリは PNG か、BITMAPFILEHEADER を持たない BMP (DIB) のどちらか。
func decodeICO(data []byte) (image.Image, error) {
	// ICONDIR: reserved=0, type=1 (icon), count
	if len(data) < 6 || data[0] != 0 || data[1] != 0 || data[2] != 1 || data[3] != 0 {
		return nil, errors.New("ICO 形式ではない")
	}
	count := int(binary.LittleEndian.Uint16(data[4:6]))
	bestW := -1
	var entry []byte
	for i := 0; i < count; i++ {
		off := 6 + 16*i
		if off+16 > len(data) {
			break
		}
		w := int(data[off])
		if w == 0 {
			w = 256 // 幅 0 は 256px の意味
		}
		size := int(binary.LittleEndian.Uint32(data[off+8:]))
		dataOff := int(binary.LittleEndian.Uint32(data[off+12:]))
		if dataOff < 0 || size <= 0 || dataOff+size > len(data) {
			continue
		}
		if w > bestW {
			bestW = w
			entry = data[dataOff : dataOff+size]
		}
	}
	if entry == nil {
		return nil, errors.New("ICO に有効なエントリが無い")
	}
	if bytes.HasPrefix(entry, []byte("\x89PNG\r\n\x1a\n")) {
		return png.Decode(bytes.NewReader(entry))
	}
	return decodeICODIB(entry)
}

// decodeICODIB は ICO 内の DIB に BITMAPFILEHEADER を補って BMP としてデコードする。
// DIB の高さは AND マスク分を含めて実寸の 2 倍で記録されているため半分に戻す。
func decodeICODIB(dib []byte) (image.Image, error) {
	const fileHeaderSize = 14
	if len(dib) < 40 {
		return nil, errors.New("DIB が短すぎる")
	}
	hdrSize := binary.LittleEndian.Uint32(dib[0:4])
	if hdrSize != 40 {
		return nil, fmt.Errorf("未対応の DIB ヘッダサイズ: %d", hdrSize)
	}
	fixed := make([]byte, len(dib))
	copy(fixed, dib)
	height := int32(binary.LittleEndian.Uint32(dib[8:12]))
	binary.LittleEndian.PutUint32(fixed[8:12], uint32(height/2))

	bpp := binary.LittleEndian.Uint16(dib[14:16])
	colors := binary.LittleEndian.Uint32(dib[32:36])
	if colors == 0 && bpp <= 8 {
		colors = 1 << bpp
	}
	var buf bytes.Buffer
	buf.WriteString("BM")
	binary.Write(&buf, binary.LittleEndian, uint32(fileHeaderSize+len(fixed)))
	binary.Write(&buf, binary.LittleEndian, uint32(0)) // reserved
	binary.Write(&buf, binary.LittleEndian, fileHeaderSize+hdrSize+colors*4)
	buf.Write(fixed)
	return bmp.Decode(&buf)
}

// svgRasterSize は SVG をラスタライズするときの長辺ピクセル数。
// Tシャツ印刷用キャンバスに 25% 幅で載せても粗くならない大きさにしている。
const svgRasterSize = 512

// rasterizeSVG は SVG バイト列を長辺 svgRasterSize px、アスペクト比維持でラスタライズする。
func rasterizeSVG(data []byte) (img image.Image, err error) {
	// oksvg は不正な入力で panic することがあるため、外部サイト由来の
	// データを渡す以上ここで回収してエラーに変換する
	defer func() {
		if r := recover(); r != nil {
			img, err = nil, fmt.Errorf("SVG のラスタライズに失敗: %v", r)
		}
	}()
	icon, err := oksvg.ReadIconStream(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	vw, vh := icon.ViewBox.W, icon.ViewBox.H
	if vw <= 0 || vh <= 0 {
		vw, vh = 1, 1 // viewBox が無い/不正なら正方形として扱う
	}
	scale := svgRasterSize / vw
	if vh > vw {
		scale = svgRasterSize / vh
	}
	w := int(vw*scale + 0.5)
	h := int(vh*scale + 0.5)
	icon.SetTarget(0, 0, float64(w), float64(h))
	rgba := image.NewRGBA(image.Rect(0, 0, w, h))
	scanner := rasterx.NewScannerGV(w, h, rgba, rgba.Bounds())
	icon.Draw(rasterx.NewDasher(w, h, scanner), 1.0)
	return rgba, nil
}

// fetchSiteLogo は対象ドメインの Web サイトから icon/logo を取得してデコード済み画像を返す。
// https を優先し、失敗したら http も試す。見つからなければ (nil, nil) を返す（エラーではない）。
func fetchSiteLogo(hc *http.Client, domain string) (image.Image, error) {
	return fetchSiteLogoAt(hc, "https://"+domain+"/", "http://"+domain+"/")
}

// fetchSiteLogoAt は指定したトップページ URL 群を順に試して icon/logo を取得する。
// 最初に到達できたページから候補を集める。見つからなければ (nil, nil) を返す。
func fetchSiteLogoAt(hc *http.Client, pageURLs ...string) (image.Image, error) {
	var cands []logoCandidate
	var pageURL *url.URL
	for _, u := range pageURLs {
		req, err := http.NewRequest(http.MethodGet, u, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "dkip")
		resp, err := hc.Do(req)
		if err != nil {
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			continue
		}
		pageURL = resp.Request.URL // リダイレクト後の URL を基準にする
		cands = extractLogoCandidates(pageURL, io.LimitReader(resp.Body, 5<<20))
		resp.Body.Close()
		break
	}
	if pageURL == nil {
		return nil, nil // サイトに到達できなかった
	}
	// /favicon.ico を最後の候補として常に追加
	fav := *pageURL
	fav.Path = "/favicon.ico"
	fav.RawQuery = ""
	cands = append(cands, logoCandidate{url: fav.String(), priority: prioFavicon})

	// 優先度順（安定ソート: 同順位は出現順を維持）に並べ、取得できた最初の 1 枚を使う
	sortByPriority(cands)
	seen := map[string]bool{}
	for _, c := range cands {
		if seen[c.url] {
			continue
		}
		seen[c.url] = true
		if img, err := downloadImage(hc, c.url); err == nil && img != nil {
			return img, nil
		}
	}
	return nil, nil
}

// sortByPriority は priority 昇順の安定ソート（挿入ソート）。候補数は少ないので十分。
func sortByPriority(cs []logoCandidate) {
	for i := 1; i < len(cs); i++ {
		for j := i; j > 0 && cs[j].priority < cs[j-1].priority; j-- {
			cs[j], cs[j-1] = cs[j-1], cs[j]
		}
	}
}

// ---- サイトマップの取得 ----

// maxSitemapURLs は背面に載せる URL の上限。超過分は「+N more」で示す。
const maxSitemapURLs = 60

// parseSitemap は sitemap XML をパースし、<urlset> なら <loc> を、
// <sitemapindex> なら子 sitemap の URL を返す（後者は fetchSitemapURLs 側で 1 階層だけ辿る）。
func parseSitemap(r io.Reader) (locs []string, childSitemaps []string) {
	dec := xml.NewDecoder(r)
	var inSitemap bool // 現在 <sitemap>（index の子）要素の中か
	var cur strings.Builder
	var capturing bool
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch t.Name.Local {
			case "sitemap":
				inSitemap = true
			case "loc":
				capturing = true
				cur.Reset()
			}
		case xml.CharData:
			if capturing {
				cur.Write(t)
			}
		case xml.EndElement:
			switch t.Name.Local {
			case "loc":
				capturing = false
				u := strings.TrimSpace(cur.String())
				if u == "" {
					break
				}
				if inSitemap {
					childSitemaps = append(childSitemaps, u)
				} else {
					locs = append(locs, u)
				}
			case "sitemap":
				inSitemap = false
			}
		}
	}
	return locs, childSitemaps
}

// fetchSitemapURLs は対象ドメインの /sitemap.xml から URL 一覧を取得する。
// sitemapindex の場合は子 sitemap を 1 階層だけ辿る。取れなければ nil を返す（エラーではない）。
func fetchSitemapURLs(hc *http.Client, domain string) []string {
	return fetchSitemapURLsAt(hc, "https://"+domain+"/sitemap.xml", "http://"+domain+"/sitemap.xml")
}

// fetchSitemapURLsAt は指定した sitemap URL 群を順に試して URL 一覧を返す（全件。切り詰めは呼び出し側）。
// テスト用に URL を差し替えられる。子 sitemap の辿りすぎを防ぐため過剰取得時点で打ち切る。
func fetchSitemapURLsAt(hc *http.Client, sitemapURLs ...string) []string {
	locs, children := fetchOneSitemap(hc, sitemapURLs...)
	// sitemapindex だった場合、子 sitemap を 1 階層だけ辿って loc を集める
	for _, child := range children {
		if len(locs) >= maxSitemapURLs*4 { // 上限の数倍集まれば十分（「+N more」用の概数）
			break
		}
		childLocs, _ := fetchOneSitemap(hc, child)
		locs = append(locs, childLocs...)
	}
	if len(locs) == 0 {
		return nil
	}
	return locs
}

// limitSitemapURLs は URL 一覧を上限まで切り詰め、切り詰め後の一覧と切り詰め前の総数を返す。
func limitSitemapURLs(urls []string) (shown []string, total int) {
	total = len(urls)
	if total > maxSitemapURLs {
		return urls[:maxSitemapURLs], total
	}
	return urls, total
}

// fetchOneSitemap は最初に到達できた URL の sitemap をパースして返す。
func fetchOneSitemap(hc *http.Client, urls ...string) (locs []string, children []string) {
	for _, u := range urls {
		req, err := http.NewRequest(http.MethodGet, u, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "dkip")
		resp, err := hc.Do(req)
		if err != nil {
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			continue
		}
		l, c := parseSitemap(io.LimitReader(resp.Body, 10<<20))
		resp.Body.Close()
		return l, c
	}
	return nil, nil
}

// sitemapPaths は URL 一覧を背面表示用のパス（+クエリ）文字列に変換する。ホスト部は省く。
func sitemapPaths(urls []string) []string {
	paths := make([]string, 0, len(urls))
	for _, raw := range urls {
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		p := u.Path
		if p == "" {
			p = "/"
		}
		if u.RawQuery != "" {
			p += "?" + u.RawQuery
		}
		paths = append(paths, p)
	}
	return paths
}

// ---- 画像化 ----

// renderText は basicfont で文字列を描画した小さな白黒画像を返す。
func renderText(text string) *image.RGBA {
	face := basicfont.Face7x13
	w := face.Advance * len(text)
	h := face.Height
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	draw.Draw(img, img.Bounds(), image.White, image.Point{}, draw.Src)
	d := &font.Drawer{
		Dst:  img,
		Src:  image.Black,
		Face: face,
		Dot:  fixed.P(0, face.Ascent),
	}
	d.DrawString(text)
	return img
}

// pasteScaled は src を整数倍 scale で拡大し、dst の (x, y) を左上として貼り付ける（最近傍）。
func pasteScaled(dst *image.RGBA, src *image.RGBA, x, y, scale int) {
	b := src.Bounds()
	for sy := 0; sy < b.Dy(); sy++ {
		for sx := 0; sx < b.Dx(); sx++ {
			c := src.RGBAAt(sx, sy)
			for dy := 0; dy < scale; dy++ {
				for dx := 0; dx < scale; dx++ {
					dst.SetRGBA(x+sx*scale+dx, y+sy*scale+dy, c)
				}
			}
		}
	}
}

// qrModules は URL を QR コード化し、クワイエットゾーン込みのモジュール行列（true=黒）を返す。
func qrModules(u string) ([][]bool, error) {
	q, err := qrcode.New(u, qrcode.Medium)
	if err != nil {
		return nil, err
	}
	return q.Bitmap(), nil
}

// qrImage はモジュール行列を 1 モジュール = 1 ピクセルの白黒画像にする。
func qrImage(modules [][]bool) *image.RGBA {
	n := len(modules)
	img := image.NewRGBA(image.Rect(0, 0, n, n))
	draw.Draw(img, img.Bounds(), image.White, image.Point{}, draw.Src)
	for y, row := range modules {
		for x, black := range row {
			if black {
				img.Set(x, y, color.Black)
			}
		}
	}
	return img
}

// qrPixelSize は QR の描画ピクセルサイズを返す。キャンバス幅の 3 割を目標に整数倍率で拡大する。
func qrPixelSize(modules, canvasSize int) int {
	scale := canvasSize * 3 / 10 / modules
	if scale < 2 {
		scale = 2
	}
	return modules * scale
}

// drawLogo は logo をキャンバス上部中央に、幅がキャンバスの約 25% になるよう縦横比維持で
// 高品質縮小して描き、ロゴ下端の Y 座標を返す。logo が nil なら何もせず 0 を返す。
func drawLogo(canvas *image.RGBA, logo image.Image, size int) int {
	if logo == nil {
		return 0
	}
	src := logo.Bounds()
	if src.Dx() <= 0 || src.Dy() <= 0 {
		return 0
	}
	targetW := size * 25 / 100
	targetH := targetW * src.Dy() / src.Dx()
	top := size / 20 // 上端から 5% の余白
	x := (size - targetW) / 2
	dst := image.Rect(x, top, x+targetW, top+targetH)
	xdraw.CatmullRom.Scale(canvas, dst, logo, src, xdraw.Over, nil)
	return top + targetH
}

// renderJPEG はドメイン名（＋ since <year>）と検証 URL の QR コードを描いた JPEG を生成し、
// base64 データ URI で返す。qrURL が空なら QR は描かない。logo が非 nil なら上部中央に取り込む。
func renderJPEG(domain, year, qrURL string, logo image.Image) (string, error) {
	const size = 2000
	canvas := image.NewRGBA(image.Rect(0, 0, size, size))
	draw.Draw(canvas, canvas.Bounds(), image.White, image.Point{}, draw.Src)

	// サイトロゴがあれば上部中央に描画し、その下端分だけ以降の要素を押し下げる
	logoBottom := drawLogo(canvas, logo, size)

	// ドメイン名: キャンバス幅の約 8 割に収まる整数倍率で拡大し、上寄りの中央に描く
	main := renderText(domain)
	scale := size * 8 / 10 / main.Bounds().Dx()
	if scale < 1 {
		scale = 1
	}
	mainW := main.Bounds().Dx() * scale
	mainH := main.Bounds().Dy() * scale
	mainY := size*3/10 - mainH/2
	// ロゴと重なる場合はドメイン名をロゴの下へずらす
	if logoBottom > 0 && mainY < logoBottom+size/40 {
		mainY = logoBottom + size/40
	}
	pasteScaled(canvas, main, (size-mainW)/2, mainY, scale)

	bottom := mainY + mainH
	if year != "unknown" {
		sub := renderText("since " + year)
		subScale := scale / 3
		if subScale < 1 {
			subScale = 1
		}
		subW := sub.Bounds().Dx() * subScale
		subY := mainY + mainH + mainH/2
		pasteScaled(canvas, sub, (size-subW)/2, subY, subScale)
		bottom = subY + sub.Bounds().Dy()*subScale
	}

	if qrURL != "" {
		modules, err := qrModules(qrURL)
		if err != nil {
			return "", err
		}
		// キャンバス幅の約 3 割の大きさで下部中央に置く。文字と重なる場合は重ならない倍率まで縮める
		qrScale := qrPixelSize(len(modules), size) / len(modules)
		for qrScale > 2 && size-len(modules)*qrScale-80 < bottom+60 {
			qrScale--
		}
		qrPx := len(modules) * qrScale
		pasteScaled(canvas, qrImage(modules), (size-qrPx)/2, size-qrPx-80, qrScale)
	}

	return encodeJPEGDataURI(canvas)
}

// encodeJPEGDataURI は画像を高品質 JPEG にして base64 データ URI で返す。
// 白背景に細い黒文字はモスキートノイズが出やすいので高品質でエンコードする。
func encodeJPEGDataURI(img image.Image) (string, error) {
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: 95}); err != nil {
		return "", err
	}
	return "data:image/jpeg;base64," + base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

// renderSitemapJPEG は背面用に、見出し（domain / sitemap）と URL パス一覧を縦に並べた
// JPEG を生成して base64 データ URI で返す。paths が空なら ("", nil) を返す（背面なし）。
// total は省略前の総件数で、paths より多ければ末尾に「+N more」を添える。
func renderSitemapJPEG(domain string, paths []string, total int) (string, error) {
	if len(paths) == 0 {
		return "", nil
	}
	const size = 2000
	canvas := image.NewRGBA(image.Rect(0, 0, size, size))
	draw.Draw(canvas, canvas.Bounds(), image.White, image.Point{}, draw.Src)

	// 見出し: domain（大きめ）→ sitemap（小さめ）を上部中央に
	head := renderText(domain)
	headScale := size * 6 / 10 / head.Bounds().Dx()
	if headScale < 1 {
		headScale = 1
	}
	headW := head.Bounds().Dx() * headScale
	headH := head.Bounds().Dy() * headScale
	pasteScaled(canvas, head, (size-headW)/2, size/20, headScale)

	sub := renderText("sitemap")
	subScale := headScale / 2
	if subScale < 1 {
		subScale = 1
	}
	subW := sub.Bounds().Dx() * subScale
	subY := size/20 + headH + headH/4
	pasteScaled(canvas, sub, (size-subW)/2, subY, subScale)
	subBottom := subY + sub.Bounds().Dy()*subScale

	// 表示行を確定（超過分は「+N more」を末尾に）
	lines := paths
	if extra := total - len(paths); extra > 0 {
		lines = append(append([]string{}, paths...), fmt.Sprintf("+%d more", extra))
	}

	// リスト領域: 見出しの下〜下端。上下左右に余白 margin をとり、幅は約 85% まで使う
	const margin = 120
	listTop := subBottom + size/20
	availH := size - listTop - margin
	availW := size * 85 / 100

	adv := basicfont.Face7x13.Advance // 1 文字の送り幅
	glyphH := renderText("M").Bounds().Dy()

	// 最長行がキャンバス幅の約 85% に収まる整数倍率を基準サイズにする（大きめ・上限あり）
	maxLen := 1
	for _, l := range lines {
		if len(l) > maxLen {
			maxLen = len(l)
		}
	}
	pathScale := availW / (maxLen * adv)
	if pathScale > 14 {
		pathScale = 14
	}
	// 縦に全行が入らなければ、入るまでサイズを下げる（行間はサイズの 1.4 倍）
	for pathScale > 2 && len(lines)*glyphH*pathScale*14/10 > availH {
		pathScale--
	}
	if pathScale < 2 {
		pathScale = 2
	}
	lineH := glyphH * pathScale * 14 / 10

	// 収まらない長さは末尾を ~ で省略（basicfont は ASCII のみ）
	maxChars := availW / (adv * pathScale)

	// ブロック全体を縦中央寄せ、左端はキャンバス中央（はみ出す場合は収まる位置まで左へ）
	blockH := len(lines) * lineH
	startY := listTop + (availH-blockH)/2
	if startY < listTop {
		startY = listTop
	}
	blockW := maxLen * adv * pathScale
	if blockW > maxChars*adv*pathScale {
		blockW = maxChars * adv * pathScale
	}
	// ブロック（最長行の幅）の中心をキャンバス中心に合わせる
	blockX := (size - blockW) / 2
	if blockX < margin {
		blockX = margin
	}

	for i, line := range lines {
		if maxChars > 1 && len(line) > maxChars {
			line = line[:maxChars-1] + "~"
		}
		y := startY + i*lineH
		if y+glyphH*pathScale > size-margin {
			break
		}
		pasteScaled(canvas, renderText(line), blockX, y, pathScale)
	}

	return encodeJPEGDataURI(canvas)
}

// ---- 秘密鍵の保存 ----

// savePrivateKey は秘密鍵を PKCS#8 PEM 形式・パーミッション 0600 で保存する。
func savePrivateKey(path string, priv ed25519.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	return os.WriteFile(path, pemBytes, 0o600)
}

// loadPrivateKey は PKCS#8 PEM 形式の Ed25519 秘密鍵を読み込む。
func loadPrivateKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("%s は PEM 形式ではありません", path)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	priv, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s は Ed25519 秘密鍵ではありません", path)
	}
	return priv, nil
}

// loadOrCreateKey は path に鍵ファイルがあればそれを再利用し、無ければ新規生成して即保存する。
// 鍵を再利用しないと、DNS に登録済みの公開鍵と食い違って署名が検証できなくなる。
func loadOrCreateKey(path string) (ed25519.PublicKey, ed25519.PrivateKey, bool, error) {
	if _, err := os.Stat(path); err == nil {
		priv, err := loadPrivateKey(path)
		if err != nil {
			return nil, nil, false, err
		}
		return priv.Public().(ed25519.PublicKey), priv, true, nil
	}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, nil, false, err
	}
	if err := savePrivateKey(path, priv); err != nil {
		return nil, nil, false, err
	}
	return pub, priv, false, nil
}

// ---- 実況ログ ----

func step(emoji, msg string) {
	fmt.Printf("%s %s\n", emoji, msg)
}

func detail(msg string) {
	fmt.Printf("   %s\n", msg)
}

func fail(msg string, err error) {
	fmt.Printf("❌ %s\n", msg)
	fmt.Printf("   %v\n", err)
	os.Exit(1)
}

// chooseDomain は DOMAIN 未指定で複数ドメインがあるとき対話選択させる。読み取れなければ先頭を採用。
func chooseDomain(domains []domainInfo, want string) (domainInfo, error) {
	if want != "" || len(domains) <= 1 {
		return pickDomain(domains, want)
	}
	fmt.Println("   複数のドメインが見つかりました:")
	for i, d := range domains {
		fmt.Printf("     [%d] %s\n", i+1, d.FQDN)
	}
	fmt.Print("   番号を選んでください [1]: ")
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return domains[0], nil
	}
	n, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil || n < 1 || n > len(domains) {
		return domains[0], nil
	}
	return domains[n-1], nil
}

// ---- 全体フロー ----

func main() {
	cfg, err := loadConfig(os.Args[1:])
	if err != nil {
		fail("設定の読み込みに失敗しました", err)
	}
	hc := &http.Client{Timeout: 30 * time.Second}

	step("🔑", "鍵ペアを準備中...")
	pub, priv, reused, err := loadOrCreateKey(keyFilePath)
	if err != nil {
		fail("鍵ペアの準備に失敗しました", err)
	}
	if reused {
		detail(fmt.Sprintf("→ 既存の秘密鍵 ./%s を再利用します", keyFilePath))
	} else {
		detail(fmt.Sprintf("→ 生成しました (Ed25519)。秘密鍵を ./%s に保存しました（大切に保管してください）", keyFilePath))
	}

	step("🌐", "あなたのドメインを確認中...")
	domains, err := listDomains(hc, cfg.MuumuuBase, cfg.MuuPAT)
	if err != nil {
		fail("ドメイン一覧の取得に失敗しました", err)
	}
	target, err := chooseDomain(domains, cfg.Domain)
	if err != nil {
		fail("ドメインの選択に失敗しました", err)
	}
	if err := checkASCIIDomain(target.FQDN); err != nil {
		fail("このドメインには対応していません", err)
	}
	year, err := getDomainYear(hc, cfg.MuumuuBase, cfg.MuuPAT, target.ID)
	if err != nil {
		fail("ドメイン詳細の取得に失敗しました", err)
	}
	if year == "unknown" {
		detail(fmt.Sprintf("→ %s が見つかりました（取得年は不明でした）", target.FQDN))
	} else {
		detail(fmt.Sprintf("→ %s が見つかりました (取得: %s年)", target.FQDN, year))
	}

	issuedAt := time.Now().UTC().Format("2006-01-02")
	nonce, err := newNonce()
	if err != nil {
		fail("ノンスの生成に失敗しました", err)
	}
	payload := buildPayload(target.FQDN, year, issuedAt, nonce)
	sig := signPayload(priv, payload)
	step("✍️ ", "署名しました")
	detail("payload: " + payload)

	step("📡", "公開鍵を DNS に刻んでいます...")
	name := txtName(cfg.Selector, target.FQDN)
	detail("TXT  " + name)
	created, err := ensureTXT(hc, cfg.MuumuuBase, cfg.MuuPAT, target.ID, name, txtValue(encodePublicKey(pub)))
	if err != nil {
		fail("TXT レコードの登録に失敗しました", err)
	}
	if created {
		detail("→ 世界中から検証できるようになりました ✅")
	} else {
		detail("→ 既に同じ公開鍵で登録済みです（このまま続行します）")
	}

	step("👕", "T シャツを生成中...")
	// 対象ドメインのサイトから icon/logo を取得できれば取り込む（失敗しても続行）
	logo, err := fetchSiteLogo(hc, target.FQDN)
	if err != nil {
		logo = nil
	}
	if logo != nil {
		detail("→ サイトのロゴを取り込みました")
	} else {
		detail("→ サイトのロゴは見つかりませんでした（ドメイン名だけで作ります）")
	}
	// QR には item なしの検証 URL を入れる（商品 URL は T シャツ生成後にしか分からないため）
	qrURL := buildVerifyURL(cfg.VerifyBase, target.FQDN, year, issuedAt, nonce, sig, "")
	dataURI, err := renderJPEG(target.FQDN, year, qrURL, logo)
	if err != nil {
		fail("画像の生成に失敗しました", err)
	}

	// 背面: sitemap.xml から URL 一覧を取得できれば背面プリントにする（失敗しても続行）
	sitemapURLs := fetchSitemapURLs(hc, target.FQDN)
	backDataURI := ""
	shownCount := 0
	if len(sitemapURLs) > 0 {
		shown, total := limitSitemapURLs(sitemapURLs)
		shownCount = len(shown)
		backDataURI, err = renderSitemapJPEG(target.FQDN, sitemapPaths(shown), total)
		if err != nil {
			backDataURI = ""
		}
	}
	if backDataURI != "" {
		detail(fmt.Sprintf("→ サイトマップ %d 件を背面に入れました（全 %d 件）", shownCount, len(sitemapURLs)))
	} else {
		detail("→ サイトマップは見つかりませんでした（背面はなしで作ります）")
	}

	teeURL, err := createTee(hc, cfg.SuzuriBase, cfg.SuzuriKey, dataURI, target.FQDN, backDataURI)
	if err != nil {
		fail("SUZURI での T シャツ生成に失敗しました", err)
	}
	if teeURL == "" {
		detail("→ できました！（商品ページ URL は SUZURI のマイページで確認してください）")
	} else {
		detail("→ できました！ " + teeURL)
	}

	step("🔗", "検証 URL: "+buildVerifyURL(cfg.VerifyBase, target.FQDN, year, issuedAt, nonce, sig, teeURL))
}
