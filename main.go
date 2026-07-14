package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/jpeg"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"
	"golang.org/x/image/font"
	"golang.org/x/image/font/basicfont"
	"golang.org/x/image/math/fixed"
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
	if cfg.MuuPAT == "" {
		return cfg, errors.New("環境変数 MUU_PAT（ムームー Personal Access Token）を設定してください")
	}
	if cfg.SuzuriKey == "" {
		return cfg, errors.New("環境変数 SUZURI_API_KEY（SUZURI API キー）を設定してください")
	}
	return cfg, nil
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

// txtValue は TXT レコード値 v=DKIM1; k=ed25519; p=<base64公開鍵> を返す。
func txtValue(pubB64 string) string {
	return "v=DKIM1; k=ed25519; p=" + pubB64
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

// ---- SUZURI API ----

// createTee は JPEG データ URI を素材として T シャツを生成し、商品ページ URL を返す。
func createTee(hc *http.Client, base, token, dataURI, title string) (string, error) {
	reqBody := map[string]any{
		"texture": dataURI,
		"title":   title,
		"products": []map[string]any{
			{"itemId": 1, "published": true}, // itemId 1 = スタンダード T シャツ
		},
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

// renderJPEG はドメイン名（＋ since <year>）と検証 URL の QR コードを描いた JPEG を生成し、
// base64 データ URI で返す。qrURL が空なら QR は描かない。
func renderJPEG(domain, year, qrURL string) (string, error) {
	const size = 1200
	canvas := image.NewRGBA(image.Rect(0, 0, size, size))
	draw.Draw(canvas, canvas.Bounds(), image.White, image.Point{}, draw.Src)

	// ドメイン名: キャンバス幅の約 8 割に収まる整数倍率で拡大し、やや上寄りの中央に描く
	main := renderText(domain)
	scale := size * 8 / 10 / main.Bounds().Dx()
	if scale < 1 {
		scale = 1
	}
	mainW := main.Bounds().Dx() * scale
	mainH := main.Bounds().Dy() * scale
	mainY := size*2/5 - mainH/2
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
		// スキャン可能な大きさ（240px 前後）になる整数倍率で拡大して下部中央に置く
		qrScale := 240 / len(modules)
		if qrScale < 2 {
			qrScale = 2
		}
		qrPx := len(modules) * qrScale
		qrY := size - qrPx - 60
		if qrY < bottom+40 {
			qrY = bottom + 40
		}
		pasteScaled(canvas, qrImage(modules), (size-qrPx)/2, qrY, qrScale)
	}

	var buf bytes.Buffer
	// 白背景に細い黒文字はモスキートノイズが出やすいので高品質でエンコードする
	if err := jpeg.Encode(&buf, canvas, &jpeg.Options{Quality: 95}); err != nil {
		return "", err
	}
	return "data:image/jpeg;base64," + base64.StdEncoding.EncodeToString(buf.Bytes()), nil
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

	step("🔑", "鍵ペアを生成中...")
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		fail("鍵ペアの生成に失敗しました", err)
	}
	detail("done (Ed25519)")

	step("🌐", "あなたのドメインを確認中...")
	domains, err := listDomains(hc, cfg.MuumuuBase, cfg.MuuPAT)
	if err != nil {
		fail("ドメイン一覧の取得に失敗しました", err)
	}
	target, err := chooseDomain(domains, cfg.Domain)
	if err != nil {
		fail("ドメインの選択に失敗しました", err)
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
	created, err := putTXT(hc, cfg.MuumuuBase, cfg.MuuPAT, target.ID, name, txtValue(encodePublicKey(pub)))
	if err != nil {
		fail("TXT レコードの登録に失敗しました", err)
	}
	if created {
		detail("→ 世界中から検証できるようになりました ✅")
	} else {
		detail("→ 既に登録済みです（セレクタを変える場合は SELECTOR=dkip2 などで再実行してください）")
	}

	step("👕", "T シャツを生成中...")
	// QR には item なしの検証 URL を入れる（商品 URL は T シャツ生成後にしか分からないため）
	qrURL := buildVerifyURL(cfg.VerifyBase, target.FQDN, year, issuedAt, nonce, sig, "")
	dataURI, err := renderJPEG(target.FQDN, year, qrURL)
	if err != nil {
		fail("画像の生成に失敗しました", err)
	}
	teeURL, err := createTee(hc, cfg.SuzuriBase, cfg.SuzuriKey, dataURI, target.FQDN)
	if err != nil {
		fail("SUZURI での T シャツ生成に失敗しました", err)
	}
	if teeURL == "" {
		detail("→ できました！（商品ページ URL は SUZURI のマイページで確認してください）")
	} else {
		detail("→ できました！ " + teeURL)
	}

	step("🔗", "検証 URL: "+buildVerifyURL(cfg.VerifyBase, target.FQDN, year, issuedAt, nonce, sig, teeURL))

	if err := savePrivateKey(keyFilePath, priv); err != nil {
		fail("秘密鍵の保存に失敗しました", err)
	}
	step("🔐", fmt.Sprintf("秘密鍵を ./%s に保存しました（大切に保管してください。これを無くすと同じ鍵で再発行できません）", keyFilePath))
}
