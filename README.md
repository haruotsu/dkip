# DKIP (DomainKeys Identified Product)

自分のドメインを、DNS が保証してくれる T シャツにする発行 CLI。

DKIM の発想（秘密鍵で署名 → 公開鍵を DNS の TXT に置く → 第三者が DNS 越しに検証）を踏襲しています。
証明できるのは「発行時点でそのドメインの DNS を操作できた人が署名した」ことまで。TXT レコードを消すと検証は失敗します（＝失効。裏を返せば「今も本物」を示せます）。

## インストール

```sh
go install github.com/haruotsu/dkip@latest
```

## 使い方

```sh
export MUU_PAT=<ムームードメインの Personal Access Token>   # スコープ: domains:read, dns:write
export SUZURI_API_KEY=<SUZURI の API キー>                  # read / write

# ドメインを指定して実行（省略すると保有ドメイン一覧から対話選択）
dkip example.com
```

実行すると以下を順に行い、各ステップを実況ログで表示します。

1. Ed25519 鍵ペアを生成
2. ムームー API で保有ドメイン一覧を取得し、1 つ選ぶ
3. 署名対象文字列（payload）を組み立て、秘密鍵で署名
4. 公開鍵をムームー API で DNS の TXT レコードに登録（`<selector>._domainkey.<domain>`）
5. ドメイン名を JPEG 画像に描画 → SUZURI API で T シャツ生成
6. 検証 URL を表示し、秘密鍵を `./dns-signed-tee.key` に保存

```
🔑 鍵ペアを生成中... done (Ed25519)
🌐 あなたのドメインを確認中...
   → example.com が見つかりました (取得: 2014年)
✍️  署名しました
   payload: example.com|2014|2026-07-14|9f3a1c
📡 公開鍵を DNS に刻んでいます...
   TXT  dkip._domainkey.example.com
   → 世界中から検証できるようになりました ✅
👕 T シャツを生成中...
   → できました！ https://suzuri.jp/...
🔗 検証 URL: https://verify.example/?d=example.com&y=2014&t=2026-07-14&n=9f3a1c&sig=...
🔐 秘密鍵を ./dns-signed-tee.key に保存しました（大切に保管してください）
```

## 環境変数

| 変数 | 必須 | 説明 |
| --- | --- | --- |
| `MUU_PAT` | 必須 | ムームードメインの Personal Access Token（`MUUMUU_PAT` でも可） |
| `SUZURI_API_KEY` | 必須 | SUZURI API キー（`SUZURI_TOKEN` でも可） |
| `SELECTOR` | 任意 | DKIM セレクタ。既定 `dkip`。再発行時は `dkip2` などに変える |

対象ドメインは環境変数ではなく CLI の第 1 引数で指定します（`dkip example.com`）。

## DNS に登録されるレコード

```
名前:  <SELECTOR>._domainkey.<domain>      例: dkip._domainkey.example.com
値:    v=DKIM1; k=ed25519; p=<base64 公開鍵>
```

## 開発

```sh
go test ./...
```

## API ドキュメント

- [ムームードメイン API](https://muumuu-domain.com/developers/openapi-me.html)
- [SUZURI API v1](https://suzuri.jp/developer/documentation/v1)
