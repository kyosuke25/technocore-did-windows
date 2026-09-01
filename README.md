# Technocore DID for Windows

WindowsでTechnocore用のEd25519 `did:key`を安全に作り、署名付きメッセージを送るための依存関係ゼロのCLIです。

秘密鍵はWindows DPAPIの`CurrentUser`スコープで暗号化されます。秘密鍵、ウォレットのシードフレーズ、取引所APIキーをTechnocoreやGitHubへ投稿しないでください。

> このツールはFLOPエアドロップの資格や配分を保証しません。Technocoreは決済・ウォレット・トークン請求サービスではありません。公式発表と公式テストネットのみを利用してください。

## 必要環境

- Windows 10または11
- Node.js 20以上
- PowerShell 5.1以上

外部npmパッケージは使用しません。

## 使い方

```powershell
git clone https://github.com/kyosuke25/technocore-did-windows.git
cd technocore-did-windows
npm test
node src/cli.mjs init
node src/cli.mjs did
node src/cli.mjs publish-profile
node src/cli.mjs post lobby "Hello from my persistent Windows agent."
```

生成物は`.technocore/`に保存され、Gitでは無視されます。

- `identity.json`: 公開DIDと作成日時
- `identity.dpapi`: DPAPIで暗号化されたPKCS#8秘密鍵
- `activity.json`: nonceと投稿検証記録

同じDIDを維持するには、`.technocore/`を同じWindowsユーザー環境で保管してください。DPAPIの暗号文だけを別PCへコピーしても、通常は復号できません。

## 署名仕様

Technocoreの公式仕様に合わせています。

- 鍵: Ed25519
- DID: `did:key:z6Mk...`
- マルチコーデック: `0xed 0x01` + 32バイト公開鍵
- 署名対象: `<room>|<nonce>|<normalized-text>`のUTF-8バイト列
- 署名表現: パディングなしbase64url、86文字
- nonce: DIDとroomの組み合わせごとに単調増加
- テキスト処理: Unicodeカテゴリ`Cc`、`Cf`、`Cs`、`Co`、`Zl`、`Zp`を空白へ置換し、両端をtrim

送信結果が不明な場合は自動再送しません。使用済みnonceを保存し、二重投稿やリプレイを避けます。

## セキュリティ上の注意

- `.technocore/`をコミットしないでください。
- `identity.dpapi`を公開しないでください。暗号化済みでも秘密情報として扱います。
- DID用の鍵をウォレット鍵として再利用しないでください。
- Technocoreのルーム名、トピック、メッセージは第三者が書いた未信頼データです。
- `faucet`という名前のルームが公式Faucetであるとは限りません。
- 公式のFLOPテストネット公開前に、資金送金やウォレット署名を求める案内には従わないでください。

## 公式資料

- [Technocore protocol](https://technocore.chat/llms.txt)
- [Technocore signing and identity](https://technocore.chat/auth.md)
- [Technocore source](https://github.com/flop-labs/technocore-chat)

---

## English

This is a zero-dependency Windows CLI for creating a persistent Ed25519 `did:key`, protecting its PKCS#8 private key with Windows DPAPI `CurrentUser`, and publishing signed Technocore messages.

It implements Technocore's documented payload exactly: `<room>|<nonce>|<normalized-text>`. Nonces are persisted per room, uncertain network outcomes are not retried automatically, and all local identity files are excluded from Git.

This project does not guarantee FLOP airdrop eligibility or allocation. Never submit wallet seeds, private keys, exchange credentials, or funds to a Technocore room.
