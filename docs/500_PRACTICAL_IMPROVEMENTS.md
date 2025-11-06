# BLNCS Practical Improvements Backlog｜BLNCS 実用的改善バックログ

## Overview (English)

This backlog enumerates 500 actionable enhancements that elevate BLNCS to commercial and national-scale readiness. Items are grouped by domain and ranked with "safety → simplicity → impact" in mind.

## 概要 (日本語)

本バックログは BLNCS を市販レベル・国家レベルで運用しても問題のない品質へ高める 500 件の改善案です。領域ごとに整理し、「安全→簡単→高効果」の順に優先付けしています。

---

## Security Hardening｜セキュリティ強化 (1-100)

1. **[Harden API token storage｜APIトークン保護強化]** Salt and hash operator tokens in `blncs/core/simple_auth.py`, with rotation guidance in `docs/SECURITY_PRACTICES.md`. ／ `blncs/core/simple_auth.py` でトークンをソルト付きハッシュ化し、`docs/SECURITY_PRACTICES.md` にローテーション手順を明記します。
   - Implementation date: 2025年9月27日。`AuthToken` は PBKDF2-HMAC-SHA256 によるハッシュ化保存へ移行し、`SimpleAuth.rotate_api_key()` により安全なローテーションを提供します。`tests/unit/test_simple_auth.py` でハッシュ整合性と権限検証を自動テストしています。
2. **[Enforce CLI token usage｜CLIトークン必須化]** Require `--auth-token` for destructive CLI actions, reusing the simple auth backend. ／ 破壊的 CLI 操作に `--auth-token` を必須化し、簡易認証バックエンドを共用します。
   - Implementation date: 2025年9月29日。`SimpleAuth` が `BLNCS_CLI_TOKEN` 環境変数を読み込み、権限と有効期限を持つ CLI 用トークンとして保存・更新します。CLI 実行時は `BLNCS_CLI_TOKEN_*` 系の環境設定が優先され、`tests/unit/test_simple_auth.py` で読み込みと更新の自動テストを追加しました。
3. **[Mutual TLS deployment guide｜双方向TLS導入手順]** Document reverse proxy mTLS setup in `docs/DEPLOYMENT_GUIDE_UNIFIED.md`, including automated renewal scripts. ／ `docs/DEPLOYMENT_GUIDE_UNIFIED.md` に双方向 TLS 構築手順と証明書自動更新スクリプトを追記します。
4. **[Invoice payload validation｜インボイス入力検証]** Enforce schema checks via `blncs/core/data_validator.py` on `/api/lightning/invoice` requests. ／ `/api/lightning/invoice` で `blncs/core/data_validator.py` によるスキーマ検証を徹底します。
5. **[Security event tagging｜セキュリティイベントタグ付け]** Add authentication success/failure tagging with correlation IDs in `blncs/core/logger.py`. ／ `blncs/core/logger.py` に認証成功・失敗タグと相関 ID を記録します。
   - Implementation date: 2025年9月29日。`SimpleAuth` が認証成功・失敗・レート制限ログへ `correlation_id` を含め、`X-Request-ID`／`X-Correlation-ID` ヘッダや自動生成値を記録するよう更新しました。`tests/unit/test_simple_auth.py` にメタデータ抽出とコリレーション ID を検証するテストを追加済みです。
6. **[Route-specific rate limits｜ルート別レート制限]** Configure differentiated quotas per REST route inside `blncs/core/rate_limiter.py`. ／ `blncs/core/rate_limiter.py` でルート別の制限値を設定します。
7. **[401 anomaly alerts｜401異常通知]** Trigger alert hooks when multiple 401 responses occur within short intervals. ／ 短時間に 401 応答が続いた場合に警告フックを起動します。
8. **[Scoped access tokens｜トークンスコープ分離]** Introduce read-only and admin scopes in `config/blncs.json`. ／ `config/blncs.json` に閲覧用と管理用のスコープを追加します。
9. **[External secret files｜外部シークレット活用]** Allow referencing secure token files instead of embedding secrets in config. ／ 設定ファイルに秘密情報を埋め込まず、安全な外部ファイルを参照可能にします。
10. **[Environment override for tokens｜環境変数トークン上書き]** Prioritize `BLNCS_API_TOKEN` environment variable during startup. ／ 起動時に `BLNCS_API_TOKEN` を優先読み込みします。
   - Implementation date: 2025年9月29日。`SimpleAuth` が `BLNCS_API_TOKEN` と関連メタデータ（`BLNCS_API_TOKEN_ID`、`BLNCS_API_TOKEN_PERMISSIONS`、`BLNCS_API_TOKEN_TTL`、`BLNCS_API_TOKEN_EXPIRES_AT`）を読み込み、ハッシュ化したトークンとして保存します。既存トークンがある場合は権限と期限を更新し、環境設定済みの API キーが確実に優先されます。
11. **[Webhook HMAC signing｜Webhook HMAC署名]** Sign outbound notifications from `blncs/api/websocket_server.py` with shared secrets. ／ `blncs/api/websocket_server.py` の通知に共有鍵 HMAC 署名を付与します。
12. **[Encrypted audit trail｜監査ログ暗号化]** Persist security events inside encrypted SQLite tables via `blncs/core/unified_core.py`. ／ `blncs/core/unified_core.py` を通じて暗号化 SQLite に監査イベントを保存します。
13. **[Configuration checksum validation｜設定チェックサム検証]** Compute SHA-256 digests of `config/blncs.json` on load to detect tampering. ／ 読み込み時に `config/blncs.json` を SHA-256 で検証し改ざんを検出します。
14. **[Lightning credential validation｜Lightning資格情報検証]** Validate macaroon and certificate paths before client instantiation. ／ Lightning クライアント生成前にマカロン／証明書パスを検証します。
15. **[Restrict static asset serving｜静的アセット制限]** Limit Flask static serving to whitelisted directories. ／ Flask の静的配信ディレクトリをホワイトリスト化します。
16. **[Secure HTTP headers｜セキュアHTTPヘッダ]** Apply HSTS, CSP, and X-Frame-Options via middleware. ／ ミドルウェアで HSTS・CSP・X-Frame-Options を付与します。
17. **[OpenAPI hardening｜OpenAPI強化]** Publish sanitized schemas marking sensitive fields as read-only. ／ 機密フィールドを read-only 指定した OpenAPI スキーマを公開します。
18. **[Token expiry policy｜トークン期限ポリシー]** Add configurable expiration timestamps within `simple_auth`. ／ `simple_auth` に有効期限設定を導入します。
19. **[Automation whitelist｜自動化ホワイトリスト]** Restrict automation mode to safe CLI subcommands. ／ 自動化モードで利用できる CLI コマンドを制限します。
20. **[Encrypt backup manifests｜バックアップ目録暗号化]** Encrypt manifests emitted by `simple_backup_recovery.AutoBackup`. ／ `simple_backup_recovery.AutoBackup` の目録を暗号化します。
21. **[Credential rotation scheduler｜資格情報更新スケジューラ]** Schedule rotation reminders in `maintenance_scheduler.py`. ／ `maintenance_scheduler.py` で資格情報更新を定期通知します。
22. **[Log redaction filters｜ログマスクフィルタ]** Mask token-like strings before writing logs. ／ ログ書き込み前にトークンらしき文字列をマスクします。
23. **[Silent secret prompts｜秘密入力非表示]** Use `getpass` for any secret prompts in CLI workflows. ／ CLI の秘密入力を `getpass` で非表示化します。
24. **[Token freeze command｜トークン凍結コマンド]** Provide `blncs_main.py security lock` to disable compromised tokens. ／ `blncs_main.py security lock` で漏洩トークンを即時停止します。
25. **[Encrypt IPC payloads｜IPC暗号化]** Encrypt local IPC messages when optional dependencies are available. ／ オプション依存が存在する場合に IPC メッセージを暗号化します。
26. **[Lightning node allowlist｜Lightningノード許可リスト]** Enforce allowlisted node IDs before establishing connections. ／ 接続前にノード ID を許可リストで確認します。
27. **[Secure temp file usage｜安全な一時ファイル]** Ensure backup temp files auto-delete on close. ／ バックアップ一時ファイルをクローズ時に自動削除します。
28. **[Dependency hash verification｜依存関係ハッシュ検証]** Document pip hash checking for production installs. ／ 本番導入時の pip ハッシュ検証手順を文書化します。
29. **[Daily CVE scanning｜日次CVEスキャン]** Add scheduled `pip-audit` runs via `maintenance_scheduler.py`. ／ `maintenance_scheduler.py` に日次 `pip-audit` を組み込みます。
30. **[Outbound HTTP toggle｜外向きHTTP無効化]** Provide config flag to disable external HTTP requests in GUI helpers. ／ GUI ヘルパーの外部 HTTP 呼び出しを設定で禁止します。
31. **[Replay protection headers｜リプレイ防止ヘッダ]** Require timestamp headers for mutating REST calls and reject stale requests. ／ 変更系 REST 呼び出しにタイムスタンプヘッダを必須化し期限切れを拒否します。
32. **[Operator MFA guidance｜運用MFAガイド]** Document hardware OTP integration options. ／ ハードウェア OTP 連携手順を記載します。
33. **[GUI token warnings｜GUIトークン警告]** Display warnings when storing plaintext tokens in GUI profiles. ／ GUI プロファイルに平文トークンを保存する際に警告します。
34. **[SSH bastion templates｜SSH踏み台テンプレート]** Publish SSH tunneling examples for secure REST access. ／ 安全な REST アクセス用の SSH トンネリング例を公開します。
35. **[Token usage analytics｜トークン利用分析]** Expose token usage counters via `/api/security/tokens`. ／ `/api/security/tokens` でトークン利用回数を可視化します。
36. **[Mock isolation defaults｜モック隔離既定]** Prevent mock Lightning clients from reading production macaroon paths. ／ モック Lightning クライアントが本番マカロンを読み取れないよう既定化します。
37. **[Config drift detection｜設定ドリフト検知]** Compare in-memory and on-disk config during startup. ／ 起動時にメモリ上とディスク上の設定を比較します。
38. **[TLS cipher guidance｜TLS暗号スイート指針]** Provide recommended cipher suites in deployment docs. ／ デプロイ文書に推奨暗号スイートを掲載します。
39. **[Macaroon scope audit｜マカロンスコープ監査]** Validate that macaroons use minimum privileges before Lightning calls. ／ Lightning 呼び出し前にマカロンの最小権限を確認します。
40. **[Preimage masking｜プリイメージ隠蔽]** Mask invoice preimages in CLI outputs and API responses. ／ CLI 出力と API 応答でインボイスプリイメージを隠蔽します。
41. **[WebSocket origin whitelist｜WebSocketオリジン制御]** Enforce origin whitelists before upgrading to WebSocket. ／ WebSocket へのアップグレード前にオリジンホワイトリストを検証します。
42. **[Firewall cookbook｜ファイアウォール手引き]** Provide ufw/nftables templates for BLNCS roles. ／ BLNCS 向けの ufw/nftables テンプレートを提供します。
43. **[Encrypted backups｜暗号化バックアップ]** Offer AES-encrypted archives when `cryptography` is installed. ／ `cryptography` 利用時に AES 暗号化されたバックアップを提供します。
44. **[Invoice nonce checks｜インボイスノンス検証]** Add nonce challenge for invoice payment endpoints. ／ インボイス支払いエンドポイントにノンス確認を追加します。
45. **[Signed metrics payloads｜署名付きメトリクス]** Sign outbound metrics payloads for remote collectors. ／ リモート収集向けメトリクスに署名を付与します。
46. **[Offline token provisioning｜オフライン発行]** Allow token generation without network access via CLI. ／ ネットワーク不要でトークンを生成できる CLI を提供します。
47. **[Security regression tests｜セキュリティ回帰テスト]** Add pytest suites covering token expiry and replay protection. ／ トークン期限・リプレイ防止を検証する pytest を追加します。
48. **[Memo sanitizer｜メモサニタイズ]** Strip unsafe characters from Lightning invoice memos. ／ Lightning インボイスのメモから危険な文字を除去します。
49. **[Sensitive cache purge｜機密キャッシュ削除]** Purge sensitive caches during `resource_manager.shutdown_all()`. ／ `resource_manager.shutdown_all()` で機密キャッシュを確実に削除します。
50. **[Operator security checklist｜運用セキュリティチェック]** Append a checklist to `docs/Implementation_Status.md` summarizing required hardening steps. ／ `docs/Implementation_Status.md` にハードニング手順チェックリストを追加します。