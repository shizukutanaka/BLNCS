# BLNCS Practical Improvements Backlog｜BLNCS 実用的改善バックログ

## Overview (English)

This backlog enumerates 500 actionable enhancements that elevate BLNCS to commercial and national-scale readiness. Items are grouped by domain and ranked with "safety → simplicity → impact" in mind.

## 概要 (日本語)

本バックログは BLNCS を市販レベル・国家レベルで運用しても問題のない品質へ高める 500 件の改善案です。領域ごとに整理し、「安全→簡単→高効果」の順に優先付けしています。

---

## Security Hardening｜セキュリティ強化 (1-100)

1. **[Harden API token storage｜APIトークン保護強化]** Salt and hash operator tokens in `blncs/core/simple_auth.py`, with rotation guidance in `docs/SECURITY_PRACTICES.md`. ／ `blncs/core/simple_auth.py` でトークンをソルト付きハッシュ化し、`docs/SECURITY_PRACTICES.md` にローテーション手順を明記します。
2. **[Enforce CLI token usage｜CLIトークン必須化]** Require `--auth-token` for destructive CLI actions, reusing the simple auth backend. ／ 破壊的 CLI 操作に `--auth-token` を必須化し、簡易認証バックエンドを共用します。
3. **[Mutual TLS deployment guide｜双方向TLS導入手順]** Document reverse proxy mTLS setup in `docs/DEPLOYMENT_GUIDE_UNIFIED.md`, including automated renewal scripts. ／ `docs/DEPLOYMENT_GUIDE_UNIFIED.md` に双方向 TLS 構築手順と証明書自動更新スクリプトを追記します。
4. **[Invoice payload validation｜インボイス入力検証]** Enforce schema checks via `blncs/core/data_validator.py` on `/api/lightning/invoice` requests. ／ `/api/lightning/invoice` で `blncs/core/data_validator.py` によるスキーマ検証を徹底します。
5. **[Security event tagging｜セキュリティイベントタグ付け]** Add authentication success/failure tagging with correlation IDs in `blncs/core/logger.py`. ／ `blncs/core/logger.py` に認証成功・失敗タグと相関 ID を記録します。
6. **[Route-specific rate limits｜ルート別レート制限]** Configure differentiated quotas per REST route inside `blncs/core/rate_limiter.py`. ／ `blncs/core/rate_limiter.py` でルート別の制限値を設定します。
7. **[401 anomaly alerts｜401異常通知]** Trigger alert hooks when multiple 401 responses occur within short intervals. ／ 短時間に 401 応答が続いた場合に警告フックを起動します。
8. **[Scoped access tokens｜トークンスコープ分離]** Introduce read-only and admin scopes in `config/blncs.json`. ／ `config/blncs.json` に閲覧用と管理用のスコープを追加します。
9. **[External secret files｜外部シークレット活用]** Allow referencing secure token files instead of embedding secrets in config. ／ 設定ファイルに秘密情報を埋め込まず、安全な外部ファイルを参照可能にします。
10. **[Environment override for tokens｜環境変数トークン上書き]** Prioritize `BLNCS_API_TOKEN` environment variable during startup. ／ 起動時に `BLNCS_API_TOKEN` を優先読み込みします。
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
27. **[Secure temp file usage｜安全な一時ファイル]** Ensure backup temp files auto-delete on close. ／ バックアップ一時ファイルをクローズ時に自動删除します。
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
51. **[Backup integrity verification｜バックアップ整合性検証]** Validate backup archives with SHA-256 manifests stored separately from payloads. ／ バックアップアーカイブを SHA-256 マニフェストで検証し、本体とは別に保管します。
52. **[Secrets access audit｜シークレットアクセス監査]** Log every access to credential files within `blncs/utils/simple_backup_recovery.py`. ／ `blncs/utils/simple_backup_recovery.py` 内で資格情報ファイルへのアクセスをすべて記録します。
53. **[Lightning RPC throttling｜Lightning RPCスロットリング]** Apply rate limits directly on Lightning RPC helpers to mitigate brute force attempts. ／ Lightning RPC ヘルパーにレート制限を適用し総当たり攻撃を抑止します。
54. **[Network segmentation guidance｜ネットワーク分離指針]** Document recommended VLAN or subnet layouts for BLNCS components. ／ BLNCS 各コンポーネントに適した VLAN／サブネット構成を文書化します。
55. **[Sensitive env var scrubbing｜機密環境変数除去]** Scrub sensitive environment variables from diagnostic outputs generated by `blncs/utils/system_info.py`. ／ `blncs/utils/system_info.py` が出力する診断情報から機密環境変数を除去します。
56. **[CLI dry-run safeguards｜CLIドライラン安全策]** Provide `--dry-run` for configuration-altering CLI commands to preview changes safely. ／ 設定変更 CLI コマンドに `--dry-run` を追加し、安全に事前確認できるようにします。
57. **[TLS renewal alarms｜TLS更新アラーム]** Schedule TLS certificate renewal reminders through `blncs/utils/maintenance_scheduler.py`. ／ `blncs/utils/maintenance_scheduler.py` で TLS 証明書更新リマインダーを登録します。
58. **[REST method consistency checks｜RESTメソッド整合性検証]** Ensure mutating endpoints reject GET requests even when misproxied. ／ プロキシ誤設定時でも変更系エンドポイントが GET を拒否するよう確認します。
59. **[Lightning invoice caps｜インボイス金額上限]** Enforce configurable invoice amount ceilings to constrain exposure. ／ 請求額の上限を設定可能にしリスクを抑えます。
60. **[Password complexity guidance｜パスワード複雑度ガイド]** Publish recommended entropy levels for operator credentials. ／ 運用者資格情報の推奨複雑度を提示します。
61. **[Token leak detection｜トークン漏洩検出]** Scan log buffers for leaked token patterns and alert operators. ／ ログバッファで漏洩トークンパターンを検査し運用者に警告します。
62. **[Lightning channel ACL guidance｜チャネルACL指針]** Document safe node and channel allowlists for production Lightning usage. ／ 本番 Lightning 運用向けのノード／チャネル許可リストを文書化します。
63. **[Secure mock defaults｜モック安全既定]** Ensure mock Lightning mode disables external networking by default. ／ モック Lightning モードで外部ネットワーク接続を既定で無効化します。
64. **[Tamper-evident logs｜改ざん検知ログ]** Chain log entries with hashes to highlight manipulation attempts. ／ ログエントリをハッシュ連結し改ざんを検知します。
65. **[Dual-operator approvals｜二重承認]** Require dual approvals for high-risk CLI tasks such as database resets. ／ データベース再初期化など高リスク CLI 操作に二重承認を要求します。
66. **[Lightning key rotation policy｜Lightning鍵ローテーション方針]** Document procedures for rotating Lightning macaroons and certificates. ／ Lightning マカロンと証明書をローテーションする手順を整備します。
67. **[Signed config export｜署名付き設定エクスポート]** Provide signed export and import commands for `config/blncs.json`. ／ `config/blncs.json` の署名付きエクスポート／インポートコマンドを提供します。
68. **[Signed pagination tokens｜署名付きページネーション]** Sign pagination tokens to prevent tampering between requests. ／ ページネーションのトークンに署名を施し改ざんを防ぎます。
69. **[CLI privilege warnings｜CLI特権警告]** Detect unnecessary root execution and warn operators. ／ 不要な root 実行を検知し運用者に警告します。
70. **[Secure webhook retries｜安全なWebhook再試行]** Randomize retry intervals and cap attempts for outbound webhooks. ／ 外向き Webhook の再試行間隔をランダム化し回数に上限を設けます。
71. **[Lightning fee policy controls｜手数料ポリシー制御]** Enforce fee policy thresholds via configuration validation. ／ 手数料ポリシーの閾値を設定し構成検証で強制します。
72. **[Operator role separation｜運用者役割分離]** Create distinct CLI profiles for monitoring versus maintenance duties. ／ 監視用と保守用の CLI プロファイルを分離します。
73. **[Encrypted crash diagnostics｜暗号化クラッシュ診断]** Encrypt crash dump files before writing to disk. ／ クラッシュデータをディスクに保存する前に暗号化します。
74. **[REST response size caps｜レスポンスサイズ上限]** Cap REST payload sizes to reduce exfiltration risk. ／ REST 応答サイズに上限を設け情報流出リスクを下げます。
75. **[Security banner prompts｜セキュリティバナー表示]** Display authorized-use warnings on CLI startup and GUI login. ／ CLI 起動時と GUI ログイン時に認可利用警告を表示します。
76. **[Lightning fingerprint pinning｜Lightning指紋固定]** Pin TLS fingerprints for trusted Lightning nodes. ／ 信頼済み Lightning ノードの TLS 指紋を固定します。
77. **[Fail2ban integration templates｜fail2ban統合テンプレ]** Supply sample fail2ban rules for REST API and SSH log patterns. ／ REST API と SSH ログ向け fail2ban ルール例を提供します。
78. **[Sensitive metrics segregation｜機密メトリクス分離]** Serve sensitive metrics from dedicated authenticated endpoints. ／ 機密メトリクスを専用認証済みエンドポイントから提供します。
79. **[Lightning node health verification｜ノード健全性確認]** Check remote node status before processing invoices. ／ インボイス処理前にリモートノードの健全性を確認します。
80. **[Geo-IP alerting｜Geo-IP警告]** Alert on API access from unexpected geographic regions. ／ 想定外地域からの API アクセスに警告を発します。
81. **[Security documentation index｜セキュリティ文書索引]** Build an index aggregating all security guides for quick reference. ／ セキュリティ関連文書を一覧化した索引を作成します。
82. **[Lightning RPC sandbox tests｜RPCサンドボックステスト]** Execute Lightning RPC integration tests inside restricted containers. ／ Lightning RPC 統合テストを制限付きコンテナで実行します。
83. **[Time-based access windows｜時間制限アクセス]** Permit privileged operations only during configured maintenance windows. ／ 特権操作を設定した保守時間のみ許可します。
84. **[REST IP allowlists｜REST IP許可リスト]** Support static allowlists for REST endpoints in `config/blncs.json`. ／ `config/blncs.json` で REST エンドポイントの IP 許可リストを設定します。
