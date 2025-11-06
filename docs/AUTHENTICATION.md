# Authentication Operations Guide / 認証運用ガイド

## English

### Scope
This document explains how to manage API authentication for BLNCS using the `SimpleAuth` module and the CLI entry point `blncs_fast.py`. It covers token creation, inspection, revocation, and storage layout.

### Components
- `blncs/core/simple_auth.py`: File-backed API key manager (`SimpleAuth`).
- `blncs_fast.py`: CLI entry point with `auth` subcommands.
- `config/auth.json`: Default token storage (can be overridden per command).

### CLI Usage
```bash
python blncs_fast.py auth list
python blncs_fast.py auth create operator --permissions read,write --expires-in 3600
python blncs_fast.py auth show operator
python blncs_fast.py auth rotate --token-id operator --expires-in 600
python blncs_fast.py auth revoke operator
python blncs_fast.py auth audit --log-file logs/blncs.log --limit 20
```

| Subcommand | Description |
| --- | --- |
| `list` | Outputs a JSON array of stored tokens without secret material. |
| `create` | Generates or replaces a token. Optional flags: `--permissions`, `--expires-in`, `--expires-at`, `--auth-file`. |
| `show` | Prints a single token summary by `token_id` without secret material. |
| `rotate` | Issues a new secret for an existing token. Accepts `--token-id` or `--api-key` plus optional expiry/permissions. |
| `revoke` | Removes a token by identifier or plaintext key. |
| `audit` | Reads the latest `AUTH_KEY_*` entries from a log file (default `logs/blncs.log`). |

### Permissions
`SimpleAuth` supports `read`, `write`, and `admin`. Omitted values fall back to defaults (`read` enabled, others disabled).

### Expiration
- `--expires-in <seconds>` sets a relative expiry window.
- `--expires-at <epoch or ISO-8601>` sets an absolute expiry.
- Tokens without expiration stay valid until revoked.

### Storage Notes
- Token metadata is stored under `config/auth.json` by default.
- Use `--auth-file <path>` to target a specific storage file.
- Generated API keys are printed once; store them securely.

### Environment Overrides
`SimpleAuth` reads environment variables on startup (`BLNCS_API_TOKEN*`, `BLNCS_CLI_TOKEN*`). These entries are hashed into storage automatically.

### Operational Checklist
1. Create a dedicated token for each integration.
2. Record the plaintext key in a secure secret manager.
3. Schedule periodic reviews with `auth list`.
4. Revoke unused or compromised tokens immediately.
5. Monitor application logs (`blncs.auth`) for `AUTH_KEY_*` events to audit lifecycle operations.

## 日本語

### 対象範囲
本資料は、`SimpleAuth` モジュールと CLI エントリ `blncs_fast.py` を利用した BLNCS の API 認証管理手順を説明します。トークンの発行、確認、失効、保管先構造を含みます。

### 主な構成
- `blncs/core/simple_auth.py`: ファイル保存型 API キーマネージャ (`SimpleAuth`).
- `blncs_fast.py`: `auth` サブコマンドを備えた CLI エントリポイント。
- `config/auth.json`: デフォルトのトークン保存先（コマンドごとに上書き可能）。

### CLI 利用例
```bash
python blncs_fast.py auth list
python blncs_fast.py auth create operator --permissions read,write --expires-in 3600
python blncs_fast.py auth show operator
python blncs_fast.py auth rotate --token-id operator --expires-in 600
python blncs_fast.py auth revoke operator
python blncs_fast.py auth audit --log-file logs/blncs.log --limit 20
```

| サブコマンド | 説明 |
| --- | --- |
| `list` | 秘密情報を含まないトークン一覧を JSON 配列で出力します。|
| `create` | トークンを新規発行または再発行します。オプション: `--permissions`, `--expires-in`, `--expires-at`, `--auth-file`. |
| `show` | `token_id` を指定してトークン詳細を表示します（秘密情報は含まれません）。|
| `rotate` | 既存トークンの秘密値を再発行します。`--token-id` または `--api-key` と期限/権限オプションを指定可能。|
| `revoke` | 識別子または平文キーを指定してトークンを削除します。|
| `audit` | `logs/blncs.log` などのログから `AUTH_KEY_*` イベントを抽出します。|

### 権限設定
サポートされる権限は `read`, `write`, `admin` です。未指定の権限はデフォルト値（`read` 有効、それ以外は無効）が適用されます。

### 期限設定
- `--expires-in <秒>` で相対的な有効期限を指定します。
- `--expires-at <エポック秒または ISO-8601>` で絶対的な期限を指定します。
- 期限未設定のトークンは失効操作を行うまで有効です。

### 保存先
- 既定の保存先は `config/auth.json` です。
- `--auth-file <パス>` を利用すると保存先を個別に選択できます。
- 生成した API キーは発行時に一度だけ表示されるため、安全な場所に控えを保管してください。

### 環境変数の適用
`SimpleAuth` は起動時に `BLNCS_API_TOKEN*`, `BLNCS_CLI_TOKEN*` 系の環境変数を読み込み、ハッシュ化して保存します。

### 運用チェックリスト
1. 連携先ごとに専用トークンを発行する。
2. 平文キーは秘密管理ツールなど安全な場所へ保管する。
3. `auth list` で定期的に状況を確認する。
4. 未使用または危険性のあるトークンは速やかに `auth revoke` で失効させる。
5. `blncs.auth` ログで `AUTH_KEY_*` イベントを確認し、ライフサイクル操作を監査する。
