# BLNCS Quick Start Guide

## Overview (English)

This quick start covers the minimal steps required to evaluate BLNCS on a local workstation. The CLI entry point is `blncs_main.py`, which automatically provisions the default configuration at `config/blncs.json`.

## 概要 (日本語)

本ガイドはローカル環境で BLNCS を評価するための最低限の手順を説明します。CLI のエントリーポイントは `blncs_main.py` であり、初回実行時に `config/blncs.json` を自動生成します。

---

## Prerequisites｜前提条件

- Python 3.10 以上を推奨
- Git
- Lightning ノード接続は任意（モックモードで評価可能）

---

## Installation｜インストール

```bash
git clone <your-repository-url>
cd BLNCS
python -m venv .venv
. .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

開発用途の場合は `pip install -r requirements-dev.txt` を追加してください。

---

## First run｜初回実行

```bash
# Generate template if config is missing
python blncs_main.py config --template

# Inspect health and status
python blncs_main.py status
python blncs_main.py health

# Launch REST API server (development mode)
python blncs_main.py server
```

設定ファイル `config/blncs.json` には SQLite とモック Lightning クライアント向けの初期値が含まれます。`lightning.node_url` や `database.path` を環境に合わせて変更してください。

---

## Everyday commands｜日常的に利用するコマンド

```bash
# Show combined system information
python blncs_main.py info

# Manage configuration entries
python blncs_main.py config --get api.port
python blncs_main.py config --set api.port 9001

# Validate configuration file
python blncs_main.py validate --config config/blncs.json

# Lightning helpers (mock-friendly)
python blncs_main.py connect --host localhost --port 10009
python blncs_main.py invoice --amount 500 --memo "Demo" --qr
python blncs_main.py decode lnbc1000n1ps...

# Security helpers
python blncs_main.py security --show-auth-limits
python blncs_main.py security --set-auth-limits 5 120
python blncs_main.py security --reset-auth-failures
```

---

## Testing｜テスト

```bash
# Run targeted diagnostics
python blncs/utils/system_info.py --json --sections system,cpu

# Execute full test suite (may take longer)
python -m pytest
```

---

## Troubleshooting｜トラブルシューティング

**依存関係不足**
```bash
pip install -r requirements.txt
```

**Lightning ノードに接続できない**
```bash
python blncs_main.py connect --host <node-host> --port 10009
```

**設定を初期化したい**
```bash
rm -f config/blncs.json
python blncs_main.py config --template
```

**ログを確認したい**
```bash
python blncs_main.py logs --action view --lines 100
```

---

## Next steps｜次のステップ

- `docs/API_REFERENCE_UNIFIED.md` で REST API を確認
- `docs/DEPLOYMENT_GUIDE_UNIFIED.md` で本番運用に向けた構成を検討
- `docs/README_UNIFIED.md` で全体像を復習

改善点やバグがあれば Issue を作成し、再現手順と使用環境（Python バージョン、OS、Lightning 実装）を添えてください。