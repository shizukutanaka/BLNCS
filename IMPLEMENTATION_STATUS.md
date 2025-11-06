# BLNCS Implementation Status (archived)｜BLNCS 実装状況レポート（アーカイブ）

**English:** This archived status report now summarizes the lightweight improvements currently maintained in the repository. For detailed usage guidance, refer to:

- `docs/README_UNIFIED.md`
- `docs/DEPLOYMENT_GUIDE_UNIFIED.md`
- `docs/API_REFERENCE_UNIFIED.md`

**日本語:** 本レポートはアーカイブ扱いですが、現行リポジトリに存在する軽量機能の概要を以下に整理しています。詳細手順は次のドキュメントをご確認ください。

- `docs/README_UNIFIED.md`
- `docs/DEPLOYMENT_GUIDE_UNIFIED.md`
- `docs/API_REFERENCE_UNIFIED.md`

---

## Current Highlights｜現行ハイライト

- `blncs/core/fast_startup.py` で遅延インポートと `PerformanceOptimizer` による軽量チューニングを提供します。
- `blncs/core/lightweight_metrics.py` は `SystemMetricsCollector` を通じて CPU/メモリ/GC カウントを低オーバーヘッドで取得します。
- `blncs/core/resource_manager.py` がスレッドやコネクションを協調的にクリーンアップします。
- `blncs/api/unified_rest_api.py` が `/health` と `/api/system/optimize` などの REST エンドポイントを提供し、`PerformanceOptimizer.apply_all_optimizations()` を呼び出します。
- `blncs/utils/simple_backup_recovery.py` の `AutoBackup` は停止要求に即応する `threading.Event` 制御を備えています。
- CLI エントリポイント `blncs_main.py` が設定テンプレート生成とステータス/バックアップ操作を一元化します。

---

## Verification Snapshot｜検証状況

- **Metrics & Monitoring｜メトリクス**: `/api/system/metrics` と CLI `info --stats` が `SystemMetricsCollector` と整合します。
- **バックアップ**: `AutoBackup` の停止応答とフルバックアップ処理は軽量スレッド制御で確認済みです。
- **GUI**: `tests/unit/test_dashboard_gui.py` と `tests/unit/test_net_utils.py` がプロキシ制御と再接続処理を継続検証します。
- **REST コントラクト**: `tests/test_unified_comprehensive.py` で設定優先順位と API 基本機能を確認できます。

---

## Maintenance Notes｜保守メモ

- **Logging｜ログ**: `blncs/core/logger.py` が軽量なリングバッファを提供し、ファイル出力設定は `config/blncs.json` の `logging` セクションで調整します。
- **Future Work｜今後の課題**: 未使用モジュールの整理、Lightning クライアントの追加バックエンド検討、GUI 診断機能の拡充を想定しています。

---

## Operator Security Checklist｜運用セキュリティチェックリスト

- **[Token hygiene｜トークン衛生]** `blncs_main.py` の特権サブコマンド実行時は `--auth-token` または `BLNCS_CLI_TOKEN` を必ず利用し、`config/auth.json.sha256` と整合することを確認します。
- **[Configuration integrity｜設定整合性]** `config/blncs.json` と `config/blncs.json.sha256` のチェックサム一致を確認し、`blncs_main.py` 実行時に表示される警告がないことを保証します。
- **[REST payload validation｜REST ペイロード検証]** `blncs/api/unified_rest_api.py` の Lightning 請求書 API は `DataValidator` により厳格化されています。クライアント実裝は必須フィールドを満たし不正値を送らないよう調整します。
- **[Audit readiness｜監査対応]** `logs/` ディレクトリに格納された JSON 形式の操作ログを日次で保管し、設定変更・CLI 実行時の記録を保持します。
- **[Backup key rotation｜バックアップ鍵の更新]** `blncs/core/simple_auth.py` の `rotate_api_key()` を運用スケジュールに組み込み、少なくとも四半期ごとに新しい API キーへ切り替えます。

各項目は英語・日本語を併記しており、運用チームと開発チームの双方が同一ドキュメントで手順を共有できます。

---