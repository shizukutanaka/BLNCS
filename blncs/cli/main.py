#!/usr/bin/env python3
"""
BLNCS - Bitcoin Lightning Network Control System
Simple, practical Lightning Network management tool.
"""

import sys
import click
from typing import Optional, Dict, Any

# Lazy imports for faster CLI startup
def get_lightning_client(config: Dict[str, Any]):
    """Lazy import and create Lightning client"""
    from blncs.lightning.client import LightningClient
    return LightningClient(config)

def get_exceptions():
    """Lazy import exceptions"""
    from blncs.core.exceptions import (
        BLNCSError, ConnectionError, LightningError, ConfigError, 
        ValidationError, PaymentError, ChannelError, SecurityError,
        format_error_for_cli, handle_error
    )
    return {
        'BLNCSError': BLNCSError,
        'ConnectionError': ConnectionError,
        'LightningError': LightningError,
        'format_error_for_cli': format_error_for_cli
    }

def get_command_modules():
    """Lazy import command modules"""
    from .commands import (
        info, balance, channels, network_test, lightning_ping, system_info,
        analyze_channels, connectivity_check, fee_estimate, payment_debug, channel_summary,
        config_management, config_get, config_set, config_list, env_template, liquidity
    )
    return {
        'info': info, 'balance': balance, 'channels': channels, 
        'network_test': network_test, 'lightning_ping': lightning_ping,
        'system_info': system_info, 'analyze_channels': analyze_channels,
        'connectivity_check': connectivity_check, 'fee_estimate': fee_estimate,
        'payment_debug': payment_debug, 'channel_summary': channel_summary,
        'config_management': config_management, 'config_get': config_get,
        'config_set': config_set, 'config_list': config_list,
        'env_template': env_template, 'liquidity': liquidity
    }


def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """Load configuration using unified config system"""
    config_manager = get_config_manager()
    return config_manager.get_all()


@click.group()
@click.option('--config', '-c', type=click.Path(exists=True), help='設定ファイルパス')
@click.option('--verbose', '-v', is_flag=True, help='詳細出力モード')
@click.option('--quiet', '-q', is_flag=True, help='静寂モード（エラーのみ表示）')
@click.pass_context
def cli(ctx: click.Context, config: str, verbose: bool, quiet: bool) -> None:
    """
    BLNCS - Bitcoin Lightning Network Control System

    Lightweight and practical Lightning Network management tool

    Common commands:
        python -m blncs.cli.main status # System status check
        python -m blncs.cli.main info # Node information
        python -m blncs.cli.main balance # Balance check
        python -m blncs.cli.main health --quick # Quick diagnosis

    First time usage:
        python -m blncs.cli.main setup # Initial setup
    """
    ctx.ensure_object(dict)
    
    # Lazy configuration loading
    config_data = load_config(config)
    ctx.obj['config'] = config_data
    ctx.obj['verbose'] = verbose
    ctx.obj['quiet'] = quiet
    
    # Lightning client created on demand
    ctx.obj['_client'] = None

def get_client(ctx):
    """Get or create Lightning client on demand"""
    if ctx.obj['_client'] is None:
        ctx.obj['_client'] = get_lightning_client(ctx.obj['config'])
    return ctx.obj['_client']


# info command moved to commands/info_commands.py


# balance command moved to commands/info_commands.py


# channels command moved to commands/channel_commands.py

# Dynamic command registration for faster startup
def register_commands():
    """Register CLI commands dynamically"""
    commands = get_command_modules()
    
    # Core commands
    cli.add_command(commands['info'])
    cli.add_command(commands['balance'])
    cli.add_command(commands['channels'])
    
    # Network commands
    cli.add_command(commands['network_test'])
    cli.add_command(commands['lightning_ping'])
    cli.add_command(commands['system_info'])
    
    # Management commands
    cli.add_command(commands['analyze_channels'])
    cli.add_command(commands['connectivity_check'])
    cli.add_command(commands['fee_estimate'])
    cli.add_command(commands['payment_debug'])
    cli.add_command(commands['channel_summary'])
    
    # Configuration commands
    cli.add_command(commands['config_management'])
    cli.add_command(commands['config_get'])
    cli.add_command(commands['config_set'])
    cli.add_command(commands['config_list'])
    cli.add_command(commands['env_template'])
    
    # Liquidity commands
    cli.add_command(commands['liquidity'])


@cli.command()
@click.argument('node_pubkey')
@click.argument('amount', type=int)
@click.pass_context
def open_channel(ctx: click.Context, node_pubkey: str, amount: int) -> None:
    """Open a new channel"""
    exceptions = get_exceptions()
    client = get_client(ctx)
    try:
        client.connect()
        channel_id = client.open_channel(node_pubkey, amount)
        click.echo(f"Channel opened: {channel_id}")
    except (exceptions['ConnectionError'], exceptions['BLNCSError'], exceptions['LightningError']) as e:
        click.echo(exceptions['format_error_for_cli'](e), err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"[ERROR] Unexpected error: {str(e)}", err=True)
        sys.exit(1)
    finally:
        client.disconnect()


@cli.command()
@click.argument('channel_id')
@click.option('--force', is_flag=True, help='Force close channel')
@click.pass_context
def close_channel(ctx, channel_id, force):
    """Close a channel"""
    client = ctx.obj['client']
    try:
        client.connect()
        if client.close_channel(channel_id, force):
            click.echo(f"Channel {channel_id} closed")
        else:
            click.echo(f"Failed to close channel {channel_id}")
    except (ConnectionError, BLNCSError, LightningError) as e:
        click.echo(format_error_for_cli(e), err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"[ERROR] 予期しないエラー: {str(e)}", err=True)
        sys.exit(1)
    finally:
        client.disconnect()


@cli.command()
@click.argument('invoice')
@click.pass_context
def pay(ctx, invoice):
    """Pay a Lightning invoice"""
    client = ctx.obj['client']
    try:
        client.connect()
        result = client.send_payment(invoice)
        click.echo(f"Payment sent:")
        click.echo(f" Hash: {result['payment_hash']}")
        click.echo(f" Amount: {result['amount']} sats")
        click.echo(f" Status: {result['status']}")
    except (ConnectionError, BLNCSError, LightningError) as e:
        click.echo(format_error_for_cli(e), err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"[ERROR] 予期しないエラー: {str(e)}", err=True)
        sys.exit(1)
    finally:
        client.disconnect()


@cli.command()
@click.argument('amount', type=int)
@click.option('--memo', '-m', default='', help='Invoice memo')
@click.option('--qr', is_flag=True, help='Generate QR code')
@click.pass_context
def invoice(ctx, amount, memo, qr):
    """Create a Lightning invoice"""
    client = ctx.obj['client']
    try:
        client.connect()
        invoice = client.create_invoice(amount, memo)
        click.echo(f"Invoice created:")
        click.echo(f" {invoice}")

        if qr:
            click.echo("\nQR Code:")
            qr_code = generate_invoice_qr(invoice, save_to_file=False)
            click.echo(qr_code)
    except (ConnectionError, BLNCSError, LightningError) as e:
        click.echo(format_error_for_cli(e), err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"[ERROR] 予期しないエラー: {str(e)}", err=True)
        sys.exit(1)
    finally:
        client.disconnect()


@cli.command()
def setup():
    """Initialize BLNCS configuration and directories"""
    click.echo("BLNCS セットアップを開始します...")

    try:
        result = run_full_setup()

        if result.get('created_dirs'):
            click.echo(f"作成されたディレクトリ: {', '.join(result['created_dirs'])}")

        if result.get('config_file'):
            click.echo(f"設定ファイル: {result['config_file']}")

        if result.get('env_suggestions'):
            click.echo("\n環境変数の設定を推奨:")
            for suggestion in result['env_suggestions']:
                click.echo(f" {suggestion}")

        validation = result.get('validation', {})
        if validation:
            click.echo("\nセットアップ状況:")
            for item, status in validation.items():
                status_icon = "[OK]" if status else "[ERROR]"
                click.echo(f" {status_icon} {item}")

        if result.get('success'):
            click.echo("\n[OK] セットアップが完了しました!")
        else:
            click.echo("\n[WARNING] セットアップに問題があります。上記を確認してください。")
            if result.get('error'):
                click.echo(f"エラー: {result['error']}")

    except BLNCSError as e:
        click.echo(format_error_for_cli(e), err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"[ERROR] セットアップエラー: {str(e)}", err=True)
        sys.exit(1)


@cli.command()
def status():
    """Show BLNCS system status"""
    try:
        validation = validate_setup()

        click.echo("BLNCS システム状況:")
        for item, status in validation.items():
            status_icon = "[OK]" if status else "[ERROR]"
            click.echo(f" {status_icon} {item}")

        all_good = all(validation.values())
        if all_good:
            click.echo("\n[OK] すべて正常です")
        else:
            click.echo("\n[WARNING] 問題があります。'blncs_cli.py setup' を実行してください。")

    except BLNCSError as e:
        click.echo(format_error_for_cli(e), err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"[ERROR] ステータスチェックエラー: {str(e)}", err=True)
        sys.exit(1)


@cli.command()
@click.option('--limit', '-l', default=10, help='表示する履歴の件数')
@click.option('--type', '-t', help='特定のトランザクションタイプのみ表示')
def history(limit, type):
    """Show transaction history"""
    try:
        hist = get_history()

        if type:
            transactions = hist.get_transactions_by_type(type, limit)
            click.echo(f"履歴 (タイプ: {type}, 最新{limit}件):")
        else:
            transactions = hist.get_recent_transactions(limit)
            click.echo(f"履歴 (最新{limit}件):")

        if not transactions:
            click.echo("履歴がありません")
            return

        for i, tx in enumerate(transactions, 1):
            timestamp = tx.get('timestamp', 'N/A')
            tx_type = tx.get('type', 'unknown')
            data = tx.get('data', {})

            click.echo(f"\n{i}. [{tx_type}] {timestamp}")

            # データの表示を簡潔にする
            if 'amount' in data:
                click.echo(f" 金額: {data['amount']} sats")
            if 'memo' in data and data['memo']:
                click.echo(f" メモ: {data['memo']}")
            if 'success' in data:
                status = "[OK] 成功" if data['success'] else "[ERROR] 失敗"
                click.echo(f" 状態: {status}")
            if 'error' in data:
                click.echo(f" エラー: {data['error']}")

    except Exception as e:
        click.echo(f"履歴表示エラー: {str(e)}", err=True)
        sys.exit(1)


@cli.command()
def stats():
    """Show transaction statistics"""
    try:
        hist = get_history()
        stats = hist.get_statistics()

        click.echo("トランザクション統計:")
        click.echo(f" 総件数: {stats['total_transactions']}")

        if stats['types']:
            click.echo(" タイプ別:")
            for tx_type, count in stats['types'].items():
                click.echo(f" {tx_type}: {count}件")

        if stats['newest_entry']:
            click.echo(f" 最新: {stats['newest_entry']}")
        if stats['oldest_entry']:
            click.echo(f" 最古: {stats['oldest_entry']}")

        # ファイルサイズを人間が読みやすい形に変換
        size = stats.get('file_size_bytes', 0)
        if size < 1024:
            size_str = f"{size}B"
        elif size < 1024 * 1024:
            size_str = f"{size / 1024:.1f}KB"
        else:
            size_str = f"{size / (1024 * 1024):.1f}MB"

        click.echo(f" ファイルサイズ: {size_str}")

    except Exception as e:
        click.echo(f"統計表示エラー: {str(e)}", err=True)
        sys.exit(1)


@cli.command()
@click.option('--quick', '-q', is_flag=True, help='クイックチェックのみ実行')
def health(quick):
    """Run system health check"""
    try:
        checker = get_health_checker()

        if quick:
            click.echo("クイックヘルスチェック実行中...")
            result = checker.get_quick_status()

            status_icon = {"healthy": "[OK]", "warning": "[WARNING]", "critical": "[ERROR]"}.get(result.get('status'), "[?]")
            click.echo(f"\n{status_icon} 全体ステータス: {result.get('status', 'unknown')}")

            if 'cpu_percent' in result:
                click.echo(f"CPU: {result['cpu_percent']:.1f}%")
            if 'memory_percent' in result:
                click.echo(f"メモリ: {result['memory_percent']:.1f}%")
            if 'lightning_node' in result:
                ln_icon = "[OK]" if result['lightning_node'] == 'connected' else "[ERROR]"
                click.echo(f"Lightning ノード: {ln_icon} {result['lightning_node']}")

            if 'error' in result:
                click.echo(f"エラー: {result['error']}")

        else:
            click.echo("フルヘルスチェック実行中...")
            result = checker.run_full_health_check()

            status_icon = {"healthy": "[OK]", "warning": "[WARNING]", "critical": "[ERROR]"}.get(result['overall_status'], "[?]")
            click.echo(f"\n{status_icon} 全体ステータス: {result['overall_status']} ({result.get('health_score', 'N/A')})")

            # 各チェック結果を表示
            for check_name, check_result in result.get('checks', {}).items():
                status = check_result.get('status', 'unknown')
                status_icon = {"healthy": "[OK]", "warning": "[WARNING]", "critical": "[ERROR]"}.get(status, "[?]")
                click.echo(f"\n{status_icon} {check_name.replace('_', ' ').title()}:")

                if check_name == 'system_resources':
                    if 'cpu' in check_result:
                        click.echo(f" CPU: {check_result['cpu']['percent']:.1f}%")
                    if 'memory' in check_result:
                        click.echo(f" メモリ: {check_result['memory']['percent']:.1f}% (利用可能: {check_result['memory']['available_mb']:.0f}MB)")
                    if 'disk' in check_result:
                        click.echo(f" ディスク: {check_result['disk']['percent']:.1f}% (空き: {check_result['disk']['free_gb']:.1f}GB)")

                elif check_name == 'lightning_node':
                    if check_result.get('connected'):
                        click.echo(f" 接続: [OK] {check_result.get('node_alias', 'Unknown')}")
                        click.echo(f" 応答時間: {check_result.get('response_time_ms', 0):.1f}ms")
                        sync_icon = "[OK]" if check_result.get('synced_to_chain') else "[ERROR]"
                        click.echo(f" ブロックチェーン同期: {sync_icon}")
                    else:
                        click.echo(f" 接続: [ERROR] {check_result.get('error', '不明なエラー')}")

                elif check_name == 'network':
                    if 'internet_available' in check_result:
                        internet_icon = "[OK]" if check_result['internet_available'] else "[ERROR]"
                        click.echo(f" インターネット: {internet_icon}")
                    if 'lightning_port_open' in check_result:
                        port_icon = "[OK]" if check_result['lightning_port_open'] else "[ERROR]"
                        click.echo(f" Lightning ポート: {port_icon}")

                if 'error' in check_result:
                    click.echo(f" エラー: {check_result['error']}")

    except Exception as e:
        click.echo(f"ヘルスチェックエラー: {str(e)}", err=True)
        sys.exit(1)


@cli.command()
@click.option('--clean-logs', '-l', is_flag=True, help='古いログファイルを削除')
@click.option('--optimize-cache', '-c', is_flag=True, help='キャッシュを最適化')
@click.option('--optimize-history', '-h', is_flag=True, help='履歴を最適化')
@click.option('--all', '-a', is_flag=True, help='すべての最適化を実行')
def optimize(clean_logs, optimize_cache, optimize_history, all):
    """Optimize system performance and cleanup resources"""
    try:
        if all:
            clean_logs = optimize_cache = optimize_history = True

        if not any([clean_logs, optimize_cache, optimize_history]):
            click.echo("最適化オプションを指定してください。--help を参照してください。")
            return

        optimizations_done = []

        if clean_logs:
            click.echo("ログファイルのクリーンアップ中...")
            cleanup_old_logs(days=7)
            optimize_logging_memory()
            optimizations_done.append("ログクリーンアップ")

        if optimize_cache:
            click.echo("キャッシュの最適化中...")
            cache = get_cache()
            expired_count = cache.cleanup_expired()
            cache.optimize_memory()
            cache_stats = cache.stats()
            click.echo(f" 期限切れエントリ削除: {expired_count}個")
            click.echo(f" アクティブエントリ: {cache_stats['active_entries']}個")
            optimizations_done.append("キャッシュ最適化")

        if optimize_history:
            click.echo("履歴の最適化中...")
            history = get_history()
            removed_count = history.optimize_storage()
            stats = history.get_statistics()

            size_mb = stats['file_size_bytes'] / (1024 * 1024) if stats['file_size_bytes'] > 0 else 0
            compression_status = "(圧縮済み)" if stats.get('compressed', False) else ""

            click.echo(f" 削除されたエントリ: {removed_count}個")
            click.echo(f" 総トランザクション: {stats['total_transactions']}個")
            click.echo(f" ファイルサイズ: {size_mb:.2f}MB {compression_status}")
            optimizations_done.append("履歴最適化")

        click.echo(f"\n[OK] 最適化完了: {', '.join(optimizations_done)}")

    except Exception as e:
        click.echo(f"最適化エラー: {str(e)}", err=True)
        sys.exit(1)


@cli.command()
@click.option('--create', is_flag=True, help='バックアップを作成')
@click.option('--restore', type=str, help='バックアップからリストア')
@click.option('--list', 'list_backups', is_flag=True, help='バックアップ一覧を表示')
@click.option('--include-logs', is_flag=True, help='ログファイルも含める')
def backup(create, restore, list_backups, include_logs):
    """Backup and restore system data"""
    try:
        manager = get_backup_manager()

        if create:
            click.echo("システムバックアップを作成中...")
            backup_path = manager.create_backup(include_logs)
            click.echo(f"[OK] バックアップ作成完了: {backup_path}")

        elif restore:
            click.echo(f"バックアップからリストア中: {restore}")
            if manager.restore_backup(restore):
                click.echo("[OK] リストア完了")
            else:
                click.echo("[ERROR] リストア失敗", err=True)
                sys.exit(1)

        elif list_backups:
            backups = manager.list_backups()
            if not backups:
                click.echo("バックアップが見つかりません")
            else:
                click.echo(f"利用可能なバックアップ ({len(backups)}個):")
                for b in backups:
                    size_str = f"{b['size_mb']:.1f}MB"
                    click.echo(f" - {b['name']} ({size_str}) - {b['created']}")

        else:
            click.echo("オプションを指定してください。--help を参照してください。")

    except Exception as e:
        click.echo(f"バックアップエラー: {str(e)}", err=True)
        sys.exit(1)


@cli.command()
@click.option('--status', is_flag=True, help='回復システムの状態を表示')
@click.option('--reset', help='指定操作の回復状態をリセット（全体は "all" を指定）')
@click.pass_context
def recovery(ctx, status, reset):
    """エラー回復システムの管理"""
    try:
        recovery_system = get_error_recovery()

        if status:
            click.echo(" エラー回復システム状態:")
            status_info = recovery_system.get_recovery_status()

            click.echo(f"最大再試行回数: {status_info['max_retries']}")
            click.echo(f"再試行遅延: {status_info['retry_delay']}秒")
            click.echo(f"指数バックオフ: {'有効' if status_info['exponential_backoff'] else '無効'}")
            click.echo(f"回復タイムアウト: {status_info['recovery_timeout']}秒")

            active_recoveries = status_info['active_recoveries']
            if active_recoveries:
                click.echo("\n[PROGRESS] 進行中の回復:")
                for operation, attempts in active_recoveries.items():
                    click.echo(f" - {operation}: {attempts}回試行済み")
            else:
                click.echo("\n[OK] 進行中の回復はありません")

        elif reset:
            if reset.lower() == 'all':
                recovery_system.reset_recovery_state()
                click.echo("[OK] 全ての回復状態をリセットしました")
            else:
                recovery_system.reset_recovery_state(reset)
                click.echo(f"[OK] {reset} の回復状態をリセットしました")

        else:
            click.echo("オプションを指定してください。--help を参照してください。")

    except Exception as e:
        click.echo(f"回復システムエラー: {str(e)}", err=True)
        sys.exit(1)


@cli.command()
@click.option('--start', is_flag=True, help='監視を開始')
@click.option('--stop', is_flag=True, help='監視を停止')
@click.option('--status', is_flag=True, help='監視状態を表示')
@click.pass_context
def monitor(ctx, start, stop, status):
    """Monitor wallet balance, channels, and system performance"""
    try:
        monitor = get_monitor()
        client = ctx.obj['client']

        if start:
            click.echo("統合監視を開始中...")
            monitor.start_monitoring(client)
            click.echo("[OK] 統合監視を開始しました（パフォーマンス + ウォレット）")

        elif stop:
            click.echo("統合監視を停止中...")
            monitor.stop()
            click.echo("[OK] 統合監視を停止しました")

        elif status:
            # ウォレット情報
            wallet_summary = monitor.get_wallet_summary()

            # パフォーマンス情報
            perf_summary = monitor.get_performance_summary()

            click.echo("統合監視状態:")
            click.echo(f" 監視中: {'[OK]' if monitor.monitor_thread and monitor.monitor_thread.is_alive() else '[ERROR]'}")

            if wallet_summary.get('status') != 'no_data':
                click.echo("\n ウォレット監視:")
                click.echo(f" 現在の残高: {wallet_summary['current_balance']} sats")
                click.echo(f" ウォレット: {wallet_summary['wallet_balance']} sats")
                click.echo(f" チャネル: {wallet_summary['channel_balance']} sats")
                click.echo(f" 24時間変化: {wallet_summary['change_24h']:+} sats")
                click.echo(f" チャネル: {wallet_summary['active_channels']}/{wallet_summary['total_channels']} アクティブ")
                click.echo(f" 最終更新: {wallet_summary['last_update']}")

            if perf_summary.get('status') != 'no_data':
                click.echo("\n パフォーマンス監視:")
                click.echo(f" 自動調整: {'[OK]' if perf_summary['auto_tune_enabled'] else '[ERROR]'}")
                click.echo(f" 総サンプル数: {perf_summary['total_samples']}")

                if 'metrics' in perf_summary:
                    for name, data in perf_summary['metrics'].items():
                        click.echo(f" {name}: {data['current']:.1f} {data['unit']}")
        else:
            click.echo("オプションを指定してください。--help を参照してください。")

    except Exception as e:
        click.echo(f"監視エラー: {str(e)}", err=True)
        sys.exit(1)


@cli.command()
@click.option('--validate', is_flag=True, help='設定ファイルを検証')
@click.option('--repair', is_flag=True, help='設定ファイルを自動修復')
@click.option('--env-template', is_flag=True, help='環境変数テンプレートを生成')
@click.option('--show', is_flag=True, help='現在の設定を表示')
@click.option('--section', help='特定のセクションのみ表示')
def config(validate, repair, env_template, show, section):
    """Configuration management and validation"""
    try:
        from blncs.core.config_manager import get_config_manager
        validator = get_validator()
        config_manager = get_config()

        if show:
            click.echo("現在の設定:")
            if section:
                section_data = config_manager.get_section(section)
                if section_data:
                    import yaml
                    click.echo(f"\n[{section}]")
                    click.echo(yaml.dump(section_data, default_flow_style=False))
                else:
                    click.echo(f"セクション '{section}' が見つかりません")
            else:
                import yaml
                click.echo(yaml.dump(config_manager.data, default_flow_style=False))

        elif env_template:
            template = config_manager.get_env_template()
            click.echo("環境変数テンプレート:")
            click.echo(template)

            # ファイルに保存するかオプションで確認
            if click.confirm('\n.env.template ファイルに保存しますか？'):
                with open('.env.template', 'w') as f:
                    f.write(template)
                click.echo("[OK] .env.template ファイルに保存しました")

        elif validate:
            click.echo("設定ファイルを検証中...")
            result = validator.validate_config()

            if result['valid']:
                click.echo("[OK] 設定ファイルは有効です")
                if result.get('warnings'):
                    click.echo("\n[WARNING] 警告:")
                    for warning in result['warnings']:
                        click.echo(f" - {warning}")
            else:
                click.echo("[ERROR] 設定ファイルに問題があります")
                if result.get('errors'):
                    click.echo("\nエラー:")
                    for error in result['errors']:
                        click.echo(f" - {error}")
                if repair:
                    click.echo("\n自動修復を試行中...")
                    repair_result = validator.repair_config()
                    if repair_result['repaired']:
                        click.echo("[OK] 設定ファイルを修復しました")
                        if repair_result.get('changes'):
                            click.echo("修復された項目:")
                            for change in repair_result['changes']:
                                click.echo(f" - {change}")
                    else:
                        click.echo("[ERROR] 自動修復に失敗しました")

        elif repair:
            click.echo("設定ファイルの自動修復を実行中...")
            result = validator.repair_config()
            if result['repaired']:
                click.echo("[OK] 設定ファイルを修復しました")
                if result.get('changes'):
                    click.echo("修復された項目:")
                    for change in result['changes']:
                        click.echo(f" - {change}")
            else:
                click.echo("[OK] 修復の必要はありませんでした")

        else:
            click.echo("オプションを指定してください。--help を参照してください。")

    except Exception as e:
        click.echo(f"設定管理エラー: {str(e)}", err=True)
        sys.exit(1)


@cli.command()
@click.argument('amount', type=int)
@click.option('--urgent', is_flag=True, help='緊急支払い（高速確認）')
def fee_estimate(amount, urgent):
    """Estimate optimal fees for payments"""
    try:
        optimizer = get_fee_optimizer()

        click.echo(f"支払い金額: {amount} sats の手数料見積もり")

        # Lightning 手数料
        ln_rec = optimizer.get_lightning_fee_recommendation(amount)
        click.echo(f"\n Lightning Network:")
        click.echo(f" 手数料率: {ln_rec.fee_rate} ppm")
        click.echo(f" 予想手数料: {ln_rec.estimated_cost} sats")
        click.echo(f" 確認時間: {ln_rec.confirmation_time}")

        # On-chain 手数料
        priority = 'fast' if urgent else 'medium'
        onchain_rec = optimizer.get_onchain_fee_recommendation(priority)
        click.echo(f"\n🔗 On-chain:")
        click.echo(f" 手数料率: {onchain_rec.fee_rate} sat/vbyte")
        click.echo(f" 予想手数料: {onchain_rec.estimated_cost} sats")
        click.echo(f" 確認時間: {onchain_rec.confirmation_time}")

        # 最適化推奨
        optimization = optimizer.optimize_payment_method(amount, urgent)
        click.echo(f"\n 推奨:")
        click.echo(f" 最適な方法: {optimization['recommended_method']}")
        click.echo(f" 理由: {optimization['reason']}")
        if optimization.get('savings', 0) > 0:
            click.echo(f" 節約: {optimization['savings']} sats")

    except Exception as e:
        click.echo(f"手数料見積もりエラー: {str(e)}", err=True)
        sys.exit(1)


@cli.command()
@click.option('--analyze', is_flag=True, help='チャネル状態を分析')
@click.option('--recommendations', is_flag=True, help='推奨アクションを表示')
@click.pass_context
def channels_advanced(ctx, analyze, recommendations):
    """Advanced channel management and analysis"""
    try:
        manager = get_channel_manager()
        client = ctx.obj['client']

        if analyze or recommendations:
            click.echo("チャネル分析を実行中...")
            client.connect()
        analysis = manager.analyze_channels(client)
        client.disconnect()

        if analyze:
            click.echo(f"\n チャネル分析結果:")
        click.echo(f" 総チャネル数: {analysis['total_channels']}")
        click.echo(f" アクティブチャネル: {analysis['active_channels']}")
        click.echo(f" 総容量: {analysis['total_capacity']:,} sats")
        click.echo(f" ローカル残高: {analysis['local_balance']:,} sats")
        click.echo(f" リモート残高: {analysis['remote_balance']:,} sats")
        click.echo(f" ウォレット残高: {analysis['wallet_balance']:,} sats")
        click.echo(f" 健全性スコア: {analysis['health_score']}/100")

        if recommendations and analysis.get('recommendations'):
            click.echo(f"\n 推奨アクション ({len(analysis['recommendations'])}件):")
        for i, rec in enumerate(analysis['recommendations'], 1):
            priority_icon = {'1': '🔴', '2': '🟡', '3': '🟢'}.get(str(rec.priority), '⚪')
        click.echo(f" {i}. {priority_icon} {rec.action}: {rec.reason}")
        if rec.target != 'new_peer':
            click.echo(f" 対象: {rec.target}")
        if rec.amount > 0:
            click.echo(f" 金額: {rec.amount:,} sats")

        elif recommendations:
            click.echo("[OK] 推奨アクションはありません")

        else:
            click.echo("オプションを指定してください。--help を参照してください。")

    except Exception as e:
        click.echo(f"チャネル管理エラー: {str(e)}", err=True)
        sys.exit(1)


@cli.command()
@click.option('--status', is_flag=True, help='接続状態を表示')
@click.option('--reconnect', is_flag=True, help='再接続を試行')
@click.pass_context
def connection(ctx, status, reconnect):
    """Lightning node connection management"""
    try:
        conn_pool = ConnectionPool()
        client = ctx.obj['client']

        if status:
            # Check connection status using pool
            click.echo("Lightning Node Connection Status:")
            click.echo(f" Status: Connected")
        click.echo(f" 接続試行回数: {conn_status['attempts']}")
        click.echo(f" 自動再試行: {'[OK]' if conn_status['auto_retry'] else '[ERROR]'}")
        click.echo(f" 稼働時間: {conn_status['uptime_seconds']:.0f}秒")

        if conn_status.get('last_error'):
            click.echo(f" 最新エラー: {conn_status['last_error']}")

        elif reconnect:
            click.echo("Lightning Node への再接続を試行中...")
            success = conn_manager.connect(client)
            if success:
                click.echo("[OK] 再接続に成功しました")
            else:
                click.echo("[ERROR] 再接続に失敗しました")

        else:
            click.echo("オプションを指定してください。--help を参照してください。")

    except Exception as e:
        click.echo(f"接続管理エラー: {str(e)}", err=True)
        sys.exit(1)


@cli.command('quick-status')
@click.pass_context 
def quick_status(ctx):
    """クイック状態確認 - よく使う情報をまとめて表示"""
    try:
        client = ctx.obj['client']
        quiet = ctx.obj.get('quiet', False)

        if not quiet:
            click.echo("BLNCS Quick Status Check")
            click.echo("=" * 40)

        # システム状態
        try:
            validation = validate_setup()
            all_good = all(validation.values())
            status = "OK" if all_good else "CHECK"
            click.echo(f"System: {status}")
        except:
            click.echo("System: Configuration Error")

        # Lightning Node接続（クイック確認）
        try:
            # タイムアウトを短く設定
            original_timeout = client.timeout
            original_connect_timeout = client.connect_timeout
            client.timeout = 5
            client.connect_timeout = 3

            client.connect()
            info = client.get_info()
            click.echo(f"Node: {info.get('alias', 'Unknown')} (Connected)")

            # 残高も取得
            balance = client.get_balance()
            total = balance.get('total', 0)
            click.echo(f"Balance: {total:,} sats")

        except:
            click.echo("Node: Disconnected")
            click.echo("Balance: Unavailable")
        finally:
            # タイムアウトを元に戻す
            client.timeout = original_timeout
            client.connect_timeout = original_connect_timeout
            try:
                client.disconnect()
            except:
                pass

        if not quiet:
            click.echo("\nFor details: python -m blncs.cli.main status")

    except Exception as e:
        click.echo(f"Quick check error: {str(e)}", err=True)
        sys.exit(1)


@cli.command('node')
@click.pass_context
def node_info(ctx):
    """Lightning Node の詳細情報を表示"""
    try:
        client = ctx.obj['client']
        client.connect()
        info = client.get_info()

        click.echo(" Lightning Node 情報:")
        click.echo(f" エイリアス: {info.get('alias', 'Unknown')}")
        click.echo(f" PubKey: {info.get('identity_pubkey', '')[:20]}...")
        click.echo(f" ネットワーク: {info.get('network', 'unknown')}")
        click.echo(f" バージョン: {info.get('version', 'unknown')}")
        click.echo(f" チェーン同期: {'[OK]' if info.get('synced_to_chain', False) else '[ERROR]'}")
        click.echo(f" グラフ同期: {'[OK]' if info.get('synced_to_graph', False) else '[ERROR]'}")

    except (ConnectionError, LightningError, BLNCSError) as e:
        click.echo(format_error_for_cli(e), err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"[ERROR] 予期しないエラー: {str(e)}", err=True)
        sys.exit(1)
    finally:
        client.disconnect()


@cli.command('dashboard')
@click.pass_context
def dashboard(ctx):
    """ダッシュボード表示 - 全体的な状況を一画面で"""
    try:
        client = ctx.obj['client']
        click.echo(" BLNCS ダッシュボード")
        click.echo("=" * 50)

        # システム状態
        click.echo("\n システム状態:")
        validation = validate_setup()
        for item, status in validation.items():
            icon = "[OK]" if status else "[ERROR]"
            click.echo(f" {icon} {item}")

        # ノード状態
        click.echo("\n Lightning Node:")
        try:
            client.connect()
            info = client.get_info()
            click.echo(f" ノード: {info.get('alias', 'Unknown')}")
            click.echo(f" 同期状態: {'[OK]' if info.get('synced_to_chain') else '[ERROR]'}")

            # 残高
            balance = client.get_balance()
            click.echo(f" ウォレット残高: {balance.get('total', 0):,} sats")

            # チャネル
            channels = client.list_channels()
            active = len([ch for ch in channels if ch.get('active', False)])
            click.echo(f" チャネル: {active}/{len(channels)} アクティブ")

        except Exception as e:
            click.echo(f" [ERROR] 接続エラー: {str(e)}")
        finally:
            try:
                client.disconnect()
            except:
                pass

        # 監視状態
        click.echo("\n 監視状態:")
        try:
            monitor = get_monitor()
            if hasattr(monitor, 'monitor_thread') and monitor.monitor_thread and monitor.monitor_thread.is_alive():
                click.echo(" [OK] 統合監視: 実行中")
            else:
                click.echo(" [ERROR] 統合監視: 停止中")
        except:
            click.echo(" [ERROR] 監視: 状態不明")

        click.echo(f"\n最終更新: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    except Exception as e:
        click.echo(f"[ERROR] ダッシュボードエラー: {str(e)}", err=True)
        sys.exit(1)


def main():
    """Main entry point with graceful shutdown and dynamic command registration"""
    # Register commands dynamically when CLI starts
    register_commands()
    
    # Initialize shutdown handler
    from blncs.core.shutdown import get_shutdown_handler, register_cleanup
    shutdown_handler = get_shutdown_handler()

    # Register cleanup for CLI-specific resources
    def cli_cleanup():
        click.echo("\nBLNCS CLI を終了中...")

    register_cleanup(cli_cleanup)

    try:
        cli()
    except KeyboardInterrupt:
        click.echo("\n\n中断されました。クリーンアップ中...")
        shutdown_handler.shutdown(0)
    except Exception as e:
        exceptions = get_exceptions()
        if 'BLNCSError' in exceptions and isinstance(e, exceptions['BLNCSError']):
            click.echo(exceptions['format_error_for_cli'](e), err=True)
        else:
            click.echo(f"予期しないエラー: {str(e)}", err=True)
        shutdown_handler.emergency_shutdown()


if __name__ == '__main__':
    main()