"""
Lightning Network liquidity management commands
"""

import click
from typing import Dict, Any

from ...core.exceptions import format_error_for_cli
from ...lightning.client import LightningClient
from ...core.liquidity_manager import get_liquidity_manager


@click.group()
def liquidity():
    """Lightning Network流動性管理コマンド"""
    pass


@liquidity.command()
@click.option('--detailed', '-d', is_flag=True, help='詳細情報を表示')
def analyze(detailed: bool):
    """チャネル流動性分析"""
    try:
        client = LightningClient()
        liquidity_mgr = get_liquidity_manager()
        
        # チャネル情報取得
        channels = client.list_channels()
        if not channels:
            click.echo("アクティブなチャネルが見つかりません。")
            return
        
        # 流動性分析
        analysis = liquidity_mgr.analyze_liquidity(channels)
        
        # 結果表示
        click.echo("=== Lightning Network 流動性分析 ===")
        click.echo(f"総チャネル数: {analysis['total_channels']}")
        click.echo(f"不均衡チャネル数: {analysis['unbalanced_channels']}")
        click.echo(f"総容量: {analysis['total_capacity']:,} sats")
        click.echo(f"ローカル残高: {analysis['total_local_balance']:,} sats")
        click.echo(f"リモート残高: {analysis['total_remote_balance']:,} sats")
        click.echo(f"全体バランス比率: {analysis['overall_balance_ratio']:.1%}")
        
        health_color = {
            'excellent': 'green',
            'good': 'green', 
            'fair': 'yellow',
            'poor': 'red'
        }.get(analysis['liquidity_health'], 'white')
        
        click.echo(f"流動性健康度: ", nl=False)
        click.secho(analysis['liquidity_health'].upper(), fg=health_color)
        
        if analysis['rebalancing_needed']:
            click.echo("\n⚠️  リバランスが推奨されます")
        else:
            click.echo("\n✅ 流動性は良好です")
        
        if detailed:
            click.echo("\n=== チャネル詳細 ===")
            for ch in analysis['channel_details']:
                status = "⚠️" if ch['needs_rebalancing'] else "✅"
                click.echo(f"{status} {ch['channel_id'][:16]}... "
                          f"Local: {ch['local_ratio']:.1%} "
                          f"({ch['capacity']:,} sats)")
                
    except Exception as e:
        click.echo(format_error_for_cli(e))


@liquidity.command()
@click.option('--limit', '-l', default=5, help='表示する提案数制限')
def suggest(limit: int):
    """リバランス提案"""
    try:
        client = LightningClient()
        liquidity_mgr = get_liquidity_manager()
        
        channels = client.list_channels()
        if not channels:
            click.echo("アクティブなチャネルが見つかりません。")
            return
        
        suggestions = liquidity_mgr.suggest_rebalancing(channels)
        
        if not suggestions:
            click.echo("✅ リバランスは不要です。流動性は良好です。")
            return
        
        click.echo("=== リバランス提案 ===")
        
        for i, suggestion in enumerate(suggestions[:limit], 1):
            priority_color = 'red' if suggestion['priority'] > 70 else 'yellow' if suggestion['priority'] > 40 else 'white'
            
            click.echo(f"\n{i}. チャネル: {suggestion['channel_id'][:16]}...")
            click.echo(f"   優先度: ", nl=False)
            click.secho(f"{suggestion['priority']}/100", fg=priority_color)
            click.echo(f"   現在比率: {suggestion['current_ratio']:.1%}")
            click.echo(f"   {suggestion['description']}")
            
            # 費用見積もり
            cost_estimate = liquidity_mgr.estimate_rebalancing_cost(suggestion['amount'])
            if cost_estimate['recommended']:
                click.echo(f"   見積費用: {cost_estimate['estimated_fee']} sats "
                          f"({cost_estimate['fee_rate_ppm']} ppm) ✅")
            else:
                click.echo(f"   見積費用: {cost_estimate['estimated_fee']} sats "
                          f"({cost_estimate['fee_rate_ppm']} ppm) ⚠️ 高コスト")
        
    except Exception as e:
        click.echo(format_error_for_cli(e))


@liquidity.command()
@click.argument('channel_id')
@click.argument('amount', type=int)
@click.option('--max-fee', default=1000, help='最大手数料 (sats)')
@click.option('--dry-run', is_flag=True, help='実行せずに計画のみ表示')
def rebalance(channel_id: str, amount: int, max_fee: int, dry_run: bool):
    """チャネルリバランス実行"""
    try:
        client = LightningClient()
        liquidity_mgr = get_liquidity_manager()
        
        if dry_run:
            cost_estimate = liquidity_mgr.estimate_rebalancing_cost(amount)
            click.echo("=== リバランス計画 ===")
            click.echo(f"チャネル: {channel_id}")
            click.echo(f"金額: {amount:,} sats")
            click.echo(f"見積費用: {cost_estimate['estimated_fee']} sats")
            click.echo(f"費用比率: {cost_estimate['cost_ratio']:.2%}")
            
            if cost_estimate['estimated_fee'] > max_fee:
                click.echo(f"⚠️  見積費用が最大手数料 ({max_fee} sats) を超過")
                return
            
            click.echo("✅ 実行準備完了")
            return
        
        click.echo("⚠️  実際のリバランス実行は現在開発中です。")
        click.echo("--dry-run オプションで計画を確認してください。")
        
    except Exception as e:
        click.echo(format_error_for_cli(e))


@liquidity.command()
def recommendations():
    """流動性改善の総合推奨事項"""
    try:
        client = LightningClient()
        liquidity_mgr = get_liquidity_manager()
        
        channels = client.list_channels()
        if not channels:
            click.echo("アクティブなチャネルが見つかりません。")
            return
        
        recs = liquidity_mgr.get_liquidity_recommendations(channels)
        
        click.echo("=== 流動性改善推奨事項 ===")
        
        # 次のアクション
        click.echo(f"\n🎯 次のアクション:")
        click.echo(f"   {recs['next_action']}")
        
        # 推奨事項
        if recs['recommendations']:
            click.echo(f"\n💡 推奨事項:")
            for i, rec in enumerate(recs['recommendations'], 1):
                click.echo(f"   {i}. {rec}")
        
        # トップ提案
        if recs['rebalancing_suggestions']:
            click.echo(f"\n⚡ 優先リバランス:")
            for suggestion in recs['rebalancing_suggestions'][:3]:
                click.echo(f"   • {suggestion['description']} "
                          f"(優先度: {suggestion['priority']}/100)")
        
        # 健康度サマリー
        analysis = recs['analysis']
        click.echo(f"\n📊 サマリー:")
        click.echo(f"   流動性健康度: {analysis['liquidity_health'].upper()}")
        click.echo(f"   全体バランス: {analysis['overall_balance_ratio']:.1%}")
        click.echo(f"   不均衡チャネル: {analysis['unbalanced_channels']}/{analysis['total_channels']}")
        
    except Exception as e:
        click.echo(format_error_for_cli(e))


@liquidity.command()
@click.argument('amount', type=int)
@click.option('--hops', default=3, help='予想ホップ数')
def cost(amount: int, hops: int):
    """リバランス費用見積もり"""
    try:
        liquidity_mgr = get_liquidity_manager()
        estimate = liquidity_mgr.estimate_rebalancing_cost(amount, hops)
        
        click.echo("=== リバランス費用見積もり ===")
        click.echo(f"金額: {estimate['amount']:,} sats")
        click.echo(f"予想ホップ数: {hops}")
        click.echo(f"見積費用: {estimate['estimated_fee']} sats")
        click.echo(f"費用率: {estimate['fee_rate_ppm']} ppm ({estimate['cost_ratio']:.2%})")
        
        if estimate['recommended']:
            click.echo("✅ 推奨: 費用対効果が良好")
        else:
            click.echo("⚠️  注意: 高コストの可能性")
        
    except Exception as e:
        click.echo(format_error_for_cli(e))