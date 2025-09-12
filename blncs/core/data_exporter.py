#!/usr/bin/env python3
"""
BLNCS Data Exporter - データエクスポート機能
Comprehensive data export functionality for various formats.
"""

import os
import json
import csv
import sqlite3
import zipfile
import pandas as pd
from datetime import datetime, timedelta
from pathlib import Path
import xml.etree.ElementTree as ET
import yaml
import xlsxwriter
from io import BytesIO, StringIO

try:
    from .config_manager import get_config_manager
    from ..lightning.client_simple import get_lightning_client
    from .history import get_history_manager
    from .metrics import get_metrics_collector
except ImportError:
    import sys
    sys.path.append(str(Path(__file__).parent.parent))
    from config_manager import get_config_manager
    from lightning.client_simple import get_lightning_client
    from history import get_history_manager
    from metrics import get_metrics_collector


class DataExporter:
    """データエクスポータークラス"""
    
    def __init__(self, config_manager=None):
        self.config = config_manager or get_config_manager()
        self.lightning_client = get_lightning_client()
        self.history_manager = get_history_manager()
        self.metrics = get_metrics_collector()
        
        # エクスポートディレクトリ
        self.export_dir = Path(self.config.get_data_dir()) / "exports"
        self.export_dir.mkdir(exist_ok=True, parents=True)
        
        # サポートするフォーマット
        self.supported_formats = {
            'json': self.export_to_json,
            'csv': self.export_to_csv,
            'excel': self.export_to_excel,
            'xml': self.export_to_xml,
            'yaml': self.export_to_yaml,
            'html': self.export_to_html,
            'pdf': self.export_to_pdf,
            'sqlite': self.export_to_sqlite
        }
    
    def export_data(self, data_type, format_type, options=None):
        """データをエクスポート"""
        options = options or {}
        
        if format_type not in self.supported_formats:
            raise ValueError(f"サポートされていないフォーマット: {format_type}")
        
        # データ取得
        data = self.fetch_data(data_type, options)
        
        if not data:
            return {'success': False, 'error': 'エクスポートするデータがありません'}
        
        # エクスポート実行
        export_func = self.supported_formats[format_type]
        result = export_func(data, data_type, options)
        
        return result
    
    def fetch_data(self, data_type, options):
        """データを取得"""
        if data_type == 'transactions':
            return self.fetch_transactions(options)
        elif data_type == 'channels':
            return self.fetch_channels(options)
        elif data_type == 'invoices':
            return self.fetch_invoices(options)
        elif data_type == 'payments':
            return self.fetch_payments(options)
        elif data_type == 'metrics':
            return self.fetch_metrics(options)
        elif data_type == 'node_info':
            return self.fetch_node_info(options)
        elif data_type == 'network_graph':
            return self.fetch_network_graph(options)
        elif data_type == 'full_backup':
            return self.fetch_full_backup(options)
        else:
            raise ValueError(f"サポートされていないデータタイプ: {data_type}")
    
    def fetch_transactions(self, options):
        """取引データ取得"""
        start_date = options.get('start_date')
        end_date = options.get('end_date')
        status_filter = options.get('status')
        
        # サンプルデータ生成
        transactions = []
        for i in range(100):
            transactions.append({
                'id': f'tx_{i+1}',
                'timestamp': (datetime.now() - timedelta(days=i)).isoformat(),
                'type': 'payment' if i % 2 == 0 else 'invoice',
                'amount': 10000 + i * 1000,
                'fee': 10 + i,
                'status': 'completed' if i % 10 != 0 else 'failed',
                'description': f'Transaction {i+1}',
                'peer': f'node_{i % 10}'
            })
        
        return transactions
    
    def fetch_channels(self, options):
        """チャンネルデータ取得"""
        active_only = options.get('active_only', False)
        
        channels = []
        for i in range(20):
            channels.append({
                'channel_id': f'ch_{i+1}',
                'peer_id': f'node_{i}',
                'peer_alias': f'Lightning Node {i}',
                'capacity': 1000000 + i * 100000,
                'local_balance': 500000 + i * 50000,
                'remote_balance': 500000 + i * 50000,
                'state': 'active' if i % 5 != 0 else 'inactive',
                'opened_at': (datetime.now() - timedelta(days=30+i)).isoformat(),
                'last_update': datetime.now().isoformat()
            })
        
        if active_only:
            channels = [ch for ch in channels if ch['state'] == 'active']
        
        return channels
    
    def fetch_invoices(self, options):
        """請求書データ取得"""
        invoices = []
        for i in range(50):
            invoices.append({
                'invoice_id': f'inv_{i+1}',
                'payment_hash': f'hash_{i+1}',
                'amount': 5000 + i * 500,
                'description': f'Invoice {i+1}',
                'created_at': (datetime.now() - timedelta(hours=i)).isoformat(),
                'expires_at': (datetime.now() + timedelta(hours=24-i)).isoformat(),
                'settled': i % 3 == 0,
                'settled_at': datetime.now().isoformat() if i % 3 == 0 else None
            })
        
        return invoices
    
    def fetch_payments(self, options):
        """支払いデータ取得"""
        payments = []
        for i in range(75):
            payments.append({
                'payment_id': f'pay_{i+1}',
                'payment_hash': f'hash_{i+1}',
                'amount': 8000 + i * 800,
                'fee': 8 + i,
                'destination': f'node_{i % 15}',
                'created_at': (datetime.now() - timedelta(hours=i*2)).isoformat(),
                'status': 'completed' if i % 8 != 0 else 'failed',
                'failure_reason': None if i % 8 != 0 else 'No route found'
            })
        
        return payments
    
    def fetch_metrics(self, options):
        """メトリクスデータ取得"""
        period = options.get('period', '24h')
        
        metrics = {
            'timestamp': datetime.now().isoformat(),
            'period': period,
            'node_metrics': {
                'uptime': 99.5,
                'cpu_usage': 45.2,
                'memory_usage': 62.8,
                'disk_usage': 71.3
            },
            'lightning_metrics': {
                'total_capacity': 25000000,
                'total_channels': 15,
                'active_channels': 13,
                'pending_channels': 2,
                'total_balance': 12500000,
                'pending_htlcs': 3
            },
            'payment_metrics': {
                'total_sent': 150,
                'total_received': 120,
                'success_rate': 92.5,
                'average_fee': 12.3,
                'total_volume': 5000000
            }
        }
        
        return metrics
    
    def fetch_node_info(self, options):
        """ノード情報取得"""
        return {
            'node_id': '03abcdef1234567890',
            'alias': 'BLNCS Lightning Node',
            'color': '#4a9eff',
            'version': '0.15.0',
            'network': 'mainnet',
            'block_height': 805234,
            'synced': True,
            'num_peers': 25,
            'num_channels': 15,
            'addresses': [
                {'type': 'ipv4', 'address': '192.168.1.100', 'port': 9735},
                {'type': 'tor', 'address': 'abcdef.onion', 'port': 9735}
            ]
        }
    
    def fetch_network_graph(self, options):
        """ネットワークグラフデータ取得"""
        nodes = []
        edges = []
        
        for i in range(30):
            nodes.append({
                'node_id': f'node_{i}',
                'alias': f'Lightning Node {i}',
                'color': '#4a9eff',
                'last_update': datetime.now().isoformat()
            })
        
        for i in range(40):
            edges.append({
                'channel_id': f'edge_{i}',
                'node1': f'node_{i % 30}',
                'node2': f'node_{(i+1) % 30}',
                'capacity': 500000 + i * 10000,
                'last_update': datetime.now().isoformat()
            })
        
        return {'nodes': nodes, 'edges': edges}
    
    def fetch_full_backup(self, options):
        """完全バックアップデータ取得"""
        return {
            'transactions': self.fetch_transactions({}),
            'channels': self.fetch_channels({}),
            'invoices': self.fetch_invoices({}),
            'payments': self.fetch_payments({}),
            'metrics': self.fetch_metrics({}),
            'node_info': self.fetch_node_info({}),
            'timestamp': datetime.now().isoformat()
        }
    
    # エクスポート形式別メソッド
    def export_to_json(self, data, data_type, options):
        """JSON形式でエクスポート"""
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{data_type}_{timestamp}.json"
            filepath = self.export_dir / filename
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False, default=str)
            
            return {
                'success': True,
                'format': 'json',
                'filepath': str(filepath),
                'size': os.path.getsize(filepath)
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def export_to_csv(self, data, data_type, options):
        """CSV形式でエクスポート"""
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            
            # データがリストでない場合は変換
            if not isinstance(data, list):
                if isinstance(data, dict):
                    # ネストされた辞書の場合
                    if 'nodes' in data and 'edges' in data:
                        # ネットワークグラフの場合は個別にエクスポート
                        results = []
                        for key, value in data.items():
                            if isinstance(value, list):
                                filename = f"{data_type}_{key}_{timestamp}.csv"
                                filepath = self.export_dir / filename
                                
                                df = pd.DataFrame(value)
                                df.to_csv(filepath, index=False, encoding='utf-8')
                                
                                results.append({
                                    'file': str(filepath),
                                    'size': os.path.getsize(filepath)
                                })
                        
                        return {
                            'success': True,
                            'format': 'csv',
                            'files': results
                        }
                    else:
                        data = [data]
                else:
                    data = [{'value': data}]
            
            filename = f"{data_type}_{timestamp}.csv"
            filepath = self.export_dir / filename
            
            if data:
                df = pd.DataFrame(data)
                df.to_csv(filepath, index=False, encoding='utf-8')
            
            return {
                'success': True,
                'format': 'csv',
                'filepath': str(filepath),
                'size': os.path.getsize(filepath)
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def export_to_excel(self, data, data_type, options):
        """Excel形式でエクスポート"""
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{data_type}_{timestamp}.xlsx"
            filepath = self.export_dir / filename
            
            with pd.ExcelWriter(filepath, engine='xlsxwriter') as writer:
                if isinstance(data, list):
                    df = pd.DataFrame(data)
                    df.to_excel(writer, sheet_name=data_type, index=False)
                elif isinstance(data, dict):
                    for sheet_name, sheet_data in data.items():
                        if isinstance(sheet_data, list):
                            df = pd.DataFrame(sheet_data)
                            df.to_excel(writer, sheet_name=sheet_name[:31], index=False)
                        elif isinstance(sheet_data, dict):
                            df = pd.DataFrame([sheet_data])
                            df.to_excel(writer, sheet_name=sheet_name[:31], index=False)
                else:
                    df = pd.DataFrame([{'data': str(data)}])
                    df.to_excel(writer, sheet_name='data', index=False)
                
                # フォーマット設定
                workbook = writer.book
                header_format = workbook.add_format({
                    'bold': True,
                    'bg_color': '#D3D3D3',
                    'border': 1
                })
                
                for worksheet in writer.sheets.values():
                    worksheet.set_row(0, None, header_format)
            
            return {
                'success': True,
                'format': 'excel',
                'filepath': str(filepath),
                'size': os.path.getsize(filepath)
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def export_to_xml(self, data, data_type, options):
        """XML形式でエクスポート"""
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{data_type}_{timestamp}.xml"
            filepath = self.export_dir / filename
            
            root = ET.Element('blncs_export')
            root.set('type', data_type)
            root.set('timestamp', datetime.now().isoformat())
            
            def dict_to_xml(parent, data):
                if isinstance(data, dict):
                    for key, value in data.items():
                        child = ET.SubElement(parent, str(key))
                        dict_to_xml(child, value)
                elif isinstance(data, list):
                    for item in data:
                        child = ET.SubElement(parent, 'item')
                        dict_to_xml(child, item)
                else:
                    parent.text = str(data)
            
            data_element = ET.SubElement(root, 'data')
            dict_to_xml(data_element, data)
            
            tree = ET.ElementTree(root)
            tree.write(filepath, encoding='utf-8', xml_declaration=True)
            
            return {
                'success': True,
                'format': 'xml',
                'filepath': str(filepath),
                'size': os.path.getsize(filepath)
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def export_to_yaml(self, data, data_type, options):
        """YAML形式でエクスポート"""
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{data_type}_{timestamp}.yaml"
            filepath = self.export_dir / filename
            
            export_data = {
                'blncs_export': {
                    'type': data_type,
                    'timestamp': datetime.now().isoformat(),
                    'data': data
                }
            }
            
            with open(filepath, 'w', encoding='utf-8') as f:
                yaml.dump(export_data, f, default_flow_style=False, 
                         allow_unicode=True, sort_keys=False)
            
            return {
                'success': True,
                'format': 'yaml',
                'filepath': str(filepath),
                'size': os.path.getsize(filepath)
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def export_to_html(self, data, data_type, options):
        """HTML形式でエクスポート"""
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{data_type}_{timestamp}.html"
            filepath = self.export_dir / filename
            
            html_content = f"""
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BLNCS Export - {data_type}</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }}
        h1 {{
            color: #333;
            border-bottom: 2px solid #4a9eff;
            padding-bottom: 10px;
        }}
        .metadata {{
            background-color: #e9ecef;
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 20px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background-color: white;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        th {{
            background-color: #4a9eff;
            color: white;
            padding: 12px;
            text-align: left;
        }}
        td {{
            padding: 10px;
            border-bottom: 1px solid #ddd;
        }}
        tr:hover {{
            background-color: #f5f5f5;
        }}
        .json-view {{
            background-color: #282c34;
            color: #abb2bf;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            font-family: 'Consolas', 'Monaco', monospace;
        }}
    </style>
</head>
<body>
    <h1>BLNCS データエクスポート - {data_type}</h1>
    <div class="metadata">
        <p><strong>エクスポート日時:</strong> {datetime.now().strftime('%Y年%m月%d日 %H:%M:%S')}</p>
        <p><strong>データタイプ:</strong> {data_type}</p>
    </div>
"""
            
            if isinstance(data, list) and data:
                # テーブル形式で表示
                html_content += "<table>\n<thead>\n<tr>\n"
                
                # ヘッダー
                for key in data[0].keys():
                    html_content += f"<th>{key}</th>\n"
                html_content += "</tr>\n</thead>\n<tbody>\n"
                
                # データ行
                for item in data:
                    html_content += "<tr>\n"
                    for value in item.values():
                        html_content += f"<td>{value}</td>\n"
                    html_content += "</tr>\n"
                
                html_content += "</tbody>\n</table>\n"
            else:
                # JSON形式で表示
                html_content += '<div class="json-view">\n'
                html_content += f"<pre>{json.dumps(data, indent=2, ensure_ascii=False, default=str)}</pre>\n"
                html_content += "</div>\n"
            
            html_content += """
</body>
</html>
"""
            
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            return {
                'success': True,
                'format': 'html',
                'filepath': str(filepath),
                'size': os.path.getsize(filepath)
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def export_to_pdf(self, data, data_type, options):
        """PDF形式でエクスポート（要: reportlab）"""
        try:
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import letter, A4
            from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{data_type}_{timestamp}.pdf"
            filepath = self.export_dir / filename
            
            # PDFドキュメント作成
            doc = SimpleDocTemplate(str(filepath), pagesize=A4)
            elements = []
            
            # スタイル設定
            styles = getSampleStyleSheet()
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Title'],
                fontSize=24,
                textColor=colors.HexColor('#4a9eff')
            )
            
            # タイトル
            elements.append(Paragraph(f"BLNCS データエクスポート - {data_type}", title_style))
            elements.append(Spacer(1, 0.3*inch))
            
            # メタデータ
            metadata = Paragraph(
                f"エクスポート日時: {datetime.now().strftime('%Y年%m月%d日 %H:%M:%S')}<br/>"
                f"データタイプ: {data_type}",
                styles['Normal']
            )
            elements.append(metadata)
            elements.append(Spacer(1, 0.3*inch))
            
            # データテーブル
            if isinstance(data, list) and data:
                # テーブルデータ準備
                table_data = [list(data[0].keys())]  # ヘッダー
                for item in data[:50]:  # 最大50行
                    table_data.append([str(v)[:30] for v in item.values()])
                
                # テーブル作成
                table = Table(table_data)
                table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#4a9eff')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 10),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                    ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 1), (-1, -1), 8),
                ]))
                
                elements.append(table)
            else:
                # テキストとして追加
                data_text = json.dumps(data, indent=2, ensure_ascii=False, default=str)
                elements.append(Paragraph(f"<pre>{data_text[:2000]}</pre>", styles['Code']))
            
            # PDF生成
            doc.build(elements)
            
            return {
                'success': True,
                'format': 'pdf',
                'filepath': str(filepath),
                'size': os.path.getsize(filepath)
            }
            
        except ImportError:
            return {'success': False, 'error': 'PDFエクスポートにはreportlabライブラリが必要です'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def export_to_sqlite(self, data, data_type, options):
        """SQLite形式でエクスポート"""
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{data_type}_{timestamp}.db"
            filepath = self.export_dir / filename
            
            # SQLiteデータベース作成
            conn = sqlite3.connect(str(filepath))
            cursor = conn.cursor()
            
            if isinstance(data, list) and data:
                # テーブル作成
                columns = data[0].keys()
                column_defs = ', '.join([f'"{col}" TEXT' for col in columns])
                cursor.execute(f'CREATE TABLE {data_type} ({column_defs})')
                
                # データ挿入
                for item in data:
                    placeholders = ', '.join(['?' for _ in columns])
                    values = [str(item.get(col, '')) for col in columns]
                    cursor.execute(f'INSERT INTO {data_type} VALUES ({placeholders})', values)
            
            elif isinstance(data, dict):
                # 複数テーブルの場合
                for table_name, table_data in data.items():
                    if isinstance(table_data, list) and table_data:
                        columns = table_data[0].keys()
                        column_defs = ', '.join([f'"{col}" TEXT' for col in columns])
                        cursor.execute(f'CREATE TABLE {table_name} ({column_defs})')
                        
                        for item in table_data:
                            placeholders = ', '.join(['?' for _ in columns])
                            values = [str(item.get(col, '')) for col in columns]
                            cursor.execute(f'INSERT INTO {table_name} VALUES ({placeholders})', values)
            
            conn.commit()
            conn.close()
            
            return {
                'success': True,
                'format': 'sqlite',
                'filepath': str(filepath),
                'size': os.path.getsize(filepath)
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def create_export_package(self, data_types, format_type, options=None):
        """複数データタイプをパッケージとしてエクスポート"""
        options = options or {}
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        package_name = f"blncs_export_package_{timestamp}"
        package_dir = self.export_dir / package_name
        package_dir.mkdir(exist_ok=True)
        
        results = []
        for data_type in data_types:
            try:
                data = self.fetch_data(data_type, options)
                
                # 一時的にエクスポートディレクトリを変更
                original_export_dir = self.export_dir
                self.export_dir = package_dir
                
                result = self.export_data(data_type, format_type, options)
                
                self.export_dir = original_export_dir
                
                if result['success']:
                    results.append({
                        'data_type': data_type,
                        'file': result.get('filepath') or result.get('files')
                    })
                
            except Exception as e:
                results.append({
                    'data_type': data_type,
                    'error': str(e)
                })
        
        # ZIPアーカイブ作成
        zip_filepath = self.export_dir / f"{package_name}.zip"
        with zipfile.ZipFile(zip_filepath, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(package_dir):
                for file in files:
                    file_path = Path(root) / file
                    arcname = file_path.relative_to(package_dir)
                    zipf.write(file_path, arcname)
        
        # 一時ディレクトリ削除
        import shutil
        shutil.rmtree(package_dir)
        
        return {
            'success': True,
            'package': str(zip_filepath),
            'size': os.path.getsize(zip_filepath),
            'contents': results
        }
    
    def schedule_export(self, data_type, format_type, schedule, options=None):
        """定期エクスポートをスケジュール"""
        # スケジューリング実装（cronやAPSchedulerを使用）
        pass
    
    def get_export_history(self, limit=50):
        """エクスポート履歴取得"""
        exports = []
        
        for file_path in sorted(self.export_dir.glob('*'), key=lambda x: x.stat().st_mtime, reverse=True)[:limit]:
            exports.append({
                'filename': file_path.name,
                'filepath': str(file_path),
                'size': file_path.stat().st_size,
                'created_at': datetime.fromtimestamp(file_path.stat().st_mtime),
                'format': file_path.suffix[1:] if file_path.suffix else 'unknown'
            })
        
        return exports
    
    def cleanup_old_exports(self, days=30):
        """古いエクスポートファイルを削除"""
        cutoff_time = datetime.now() - timedelta(days=days)
        deleted_count = 0
        
        for file_path in self.export_dir.glob('*'):
            if datetime.fromtimestamp(file_path.stat().st_mtime) < cutoff_time:
                file_path.unlink()
                deleted_count += 1
        
        return deleted_count


def get_data_exporter():
    """データエクスポーターのシングルトンインスタンス取得"""
    if not hasattr(get_data_exporter, '_instance'):
        get_data_exporter._instance = DataExporter()
    return get_data_exporter._instance


def main():
    """テスト用メイン関数"""
    exporter = DataExporter()
    
    print("=== BLNCS データエクスポーター テスト ===")
    
    # サポートフォーマット表示
    print("\n1. サポートフォーマット:")
    for format_type in exporter.supported_formats.keys():
        print(f"  - {format_type}")
    
    # JSON エクスポートテスト
    print("\n2. JSONエクスポートテスト")
    result = exporter.export_data('transactions', 'json')
    print(f"結果: {result}")
    
    # CSV エクスポートテスト
    print("\n3. CSVエクスポートテスト")
    result = exporter.export_data('channels', 'csv')
    print(f"結果: {result}")
    
    # エクスポート履歴
    print("\n4. エクスポート履歴")
    history = exporter.get_export_history(10)
    for export in history:
        print(f"  - {export['filename']} ({export['size']} bytes)")


if __name__ == "__main__":
    main()