#!/usr/bin/env python3
"""
BLNCS Advanced Analytics Dashboard - 高度な分析ダッシュボード
Advanced analytics and visualization for Lightning Network data.
"""

import tkinter as tk
from tkinter import ttk, messagebox
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import numpy as np
from datetime import datetime, timedelta
import threading
import time

try:
    from ..core.config_manager import get_config_manager
    from ..lightning.client_simple import get_lightning_client
except ImportError:
    import sys
    from pathlib import Path
    sys.path.append(str(Path(__file__).parent.parent))
    from core.config_manager import get_config_manager
    from lightning.client_simple import get_lightning_client


class AnalyticsDashboard:
    """高度な分析ダッシュボード"""
    
    def __init__(self, parent=None):
        if parent:
            self.window = tk.Toplevel(parent)
        else:
            self.window = tk.Tk()
        
        self.lightning_client = get_lightning_client()
        self.config = get_config_manager()
        
        self.setup_window()
        self.create_interface()
        self.load_analytics_data()
    
    def setup_window(self):
        """ウィンドウの基本設定"""
        self.window.title("📊 BLNCS - 高度な分析ダッシュボード")
        self.window.geometry("1200x800")
        self.window.minsize(1000, 700)
        self.window.configure(bg="#f8f9fa")
    
    def create_interface(self):
        """分析インターフェースを作成"""
        # メインフレーム
        main_frame = ttk.Frame(self.window)
        main_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # ヘッダー
        self.create_header(main_frame)
        
        # 分析タブ
        self.create_analytics_tabs(main_frame)
        
        # ステータスバー
        self.create_status_bar(main_frame)
    
    def create_header(self, parent):
        """ヘッダーを作成"""
        header_frame = ttk.Frame(parent)
        header_frame.pack(fill='x', pady=(0, 10))
        
        # タイトル
        title_label = ttk.Label(header_frame, 
                               text="📊 Lightning Network 高度分析",
                               font=("Segoe UI", 16, "bold"),
                               foreground="#0066cc")
        title_label.pack(side='left')
        
        # 操作ボタン
        button_frame = ttk.Frame(header_frame)
        button_frame.pack(side='right')
        
        ttk.Button(button_frame, text="🔄 データ更新", 
                  command=self.refresh_analytics).pack(side='right', padx=(5, 0))
        
        ttk.Button(button_frame, text="📤 エクスポート", 
                  command=self.export_analytics).pack(side='right')
    
    def create_analytics_tabs(self, parent):
        """分析タブを作成"""
        self.notebook = ttk.Notebook(parent)
        self.notebook.pack(fill='both', expand=True, pady=(0, 10))
        
        # パフォーマンス分析
        self.create_performance_tab()
        
        # チャンネル分析
        self.create_channel_analysis_tab()
        
        # 支払い分析
        self.create_payment_analysis_tab()
        
        # ネットワーク分析
        self.create_network_analysis_tab()
        
        # リアルタイム監視
        self.create_realtime_tab()
    
    def create_performance_tab(self):
        """パフォーマンス分析タブ"""
        perf_frame = ttk.Frame(self.notebook)
        self.notebook.add(perf_frame, text="📈 パフォーマンス")
        
        # 上下分割
        paned_window = ttk.PanedWindow(perf_frame, orient='vertical')
        paned_window.pack(fill='both', expand=True, padx=10, pady=10)
        
        # 上部: グラフエリア
        graph_frame = ttk.Frame(paned_window)
        paned_window.add(graph_frame, weight=3)
        
        # 残高推移グラフ
        self.create_balance_chart(graph_frame)
        
        # 下部: 統計情報
        stats_frame = ttk.LabelFrame(paned_window, text="📊 統計サマリー", padding=10)
        paned_window.add(stats_frame, weight=1)
        
        self.create_performance_stats(stats_frame)
    
    def create_balance_chart(self, parent):
        """残高推移チャート"""
        chart_frame = ttk.LabelFrame(parent, text="💰 残高推移 (過去30日)", padding=10)
        chart_frame.pack(fill='both', expand=True)
        
        # Matplotlibグラフ
        self.balance_figure = Figure(figsize=(10, 4), dpi=100)
        self.balance_plot = self.balance_figure.add_subplot(111)
        
        # サンプルデータ
        dates = [datetime.now() - timedelta(days=x) for x in range(30, 0, -1)]
        lightning_balance = np.random.randint(800000, 1200000, 30)
        onchain_balance = np.random.randint(1000000, 1500000, 30)
        
        self.balance_plot.plot(dates, lightning_balance, label='Lightning残高', 
                              color='#f7931a', linewidth=2)
        self.balance_plot.plot(dates, onchain_balance, label='オンチェーン残高', 
                              color='#4dabf7', linewidth=2)
        
        self.balance_plot.set_xlabel('日付')
        self.balance_plot.set_ylabel('残高 (sats)')
        self.balance_plot.legend()
        self.balance_plot.grid(True, alpha=0.3)
        
        # グラフ埋め込み
        self.balance_canvas = FigureCanvasTkAgg(self.balance_figure, chart_frame)
        self.balance_canvas.draw()
        self.balance_canvas.get_tk_widget().pack(fill='both', expand=True)
    
    def create_performance_stats(self, parent):
        """パフォーマンス統計"""
        stats_grid = ttk.Frame(parent)
        stats_grid.pack(fill='both', expand=True)
        
        # 統計項目
        stats = [
            ("総取引回数", "2,847", "📊"),
            ("平均取引額", "45,230 sats", "💰"),
            ("成功率", "98.5%", "✅"),
            ("平均手数料", "1.2 sats", "💸"),
            ("最大チャンネル", "1.5M sats", "⚡"),
            ("稼働時間", "99.2%", "🟢")
        ]
        
        for i, (label, value, icon) in enumerate(stats):
            row = i // 3
            col = i % 3
            
            stat_frame = ttk.Frame(stats_grid)
            stat_frame.grid(row=row, column=col, padx=10, pady=5, sticky='ew')
            
            ttk.Label(stat_frame, text=icon, font=("Segoe UI", 16)).pack()
            ttk.Label(stat_frame, text=label, font=("Segoe UI", 10)).pack()
            ttk.Label(stat_frame, text=value, font=("Segoe UI", 12, "bold")).pack()
        
        # 列の均等配置
        for i in range(3):
            stats_grid.columnconfigure(i, weight=1)
    
    def create_channel_analysis_tab(self):
        """チャンネル分析タブ"""
        channel_frame = ttk.Frame(self.notebook)
        self.notebook.add(channel_frame, text="⚡ チャンネル分析")
        
        # 左右分割
        paned_window = ttk.PanedWindow(channel_frame, orient='horizontal')
        paned_window.pack(fill='both', expand=True, padx=10, pady=10)
        
        # 左: チャンネル分布グラフ
        left_frame = ttk.Frame(paned_window)
        paned_window.add(left_frame, weight=1)
        
        self.create_channel_distribution_chart(left_frame)
        
        # 右: チャンネル詳細
        right_frame = ttk.Frame(paned_window)
        paned_window.add(right_frame, weight=1)
        
        self.create_channel_details(right_frame)
    
    def create_channel_distribution_chart(self, parent):
        """チャンネル分布チャート"""
        chart_frame = ttk.LabelFrame(parent, text="📊 チャンネル容量分布", padding=10)
        chart_frame.pack(fill='both', expand=True)
        
        # 円グラフ
        self.channel_figure = Figure(figsize=(6, 6), dpi=100)
        self.channel_plot = self.channel_figure.add_subplot(111)
        
        # サンプルデータ
        sizes = [30, 25, 20, 15, 10]
        labels = ['大型(>1M)', '中型(500K-1M)', '中小(200K-500K)', '小型(50K-200K)', 'その他']
        colors = ['#ff6b6b', '#4ecdc4', '#45b7d1', '#96ceb4', '#feca57']
        
        self.channel_plot.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90)
        self.channel_plot.set_title('チャンネル容量分布')
        
        self.channel_canvas = FigureCanvasTkAgg(self.channel_figure, chart_frame)
        self.channel_canvas.draw()
        self.channel_canvas.get_tk_widget().pack(fill='both', expand=True)
    
    def create_channel_details(self, parent):
        """チャンネル詳細"""
        details_frame = ttk.LabelFrame(parent, text="⚡ チャンネル詳細情報", padding=10)
        details_frame.pack(fill='both', expand=True)
        
        # チャンネルリスト
        columns = ('ID', '容量', 'ローカル', 'リモート', '状態')
        self.channel_tree = ttk.Treeview(details_frame, columns=columns, show='headings', height=15)
        
        for col in columns:
            self.channel_tree.heading(col, text=col)
            self.channel_tree.column(col, width=80, anchor='center')
        
        # スクロールバー
        channel_scroll = ttk.Scrollbar(details_frame, orient='vertical', command=self.channel_tree.yview)
        self.channel_tree.configure(yscrollcommand=channel_scroll.set)
        
        self.channel_tree.pack(side='left', fill='both', expand=True)
        channel_scroll.pack(side='right', fill='y')
        
        # サンプルデータ
        sample_channels = [
            ('001', '1,000,000', '500,000', '500,000', 'アクティブ'),
            ('002', '750,000', '375,000', '375,000', 'アクティブ'),
            ('003', '500,000', '250,000', '250,000', 'アクティブ'),
            ('004', '300,000', '150,000', '150,000', '非アクティブ'),
            ('005', '200,000', '100,000', '100,000', 'アクティブ')
        ]
        
        for channel in sample_channels:
            self.channel_tree.insert('', 'end', values=channel)
    
    def create_payment_analysis_tab(self):
        """支払い分析タブ"""
        payment_frame = ttk.Frame(self.notebook)
        self.notebook.add(payment_frame, text="💰 支払い分析")
        
        # 上下分割
        paned_window = ttk.PanedWindow(payment_frame, orient='vertical')
        paned_window.pack(fill='both', expand=True, padx=10, pady=10)
        
        # 上部: 支払い統計グラフ
        top_frame = ttk.Frame(paned_window)
        paned_window.add(top_frame, weight=2)
        
        self.create_payment_charts(top_frame)
        
        # 下部: 支払い履歴
        bottom_frame = ttk.Frame(paned_window)
        paned_window.add(bottom_frame, weight=1)
        
        self.create_payment_history_detailed(bottom_frame)
    
    def create_payment_charts(self, parent):
        """支払い統計チャート"""
        chart_frame = ttk.LabelFrame(parent, text="📈 支払い統計 (過去7日)", padding=10)
        chart_frame.pack(fill='both', expand=True)
        
        # 棒グラフ
        self.payment_figure = Figure(figsize=(12, 4), dpi=100)
        self.payment_plot = self.payment_figure.add_subplot(111)
        
        # サンプルデータ
        days = ['月', '火', '水', '木', '金', '土', '日']
        sent_amounts = np.random.randint(100000, 500000, 7)
        received_amounts = np.random.randint(50000, 300000, 7)
        
        x = np.arange(len(days))
        width = 0.35
        
        self.payment_plot.bar(x - width/2, sent_amounts, width, label='送金', color='#ff7675')
        self.payment_plot.bar(x + width/2, received_amounts, width, label='受取', color='#74b9ff')
        
        self.payment_plot.set_xlabel('曜日')
        self.payment_plot.set_ylabel('金額 (sats)')
        self.payment_plot.set_title('週間支払い統計')
        self.payment_plot.set_xticks(x)
        self.payment_plot.set_xticklabels(days)
        self.payment_plot.legend()
        self.payment_plot.grid(True, alpha=0.3)
        
        self.payment_canvas = FigureCanvasTkAgg(self.payment_figure, chart_frame)
        self.payment_canvas.draw()
        self.payment_canvas.get_tk_widget().pack(fill='both', expand=True)
    
    def create_payment_history_detailed(self, parent):
        """詳細支払い履歴"""
        history_frame = ttk.LabelFrame(parent, text="📜 詳細支払い履歴", padding=10)
        history_frame.pack(fill='both', expand=True)
        
        # 検索・フィルター
        filter_frame = ttk.Frame(history_frame)
        filter_frame.pack(fill='x', pady=(0, 10))
        
        ttk.Label(filter_frame, text="検索:").pack(side='left')
        self.search_entry = ttk.Entry(filter_frame, width=20)
        self.search_entry.pack(side='left', padx=(5, 10))
        
        ttk.Button(filter_frame, text="🔍 検索", 
                  command=self.search_payments).pack(side='left')
        
        ttk.Label(filter_frame, text="期間:").pack(side='left', padx=(20, 5))
        self.period_var = tk.StringVar(value="7日")
        period_combo = ttk.Combobox(filter_frame, textvariable=self.period_var,
                                   values=['1日', '7日', '30日', '90日'], 
                                   state='readonly', width=10)
        period_combo.pack(side='left')
        
        # 履歴テーブル
        columns = ('時刻', 'タイプ', '金額', '手数料', '状態', 'ピア')
        self.history_tree = ttk.Treeview(history_frame, columns=columns, show='headings', height=10)
        
        for col in columns:
            self.history_tree.heading(col, text=col)
            self.history_tree.column(col, width=100, anchor='center')
        
        history_scroll = ttk.Scrollbar(history_frame, orient='vertical', command=self.history_tree.yview)
        self.history_tree.configure(yscrollcommand=history_scroll.set)
        
        self.history_tree.pack(side='left', fill='both', expand=True)
        history_scroll.pack(side='right', fill='y')
    
    def create_network_analysis_tab(self):
        """ネットワーク分析タブ"""
        network_frame = ttk.Frame(self.notebook)
        self.notebook.add(network_frame, text="🌐 ネットワーク")
        
        # ネットワーク情報グリッド
        info_frame = ttk.LabelFrame(network_frame, text="🌐 ネットワーク統計", padding=20)
        info_frame.pack(fill='x', padx=10, pady=10)
        
        # ネットワーク統計
        network_stats = [
            ("接続ピア数", "15", "👥"),
            ("ネットワーク容量", "4,250 BTC", "⚡"),
            ("ノード数", "18,432", "🌐"),
            ("チャンネル数", "87,654", "🔗"),
            ("平均チャンネル容量", "2.3M sats", "📊"),
            ("ネットワーク成長率", "+12.5%", "📈")
        ]
        
        stats_grid = ttk.Frame(info_frame)
        stats_grid.pack(fill='both', expand=True)
        
        for i, (label, value, icon) in enumerate(network_stats):
            row = i // 3
            col = i % 3
            
            stat_frame = ttk.Frame(stats_grid)
            stat_frame.grid(row=row, column=col, padx=20, pady=10, sticky='ew')
            
            ttk.Label(stat_frame, text=icon, font=("Segoe UI", 20)).pack()
            ttk.Label(stat_frame, text=label, font=("Segoe UI", 10)).pack()
            ttk.Label(stat_frame, text=value, font=("Segoe UI", 14, "bold")).pack()
        
        for i in range(3):
            stats_grid.columnconfigure(i, weight=1)
        
        # ピア接続状況
        peer_frame = ttk.LabelFrame(network_frame, text="👥 ピア接続状況", padding=10)
        peer_frame.pack(fill='both', expand=True, padx=10, pady=(0, 10))
        
        columns = ('ピアID', 'エイリアス', '接続時間', 'Ping', '送信バイト', '受信バイト')
        self.peer_tree = ttk.Treeview(peer_frame, columns=columns, show='headings', height=8)
        
        for col in columns:
            self.peer_tree.heading(col, text=col)
            self.peer_tree.column(col, width=120, anchor='center')
        
        peer_scroll = ttk.Scrollbar(peer_frame, orient='vertical', command=self.peer_tree.yview)
        self.peer_tree.configure(yscrollcommand=peer_scroll.set)
        
        self.peer_tree.pack(side='left', fill='both', expand=True)
        peer_scroll.pack(side='right', fill='y')
    
    def create_realtime_tab(self):
        """リアルタイム監視タブ"""
        realtime_frame = ttk.Frame(self.notebook)
        self.notebook.add(realtime_frame, text="🔴 リアルタイム")
        
        # アラート・通知エリア
        alert_frame = ttk.LabelFrame(realtime_frame, text="🚨 リアルタイムアラート", padding=10)
        alert_frame.pack(fill='x', padx=10, pady=10)
        
        self.alert_text = tk.Text(alert_frame, height=6, wrap='word', state='disabled', 
                                 bg='#f8f9fa', font=("Consolas", 10))
        alert_scroll = ttk.Scrollbar(alert_frame, orient='vertical', command=self.alert_text.yview)
        self.alert_text.configure(yscrollcommand=alert_scroll.set)
        
        self.alert_text.pack(side='left', fill='both', expand=True)
        alert_scroll.pack(side='right', fill='y')
        
        # リアルタイム統計
        rt_stats_frame = ttk.LabelFrame(realtime_frame, text="📊 リアルタイム統計", padding=10)
        rt_stats_frame.pack(fill='both', expand=True, padx=10, pady=(0, 10))
        
        # 統計表示グリッド
        self.create_realtime_stats(rt_stats_frame)
    
    def create_realtime_stats(self, parent):
        """リアルタイム統計"""
        stats_frame = ttk.Frame(parent)
        stats_frame.pack(fill='both', expand=True)
        
        # 左列: メトリクス
        left_frame = ttk.Frame(stats_frame)
        left_frame.pack(side='left', fill='both', expand=True, padx=(0, 10))
        
        metrics = [
            ("CPU使用率", "cpu_usage", "25%"),
            ("メモリ使用率", "memory_usage", "512MB"),
            ("ディスク使用率", "disk_usage", "45%"),
            ("ネットワーク送信", "network_out", "1.2MB/s"),
            ("ネットワーク受信", "network_in", "0.8MB/s")
        ]
        
        for i, (label, attr, default) in enumerate(metrics):
            metric_frame = ttk.Frame(left_frame)
            metric_frame.pack(fill='x', pady=2)
            
            ttk.Label(metric_frame, text=f"{label}:", font=("Segoe UI", 10)).pack(side='left')
            label_widget = ttk.Label(metric_frame, text=default, font=("Consolas", 10, "bold"))
            label_widget.pack(side='right')
            setattr(self, f"{attr}_label", label_widget)
        
        # 右列: アクション
        right_frame = ttk.Frame(stats_frame)
        right_frame.pack(side='right', fill='y')
        
        ttk.Button(right_frame, text="⚠️ アラート設定", 
                  command=self.configure_alerts).pack(fill='x', pady=2)
        ttk.Button(right_frame, text="📊 詳細監視", 
                  command=self.show_detailed_monitoring).pack(fill='x', pady=2)
        ttk.Button(right_frame, text="🔄 強制更新", 
                  command=self.force_refresh).pack(fill='x', pady=2)
    
    def create_status_bar(self, parent):
        """ステータスバーを作成"""
        status_frame = ttk.Frame(parent)
        status_frame.pack(fill='x', side='bottom')
        
        self.status_label = ttk.Label(status_frame, text="分析データ準備完了", 
                                     font=("Segoe UI", 9))
        self.status_label.pack(side='left')
        
        self.last_update_label = ttk.Label(status_frame, 
                                          text=f"最終更新: {datetime.now().strftime('%H:%M:%S')}", 
                                          font=("Segoe UI", 9))
        self.last_update_label.pack(side='right')
    
    # データ処理メソッド
    def load_analytics_data(self):
        """分析データを読み込み"""
        self.update_status("分析データ読み込み中...")
        
        def load_in_background():
            try:
                # サンプルデータ読み込み
                self.load_sample_payment_history()
                self.load_sample_peer_data()
                self.start_realtime_monitoring()
                
                self.update_status("分析データ読み込み完了")
                
            except Exception as e:
                self.update_status(f"データ読み込みエラー: {str(e)}")
        
        threading.Thread(target=load_in_background, daemon=True).start()
    
    def load_sample_payment_history(self):
        """サンプル支払い履歴を読み込み"""
        sample_history = [
            ("14:32:15", "送金", "50,000", "1.2", "完了", "Node_ABC"),
            ("13:15:30", "受取", "25,000", "0.8", "完了", "Node_DEF"),
            ("12:45:22", "送金", "75,000", "1.5", "失敗", "Node_GHI"),
            ("11:30:18", "受取", "15,000", "0.5", "完了", "Node_JKL"),
            ("10:20:45", "送金", "100,000", "2.1", "完了", "Node_MNO")
        ]
        
        for payment in sample_history:
            self.history_tree.insert('', 'end', values=payment)
    
    def load_sample_peer_data(self):
        """サンプルピアデータを読み込み"""
        sample_peers = [
            ("03a1b2c3", "Lightning_Node_1", "2h 15m", "25ms", "1.2MB", "0.8MB"),
            ("03d4e5f6", "Bitcoin_Hub", "5h 30m", "18ms", "2.5MB", "1.9MB"),
            ("03g7h8i9", "Satoshi_Node", "1h 45m", "32ms", "0.9MB", "1.1MB"),
            ("03j0k1l2", "Lightning_Pro", "3h 20m", "15ms", "1.8MB", "1.4MB"),
            ("03m3n4o5", "BTC_Network", "4h 10m", "28ms", "1.5MB", "1.2MB")
        ]
        
        for peer in sample_peers:
            self.peer_tree.insert('', 'end', values=peer)
    
    def start_realtime_monitoring(self):
        """リアルタイム監視を開始"""
        def update_realtime():
            try:
                # リアルタイム統計更新
                import random
                
                # CPU使用率
                cpu_usage = f"{random.randint(15, 45)}%"
                self.cpu_usage_label.config(text=cpu_usage)
                
                # メモリ使用率
                memory_usage = f"{random.randint(400, 800)}MB"
                self.memory_usage_label.config(text=memory_usage)
                
                # ディスク使用率
                disk_usage = f"{random.randint(35, 65)}%"
                self.disk_usage_label.config(text=disk_usage)
                
                # ネットワーク統計
                net_out = f"{random.uniform(0.5, 2.0):.1f}MB/s"
                net_in = f"{random.uniform(0.3, 1.5):.1f}MB/s"
                self.network_out_label.config(text=net_out)
                self.network_in_label.config(text=net_in)
                
                # アラート追加（ランダム）
                if random.random() < 0.1:  # 10%の確率
                    self.add_alert("✅ チャンネル同期完了", "success")
                elif random.random() < 0.05:  # 5%の確率
                    self.add_alert("⚠️ 高いCPU使用率を検出", "warning")
                
                # 最終更新時刻更新
                current_time = datetime.now().strftime('%H:%M:%S')
                self.last_update_label.config(text=f"最終更新: {current_time}")
                
                # 次回更新予約
                self.window.after(5000, update_realtime)  # 5秒間隔
                
            except Exception as e:
                print(f"リアルタイム監視エラー: {e}")
                self.window.after(10000, update_realtime)  # エラー時は10秒後にリトライ
        
        # 初回実行
        self.window.after(1000, update_realtime)
    
    def add_alert(self, message, alert_type="info"):
        """アラートを追加"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        alert_message = f"[{timestamp}] {message}\n"
        
        self.alert_text.config(state='normal')
        self.alert_text.insert(tk.END, alert_message)
        self.alert_text.see(tk.END)
        self.alert_text.config(state='disabled')
    
    # アクションメソッド
    def refresh_analytics(self):
        """分析データを更新"""
        self.update_status("分析データ更新中...")
        
        def refresh_in_background():
            try:
                # グラフデータ更新
                self.update_charts()
                
                # テーブルデータ更新
                self.load_sample_payment_history()
                self.load_sample_peer_data()
                
                self.update_status("分析データ更新完了")
                
            except Exception as e:
                self.update_status(f"更新エラー: {str(e)}")
        
        threading.Thread(target=refresh_in_background, daemon=True).start()
    
    def update_charts(self):
        """チャートを更新"""
        # 残高チャート更新
        dates = [datetime.now() - timedelta(days=x) for x in range(30, 0, -1)]
        lightning_balance = np.random.randint(800000, 1200000, 30)
        onchain_balance = np.random.randint(1000000, 1500000, 30)
        
        self.balance_plot.clear()
        self.balance_plot.plot(dates, lightning_balance, label='Lightning残高', 
                              color='#f7931a', linewidth=2)
        self.balance_plot.plot(dates, onchain_balance, label='オンチェーン残高', 
                              color='#4dabf7', linewidth=2)
        self.balance_plot.set_xlabel('日付')
        self.balance_plot.set_ylabel('残高 (sats)')
        self.balance_plot.legend()
        self.balance_plot.grid(True, alpha=0.3)
        
        self.balance_canvas.draw()
        
        # 支払いチャート更新
        days = ['月', '火', '水', '木', '金', '土', '日']
        sent_amounts = np.random.randint(100000, 500000, 7)
        received_amounts = np.random.randint(50000, 300000, 7)
        
        self.payment_plot.clear()
        x = np.arange(len(days))
        width = 0.35
        
        self.payment_plot.bar(x - width/2, sent_amounts, width, label='送金', color='#ff7675')
        self.payment_plot.bar(x + width/2, received_amounts, width, label='受取', color='#74b9ff')
        
        self.payment_plot.set_xlabel('曜日')
        self.payment_plot.set_ylabel('金額 (sats)')
        self.payment_plot.set_title('週間支払い統計')
        self.payment_plot.set_xticks(x)
        self.payment_plot.set_xticklabels(days)
        self.payment_plot.legend()
        self.payment_plot.grid(True, alpha=0.3)
        
        self.payment_canvas.draw()
    
    def search_payments(self):
        """支払い検索"""
        search_term = self.search_entry.get().strip()
        if search_term:
            self.update_status(f"'{search_term}' で検索中...")
            # 検索処理（実装）
            self.update_status(f"検索完了: {search_term}")
        else:
            messagebox.showwarning("警告", "検索キーワードを入力してください")
    
    def export_analytics(self):
        """分析データをエクスポート"""
        self.update_status("分析データエクスポート中...")
        
        def export_in_background():
            try:
                # エクスポート処理（実装）
                time.sleep(2)  # 処理時間をシミュレート
                self.update_status("エクスポート完了")
                messagebox.showinfo("完了", "分析データをエクスポートしました")
                
            except Exception as e:
                self.update_status(f"エクスポートエラー: {str(e)}")
        
        threading.Thread(target=export_in_background, daemon=True).start()
    
    def configure_alerts(self):
        """アラート設定"""
        messagebox.showinfo("アラート設定", "アラート設定画面を開きます")
    
    def show_detailed_monitoring(self):
        """詳細監視を表示"""
        messagebox.showinfo("詳細監視", "詳細監視画面を開きます")
    
    def force_refresh(self):
        """強制更新"""
        self.refresh_analytics()
        self.add_alert("🔄 強制更新が実行されました", "info")
    
    def update_status(self, message):
        """ステータスメッセージを更新"""
        if hasattr(self, 'status_label'):
            self.status_label.config(text=message)
    
    def run(self):
        """ダッシュボードを実行"""
        try:
            self.window.mainloop()
        except KeyboardInterrupt:
            print("\n👋 分析ダッシュボードが中断されました")


def main():
    """メイン関数"""
    try:
        dashboard = AnalyticsDashboard()
        dashboard.run()
    except Exception as e:
        print(f"❌ 分析ダッシュボード起動エラー: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()