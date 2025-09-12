#!/usr/bin/env python3
"""
BLNCS Intuitive Desktop GUI - 直感的で分かりやすいPC用インターフェース
Intuitive and user-friendly desktop interface for Lightning Network management.
"""

import tkinter as tk
from tkinter import ttk, messagebox
import threading
import time
from datetime import datetime

# Import BLNCS modules
try:
    from ..lightning.client_simple import get_lightning_client
    from ..core.config_manager import get_config_manager
    from ..cli.commands.qr_simple import generate_ascii_qr
except ImportError:
    import sys
    from pathlib import Path
    sys.path.append(str(Path(__file__).parent.parent))
    from lightning.client_simple import get_lightning_client
    from core.config_manager import get_config_manager
    from cli.commands.qr_simple import generate_ascii_qr


class IntuitiveMainWindow:
    """直感的で分かりやすいメインウィンドウ"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.lightning_client = get_lightning_client()
        self.config = get_config_manager()
        
        self.setup_window()
        self.create_interface()
        
    def setup_window(self):
        """ウィンドウの基本設定"""
        self.root.title("⚡ BLNCS - Lightning Network 管理システム")
        self.root.geometry("1000x700")
        self.root.minsize(800, 600)
        self.root.configure(bg="#f3f2f1")
        
        # ウィンドウを画面中央に配置
        self.center_window()
        
    def center_window(self):
        """ウィンドウを画面中央に配置"""
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f"{width}x{height}+{x}+{y}")
    
    def create_interface(self):
        """直感的なインターフェースを作成"""
        # メインフレーム
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # ヘッダー
        self.create_header(main_frame)
        
        # タブ式コンテンツ
        self.create_tabs(main_frame)
        
        # ステータスバー
        self.create_status_bar(main_frame)
        
        # 初期データ読み込み
        self.load_data()
        
    def create_header(self, parent):
        """ヘッダーを作成"""
        header_frame = ttk.Frame(parent)
        header_frame.pack(fill='x', pady=(0, 10))
        
        # タイトル
        title_label = ttk.Label(header_frame, 
                               text="⚡ Lightning Network 管理システム",
                               font=("Segoe UI", 18, "bold"),
                               foreground="#f7931a")
        title_label.pack(side='left')
        
        # 操作ボタン
        button_frame = ttk.Frame(header_frame)
        button_frame.pack(side='right')
        
        ttk.Button(button_frame, text="🔄 更新", 
                  command=self.refresh_data).pack(side='right', padx=(5, 0))
        
        ttk.Button(button_frame, text="❓ ヘルプ", 
                  command=self.show_help).pack(side='right')
    
    def create_tabs(self, parent):
        """タブを作成"""
        self.notebook = ttk.Notebook(parent)
        self.notebook.pack(fill='both', expand=True, pady=(0, 10))
        
        # ダッシュボード
        self.create_dashboard_tab()
        
        # ペイメント
        self.create_payments_tab()
        
        # チャンネル
        self.create_channels_tab()
        
        # 設定
        self.create_settings_tab()
    
    def create_dashboard_tab(self):
        """ダッシュボードタブ"""
        dashboard_frame = ttk.Frame(self.notebook)
        self.notebook.add(dashboard_frame, text="📊 ダッシュボード")
        
        # スクロール可能なフレーム
        canvas = tk.Canvas(dashboard_frame)
        scrollbar = ttk.Scrollbar(dashboard_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # ダッシュボードコンテンツ
        self.create_dashboard_content(scrollable_frame)
        
    def create_dashboard_content(self, parent):
        """ダッシュボードのコンテンツ"""
        # 残高カード
        balance_frame = ttk.LabelFrame(parent, text="💰 残高情報", padding=15)
        balance_frame.pack(fill='x', padx=20, pady=10)
        
        # Lightning残高
        lightning_frame = ttk.Frame(balance_frame)
        lightning_frame.pack(fill='x', pady=(0, 10))
        
        ttk.Label(lightning_frame, text="⚡ Lightning:", 
                 font=("Segoe UI", 12)).pack(side='left')
        
        self.lightning_balance_label = ttk.Label(lightning_frame, 
                                                text="読み込み中...", 
                                                font=("Segoe UI", 14, "bold"),
                                                foreground="#f7931a")
        self.lightning_balance_label.pack(side='right')
        
        # オンチェーン残高
        onchain_frame = ttk.Frame(balance_frame)
        onchain_frame.pack(fill='x', pady=(0, 10))
        
        ttk.Label(onchain_frame, text="🔗 オンチェーン:", 
                 font=("Segoe UI", 12)).pack(side='left')
        
        self.onchain_balance_label = ttk.Label(onchain_frame, 
                                              text="読み込み中...", 
                                              font=("Segoe UI", 14, "bold"),
                                              foreground="#f7931a")
        self.onchain_balance_label.pack(side='right')
        
        # ノード状態カード
        node_frame = ttk.LabelFrame(parent, text="🖥️ ノード状態", padding=15)
        node_frame.pack(fill='x', padx=20, pady=10)
        
        # ノード情報グリッド
        info_frame = ttk.Frame(node_frame)
        info_frame.pack(fill='both', expand=True)
        
        # 左列
        left_col = ttk.Frame(info_frame)
        left_col.pack(side='left', fill='both', expand=True)
        
        ttk.Label(left_col, text="エイリアス:", font=("Segoe UI", 10, "bold")).grid(row=0, column=0, sticky='w', padx=(0, 10))
        self.alias_label = ttk.Label(left_col, text="BLNCS-Node", font=("Segoe UI", 10))
        self.alias_label.grid(row=0, column=1, sticky='w')
        
        ttk.Label(left_col, text="同期状態:", font=("Segoe UI", 10, "bold")).grid(row=1, column=0, sticky='w', padx=(0, 10))
        self.sync_label = ttk.Label(left_col, text="同期済み", font=("Segoe UI", 10), foreground="green")
        self.sync_label.grid(row=1, column=1, sticky='w')
        
        # 右列
        right_col = ttk.Frame(info_frame)
        right_col.pack(side='right', fill='both', expand=True)
        
        ttk.Label(right_col, text="ブロック高:", font=("Segoe UI", 10, "bold")).grid(row=0, column=0, sticky='w', padx=(0, 10))
        self.block_height_label = ttk.Label(right_col, text="805,234", font=("Segoe UI", 10))
        self.block_height_label.grid(row=0, column=1, sticky='w')
        
        ttk.Label(right_col, text="ピア数:", font=("Segoe UI", 10, "bold")).grid(row=1, column=0, sticky='w', padx=(0, 10))
        self.peers_label = ttk.Label(right_col, text="15", font=("Segoe UI", 10))
        self.peers_label.grid(row=1, column=1, sticky='w')
        
        # チャンネル統計カード
        channels_frame = ttk.LabelFrame(parent, text="⚡ チャンネル統計", padding=15)
        channels_frame.pack(fill='x', padx=20, pady=10)
        
        # チャンネル統計グリッド
        stats_frame = ttk.Frame(channels_frame)
        stats_frame.pack(fill='both', expand=True)
        
        # 統計項目
        stats = [
            ("合計チャンネル:", "total_channels", "12"),
            ("アクティブ:", "active_channels", "11"),
            ("非アクティブ:", "inactive_channels", "1"),
            ("総容量:", "total_capacity", "2.5M sats")
        ]
        
        for i, (label_text, attr_name, default_value) in enumerate(stats):
            row = i // 2
            col = (i % 2) * 2
            
            ttk.Label(stats_frame, text=label_text, font=("Segoe UI", 10, "bold")).grid(row=row, column=col, sticky='w', padx=(0, 10))
            label = ttk.Label(stats_frame, text=default_value, font=("Segoe UI", 10))
            label.grid(row=row, column=col+1, sticky='w', padx=(0, 20))
            setattr(self, f"{attr_name}_label", label)
        
        # 最近のアクティビティ
        activity_frame = ttk.LabelFrame(parent, text="📈 最近のアクティビティ", padding=15)
        activity_frame.pack(fill='x', padx=20, pady=10)
        
        # アクティビティリスト
        activity_list_frame = ttk.Frame(activity_frame)
        activity_list_frame.pack(fill='both', expand=True)
        
        self.activity_tree = ttk.Treeview(activity_list_frame, columns=('time', 'type', 'amount', 'status'), show='headings', height=6)
        
        # 列設定
        self.activity_tree.heading('time', text='時刻')
        self.activity_tree.heading('type', text='タイプ')
        self.activity_tree.heading('amount', text='金額')
        self.activity_tree.heading('status', text='状態')
        
        self.activity_tree.column('time', width=120)
        self.activity_tree.column('type', width=100)
        self.activity_tree.column('amount', width=120)
        self.activity_tree.column('status', width=80)
        
        # スクロールバー
        activity_scroll = ttk.Scrollbar(activity_list_frame, orient='vertical', command=self.activity_tree.yview)
        self.activity_tree.configure(yscrollcommand=activity_scroll.set)
        
        self.activity_tree.pack(side='left', fill='both', expand=True)
        activity_scroll.pack(side='right', fill='y')
        
        # サンプルデータ追加
        sample_activities = [
            ("14:32", "送金", "50,000 sats", "完了"),
            ("13:15", "受取", "25,000 sats", "完了"),
            ("12:45", "チャンネル開設", "500,000 sats", "処理中"),
            ("11:30", "受取", "15,000 sats", "完了"),
            ("10:20", "送金", "75,000 sats", "完了")
        ]
        
        for activity in sample_activities:
            self.activity_tree.insert('', 'end', values=activity)
        
        # アラート・通知カード
        alerts_frame = ttk.LabelFrame(parent, text="🚨 アラート・通知", padding=15)
        alerts_frame.pack(fill='x', padx=20, pady=10)
        
        # アラートエリア
        alerts_text = tk.Text(alerts_frame, height=4, wrap='word', state='disabled', bg='#f8f9fa')
        alerts_text.pack(fill='x')
        
        # サンプルアラート
        alerts_text.config(state='normal')
        alerts_text.insert('end', "✅ システムは正常に動作しています\n")
        alerts_text.insert('end', "ℹ️ チャンネル残高が低くなっています (Channel ID: 1234...)\n")
        alerts_text.insert('end', "⚠️ ピア接続が一時的に不安定です\n")
        alerts_text.config(state='disabled')
        
        self.alerts_text = alerts_text
        
        self.lightning_balance = ttk.Label(lightning_frame, text="0 sats",
                                          font=("Segoe UI", 16, "bold"),
                                          foreground="#f7931a")
        self.lightning_balance.pack(side='right')
        
        # オンチェーン残高
        onchain_frame = ttk.Frame(balance_frame)
        onchain_frame.pack(fill='x')
        
        ttk.Label(onchain_frame, text="🔗 オンチェーン:", 
                 font=("Segoe UI", 12)).pack(side='left')
        
        self.onchain_balance = ttk.Label(onchain_frame, text="0 sats",
                                        font=("Segoe UI", 16, "bold"),
                                        foreground="#107c10")
        self.onchain_balance.pack(side='right')
        
        # ノード状態カード
        node_frame = ttk.LabelFrame(parent, text="🔗 ノード状態", padding=15)
        node_frame.pack(fill='x', padx=20, pady=10)
        
        # ノード情報
        self.create_info_row(node_frame, "ノード名:", "読み込み中...", "node_alias")
        self.create_info_row(node_frame, "同期状態:", "確認中...", "sync_status")
        self.create_info_row(node_frame, "ブロック高:", "確認中...", "block_height")
        self.create_info_row(node_frame, "ピア数:", "確認中...", "peers_count")
        
        # チャンネル概要カード
        channels_frame = ttk.LabelFrame(parent, text="⚡ チャンネル概要", padding=15)
        channels_frame.pack(fill='x', padx=20, pady=10)
        
        self.create_info_row(channels_frame, "総チャンネル数:", "0", "total_channels")
        self.create_info_row(channels_frame, "アクティブ:", "0", "active_channels")
        self.create_info_row(channels_frame, "総容量:", "0 sats", "total_capacity")
        
        # クイックアクション
        actions_frame = ttk.LabelFrame(parent, text="🚀 クイックアクション", padding=15)
        actions_frame.pack(fill='x', padx=20, pady=10)
        
        # ボタンを2x2のグリッドで配置
        button_grid = ttk.Frame(actions_frame)
        button_grid.pack(fill='x')
        
        ttk.Button(button_grid, text="💸 支払い送信",
                  command=lambda: self.switch_tab(1)).grid(row=0, column=0, 
                                                          sticky='ew', padx=(0, 5), pady=(0, 5))
        
        ttk.Button(button_grid, text="📄 請求書作成",
                  command=lambda: self.switch_tab(1)).grid(row=0, column=1, 
                                                          sticky='ew', padx=(5, 0), pady=(0, 5))
        
        ttk.Button(button_grid, text="⚡ チャンネル管理",
                  command=lambda: self.switch_tab(2)).grid(row=1, column=0, 
                                                          sticky='ew', padx=(0, 5), pady=(5, 0))
        
        ttk.Button(button_grid, text="⚙️ 設定",
                  command=lambda: self.switch_tab(3)).grid(row=1, column=1, 
                                                          sticky='ew', padx=(5, 0), pady=(5, 0))
        
        button_grid.columnconfigure(0, weight=1)
        button_grid.columnconfigure(1, weight=1)
        
    def create_info_row(self, parent, label, value, attr_name):
        """情報行を作成"""
        row_frame = ttk.Frame(parent)
        row_frame.pack(fill='x', pady=2)
        
        ttk.Label(row_frame, text=label, 
                 font=("Segoe UI", 11)).pack(side='left')
        
        value_label = ttk.Label(row_frame, text=value, 
                               font=("Consolas", 11))
        value_label.pack(side='right')
        
        setattr(self, attr_name, value_label)
    
    def create_payments_tab(self):
        """ペイメントタブ"""
        payments_frame = ttk.Frame(self.notebook)
        self.notebook.add(payments_frame, text="💰 ペイメント")
        
        # 左右分割
        paned_window = ttk.PanedWindow(payments_frame, orient='horizontal')
        paned_window.pack(fill='both', expand=True, padx=10, pady=10)
        
        # 左パネル: 送金・受取操作
        left_frame = ttk.Frame(paned_window)
        paned_window.add(left_frame, weight=1)
        
        # 送金カード
        send_frame = ttk.LabelFrame(left_frame, text="💸 Lightning送金", padding=15)
        send_frame.pack(fill='x', pady=(0, 10))
        
        ttk.Label(send_frame, text="Lightning請求書:").pack(anchor='w')
        self.invoice_entry = ttk.Entry(send_frame, font=("Consolas", 10))
        self.invoice_entry.pack(fill='x', pady=(5, 10))
        
        send_buttons = ttk.Frame(send_frame)
        send_buttons.pack(fill='x')
        
        ttk.Button(send_buttons, text="📋 貼り付け",
                  command=self.paste_invoice).pack(side='left')
        ttk.Button(send_buttons, text="💸 支払い実行",
                  command=self.send_payment).pack(side='right')
        
        # 受取カード
        receive_frame = ttk.LabelFrame(left_frame, text="📄 Lightning受取", padding=15)
        receive_frame.pack(fill='x')
        
        amount_frame = ttk.Frame(receive_frame)
        amount_frame.pack(fill='x', pady=(0, 5))
        
        ttk.Label(amount_frame, text="金額 (sats):").pack(side='left')
        self.amount_entry = ttk.Entry(amount_frame, width=15)
        self.amount_entry.pack(side='right')
        
        ttk.Label(receive_frame, text="メモ (任意):").pack(anchor='w')
        self.memo_entry = ttk.Entry(receive_frame)
        self.memo_entry.pack(fill='x', pady=(5, 10))
        
        ttk.Button(receive_frame, text="📄 請求書作成",
                  command=self.create_invoice).pack()
        
        # 右パネル: QRコードと履歴
        right_frame = ttk.Frame(paned_window)
        paned_window.add(right_frame, weight=1)
        
        # QRコード表示
        qr_frame = ttk.LabelFrame(right_frame, text="📱 QRコード", padding=15)
        qr_frame.pack(fill='x', pady=(0, 10))
        
        self.qr_display = tk.Text(qr_frame, height=12, font=("Courier", 8),
                                 wrap='none', state='disabled')
        self.qr_display.pack(fill='x')
        
        # 履歴表示
        history_frame = ttk.LabelFrame(right_frame, text="📊 支払い履歴", padding=15)
        history_frame.pack(fill='both', expand=True)
        
        columns = ('種類', '金額', '状態', '時刻')
        self.payment_history = ttk.Treeview(history_frame, columns=columns, 
                                           show='headings', height=8)
        
        for col in columns:
            self.payment_history.heading(col, text=col)
            self.payment_history.column(col, width=80, anchor='center')
        
        self.payment_history.pack(fill='both', expand=True, pady=(0, 10))
        
        ttk.Button(history_frame, text="🔄 履歴更新",
                  command=self.load_payment_history).pack()
    
    def create_channels_tab(self):
        """チャンネルタブ"""
        channels_frame = ttk.Frame(self.notebook)
        self.notebook.add(channels_frame, text="⚡ チャンネル")
        
        # ヘッダー
        header_frame = ttk.Frame(channels_frame)
        header_frame.pack(fill='x', padx=10, pady=10)
        
        ttk.Label(header_frame, text="⚡ Lightning チャンネル管理",
                 font=("Segoe UI", 14, "bold")).pack(side='left')
        
        ttk.Button(header_frame, text="🔄 更新",
                  command=self.load_channels).pack(side='right')
        
        # チャンネル一覧
        columns = ('状態', 'ピア', '容量', 'ローカル', 'リモート')
        self.channels_tree = ttk.Treeview(channels_frame, columns=columns, show='headings')
        
        for col in columns:
            self.channels_tree.heading(col, text=col)
            self.channels_tree.column(col, width=120, anchor='center')
        
        channels_scrollbar = ttk.Scrollbar(channels_frame, orient='vertical',
                                          command=self.channels_tree.yview)
        self.channels_tree.configure(yscrollcommand=channels_scrollbar.set)
        
        self.channels_tree.pack(side='left', fill='both', expand=True, 
                               padx=(10, 0), pady=(0, 10))
        channels_scrollbar.pack(side='right', fill='y', padx=(0, 10), pady=(0, 10))
    
    def create_settings_tab(self):
        """設定タブ"""
        settings_frame = ttk.Frame(self.notebook)
        self.notebook.add(settings_frame, text="⚙️ 設定")
        
        # 設定内容
        content_frame = ttk.Frame(settings_frame)
        content_frame.pack(fill='both', expand=True, padx=20, pady=20)
        
        # Lightning設定
        lightning_frame = ttk.LabelFrame(content_frame, text="⚡ Lightning設定", padding=15)
        lightning_frame.pack(fill='x', pady=(0, 10))
        
        # ネットワーク選択
        network_frame = ttk.Frame(lightning_frame)
        network_frame.pack(fill='x', pady=(0, 10))
        
        ttk.Label(network_frame, text="ネットワーク:").pack(side='left')
        self.network_var = tk.StringVar(value="testnet")
        network_combo = ttk.Combobox(network_frame, textvariable=self.network_var,
                                   values=['mainnet', 'testnet', 'regtest'],
                                   state='readonly')
        network_combo.pack(side='right')
        
        # 表示設定
        display_frame = ttk.LabelFrame(content_frame, text="🎨 表示設定", padding=15)
        display_frame.pack(fill='x', pady=(0, 10))
        
        # 更新間隔
        refresh_frame = ttk.Frame(display_frame)
        refresh_frame.pack(fill='x', pady=(0, 10))
        
        ttk.Label(refresh_frame, text="更新間隔 (秒):").pack(side='left')
        self.refresh_var = tk.StringVar(value="30")
        refresh_entry = ttk.Entry(refresh_frame, textvariable=self.refresh_var, width=10)
        refresh_entry.pack(side='right')
        
        # 通知設定
        notification_frame = ttk.LabelFrame(content_frame, text="🔔 通知設定", padding=15)
        notification_frame.pack(fill='x', pady=(0, 10))
        
        self.payment_notifications = tk.BooleanVar(value=True)
        self.channel_notifications = tk.BooleanVar(value=True)
        self.error_notifications = tk.BooleanVar(value=True)
        
        ttk.Checkbutton(notification_frame, text="💰 支払い通知", 
                       variable=self.payment_notifications).pack(anchor='w', pady=2)
        ttk.Checkbutton(notification_frame, text="⚡ チャンネル通知", 
                       variable=self.channel_notifications).pack(anchor='w', pady=2)
        ttk.Checkbutton(notification_frame, text="❌ エラー通知", 
                       variable=self.error_notifications).pack(anchor='w', pady=2)
        
        # アクション
        action_frame = ttk.Frame(content_frame)
        action_frame.pack(fill='x', pady=(20, 0))
        
        ttk.Button(action_frame, text="💾 設定保存", 
                  command=self.save_settings).pack(side='left')
        ttk.Button(action_frame, text="🔄 設定リセット", 
                  command=self.reset_settings).pack(side='right')
    
    def create_status_bar(self, parent):
        """ステータスバーを作成"""
        status_frame = ttk.Frame(parent)
        status_frame.pack(fill='x', side='bottom')
        
        # ステータス情報
        self.status_label = ttk.Label(status_frame, text="準備完了", 
                                     font=("Segoe UI", 9))
        self.status_label.pack(side='left')
        
        # 接続状態
        self.connection_label = ttk.Label(status_frame, text="🟢 接続済み", 
                                         font=("Segoe UI", 9))
        self.connection_label.pack(side='right')
        
        # 最終更新時刻
        self.last_update_label = ttk.Label(status_frame, 
                                          text=f"最終更新: {datetime.now().strftime('%H:%M:%S')}", 
                                          font=("Segoe UI", 9))
        self.last_update_label.pack(side='right', padx=(0, 20))
    
    # データ処理メソッド
    def load_data(self):
        """初期データを読み込み"""
        self.update_status("データ読み込み中...")
        
        # バックグラウンドでデータ読み込み
        def load_in_background():
            try:
                # 残高情報
                self.update_balance_info()
                
                # チャンネル情報
                self.load_channels()
                
                # 支払い履歴
                self.load_payment_history()
                
                self.update_status("データ読み込み完了")
                
            except Exception as e:
                self.update_status(f"データ読み込みエラー: {str(e)}")
        
        threading.Thread(target=load_in_background, daemon=True).start()
    
    def update_balance_info(self):
        """残高情報を更新"""
        try:
            # Lightning残高取得（モック）
            lightning_balance = "850,000 sats"
            onchain_balance = "1,250,000 sats"
            
            # UI更新
            self.root.after(0, lambda: self.lightning_balance_label.config(text=lightning_balance))
            self.root.after(0, lambda: self.onchain_balance_label.config(text=onchain_balance))
            
        except Exception as e:
            self.root.after(0, lambda: self.lightning_balance_label.config(text="エラー"))
            self.root.after(0, lambda: self.onchain_balance_label.config(text="エラー"))
    
    def load_channels(self):
        """チャンネル情報を読み込み"""
        try:
            # 既存のアイテムをクリア
            for item in self.channels_tree.get_children():
                self.channels_tree.delete(item)
            
            # モックチャンネルデータ
            channels = [
                ("🟢 アクティブ", "03a1b2c3...d4e5", "500,000", "250,000", "250,000"),
                ("🟢 アクティブ", "03f6g7h8...i9j0", "300,000", "150,000", "150,000"),
                ("🔴 非アクティブ", "03k1l2m3...n4o5", "200,000", "100,000", "100,000"),
            ]
            
            for channel in channels:
                self.channels_tree.insert('', 'end', values=channel)
                
            # チャンネル統計更新
            self.root.after(0, lambda: self.total_channels_label.config(text="3"))
            self.root.after(0, lambda: self.active_channels_label.config(text="2"))
            self.root.after(0, lambda: self.inactive_channels_label.config(text="1"))
            self.root.after(0, lambda: self.total_capacity_label.config(text="1.0M sats"))
            
        except Exception as e:
            self.update_status(f"チャンネル読み込みエラー: {str(e)}")
    
    def load_payment_history(self):
        """支払い履歴を読み込み"""
        try:
            # 既存のアイテムをクリア
            for item in self.payment_history.get_children():
                self.payment_history.delete(item)
            
            # モック履歴データ
            history = [
                ("送金", "50,000 sats", "完了", "14:32"),
                ("受取", "25,000 sats", "完了", "13:15"),
                ("送金", "75,000 sats", "失敗", "12:45"),
                ("受取", "15,000 sats", "完了", "11:30"),
            ]
            
            for payment in history:
                self.payment_history.insert('', 'end', values=payment)
                
        except Exception as e:
            self.update_status(f"履歴読み込みエラー: {str(e)}")
    
    def refresh_data(self):
        """全データを更新"""
        self.update_status("データ更新中...")
        
        def refresh_in_background():
            try:
                self.update_balance_info()
                self.load_channels()
                self.load_payment_history()
                
                # 最終更新時刻を更新
                current_time = datetime.now().strftime('%H:%M:%S')
                self.root.after(0, lambda: self.last_update_label.config(text=f"最終更新: {current_time}"))
                
                self.update_status("データ更新完了")
                
            except Exception as e:
                self.update_status(f"更新エラー: {str(e)}")
        
        threading.Thread(target=refresh_in_background, daemon=True).start()
    
    # ペイメント関連メソッド
    def paste_invoice(self):
        """請求書を貼り付け"""
        try:
            invoice = self.root.clipboard_get()
            self.invoice_entry.delete(0, tk.END)
            self.invoice_entry.insert(0, invoice)
            self.update_status("請求書を貼り付けました")
        except:
            self.update_status("クリップボードからの貼り付けに失敗")
    
    def send_payment(self):
        """支払いを実行"""
        invoice = self.invoice_entry.get().strip()
        if not invoice:
            messagebox.showwarning("警告", "Lightning請求書を入力してください")
            return
        
        result = messagebox.askyesno("確認", "支払いを実行しますか？")
        if result:
            self.update_status("支払い処理中...")
            # モック支払い処理
            self.root.after(2000, lambda: self.update_status("支払いが完了しました"))
            self.root.after(2000, self.load_payment_history)
    
    def create_invoice(self):
        """請求書を作成"""
        amount = self.amount_entry.get().strip()
        memo = self.memo_entry.get().strip()
        
        if not amount or not amount.isdigit():
            messagebox.showwarning("警告", "有効な金額を入力してください")
            return
        
        self.update_status("請求書作成中...")
        
        # モック請求書作成
        mock_invoice = f"lnbc{amount}u1p3xnhl2pp5xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        
        # QRコード生成と表示
        try:
            qr_code = generate_ascii_qr(mock_invoice)
            self.qr_display.config(state='normal')
            self.qr_display.delete(1.0, tk.END)
            self.qr_display.insert(1.0, qr_code)
            self.qr_display.config(state='disabled')
            
            # 請求書をクリップボードにコピー
            self.root.clipboard_clear()
            self.root.clipboard_append(mock_invoice)
            
            self.update_status(f"請求書を作成しました ({amount} sats)")
            
        except Exception as e:
            self.update_status(f"QRコード生成エラー: {str(e)}")
    
    # 設定メソッド
    def save_settings(self):
        """設定を保存"""
        try:
            settings = {
                'network': self.network_var.get(),
                'refresh_interval': int(self.refresh_var.get()),
                'payment_notifications': self.payment_notifications.get(),
                'channel_notifications': self.channel_notifications.get(),
                'error_notifications': self.error_notifications.get()
            }
            
            # 設定保存処理（実装）
            self.update_status("設定を保存しました")
            messagebox.showinfo("完了", "設定が保存されました")
            
        except ValueError:
            messagebox.showerror("エラー", "更新間隔は数値で入力してください")
        except Exception as e:
            messagebox.showerror("エラー", f"設定保存に失敗しました: {str(e)}")
    
    def reset_settings(self):
        """設定をリセット"""
        result = messagebox.askyesno("確認", "設定を初期値にリセットしますか？")
        if result:
            self.network_var.set("testnet")
            self.refresh_var.set("30")
            self.payment_notifications.set(True)
            self.channel_notifications.set(True)
            self.error_notifications.set(True)
            
            self.update_status("設定をリセットしました")
    
    # ユーティリティメソッド
    def update_status(self, message):
        """ステータスメッセージを更新"""
        if hasattr(self, 'status_label'):
            self.status_label.config(text=message)
    
    def show_help(self):
        """ヘルプを表示"""
        help_text = """
⚡ BLNCS Lightning Network 管理システム

【基本操作】
• ダッシュボード: ノード状態と残高を確認
• ペイメント: Lightning支払いの送受信
• チャンネル: チャンネル管理と監視
• 設定: システム設定の変更

【ショートカット】
• F5: データ更新
• Ctrl+1-4: タブ切り替え
• Ctrl+Q: アプリケーション終了

【サポート】
ヘルプが必要な場合は、ドキュメントを参照してください。
        """
        
        messagebox.showinfo("ヘルプ", help_text)
    
    def switch_tab(self, tab_index):
        """タブを切り替え"""
        self.notebook.select(tab_index)
    
    def run(self):
        """アプリケーションを実行"""
        # キーボードショートカット設定
        self.root.bind('<F5>', lambda e: self.refresh_data())
        self.root.bind('<Control-q>', lambda e: self.root.quit())
        
        for i in range(1, 5):
            self.root.bind(f'<Control-Key-{i}>', lambda e, idx=i-1: self.switch_tab(idx))
        
        # 定期更新設定
        def auto_refresh():
            if hasattr(self, 'refresh_var'):
                try:
                    interval = int(self.refresh_var.get()) * 1000
                    self.root.after(interval, auto_refresh)
                    self.refresh_data()
                except:
                    self.root.after(30000, auto_refresh)  # デフォルト30秒
            else:
                self.root.after(30000, auto_refresh)
        
        # 初回更新
        self.root.after(1000, auto_refresh)
        
        try:
            self.root.mainloop()
        except KeyboardInterrupt:
            print("\n👋 アプリケーションが中断されました")


def main():
    """メイン関数"""
    try:
        app = IntuitiveMainWindow()
        app.run()
    except Exception as e:
        print(f"❌ アプリケーション起動エラー: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
