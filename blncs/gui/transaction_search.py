#!/usr/bin/env python3
"""
BLNCS Transaction Search & Filtering - 取引履歴検索・フィルタリング
Advanced transaction history search and filtering capabilities.
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from datetime import datetime, timedelta
import threading
import json
import csv

try:
    from ..core.config_manager import get_config_manager
    from ..lightning.client_simple import get_lightning_client
    from ..core.history import get_history_manager
except ImportError:
    import sys
    from pathlib import Path
    sys.path.append(str(Path(__file__).parent.parent))
    from core.config_manager import get_config_manager
    from lightning.client_simple import get_lightning_client
    from core.history import get_history_manager


class TransactionSearchWindow:
    """取引履歴検索・フィルタリングウィンドウ"""
    
    def __init__(self, parent=None):
        if parent:
            self.window = tk.Toplevel(parent)
        else:
            self.window = tk.Tk()
        
        self.lightning_client = get_lightning_client()
        self.config = get_config_manager()
        self.history_manager = get_history_manager()
        
        self.setup_window()
        self.create_interface()
        self.load_initial_data()
    
    def setup_window(self):
        """ウィンドウの基本設定"""
        self.window.title("🔍 BLNCS - 取引履歴検索・フィルタリング")
        self.window.geometry("1100x700")
        self.window.minsize(900, 600)
        self.window.configure(bg="#f8f9fa")
    
    def create_interface(self):
        """インターフェースを作成"""
        # メインフレーム
        main_frame = ttk.Frame(self.window)
        main_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # ヘッダー
        self.create_header(main_frame)
        
        # 検索・フィルター
        self.create_search_filters(main_frame)
        
        # 結果表示
        self.create_results_area(main_frame)
        
        # ステータスバー
        self.create_status_bar(main_frame)
    
    def create_header(self, parent):
        """ヘッダーを作成"""
        header_frame = ttk.Frame(parent)
        header_frame.pack(fill='x', pady=(0, 10))
        
        # タイトル
        title_label = ttk.Label(header_frame, 
                               text="🔍 取引履歴検索・フィルタリング",
                               font=("Segoe UI", 16, "bold"),
                               foreground="#0066cc")
        title_label.pack(side='left')
        
        # 操作ボタン
        button_frame = ttk.Frame(header_frame)
        button_frame.pack(side='right')
        
        ttk.Button(button_frame, text="📤 エクスポート", 
                  command=self.export_results).pack(side='right', padx=(5, 0))
        
        ttk.Button(button_frame, text="🔄 更新", 
                  command=self.refresh_data).pack(side='right')
    
    def create_search_filters(self, parent):
        """検索・フィルター部分を作成"""
        filter_frame = ttk.LabelFrame(parent, text="🔍 検索・フィルター", padding=15)
        filter_frame.pack(fill='x', pady=(0, 10))
        
        # 上段: テキスト検索
        search_row = ttk.Frame(filter_frame)
        search_row.pack(fill='x', pady=(0, 10))
        
        ttk.Label(search_row, text="キーワード:", font=("Segoe UI", 10, "bold")).pack(side='left')
        self.search_entry = ttk.Entry(search_row, font=("Segoe UI", 10), width=30)
        self.search_entry.pack(side='left', padx=(10, 10))
        
        ttk.Button(search_row, text="🔍 検索", 
                  command=self.perform_search).pack(side='left')
        ttk.Button(search_row, text="🧹 クリア", 
                  command=self.clear_search).pack(side='left', padx=(5, 0))
        
        # 中段: フィルター条件
        filter_row1 = ttk.Frame(filter_frame)
        filter_row1.pack(fill='x', pady=(0, 10))
        
        # 期間選択
        ttk.Label(filter_row1, text="期間:", font=("Segoe UI", 10, "bold")).pack(side='left')
        self.period_var = tk.StringVar(value="30日")
        period_combo = ttk.Combobox(filter_row1, textvariable=self.period_var,
                                   values=['1日', '7日', '30日', '90日', '1年', 'カスタム'],
                                   state='readonly', width=12)
        period_combo.pack(side='left', padx=(10, 20))
        period_combo.bind('<<ComboboxSelected>>', self.on_period_changed)
        
        # 取引タイプ
        ttk.Label(filter_row1, text="タイプ:", font=("Segoe UI", 10, "bold")).pack(side='left')
        self.type_var = tk.StringVar(value="すべて")
        type_combo = ttk.Combobox(filter_row1, textvariable=self.type_var,
                                 values=['すべて', '送金', '受取', 'チャンネル開設', 'チャンネル閉鎖'],
                                 state='readonly', width=15)
        type_combo.pack(side='left', padx=(10, 20))
        
        # ステータス
        ttk.Label(filter_row1, text="ステータス:", font=("Segoe UI", 10, "bold")).pack(side='left')
        self.status_var = tk.StringVar(value="すべて")
        status_combo = ttk.Combobox(filter_row1, textvariable=self.status_var,
                                   values=['すべて', '完了', '処理中', '失敗', 'キャンセル'],
                                   state='readonly', width=12)
        status_combo.pack(side='left', padx=(10, 0))
        
        # 下段: 金額範囲・詳細フィルター
        filter_row2 = ttk.Frame(filter_frame)
        filter_row2.pack(fill='x', pady=(0, 10))
        
        # 金額範囲
        ttk.Label(filter_row2, text="金額範囲:", font=("Segoe UI", 10, "bold")).pack(side='left')
        self.min_amount_entry = ttk.Entry(filter_row2, width=12, font=("Segoe UI", 10))
        self.min_amount_entry.pack(side='left', padx=(10, 5))
        ttk.Label(filter_row2, text="〜").pack(side='left')
        self.max_amount_entry = ttk.Entry(filter_row2, width=12, font=("Segoe UI", 10))
        self.max_amount_entry.pack(side='left', padx=(5, 10))
        ttk.Label(filter_row2, text="sats").pack(side='left', padx=(0, 20))
        
        # 高度なフィルター
        self.advanced_filters_var = tk.BooleanVar()\n        ttk.Checkbutton(filter_row2, text="高度なフィルターを表示",
                       variable=self.advanced_filters_var,
                       command=self.toggle_advanced_filters).pack(side='left')
        
        # アクションボタン
        action_row = ttk.Frame(filter_frame)
        action_row.pack(fill='x')
        
        ttk.Button(action_row, text="🔍 フィルター適用", 
                  command=self.apply_filters).pack(side='left')
        ttk.Button(action_row, text="🔄 リセット", 
                  command=self.reset_filters).pack(side='left', padx=(10, 0))
        
        # 高度なフィルターエリア（初期は非表示）
        self.advanced_frame = ttk.LabelFrame(parent, text="🔧 高度なフィルター", padding=10)
        self.create_advanced_filters()
    
    def create_advanced_filters(self):
        """高度なフィルターを作成"""
        # カスタム期間選択
        date_frame = ttk.Frame(self.advanced_frame)
        date_frame.pack(fill='x', pady=(0, 10))
        
        ttk.Label(date_frame, text="開始日:", font=("Segoe UI", 10, "bold")).pack(side='left')
        self.start_date_entry = ttk.Entry(date_frame, width=12)
        self.start_date_entry.pack(side='left', padx=(10, 20))
        self.start_date_entry.insert(0, (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d'))
        
        ttk.Label(date_frame, text="終了日:", font=("Segoe UI", 10, "bold")).pack(side='left')
        self.end_date_entry = ttk.Entry(date_frame, width=12)
        self.end_date_entry.pack(side='left', padx=(10, 0))
        self.end_date_entry.insert(0, datetime.now().strftime('%Y-%m-%d'))
        
        # ピア・ノード指定
        peer_frame = ttk.Frame(self.advanced_frame)
        peer_frame.pack(fill='x', pady=(0, 10))
        
        ttk.Label(peer_frame, text="ピア/ノード:", font=("Segoe UI", 10, "bold")).pack(side='left')
        self.peer_entry = ttk.Entry(peer_frame, width=40)
        self.peer_entry.pack(side='left', padx=(10, 0))
        
        # チャンネルID指定
        channel_frame = ttk.Frame(self.advanced_frame)
        channel_frame.pack(fill='x', pady=(0, 10))
        
        ttk.Label(channel_frame, text="チャンネルID:", font=("Segoe UI", 10, "bold")).pack(side='left')
        self.channel_entry = ttk.Entry(channel_frame, width=40)
        self.channel_entry.pack(side='left', padx=(10, 0))
        
        # 手数料範囲
        fee_frame = ttk.Frame(self.advanced_frame)
        fee_frame.pack(fill='x', pady=(0, 10))
        
        ttk.Label(fee_frame, text="手数料範囲:", font=("Segoe UI", 10, "bold")).pack(side='left')
        self.min_fee_entry = ttk.Entry(fee_frame, width=10)
        self.min_fee_entry.pack(side='left', padx=(10, 5))
        ttk.Label(fee_frame, text="〜").pack(side='left')
        self.max_fee_entry = ttk.Entry(fee_frame, width=10)
        self.max_fee_entry.pack(side='left', padx=(5, 10))
        ttk.Label(fee_frame, text="sats").pack(side='left')
        
        # 正規表現検索オプション
        regex_frame = ttk.Frame(self.advanced_frame)
        regex_frame.pack(fill='x')
        
        self.regex_var = tk.BooleanVar()
        ttk.Checkbutton(regex_frame, text="正規表現を使用", variable=self.regex_var).pack(side='left')
        
        self.case_sensitive_var = tk.BooleanVar()
        ttk.Checkbutton(regex_frame, text="大文字小文字を区別", 
                       variable=self.case_sensitive_var).pack(side='left', padx=(20, 0))
    
    def create_results_area(self, parent):
        """結果表示エリアを作成"""
        results_frame = ttk.LabelFrame(parent, text="📋 検索結果", padding=10)
        results_frame.pack(fill='both', expand=True)
        
        # 結果サマリー
        summary_frame = ttk.Frame(results_frame)
        summary_frame.pack(fill='x', pady=(0, 10))
        
        self.results_summary_label = ttk.Label(summary_frame, 
                                              text="件数: 0 件, 総額: 0 sats",
                                              font=("Segoe UI", 10, "bold"))
        self.results_summary_label.pack(side='left')
        
        # ソート選択
        ttk.Label(summary_frame, text="並び替え:").pack(side='right', padx=(0, 5))
        self.sort_var = tk.StringVar(value="時刻(新しい順)")
        sort_combo = ttk.Combobox(summary_frame, textvariable=self.sort_var,
                                 values=['時刻(新しい順)', '時刻(古い順)', '金額(大きい順)', 
                                        '金額(小さい順)', 'ステータス順'],
                                 state='readonly', width=15)
        sort_combo.pack(side='right')
        sort_combo.bind('<<ComboboxSelected>>', self.sort_results)
        
        # 結果テーブル
        columns = ('時刻', 'タイプ', '金額', '手数料', 'ステータス', 'ピア', 'メモ', 'TX Hash')
        self.results_tree = ttk.Treeview(results_frame, columns=columns, show='headings', height=15)
        
        # 列設定
        column_widths = {'時刻': 120, 'タイプ': 80, '金額': 100, '手数料': 70, 
                        'ステータス': 80, 'ピア': 120, 'メモ': 150, 'TX Hash': 100}
        
        for col in columns:
            self.results_tree.heading(col, text=col, command=lambda c=col: self.sort_by_column(c))
            self.results_tree.column(col, width=column_widths.get(col, 100), anchor='center')
        
        # スクロールバー
        results_scroll = ttk.Scrollbar(results_frame, orient='vertical', 
                                      command=self.results_tree.yview)
        self.results_tree.configure(yscrollcommand=results_scroll.set)
        
        self.results_tree.pack(side='left', fill='both', expand=True)
        results_scroll.pack(side='right', fill='y')
        
        # 右クリックメニュー
        self.setup_context_menu()
    
    def setup_context_menu(self):
        """右クリックメニューを設定"""
        self.context_menu = tk.Menu(self.window, tearoff=0)
        self.context_menu.add_command(label="詳細表示", command=self.show_transaction_details)
        self.context_menu.add_command(label="コピー", command=self.copy_transaction)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="エクスポート", command=self.export_selected)
        
        self.results_tree.bind("<Button-3>", self.show_context_menu)
        self.results_tree.bind("<Double-1>", lambda e: self.show_transaction_details())
    
    def create_status_bar(self, parent):
        """ステータスバーを作成"""
        status_frame = ttk.Frame(parent)
        status_frame.pack(fill='x', side='bottom')
        
        self.status_label = ttk.Label(status_frame, text="準備完了", 
                                     font=("Segoe UI", 9))
        self.status_label.pack(side='left')
        
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(status_frame, variable=self.progress_var, 
                                           length=200, mode='determinate')
        self.progress_bar.pack(side='right', padx=(0, 10))
    
    # データ処理メソッド
    def load_initial_data(self):
        """初期データを読み込み"""
        self.update_status("初期データ読み込み中...")
        
        def load_in_background():
            try:
                # サンプル取引データを生成
                self.transaction_data = self.generate_sample_data()
                
                # 初期フィルター適用
                self.window.after(0, self.apply_filters)
                
                self.update_status("準備完了")
                
            except Exception as e:
                self.update_status(f"データ読み込みエラー: {str(e)}")
        
        threading.Thread(target=load_in_background, daemon=True).start()
    
    def generate_sample_data(self):
        """サンプル取引データを生成"""
        import random
        
        transactions = []
        types = ['送金', '受取', 'チャンネル開設', 'チャンネル閉鎖']
        statuses = ['完了', '処理中', '失敗']
        peers = ['Node_ABC', 'Lightning_Hub', 'Bitcoin_Pro', 'Satoshi_Node', 'BTC_Network']
        
        for i in range(500):  # 500件のサンプルデータ
            days_ago = random.randint(0, 365)
            timestamp = datetime.now() - timedelta(days=days_ago, 
                                                  hours=random.randint(0, 23),
                                                  minutes=random.randint(0, 59))
            
            tx_type = random.choice(types)
            amount = random.randint(1000, 1000000)
            fee = random.randint(1, amount // 100) if tx_type in ['送金', '受取'] else 0
            status = random.choice(statuses) if random.random() > 0.1 else '完了'  # 90%成功率
            peer = random.choice(peers)
            memo = f"Transaction {i+1}" if random.random() > 0.7 else ""
            tx_hash = f"{''.join(random.choices('0123456789abcdef', k=8))}..."
            
            transactions.append({
                'timestamp': timestamp,
                'type': tx_type,
                'amount': amount,
                'fee': fee,
                'status': status,
                'peer': peer,
                'memo': memo,
                'tx_hash': tx_hash
            })
        
        return sorted(transactions, key=lambda x: x['timestamp'], reverse=True)
    
    # 検索・フィルター機能
    def perform_search(self):
        """検索を実行"""
        self.apply_filters()
    
    def clear_search(self):
        """検索をクリア"""
        self.search_entry.delete(0, tk.END)
        self.apply_filters()
    
    def apply_filters(self):
        """フィルターを適用"""
        self.update_status("フィルター適用中...")
        self.progress_var.set(0)
        
        def filter_in_background():
            try:
                filtered_data = self.filter_transactions()
                
                self.window.after(0, lambda: self.display_results(filtered_data))
                
                self.update_status(f"フィルター完了: {len(filtered_data)} 件")
                self.progress_var.set(100)
                
            except Exception as e:
                self.update_status(f"フィルターエラー: {str(e)}")
        
        threading.Thread(target=filter_in_background, daemon=True).start()
    
    def filter_transactions(self):
        """取引データをフィルタリング"""
        if not hasattr(self, 'transaction_data'):
            return []
        
        filtered = self.transaction_data.copy()
        
        # キーワード検索
        search_term = self.search_entry.get().strip()
        if search_term:
            if self.regex_var.get():
                import re
                flags = 0 if self.case_sensitive_var.get() else re.IGNORECASE
                pattern = re.compile(search_term, flags)
                filtered = [tx for tx in filtered 
                           if any(pattern.search(str(tx.get(field, ''))) 
                                 for field in ['peer', 'memo', 'tx_hash'])]
            else:
                if not self.case_sensitive_var.get():
                    search_term = search_term.lower()
                    filtered = [tx for tx in filtered 
                               if any(search_term in str(tx.get(field, '')).lower() 
                                     for field in ['peer', 'memo', 'tx_hash'])]
                else:
                    filtered = [tx for tx in filtered 
                               if any(search_term in str(tx.get(field, '')) 
                                     for field in ['peer', 'memo', 'tx_hash'])]
        
        # 期間フィルター
        period = self.period_var.get()
        if period != 'カスタム':
            days_map = {'1日': 1, '7日': 7, '30日': 30, '90日': 90, '1年': 365}
            if period in days_map:
                cutoff_date = datetime.now() - timedelta(days=days_map[period])
                filtered = [tx for tx in filtered if tx['timestamp'] >= cutoff_date]
        else:
            # カスタム期間
            try:
                start_date = datetime.strptime(self.start_date_entry.get(), '%Y-%m-%d')
                end_date = datetime.strptime(self.end_date_entry.get(), '%Y-%m-%d') + timedelta(days=1)
                filtered = [tx for tx in filtered 
                           if start_date <= tx['timestamp'] <= end_date]
            except ValueError:
                pass
        
        # タイプフィルター
        tx_type = self.type_var.get()
        if tx_type != 'すべて':
            filtered = [tx for tx in filtered if tx['type'] == tx_type]
        
        # ステータスフィルター
        status = self.status_var.get()
        if status != 'すべて':
            filtered = [tx for tx in filtered if tx['status'] == status]
        
        # 金額範囲フィルター
        try:
            min_amount = float(self.min_amount_entry.get()) if self.min_amount_entry.get() else 0
            max_amount = float(self.max_amount_entry.get()) if self.max_amount_entry.get() else float('inf')
            filtered = [tx for tx in filtered 
                       if min_amount <= tx['amount'] <= max_amount]
        except ValueError:
            pass
        
        # 高度なフィルター（表示されている場合）
        if self.advanced_filters_var.get():
            # ピアフィルター
            peer_filter = self.peer_entry.get().strip()
            if peer_filter:
                filtered = [tx for tx in filtered if peer_filter.lower() in tx['peer'].lower()]
            
            # チャンネルIDフィルター
            channel_filter = self.channel_entry.get().strip()
            if channel_filter:
                filtered = [tx for tx in filtered if channel_filter in tx['tx_hash']]
            
            # 手数料範囲フィルター
            try:
                min_fee = float(self.min_fee_entry.get()) if self.min_fee_entry.get() else 0
                max_fee = float(self.max_fee_entry.get()) if self.max_fee_entry.get() else float('inf')
                filtered = [tx for tx in filtered 
                           if min_fee <= tx['fee'] <= max_fee]
            except ValueError:
                pass
        
        return filtered
    
    def display_results(self, transactions):
        """結果を表示"""
        # 既存の結果をクリア
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        
        # 結果を表示
        total_amount = 0
        for tx in transactions:
            values = (
                tx['timestamp'].strftime('%Y-%m-%d %H:%M'),
                tx['type'],
                f"{tx['amount']:,} sats",
                f"{tx['fee']} sats" if tx['fee'] > 0 else "-",
                tx['status'],
                tx['peer'],
                tx['memo'],
                tx['tx_hash']
            )
            self.results_tree.insert('', 'end', values=values)
            
            if tx['type'] in ['送金', '受取']:
                total_amount += tx['amount']
        
        # サマリー更新
        self.results_summary_label.config(
            text=f"件数: {len(transactions):,} 件, 総額: {total_amount:,} sats"
        )
    
    def sort_results(self, event=None):
        """結果をソート"""
        sort_type = self.sort_var.get()
        # ソート処理実装
        self.update_status(f"ソート中: {sort_type}")
    
    def sort_by_column(self, col):
        """列でソート"""
        self.update_status(f"'{col}'でソート中...")
        # 列ソート処理実装
    
    def reset_filters(self):
        """フィルターをリセット"""
        self.search_entry.delete(0, tk.END)
        self.period_var.set("30日")
        self.type_var.set("すべて")
        self.status_var.set("すべて")
        self.min_amount_entry.delete(0, tk.END)
        self.max_amount_entry.delete(0, tk.END)
        
        # 高度なフィルターもリセット
        if hasattr(self, 'peer_entry'):
            self.peer_entry.delete(0, tk.END)
            self.channel_entry.delete(0, tk.END)
            self.min_fee_entry.delete(0, tk.END)
            self.max_fee_entry.delete(0, tk.END)
            self.regex_var.set(False)
            self.case_sensitive_var.set(False)
        
        self.apply_filters()
    
    def toggle_advanced_filters(self):
        """高度なフィルターの表示・非表示を切り替え"""
        if self.advanced_filters_var.get():
            self.advanced_frame.pack(fill='x', pady=10)
        else:
            self.advanced_frame.pack_forget()
    
    def on_period_changed(self, event):
        """期間選択が変更された時の処理"""
        if self.period_var.get() == 'カスタム':
            if not self.advanced_filters_var.get():
                self.advanced_filters_var.set(True)
                self.toggle_advanced_filters()
    
    # コンテキストメニュー・アクション
    def show_context_menu(self, event):
        """右クリックメニューを表示"""
        self.context_menu.post(event.x_root, event.y_root)
    
    def show_transaction_details(self):
        """取引詳細を表示"""
        selection = self.results_tree.selection()
        if selection:
            item = self.results_tree.item(selection[0])
            values = item['values']
            
            detail_text = f"""
取引詳細情報:

時刻: {values[0]}
タイプ: {values[1]}
金額: {values[2]}
手数料: {values[3]}
ステータス: {values[4]}
ピア: {values[5]}
メモ: {values[6]}
TX Hash: {values[7]}
"""
            
            messagebox.showinfo("取引詳細", detail_text)
    
    def copy_transaction(self):
        """取引情報をコピー"""
        selection = self.results_tree.selection()
        if selection:
            item = self.results_tree.item(selection[0])
            values = item['values']
            
            # タブ区切りでコピー
            copied_text = '\t'.join(str(v) for v in values)
            self.window.clipboard_clear()
            self.window.clipboard_append(copied_text)
            
            self.update_status("取引情報をクリップボードにコピーしました")
    
    def export_selected(self):
        """選択した取引をエクスポート"""
        selection = self.results_tree.selection()
        if not selection:
            messagebox.showwarning("警告", "エクスポートする取引を選択してください")
            return
        
        # 選択された取引のエクスポート処理
        self.export_transactions([self.results_tree.item(item)['values'] for item in selection])
    
    def export_results(self):
        """検索結果をエクスポート"""
        if not self.results_tree.get_children():
            messagebox.showwarning("警告", "エクスポートするデータがありません")
            return
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if file_path:
            self.export_to_file(file_path)
    
    def export_to_file(self, file_path):
        """ファイルにエクスポート"""
        self.update_status("エクスポート中...")
        
        def export_in_background():
            try:
                # 全データを取得
                all_data = []
                for item in self.results_tree.get_children():
                    values = self.results_tree.item(item)['values']
                    all_data.append(values)
                
                if file_path.endswith('.csv'):
                    with open(file_path, 'w', newline='', encoding='utf-8') as csvfile:
                        writer = csv.writer(csvfile)
                        # ヘッダー
                        writer.writerow(['時刻', 'タイプ', '金額', '手数料', 'ステータス', 'ピア', 'メモ', 'TX Hash'])
                        # データ
                        writer.writerows(all_data)
                
                elif file_path.endswith('.json'):
                    export_data = []
                    for values in all_data:
                        export_data.append({
                            'timestamp': values[0],
                            'type': values[1],
                            'amount': values[2],
                            'fee': values[3],
                            'status': values[4],
                            'peer': values[5],
                            'memo': values[6],
                            'tx_hash': values[7]
                        })
                    
                    with open(file_path, 'w', encoding='utf-8') as jsonfile:
                        json.dump(export_data, jsonfile, ensure_ascii=False, indent=2)
                
                self.window.after(0, lambda: self.update_status(f"エクスポート完了: {file_path}"))
                self.window.after(0, lambda: messagebox.showinfo("完了", f"データをエクスポートしました:\n{file_path}"))
                
            except Exception as e:
                self.window.after(0, lambda: self.update_status(f"エクスポートエラー: {str(e)}"))
                self.window.after(0, lambda: messagebox.showerror("エラー", f"エクスポートに失敗しました:\n{str(e)}"))
        
        threading.Thread(target=export_in_background, daemon=True).start()
    
    def refresh_data(self):
        """データを更新"""
        self.update_status("データ更新中...")
        
        def refresh_in_background():
            try:
                # データを再生成（実際の実装では、Lightning ノードから取得）
                self.transaction_data = self.generate_sample_data()
                
                self.window.after(0, self.apply_filters)
                self.update_status("データ更新完了")
                
            except Exception as e:
                self.update_status(f"データ更新エラー: {str(e)}")
        
        threading.Thread(target=refresh_in_background, daemon=True).start()
    
    def update_status(self, message):
        """ステータスメッセージを更新"""
        if hasattr(self, 'status_label'):
            self.status_label.config(text=message)
    
    def run(self):
        """ウィンドウを実行"""
        try:
            self.window.mainloop()
        except KeyboardInterrupt:
            print("\n👋 取引履歴検索が中断されました")


def main():
    """メイン関数"""
    try:
        search_window = TransactionSearchWindow()
        search_window.run()
    except Exception as e:
        print(f"❌ 取引履歴検索起動エラー: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()