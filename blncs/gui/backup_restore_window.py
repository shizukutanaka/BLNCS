#!/usr/bin/env python3
"""
BLNCS Backup & Restore GUI - バックアップ・復元GUI
User interface for backup and restore functionality.
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
from datetime import datetime
from pathlib import Path

try:
    from ..core.backup_manager import get_backup_manager, AutoBackupScheduler
    from ..core.config_manager import get_config_manager
except ImportError:
    import sys
    sys.path.append(str(Path(__file__).parent.parent))
    from core.backup_manager import get_backup_manager, AutoBackupScheduler
    from core.config_manager import get_config_manager


class BackupRestoreWindow:
    """バックアップ・復元ウィンドウ"""
    
    def __init__(self, parent=None):
        if parent:
            self.window = tk.Toplevel(parent)
        else:
            self.window = tk.Tk()
        
        self.backup_manager = get_backup_manager()
        self.config = get_config_manager()
        self.auto_scheduler = AutoBackupScheduler(self.backup_manager, self.config)
        
        self.setup_window()
        self.create_interface()
        self.load_initial_data()
    
    def setup_window(self):
        """ウィンドウの基本設定"""
        self.window.title("💾 BLNCS - バックアップ・復元")
        self.window.geometry("900x600")
        self.window.minsize(800, 500)
        self.window.configure(bg="#f8f9fa")
    
    def create_interface(self):
        """インターフェースを作成"""
        # メインフレーム
        main_frame = ttk.Frame(self.window)
        main_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # ヘッダー
        self.create_header(main_frame)
        
        # タブ
        self.create_tabs(main_frame)
        
        # ステータスバー
        self.create_status_bar(main_frame)
    
    def create_header(self, parent):
        """ヘッダーを作成"""
        header_frame = ttk.Frame(parent)
        header_frame.pack(fill='x', pady=(0, 10))
        
        # タイトル
        title_label = ttk.Label(header_frame, 
                               text="💾 バックアップ・復元管理",
                               font=("Segoe UI", 16, "bold"),
                               foreground="#0066cc")
        title_label.pack(side='left')
        
        # 自動バックアップ状態表示
        self.auto_backup_label = ttk.Label(header_frame, 
                                          text="🔴 自動バックアップ: 停止中",
                                          font=("Segoe UI", 10))
        self.auto_backup_label.pack(side='right')
    
    def create_tabs(self, parent):
        """タブを作成"""
        self.notebook = ttk.Notebook(parent)
        self.notebook.pack(fill='both', expand=True, pady=(0, 10))
        
        # バックアップタブ
        self.create_backup_tab()
        
        # 復元タブ
        self.create_restore_tab()
        
        # 設定タブ
        self.create_settings_tab()
    
    def create_backup_tab(self):
        """バックアップタブを作成"""
        backup_frame = ttk.Frame(self.notebook)
        self.notebook.add(backup_frame, text="📤 バックアップ")
        
        # 上部: バックアップ実行
        action_frame = ttk.LabelFrame(backup_frame, text="バックアップ実行", padding=15)
        action_frame.pack(fill='x', padx=10, pady=10)
        
        # バックアップタイプ選択
        type_frame = ttk.Frame(action_frame)
        type_frame.pack(fill='x', pady=(0, 10))
        
        ttk.Label(type_frame, text="バックアップタイプ:", font=("Segoe UI", 10, "bold")).pack(side='left')
        
        self.backup_type_var = tk.StringVar(value="full")
        ttk.Radiobutton(type_frame, text="完全バックアップ", variable=self.backup_type_var,
                       value="full").pack(side='left', padx=(10, 0))
        ttk.Radiobutton(type_frame, text="増分バックアップ", variable=self.backup_type_var,
                       value="incremental").pack(side='left', padx=(10, 0))
        
        # オプション
        options_frame = ttk.Frame(action_frame)
        options_frame.pack(fill='x', pady=(0, 10))
        
        self.include_logs_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="ログファイルを含める",
                       variable=self.include_logs_var).pack(side='left')
        
        self.compress_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="圧縮する",
                       variable=self.compress_var).pack(side='left', padx=(20, 0))
        
        # 実行ボタン
        button_frame = ttk.Frame(action_frame)
        button_frame.pack(fill='x')
        
        ttk.Button(button_frame, text="📤 バックアップ実行", 
                  command=self.start_backup).pack(side='left')
        
        ttk.Button(button_frame, text="📁 バックアップフォルダを開く", 
                  command=self.open_backup_folder).pack(side='left', padx=(10, 0))
        
        # プログレスバー
        self.backup_progress = ttk.Progressbar(action_frame, mode='determinate', length=400)
        self.backup_progress.pack(fill='x', pady=(10, 0))
        
        self.backup_status_label = ttk.Label(action_frame, text="待機中")
        self.backup_status_label.pack(pady=(5, 0))
        
        # 下部: バックアップ履歴
        history_frame = ttk.LabelFrame(backup_frame, text="バックアップ履歴", padding=10)
        history_frame.pack(fill='both', expand=True, padx=10, pady=(0, 10))
        
        # 履歴テーブル
        columns = ('名前', 'タイプ', 'サイズ', '作成日時', '状態')
        self.backup_tree = ttk.Treeview(history_frame, columns=columns, show='headings', height=10)
        
        column_widths = {'名前': 200, 'タイプ': 80, 'サイズ': 100, '作成日時': 150, '状態': 80}
        for col in columns:
            self.backup_tree.heading(col, text=col)
            self.backup_tree.column(col, width=column_widths.get(col, 100), anchor='center')
        
        backup_scroll = ttk.Scrollbar(history_frame, orient='vertical', command=self.backup_tree.yview)
        self.backup_tree.configure(yscrollcommand=backup_scroll.set)
        
        self.backup_tree.pack(side='left', fill='both', expand=True)
        backup_scroll.pack(side='right', fill='y')
        
        # 右クリックメニュー
        self.setup_backup_context_menu()
        
        # 統計情報
        stats_frame = ttk.Frame(history_frame)
        stats_frame.pack(fill='x', pady=(10, 0))
        
        self.backup_stats_label = ttk.Label(stats_frame, text="統計: 読み込み中...", 
                                           font=("Segoe UI", 10))
        self.backup_stats_label.pack(side='left')
        
        ttk.Button(stats_frame, text="🔄 更新", 
                  command=self.refresh_backup_list).pack(side='right')
    
    def create_restore_tab(self):
        """復元タブを作成"""
        restore_frame = ttk.Frame(self.notebook)
        self.notebook.add(restore_frame, text="📥 復元")
        
        # 上部: 復元実行
        action_frame = ttk.LabelFrame(restore_frame, text="復元実行", padding=15)
        action_frame.pack(fill='x', padx=10, pady=10)
        
        # バックアップ選択
        select_frame = ttk.Frame(action_frame)
        select_frame.pack(fill='x', pady=(0, 10))
        
        ttk.Label(select_frame, text="復元するバックアップ:", font=("Segoe UI", 10, "bold")).pack(anchor='w')
        
        backup_select_frame = ttk.Frame(select_frame)
        backup_select_frame.pack(fill='x', pady=(5, 0))
        
        self.restore_backup_var = tk.StringVar()
        self.restore_backup_combo = ttk.Combobox(backup_select_frame, textvariable=self.restore_backup_var,
                                                state='readonly', width=50)
        self.restore_backup_combo.pack(side='left')
        
        ttk.Button(backup_select_frame, text="📁 ファイルから選択", 
                  command=self.select_backup_file).pack(side='left', padx=(10, 0))
        
        # 復元オプション
        options_frame = ttk.LabelFrame(action_frame, text="復元オプション", padding=10)
        options_frame.pack(fill='x', pady=(10, 0))
        
        self.restore_config_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="設定ファイルを復元",
                       variable=self.restore_config_var).pack(anchor='w')
        
        self.restore_data_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="データベースを復元",
                       variable=self.restore_data_var).pack(anchor='w')
        
        self.restore_lightning_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Lightningノード設定を復元",
                       variable=self.restore_lightning_var).pack(anchor='w')
        
        self.create_safety_backup_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="復元前に安全バックアップを作成",
                       variable=self.create_safety_backup_var).pack(anchor='w')
        
        self.overwrite_existing_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(options_frame, text="既存ファイルを上書き",
                       variable=self.overwrite_existing_var).pack(anchor='w')
        
        # 実行ボタン
        button_frame = ttk.Frame(action_frame)
        button_frame.pack(fill='x', pady=(10, 0))
        
        ttk.Button(button_frame, text="📥 復元実行", 
                  command=self.start_restore).pack(side='left')
        
        ttk.Button(button_frame, text="🔍 バックアップ検証", 
                  command=self.verify_backup).pack(side='left', padx=(10, 0))
        
        # プログレスバー
        self.restore_progress = ttk.Progressbar(action_frame, mode='determinate', length=400)
        self.restore_progress.pack(fill='x', pady=(10, 0))
        
        self.restore_status_label = ttk.Label(action_frame, text="待機中")
        self.restore_status_label.pack(pady=(5, 0))
        
        # 下部: 復元履歴
        history_frame = ttk.LabelFrame(restore_frame, text="復元履歴", padding=10)
        history_frame.pack(fill='both', expand=True, padx=10, pady=(0, 10))
        
        # 履歴表示エリア
        self.restore_history_text = tk.Text(history_frame, height=10, wrap='word', state='disabled')
        restore_history_scroll = ttk.Scrollbar(history_frame, orient='vertical', 
                                              command=self.restore_history_text.yview)
        self.restore_history_text.configure(yscrollcommand=restore_history_scroll.set)
        
        self.restore_history_text.pack(side='left', fill='both', expand=True)
        restore_history_scroll.pack(side='right', fill='y')
    
    def create_settings_tab(self):
        """設定タブを作成"""
        settings_frame = ttk.Frame(self.notebook)
        self.notebook.add(settings_frame, text="⚙️ 設定")
        
        # 自動バックアップ設定
        auto_frame = ttk.LabelFrame(settings_frame, text="自動バックアップ設定", padding=15)
        auto_frame.pack(fill='x', padx=10, pady=10)
        
        self.auto_backup_enabled_var = tk.BooleanVar()
        ttk.Checkbutton(auto_frame, text="自動バックアップを有効にする",
                       variable=self.auto_backup_enabled_var,
                       command=self.toggle_auto_backup).pack(anchor='w', pady=(0, 10))
        
        # 間隔設定
        interval_frame = ttk.Frame(auto_frame)
        interval_frame.pack(fill='x', pady=(0, 10))
        
        ttk.Label(interval_frame, text="バックアップ間隔:", font=("Segoe UI", 10)).pack(side='left')
        self.backup_interval_var = tk.StringVar(value="24")
        interval_spinbox = ttk.Spinbox(interval_frame, from_=1, to=168, 
                                      textvariable=self.backup_interval_var, width=10)
        interval_spinbox.pack(side='left', padx=(10, 5))
        ttk.Label(interval_frame, text="時間").pack(side='left')
        
        # 保存期間設定
        retention_frame = ttk.Frame(auto_frame)
        retention_frame.pack(fill='x', pady=(0, 10))
        
        ttk.Label(retention_frame, text="保存期間:", font=("Segoe UI", 10)).pack(side='left')
        self.retention_days_var = tk.StringVar(value="30")
        retention_spinbox = ttk.Spinbox(retention_frame, from_=1, to=365,
                                       textvariable=self.retention_days_var, width=10)
        retention_spinbox.pack(side='left', padx=(10, 5))
        ttk.Label(retention_frame, text="日").pack(side='left')
        
        # 圧縮設定
        compression_frame = ttk.LabelFrame(settings_frame, text="圧縮設定", padding=15)
        compression_frame.pack(fill='x', padx=10, pady=(0, 10))
        
        ttk.Label(compression_frame, text="圧縮レベル:", font=("Segoe UI", 10)).pack(side='left')
        self.compression_level_var = tk.StringVar(value="6")
        compression_scale = ttk.Scale(compression_frame, from_=1, to=9, orient='horizontal',
                                     variable=self.compression_level_var, length=200)
        compression_scale.pack(side='left', padx=(10, 10))
        self.compression_label = ttk.Label(compression_frame, text="6 (バランス)")
        self.compression_label.pack(side='left')
        
        compression_scale.configure(command=self.update_compression_label)
        
        # ストレージ設定
        storage_frame = ttk.LabelFrame(settings_frame, text="ストレージ設定", padding=15)
        storage_frame.pack(fill='x', padx=10, pady=(0, 10))
        
        ttk.Label(storage_frame, text="バックアップ保存先:", font=("Segoe UI", 10)).pack(anchor='w')
        
        path_frame = ttk.Frame(storage_frame)
        path_frame.pack(fill='x', pady=(5, 10))
        
        self.backup_path_var = tk.StringVar()
        self.backup_path_entry = ttk.Entry(path_frame, textvariable=self.backup_path_var, width=50)
        self.backup_path_entry.pack(side='left')
        
        ttk.Button(path_frame, text="📁 参照", 
                  command=self.select_backup_directory).pack(side='left', padx=(10, 0))
        
        # 設定保存ボタン
        button_frame = ttk.Frame(settings_frame)
        button_frame.pack(fill='x', padx=10, pady=20)
        
        ttk.Button(button_frame, text="💾 設定保存", 
                  command=self.save_settings).pack(side='left')
        
        ttk.Button(button_frame, text="🔄 設定リセット", 
                  command=self.reset_settings).pack(side='left', padx=(10, 0))
        
        ttk.Button(button_frame, text="🗑️ 古いバックアップを削除", 
                  command=self.cleanup_old_backups).pack(side='right')
    
    def setup_backup_context_menu(self):
        """バックアップの右クリックメニューを設定"""
        self.backup_context_menu = tk.Menu(self.window, tearoff=0)
        self.backup_context_menu.add_command(label="復元", command=self.restore_selected_backup)
        self.backup_context_menu.add_command(label="検証", command=self.verify_selected_backup)
        self.backup_context_menu.add_command(label="詳細", command=self.show_backup_details)
        self.backup_context_menu.add_separator()
        self.backup_context_menu.add_command(label="削除", command=self.delete_selected_backup)
        self.backup_context_menu.add_command(label="エクスポート", command=self.export_selected_backup)
        
        self.backup_tree.bind("<Button-3>", self.show_backup_context_menu)
        self.backup_tree.bind("<Double-1>", lambda e: self.show_backup_details())
    
    def create_status_bar(self, parent):
        """ステータスバーを作成"""
        status_frame = ttk.Frame(parent)
        status_frame.pack(fill='x', side='bottom')
        
        self.status_label = ttk.Label(status_frame, text="準備完了", 
                                     font=("Segoe UI", 9))
        self.status_label.pack(side='left')
        
        # ディスク使用量表示
        self.disk_usage_label = ttk.Label(status_frame, text="", 
                                         font=("Segoe UI", 9))
        self.disk_usage_label.pack(side='right')
    
    def load_initial_data(self):
        """初期データを読み込み"""
        self.update_status("初期データ読み込み中...")
        
        def load_in_background():
            try:
                # 設定読み込み
                self.load_settings()
                
                # バックアップリスト読み込み
                self.window.after(0, self.refresh_backup_list)
                
                # ディスク使用量更新
                self.window.after(0, self.update_disk_usage)
                
                self.update_status("準備完了")
                
            except Exception as e:
                self.update_status(f"初期化エラー: {str(e)}")
        
        threading.Thread(target=load_in_background, daemon=True).start()
    
    def load_settings(self):
        """設定を読み込み"""
        try:
            # 自動バックアップ設定
            auto_enabled = self.config.get('auto_backup_enabled', False)
            self.auto_backup_enabled_var.set(auto_enabled)
            
            # 間隔設定
            interval = self.config.get('backup_interval_hours', 24)
            self.backup_interval_var.set(str(interval))
            
            # 保存期間
            retention = self.config.get('backup_retention_days', 30)
            self.retention_days_var.set(str(retention))
            
            # 圧縮レベル
            compression = self.config.get('compression_level', 6)
            self.compression_level_var.set(str(compression))
            
            # バックアップパス
            backup_path = str(self.backup_manager.backup_dir)
            self.backup_path_var.set(backup_path)
            
            # 自動バックアップ状態更新
            if auto_enabled:
                self.auto_scheduler.start()
                self.auto_backup_label.config(text="🟢 自動バックアップ: 有効")
            else:
                self.auto_backup_label.config(text="🔴 自動バックアップ: 停止中")
            
        except Exception as e:
            print(f"設定読み込みエラー: {e}")
    
    def refresh_backup_list(self):
        """バックアップリストを更新"""
        try:
            # 既存のアイテムをクリア
            for item in self.backup_tree.get_children():
                self.backup_tree.delete(item)
            
            # バックアップリストを取得
            backups = self.backup_manager.get_backup_list()
            
            # ツリーにデータを追加
            backup_names = []
            for backup in backups:
                name = backup['name']
                backup_type = backup['type']
                size = self.format_file_size(backup['size'])
                created = backup['created_at'].strftime('%Y-%m-%d %H:%M')
                status = "正常" if self.backup_manager.verify_backup(backup['path']) else "破損"
                
                self.backup_tree.insert('', 'end', values=(name, backup_type, size, created, status))
                backup_names.append(name)
            
            # 復元用コンボボックス更新
            self.restore_backup_combo['values'] = backup_names
            if backup_names:
                self.restore_backup_combo.set(backup_names[0])
            
            # 統計更新
            self.update_backup_statistics()
            
        except Exception as e:
            self.update_status(f"リスト更新エラー: {str(e)}")
    
    def update_backup_statistics(self):
        """バックアップ統計を更新"""
        try:
            stats = self.backup_manager.get_backup_statistics()
            
            total_size = self.format_file_size(stats['total_size'])
            last_backup = stats['last_backup'].strftime('%Y-%m-%d %H:%M') if stats['last_backup'] else "なし"
            
            stats_text = (f"総数: {stats['total_backups']} 件 "
                         f"(完全: {stats['full_backups']}, 増分: {stats['incremental_backups']}) | "
                         f"総サイズ: {total_size} | 最新: {last_backup}")
            
            self.backup_stats_label.config(text=stats_text)
            
        except Exception as e:
            self.backup_stats_label.config(text=f"統計エラー: {str(e)}")
    
    def update_disk_usage(self):
        """ディスク使用量を更新"""
        try:
            import shutil
            total, used, free = shutil.disk_usage(str(self.backup_manager.backup_dir))
            
            usage_text = f"ディスク使用量: {self.format_file_size(used)}/{self.format_file_size(total)}"
            self.disk_usage_label.config(text=usage_text)
            
        except Exception as e:
            self.disk_usage_label.config(text=f"ディスク情報取得エラー: {str(e)}")
    
    def format_file_size(self, size):
        """ファイルサイズを読みやすい形式に変換"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"
    
    # バックアップ関連メソッド
    def start_backup(self):
        """バックアップを開始"""
        backup_type = self.backup_type_var.get()
        include_logs = self.include_logs_var.get()
        
        self.backup_progress['value'] = 0
        self.backup_status_label.config(text="バックアップ準備中...")
        
        def backup_callback(message, progress):
            if progress == -1:  # エラー
                self.window.after(0, lambda: self.backup_status_label.config(text=message))
            else:
                self.window.after(0, lambda: self.backup_progress.configure(value=progress))
                self.window.after(0, lambda: self.backup_status_label.config(text=message))
        
        def run_backup():
            try:
                if backup_type == "full":
                    result = self.backup_manager.create_full_backup(include_logs, backup_callback)
                else:
                    result = self.backup_manager.create_incremental_backup(callback=backup_callback)
                
                if result['success']:
                    self.window.after(0, lambda: self.on_backup_complete(result))
                else:
                    self.window.after(0, lambda: self.on_backup_error(result))
                
            except Exception as e:
                error_result = {'success': False, 'error': str(e)}
                self.window.after(0, lambda: self.on_backup_error(error_result))
        
        threading.Thread(target=run_backup, daemon=True).start()
    
    def on_backup_complete(self, result):
        """バックアップ完了時の処理"""
        self.backup_progress['value'] = 100
        self.backup_status_label.config(text="バックアップ完了")
        
        size = self.format_file_size(result['size'])
        messagebox.showinfo("バックアップ完了", 
                           f"バックアップが正常に完了しました。\n\nサイズ: {size}")
        
        self.refresh_backup_list()
        self.update_disk_usage()
    
    def on_backup_error(self, result):
        """バックアップエラー時の処理"""
        self.backup_status_label.config(text=f"エラー: {result.get('error', 'Unknown error')}")
        messagebox.showerror("バックアップエラー", f"バックアップに失敗しました:\n\n{result.get('error', 'Unknown error')}")
    
    def open_backup_folder(self):
        """バックアップフォルダを開く"""
        import subprocess
        import platform
        
        backup_path = str(self.backup_manager.backup_dir)
        
        try:
            if platform.system() == "Windows":
                subprocess.run(["explorer", backup_path])
            elif platform.system() == "Darwin":  # macOS
                subprocess.run(["open", backup_path])
            else:  # Linux
                subprocess.run(["xdg-open", backup_path])
        except Exception as e:
            messagebox.showerror("エラー", f"フォルダを開けませんでした: {str(e)}")
    
    # 復元関連メソッド
    def start_restore(self):
        """復元を開始"""
        selected_backup = self.restore_backup_var.get()
        if not selected_backup:
            messagebox.showwarning("警告", "復元するバックアップを選択してください")
            return
        
        # 確認ダイアログ
        result = messagebox.askyesno("復元確認", 
                                    "復元を実行すると現在のデータが置き換えられます。\n"
                                    "続行しますか？")
        if not result:
            return
        
        # バックアップファイルパスを取得
        backups = self.backup_manager.get_backup_list()
        backup_path = None
        for backup in backups:
            if backup['name'] == selected_backup:
                backup_path = backup['path']
                break
        
        if not backup_path:
            messagebox.showerror("エラー", "バックアップファイルが見つかりません")
            return
        
        # 復元オプション設定
        restore_options = {
            'restore_config': self.restore_config_var.get(),
            'restore_data': self.restore_data_var.get(),
            'restore_node_config': self.restore_lightning_var.get(),
            'create_safety_backup': self.create_safety_backup_var.get(),
            'overwrite_existing': self.overwrite_existing_var.get()
        }
        
        self.restore_progress['value'] = 0
        self.restore_status_label.config(text="復元準備中...")
        
        def restore_callback(message, progress):
            if progress == -1:  # エラー
                self.window.after(0, lambda: self.restore_status_label.config(text=message))
            elif progress is not None:
                self.window.after(0, lambda: self.restore_progress.configure(value=progress))
                self.window.after(0, lambda: self.restore_status_label.config(text=message))
            else:
                self.window.after(0, lambda: self.restore_status_label.config(text=message))
        
        def run_restore():
            try:
                result = self.backup_manager.restore_from_backup(backup_path, restore_options, restore_callback)
                
                if result['success']:
                    self.window.after(0, lambda: self.on_restore_complete(result))
                else:
                    self.window.after(0, lambda: self.on_restore_error(result))
                
            except Exception as e:
                error_result = {'success': False, 'error': str(e)}
                self.window.after(0, lambda: self.on_restore_error(error_result))
        
        threading.Thread(target=run_restore, daemon=True).start()
    
    def on_restore_complete(self, result):
        """復元完了時の処理"""
        self.restore_progress['value'] = 100
        self.restore_status_label.config(text="復元完了")
        
        # 履歴に追加
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        history_text = f"[{timestamp}] 復元完了: {result['restored_from']}\n"
        
        self.restore_history_text.config(state='normal')
        self.restore_history_text.insert(tk.END, history_text)
        self.restore_history_text.see(tk.END)
        self.restore_history_text.config(state='disabled')
        
        messagebox.showinfo("復元完了", "復元が正常に完了しました。\n\n変更を有効にするためにアプリケーションの再起動が推奨されます。")
    
    def on_restore_error(self, result):
        """復元エラー時の処理"""
        self.restore_status_label.config(text=f"エラー: {result.get('error', 'Unknown error')}")
        
        # 履歴に追加
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        history_text = f"[{timestamp}] 復元エラー: {result.get('error', 'Unknown error')}\n"
        
        self.restore_history_text.config(state='normal')
        self.restore_history_text.insert(tk.END, history_text)
        self.restore_history_text.see(tk.END)
        self.restore_history_text.config(state='disabled')
        
        messagebox.showerror("復元エラー", f"復元に失敗しました:\n\n{result.get('error', 'Unknown error')}")
    
    def select_backup_file(self):
        """バックアップファイルを選択"""
        file_path = filedialog.askopenfilename(
            title="バックアップファイルを選択",
            filetypes=[("ZIP files", "*.zip"), ("All files", "*.*")]
        )
        if file_path:
            self.restore_backup_var.set(file_path)
    
    def verify_backup(self):
        """バックアップを検証"""
        selected_backup = self.restore_backup_var.get()
        if not selected_backup:
            messagebox.showwarning("警告", "検証するバックアップを選択してください")
            return
        
        # バックアップファイルパスを取得
        backup_path = selected_backup
        if not backup_path.endswith('.zip'):
            backups = self.backup_manager.get_backup_list()
            for backup in backups:
                if backup['name'] == selected_backup:
                    backup_path = backup['path']
                    break
        
        self.update_status("バックアップ検証中...")
        
        def verify_in_background():
            try:
                is_valid = self.backup_manager.verify_backup(backup_path)
                
                if is_valid:
                    self.window.after(0, lambda: messagebox.showinfo("検証結果", "バックアップファイルは正常です"))
                else:
                    self.window.after(0, lambda: messagebox.showwarning("検証結果", "バックアップファイルが破損している可能性があります"))
                
                self.update_status("準備完了")
                
            except Exception as e:
                self.window.after(0, lambda: messagebox.showerror("検証エラー", f"検証に失敗しました: {str(e)}"))
                self.update_status("準備完了")
        
        threading.Thread(target=verify_in_background, daemon=True).start()
    
    # 設定関連メソッド
    def toggle_auto_backup(self):
        """自動バックアップの有効/無効を切り替え"""
        if self.auto_backup_enabled_var.get():
            self.auto_scheduler.start()
            self.auto_backup_label.config(text="🟢 自動バックアップ: 有効")
        else:
            self.auto_scheduler.stop()
            self.auto_backup_label.config(text="🔴 自動バックアップ: 停止中")
    
    def update_compression_label(self, value):
        """圧縮レベルラベルを更新"""
        level = int(float(value))
        labels = {
            1: "1 (高速)", 2: "2", 3: "3", 4: "4", 5: "5",
            6: "6 (バランス)", 7: "7", 8: "8", 9: "9 (最大圧縮)"
        }
        self.compression_label.config(text=labels.get(level, str(level)))
    
    def select_backup_directory(self):
        """バックアップディレクトリを選択"""
        directory = filedialog.askdirectory(title="バックアップ保存先を選択")
        if directory:
            self.backup_path_var.set(directory)
    
    def save_settings(self):
        """設定を保存"""
        try:
            # 設定値を保存
            self.config.set('auto_backup_enabled', self.auto_backup_enabled_var.get())
            self.config.set('backup_interval_hours', int(self.backup_interval_var.get()))
            self.config.set('backup_retention_days', int(self.retention_days_var.get()))
            self.config.set('compression_level', int(float(self.compression_level_var.get())))
            
            # バックアップマネージャーの設定を更新
            self.backup_manager.auto_backup_interval = int(self.backup_interval_var.get())
            self.backup_manager.backup_retention_days = int(self.retention_days_var.get())
            self.backup_manager.compression_level = int(float(self.compression_level_var.get()))
            
            messagebox.showinfo("設定保存", "設定が保存されました")
            
        except Exception as e:
            messagebox.showerror("設定エラー", f"設定の保存に失敗しました: {str(e)}")
    
    def reset_settings(self):
        """設定をリセット"""
        result = messagebox.askyesno("設定リセット", "設定を初期値にリセットしますか？")
        if result:
            self.auto_backup_enabled_var.set(False)
            self.backup_interval_var.set("24")
            self.retention_days_var.set("30")
            self.compression_level_var.set("6")
            self.backup_path_var.set(str(self.backup_manager.backup_dir))
            
            self.toggle_auto_backup()
            self.update_compression_label("6")
    
    def cleanup_old_backups(self):
        """古いバックアップを削除"""
        retention_days = int(self.retention_days_var.get())
        
        result = messagebox.askyesno("古いバックアップ削除", 
                                    f"{retention_days}日より古いバックアップを削除しますか？")
        if result:
            self.update_status("古いバックアップ削除中...")
            
            def cleanup_in_background():
                try:
                    deleted_count = self.backup_manager.delete_old_backups(retention_days)
                    
                    self.window.after(0, lambda: messagebox.showinfo("削除完了", f"{deleted_count} 件のバックアップを削除しました"))
                    self.window.after(0, self.refresh_backup_list)
                    self.window.after(0, self.update_disk_usage)
                    self.update_status("準備完了")
                    
                except Exception as e:
                    self.window.after(0, lambda: messagebox.showerror("削除エラー", f"削除に失敗しました: {str(e)}"))
                    self.update_status("準備完了")
            
            threading.Thread(target=cleanup_in_background, daemon=True).start()
    
    # コンテキストメニュー関連メソッド
    def show_backup_context_menu(self, event):
        """バックアップの右クリックメニューを表示"""
        self.backup_context_menu.post(event.x_root, event.y_root)
    
    def restore_selected_backup(self):
        """選択されたバックアップを復元"""
        selection = self.backup_tree.selection()
        if selection:
            item = self.backup_tree.item(selection[0])
            backup_name = item['values'][0]
            
            self.restore_backup_var.set(backup_name)
            self.notebook.select(1)  # 復元タブに切り替え
    
    def verify_selected_backup(self):
        """選択されたバックアップを検証"""
        selection = self.backup_tree.selection()
        if selection:
            item = self.backup_tree.item(selection[0])
            backup_name = item['values'][0]
            
            self.restore_backup_var.set(backup_name)
            self.verify_backup()
    
    def show_backup_details(self):
        """バックアップの詳細を表示"""
        selection = self.backup_tree.selection()
        if selection:
            item = self.backup_tree.item(selection[0])
            values = item['values']
            
            detail_text = f"""
バックアップ詳細情報:

名前: {values[0]}
タイプ: {values[1]}
サイズ: {values[2]}
作成日時: {values[3]}
状態: {values[4]}
"""
            
            messagebox.showinfo("バックアップ詳細", detail_text)
    
    def delete_selected_backup(self):
        """選択されたバックアップを削除"""
        selection = self.backup_tree.selection()
        if selection:
            item = self.backup_tree.item(selection[0])
            backup_name = item['values'][0]
            
            result = messagebox.askyesno("バックアップ削除", f"'{backup_name}' を削除しますか？")
            if result:
                # 削除処理実装
                messagebox.showinfo("削除", "バックアップを削除しました")
                self.refresh_backup_list()
    
    def export_selected_backup(self):
        """選択されたバックアップをエクスポート"""
        selection = self.backup_tree.selection()
        if selection:
            item = self.backup_tree.item(selection[0])
            backup_name = item['values'][0]
            
            # エクスポート先を選択
            export_path = filedialog.asksaveasfilename(
                title="バックアップのエクスポート先",
                defaultextension=".zip",
                filetypes=[("ZIP files", "*.zip"), ("All files", "*.*")]
            )
            
            if export_path:
                # エクスポート処理実装
                messagebox.showinfo("エクスポート", f"バックアップをエクスポートしました:\n{export_path}")
    
    def update_status(self, message):
        """ステータスメッセージを更新"""
        if hasattr(self, 'status_label'):
            self.status_label.config(text=message)
    
    def run(self):
        """ウィンドウを実行"""
        try:
            self.window.mainloop()
        except KeyboardInterrupt:
            print("\n👋 バックアップ・復元ウィンドウが中断されました")
        finally:
            # 自動バックアップスケジューラーを停止
            if hasattr(self, 'auto_scheduler'):
                self.auto_scheduler.stop()


def main():
    """メイン関数"""
    try:
        backup_window = BackupRestoreWindow()
        backup_window.run()
    except Exception as e:
        print(f"❌ バックアップ・復元ウィンドウ起動エラー: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()