# BLRCS Desktop UI Components
# 分離されたUIコンポーネントでコード品質向上

import tkinter as tk
from tkinter import ttk

class BLRCSStatusPanel:
    """ステータス表示専用パネル"""
    
    def __init__(self, parent):
        self.parent = parent
        self.frame = ttk.LabelFrame(parent, text="システム状態")
        self._setup_status_widgets()
    
    def _setup_status_widgets(self):
        """ステータスウィジェット初期化"""
        # データベース状態
        self.db_status_label = ttk.Label(self.frame, text="データベース: 未接続")
        self.db_status_label.grid(row=0, column=0, sticky="w", padx=5, pady=2)
        
        # LND状態
        self.lnd_status_label = ttk.Label(self.frame, text="LND: 停止")
        self.lnd_status_label.grid(row=1, column=0, sticky="w", padx=5, pady=2)
    
    def update_db_status(self, status: str):
        """データベース状態更新"""
        self.db_status_label.config(text=f"データベース: {status}")
    
    def update_lnd_status(self, status: str):
        """LND状態更新"""
        self.lnd_status_label.config(text=f"LND: {status}")

class BLRCSControlPanel:
    """操作コントロール専用パネル"""
    
    def __init__(self, parent, callbacks=None):
        self.parent = parent
        self.callbacks = callbacks or {}
        self.frame = ttk.LabelFrame(parent, text="操作")
        self._setup_control_widgets()
    
    def _setup_control_widgets(self):
        """コントロールウィジェット初期化"""
        # 開始・停止ボタン
        self.start_button = ttk.Button(
            self.frame, 
            text="開始", 
            command=self.callbacks.get('start')
        )
        self.start_button.grid(row=0, column=0, padx=5, pady=5)
        
        self.stop_button = ttk.Button(
            self.frame, 
            text="停止", 
            command=self.callbacks.get('stop')
        )
        self.stop_button.grid(row=0, column=1, padx=5, pady=5)
        
        # 設定ボタン
        self.config_button = ttk.Button(
            self.frame, 
            text="設定", 
            command=self.callbacks.get('config')
        )
        self.config_button.grid(row=0, column=2, padx=5, pady=5)

class BLRCSMetricsPanel:
    """メトリクス表示専用パネル"""
    
    def __init__(self, parent):
        self.parent = parent
        self.frame = ttk.LabelFrame(parent, text="パフォーマンス")
        self.metrics = {}
        self._setup_metrics_widgets()
    
    def _setup_metrics_widgets(self):
        """メトリクスウィジェット初期化"""
        # CPU使用率
        self.cpu_label = ttk.Label(self.frame, text="CPU: 0%")
        self.cpu_label.grid(row=0, column=0, sticky="w", padx=5, pady=2)
        
        # メモリ使用率
        self.memory_label = ttk.Label(self.frame, text="メモリ: 0MB")
        self.memory_label.grid(row=1, column=0, sticky="w", padx=5, pady=2)
        
        # 応答時間
        self.response_label = ttk.Label(self.frame, text="応答時間: 0ms")
        self.response_label.grid(row=2, column=0, sticky="w", padx=5, pady=2)
    
    def update_metrics(self, metrics: dict):
        """メトリクス更新"""
        self.metrics.update(metrics)
        
        if 'cpu_percent' in self.metrics:
            self.cpu_label.config(text=f"CPU: {self.metrics['cpu_percent']:.1f}%")
        
        if 'memory_mb' in self.metrics:
            self.memory_label.config(text=f"メモリ: {self.metrics['memory_mb']:.0f}MB")
        
        if 'response_time_ms' in self.metrics:
            self.response_label.config(text=f"応答時間: {self.metrics['response_time_ms']:.0f}ms")