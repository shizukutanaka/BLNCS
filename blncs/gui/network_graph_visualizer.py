#!/usr/bin/env python3
"""
BLNCS Network Graph Visualizer - ネットワークグラフ可視化
Interactive network graph visualization for Lightning Network topology.
"""

import tkinter as tk
from tkinter import ttk, messagebox, colorchooser
import math
import random
import threading
from datetime import datetime
from pathlib import Path
import json

try:
    from ..core.config_manager import get_config_manager
    from ..lightning.client_simple import get_lightning_client
except ImportError:
    import sys
    sys.path.append(str(Path(__file__).parent.parent))
    from core.config_manager import get_config_manager
    from lightning.client_simple import get_lightning_client


class NetworkGraphVisualizer:
    """ネットワークグラフビジュアライザー"""
    
    def __init__(self, parent=None):
        if parent:
            self.window = tk.Toplevel(parent)
        else:
            self.window = tk.Tk()
        
        self.lightning_client = get_lightning_client()
        self.config = get_config_manager()
        
        # グラフデータ
        self.nodes = {}  # node_id: {x, y, alias, color, size, channels}
        self.edges = {}  # edge_id: {node1, node2, capacity, state, color}
        self.selected_node = None
        self.dragging_node = None
        
        # 表示設定
        self.zoom_level = 1.0
        self.pan_x = 0
        self.pan_y = 0
        self.show_labels = True
        self.show_capacity = True
        self.animation_enabled = True
        
        # カラースキーム
        self.color_scheme = {
            'background': '#1e1e1e',
            'node_default': '#4a9eff',
            'node_selected': '#ff6b6b',
            'node_self': '#50fa7b',
            'edge_active': '#50fa7b',
            'edge_inactive': '#ff5555',
            'edge_pending': '#f1fa8c',
            'text': '#f8f8f2',
            'grid': '#44475a'
        }
        
        self.setup_window()
        self.create_interface()
        self.initialize_graph()
    
    def setup_window(self):
        """ウィンドウの基本設定"""
        self.window.title("🌐 BLNCS - ネットワークグラフ可視化")
        self.window.geometry("1200x800")
        self.window.minsize(1000, 700)
        self.window.configure(bg="#2b2b2b")
    
    def create_interface(self):
        """インターフェースを作成"""
        # メインフレーム
        main_frame = ttk.Frame(self.window)
        main_frame.pack(fill='both', expand=True)
        
        # ツールバー
        self.create_toolbar(main_frame)
        
        # メインコンテンツエリア
        content_frame = ttk.Frame(main_frame)
        content_frame.pack(fill='both', expand=True)
        
        # 左パネル: コントロール
        self.create_control_panel(content_frame)
        
        # 中央: キャンバス
        self.create_canvas(content_frame)
        
        # 右パネル: 詳細情報
        self.create_info_panel(content_frame)
        
        # ステータスバー
        self.create_status_bar(main_frame)
    
    def create_toolbar(self, parent):
        """ツールバーを作成"""
        toolbar = ttk.Frame(parent)
        toolbar.pack(fill='x', padx=5, pady=5)
        
        # ズームコントロール
        ttk.Label(toolbar, text="ズーム:").pack(side='left', padx=(0, 5))
        ttk.Button(toolbar, text="🔍+", command=self.zoom_in).pack(side='left')
        ttk.Button(toolbar, text="🔍-", command=self.zoom_out).pack(side='left')
        ttk.Button(toolbar, text="🔄", command=self.reset_view).pack(side='left', padx=(0, 10))
        
        # レイアウトオプション
        ttk.Button(toolbar, text="📐 自動配置", 
                  command=self.auto_layout).pack(side='left', padx=(10, 5))
        ttk.Button(toolbar, text="🎯 中央化", 
                  command=self.center_graph).pack(side='left')
        
        # 表示オプション
        self.labels_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(toolbar, text="ラベル表示", 
                       variable=self.labels_var,
                       command=self.toggle_labels).pack(side='left', padx=(20, 5))
        
        self.capacity_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(toolbar, text="容量表示", 
                       variable=self.capacity_var,
                       command=self.toggle_capacity).pack(side='left')
        
        self.animation_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(toolbar, text="アニメーション", 
                       variable=self.animation_var,
                       command=self.toggle_animation).pack(side='left', padx=(5, 0))
        
        # 更新・エクスポート
        ttk.Button(toolbar, text="🔄 更新", 
                  command=self.refresh_graph).pack(side='right', padx=(5, 0))
        ttk.Button(toolbar, text="📤 エクスポート", 
                  command=self.export_graph).pack(side='right')
        ttk.Button(toolbar, text="📷 スクリーンショット", 
                  command=self.take_screenshot).pack(side='right', padx=(0, 5))
    
    def create_control_panel(self, parent):
        """コントロールパネルを作成"""
        panel = ttk.LabelFrame(parent, text="コントロール", width=200)
        panel.pack(side='left', fill='y', padx=(5, 0), pady=5)
        panel.pack_propagate(False)
        
        # フィルター
        filter_frame = ttk.LabelFrame(panel, text="フィルター", padding=10)
        filter_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(filter_frame, text="ノードタイプ:").pack(anchor='w')
        self.node_filter_var = tk.StringVar(value="all")
        node_filter_combo = ttk.Combobox(filter_frame, textvariable=self.node_filter_var,
                                        values=['all', 'active', 'inactive', 'peers'],
                                        state='readonly', width=15)
        node_filter_combo.pack(fill='x', pady=(0, 10))
        node_filter_combo.bind('<<ComboboxSelected>>', self.apply_filters)
        
        ttk.Label(filter_frame, text="最小容量 (sats):").pack(anchor='w')
        self.min_capacity_var = tk.StringVar(value="0")
        capacity_entry = ttk.Entry(filter_frame, textvariable=self.min_capacity_var, width=15)
        capacity_entry.pack(fill='x', pady=(0, 10))
        
        ttk.Button(filter_frame, text="フィルター適用", 
                  command=self.apply_filters).pack(fill='x')
        
        # 表示設定
        display_frame = ttk.LabelFrame(panel, text="表示設定", padding=10)
        display_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(display_frame, text="ノードサイズ:").pack(anchor='w')
        self.node_size_var = tk.DoubleVar(value=20)
        node_size_scale = ttk.Scale(display_frame, from_=10, to=50, 
                                   variable=self.node_size_var,
                                   orient='horizontal', command=self.update_node_size)
        node_size_scale.pack(fill='x', pady=(0, 10))
        
        ttk.Label(display_frame, text="エッジ幅:").pack(anchor='w')
        self.edge_width_var = tk.DoubleVar(value=2)
        edge_width_scale = ttk.Scale(display_frame, from_=1, to=10, 
                                    variable=self.edge_width_var,
                                    orient='horizontal', command=self.update_edge_width)
        edge_width_scale.pack(fill='x', pady=(0, 10))
        
        # カラー設定
        ttk.Button(display_frame, text="カラースキーム", 
                  command=self.open_color_settings).pack(fill='x')
        
        # 統計情報
        stats_frame = ttk.LabelFrame(panel, text="統計", padding=10)
        stats_frame.pack(fill='x', padx=5, pady=5)
        
        self.stats_labels = {}
        stats = ['ノード数', 'エッジ数', '総容量', '平均接続数']
        for stat in stats:
            frame = ttk.Frame(stats_frame)
            frame.pack(fill='x', pady=2)
            ttk.Label(frame, text=f"{stat}:").pack(side='left')
            label = ttk.Label(frame, text="0")
            label.pack(side='right')
            self.stats_labels[stat] = label
    
    def create_canvas(self, parent):
        """キャンバスを作成"""
        canvas_frame = ttk.Frame(parent)
        canvas_frame.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        
        # キャンバス
        self.canvas = tk.Canvas(canvas_frame, bg=self.color_scheme['background'],
                               highlightthickness=0)
        self.canvas.pack(fill='both', expand=True)
        
        # イベントバインディング
        self.canvas.bind('<Button-1>', self.on_canvas_click)
        self.canvas.bind('<B1-Motion>', self.on_canvas_drag)
        self.canvas.bind('<ButtonRelease-1>', self.on_canvas_release)
        self.canvas.bind('<Button-3>', self.on_canvas_right_click)
        self.canvas.bind('<MouseWheel>', self.on_mouse_wheel)
        self.canvas.bind('<Configure>', self.on_canvas_resize)
        
        # Ctrl+ドラッグでパン
        self.canvas.bind('<Control-Button-1>', self.start_pan)
        self.canvas.bind('<Control-B1-Motion>', self.do_pan)
    
    def create_info_panel(self, parent):
        """情報パネルを作成"""
        panel = ttk.LabelFrame(parent, text="詳細情報", width=250)
        panel.pack(side='right', fill='y', padx=(0, 5), pady=5)
        panel.pack_propagate(False)
        
        # ノード情報
        node_frame = ttk.LabelFrame(panel, text="選択ノード", padding=10)
        node_frame.pack(fill='x', padx=5, pady=5)
        
        self.node_info_text = tk.Text(node_frame, height=8, wrap='word', 
                                      font=("Consolas", 9))
        node_info_scroll = ttk.Scrollbar(node_frame, orient='vertical',
                                        command=self.node_info_text.yview)
        self.node_info_text.configure(yscrollcommand=node_info_scroll.set)
        
        self.node_info_text.pack(side='left', fill='both', expand=True)
        node_info_scroll.pack(side='right', fill='y')
        
        # チャンネル情報
        channel_frame = ttk.LabelFrame(panel, text="チャンネル", padding=10)
        channel_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        columns = ('相手', '容量', '状態')
        self.channel_tree = ttk.Treeview(channel_frame, columns=columns, 
                                        show='headings', height=10)
        
        for col in columns:
            self.channel_tree.heading(col, text=col)
            self.channel_tree.column(col, width=70, anchor='center')
        
        channel_scroll = ttk.Scrollbar(channel_frame, orient='vertical',
                                      command=self.channel_tree.yview)
        self.channel_tree.configure(yscrollcommand=channel_scroll.set)
        
        self.channel_tree.pack(side='left', fill='both', expand=True)
        channel_scroll.pack(side='right', fill='y')
        
        # アクションボタン
        action_frame = ttk.Frame(panel)
        action_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Button(action_frame, text="チャンネル開設", 
                  command=self.open_channel_dialog).pack(fill='x', pady=2)
        ttk.Button(action_frame, text="ルート探索", 
                  command=self.find_route_dialog).pack(fill='x', pady=2)
    
    def create_status_bar(self, parent):
        """ステータスバーを作成"""
        status_frame = ttk.Frame(parent)
        status_frame.pack(fill='x', side='bottom')
        
        self.status_label = ttk.Label(status_frame, text="準備完了", 
                                     font=("Segoe UI", 9))
        self.status_label.pack(side='left', padx=5)
        
        # マウス座標表示
        self.coord_label = ttk.Label(status_frame, text="X: 0, Y: 0", 
                                    font=("Segoe UI", 9))
        self.coord_label.pack(side='right', padx=5)
        
        # ズームレベル表示
        self.zoom_label = ttk.Label(status_frame, text="ズーム: 100%", 
                                   font=("Segoe UI", 9))
        self.zoom_label.pack(side='right', padx=5)
    
    def initialize_graph(self):
        """グラフを初期化"""
        self.update_status("グラフ初期化中...")
        
        def init_in_background():
            try:
                # サンプルデータ生成
                self.generate_sample_network()
                
                # 自動レイアウト
                self.window.after(0, self.auto_layout)
                
                # 統計更新
                self.window.after(0, self.update_statistics)
                
                # 描画
                self.window.after(0, self.draw_graph)
                
                self.update_status("準備完了")
                
            except Exception as e:
                self.update_status(f"初期化エラー: {str(e)}")
        
        threading.Thread(target=init_in_background, daemon=True).start()
    
    def generate_sample_network(self):
        """サンプルネットワークを生成"""
        # 中心ノード（自分）
        self.nodes['self'] = {
            'x': 400, 'y': 300,
            'alias': 'My Node',
            'color': self.color_scheme['node_self'],
            'size': 30,
            'channels': []
        }
        
        # ピアノード生成
        node_aliases = [
            'Lightning Hub', 'Bitcoin Pro', 'Satoshi Node', 'Crypto Gateway',
            'Payment Channel', 'Node Runner', 'Lightning Fast', 'Bitcoin Core',
            'Network Hub', 'Payment Pro', 'Lightning Strike', 'Bitcoin Max'
        ]
        
        for i, alias in enumerate(node_aliases):
            node_id = f'node_{i+1}'
            angle = (i / len(node_aliases)) * 2 * math.pi
            radius = 200
            
            self.nodes[node_id] = {
                'x': 400 + radius * math.cos(angle),
                'y': 300 + radius * math.sin(angle),
                'alias': alias,
                'color': self.color_scheme['node_default'],
                'size': 20 + random.randint(0, 10),
                'channels': []
            }
            
            # 自分とのチャンネル
            if random.random() > 0.3:  # 70%の確率で接続
                edge_id = f'edge_self_{node_id}'
                capacity = random.randint(100000, 5000000)
                state = 'active' if random.random() > 0.2 else 'inactive'
                
                self.edges[edge_id] = {
                    'node1': 'self',
                    'node2': node_id,
                    'capacity': capacity,
                    'state': state,
                    'color': self.color_scheme[f'edge_{state}']
                }
                
                self.nodes['self']['channels'].append(edge_id)
                self.nodes[node_id]['channels'].append(edge_id)
        
        # ピア間の接続
        node_ids = list(self.nodes.keys())
        for i in range(len(node_ids)):
            for j in range(i+1, len(node_ids)):
                if node_ids[i] != 'self' and node_ids[j] != 'self':
                    if random.random() > 0.8:  # 20%の確率で接続
                        edge_id = f'edge_{node_ids[i]}_{node_ids[j]}'
                        capacity = random.randint(50000, 2000000)
                        state = 'active' if random.random() > 0.3 else 'inactive'
                        
                        self.edges[edge_id] = {
                            'node1': node_ids[i],
                            'node2': node_ids[j],
                            'capacity': capacity,
                            'state': state,
                            'color': self.color_scheme[f'edge_{state}']
                        }
                        
                        self.nodes[node_ids[i]]['channels'].append(edge_id)
                        self.nodes[node_ids[j]]['channels'].append(edge_id)
    
    def draw_graph(self):
        """グラフを描画"""
        self.canvas.delete('all')
        
        # グリッド描画
        self.draw_grid()
        
        # エッジ描画
        for edge_id, edge in self.edges.items():
            self.draw_edge(edge_id, edge)
        
        # ノード描画
        for node_id, node in self.nodes.items():
            self.draw_node(node_id, node)
        
        # アニメーション
        if self.animation_enabled:
            self.animate_graph()
    
    def draw_grid(self):
        """グリッドを描画"""
        width = self.canvas.winfo_width()
        height = self.canvas.winfo_height()
        
        grid_size = 50 * self.zoom_level
        
        # 垂直線
        for x in range(0, width, int(grid_size)):
            self.canvas.create_line(x, 0, x, height, 
                                   fill=self.color_scheme['grid'], 
                                   dash=(2, 4), tags='grid')
        
        # 水平線
        for y in range(0, height, int(grid_size)):
            self.canvas.create_line(0, y, width, y, 
                                   fill=self.color_scheme['grid'], 
                                   dash=(2, 4), tags='grid')
    
    def draw_node(self, node_id, node):
        """ノードを描画"""
        x = (node['x'] + self.pan_x) * self.zoom_level
        y = (node['y'] + self.pan_y) * self.zoom_level
        size = node['size'] * self.zoom_level
        
        # ノード円
        self.canvas.create_oval(x - size/2, y - size/2, 
                               x + size/2, y + size/2,
                               fill=node['color'], outline='white',
                               width=2 if node_id == self.selected_node else 1,
                               tags=('node', node_id))
        
        # ラベル
        if self.show_labels:
            self.canvas.create_text(x, y + size/2 + 10,
                                   text=node['alias'],
                                   fill=self.color_scheme['text'],
                                   font=("Arial", int(9 * self.zoom_level)),
                                   tags=('label', node_id))
    
    def draw_edge(self, edge_id, edge):
        """エッジを描画"""
        node1 = self.nodes[edge['node1']]
        node2 = self.nodes[edge['node2']]
        
        x1 = (node1['x'] + self.pan_x) * self.zoom_level
        y1 = (node1['y'] + self.pan_y) * self.zoom_level
        x2 = (node2['x'] + self.pan_x) * self.zoom_level
        y2 = (node2['y'] + self.pan_y) * self.zoom_level
        
        width = self.edge_width_var.get() * self.zoom_level
        
        # エッジライン
        self.canvas.create_line(x1, y1, x2, y2,
                               fill=edge['color'],
                               width=width,
                               tags=('edge', edge_id))
        
        # 容量表示
        if self.show_capacity:
            mid_x = (x1 + x2) / 2
            mid_y = (y1 + y2) / 2
            capacity_text = self.format_capacity(edge['capacity'])
            
            self.canvas.create_text(mid_x, mid_y,
                                   text=capacity_text,
                                   fill=self.color_scheme['text'],
                                   font=("Arial", int(8 * self.zoom_level)),
                                   tags=('capacity', edge_id))
    
    def format_capacity(self, capacity):
        """容量を読みやすい形式にフォーマット"""
        if capacity >= 1000000:
            return f"{capacity/1000000:.1f}M"
        elif capacity >= 1000:
            return f"{capacity/1000:.0f}K"
        else:
            return str(capacity)
    
    def auto_layout(self):
        """自動レイアウト（Force-Directed Layout）"""
        self.update_status("自動レイアウト計算中...")
        
        iterations = 50
        k = 100  # 理想的な距離
        c = 0.1  # ダンピング係数
        
        for _ in range(iterations):
            forces = {}
            
            # 各ノードの力を計算
            for node_id in self.nodes:
                forces[node_id] = {'x': 0, 'y': 0}
                
                # 反発力（全ノード間）
                for other_id in self.nodes:
                    if node_id != other_id:
                        dx = self.nodes[node_id]['x'] - self.nodes[other_id]['x']
                        dy = self.nodes[node_id]['y'] - self.nodes[other_id]['y']
                        dist = math.sqrt(dx**2 + dy**2)
                        
                        if dist > 0:
                            repulsion = k**2 / dist
                            forces[node_id]['x'] += (dx / dist) * repulsion
                            forces[node_id]['y'] += (dy / dist) * repulsion
                
                # 引力（接続されたノード間）
                for edge_id in self.nodes[node_id]['channels']:
                    edge = self.edges[edge_id]
                    other_id = edge['node2'] if edge['node1'] == node_id else edge['node1']
                    
                    dx = self.nodes[other_id]['x'] - self.nodes[node_id]['x']
                    dy = self.nodes[other_id]['y'] - self.nodes[node_id]['y']
                    dist = math.sqrt(dx**2 + dy**2)
                    
                    if dist > 0:
                        attraction = dist**2 / k
                        forces[node_id]['x'] += (dx / dist) * attraction * c
                        forces[node_id]['y'] += (dy / dist) * attraction * c
            
            # 力を適用
            for node_id in self.nodes:
                if node_id != 'self':  # 中心ノードは固定
                    self.nodes[node_id]['x'] += forces[node_id]['x'] * 0.01
                    self.nodes[node_id]['y'] += forces[node_id]['y'] * 0.01
        
        self.center_graph()
        self.draw_graph()
        self.update_status("自動レイアウト完了")
    
    def center_graph(self):
        """グラフを中央に配置"""
        if not self.nodes:
            return
        
        # 重心を計算
        center_x = sum(node['x'] for node in self.nodes.values()) / len(self.nodes)
        center_y = sum(node['y'] for node in self.nodes.values()) / len(self.nodes)
        
        # キャンバスの中心
        canvas_center_x = self.canvas.winfo_width() / 2 / self.zoom_level
        canvas_center_y = self.canvas.winfo_height() / 2 / self.zoom_level
        
        # オフセットを計算
        offset_x = canvas_center_x - center_x
        offset_y = canvas_center_y - center_y
        
        # 全ノードを移動
        for node in self.nodes.values():
            node['x'] += offset_x
            node['y'] += offset_y
        
        self.draw_graph()
    
    def animate_graph(self):
        """グラフアニメーション"""
        if not self.animation_enabled:
            return
        
        # パルスアニメーション（選択ノード）
        if self.selected_node and self.selected_node in self.nodes:
            node = self.nodes[self.selected_node]
            # サイズを少し変更
            original_size = node['size']
            node['size'] = original_size + math.sin(datetime.now().timestamp() * 2) * 2
            
            # 再描画は軽量に
            self.window.after(50, self.animate_graph)
    
    # イベントハンドラー
    def on_canvas_click(self, event):
        """キャンバスクリック"""
        # クリック座標をグラフ座標に変換
        graph_x = event.x / self.zoom_level - self.pan_x
        graph_y = event.y / self.zoom_level - self.pan_y
        
        # ノード選択チェック
        for node_id, node in self.nodes.items():
            dist = math.sqrt((graph_x - node['x'])**2 + (graph_y - node['y'])**2)
            if dist <= node['size']:
                self.select_node(node_id)
                self.dragging_node = node_id
                return
        
        # 何もクリックされていない場合は選択解除
        self.select_node(None)
    
    def on_canvas_drag(self, event):
        """キャンバスドラッグ"""
        if self.dragging_node and self.dragging_node in self.nodes:
            # ノードを移動
            graph_x = event.x / self.zoom_level - self.pan_x
            graph_y = event.y / self.zoom_level - self.pan_y
            
            self.nodes[self.dragging_node]['x'] = graph_x
            self.nodes[self.dragging_node]['y'] = graph_y
            
            self.draw_graph()
    
    def on_canvas_release(self, event):
        """キャンバスリリース"""
        self.dragging_node = None
    
    def on_canvas_right_click(self, event):
        """右クリックメニュー"""
        context_menu = tk.Menu(self.window, tearoff=0)
        context_menu.add_command(label="自動配置", command=self.auto_layout)
        context_menu.add_command(label="中央化", command=self.center_graph)
        context_menu.add_separator()
        context_menu.add_command(label="スクリーンショット", command=self.take_screenshot)
        context_menu.post(event.x_root, event.y_root)
    
    def on_mouse_wheel(self, event):
        """マウスホイール（ズーム）"""
        if event.delta > 0:
            self.zoom_in()
        else:
            self.zoom_out()
    
    def on_canvas_resize(self, event):
        """キャンバスリサイズ"""
        self.draw_graph()
    
    def start_pan(self, event):
        """パン開始"""
        self.pan_start_x = event.x
        self.pan_start_y = event.y
    
    def do_pan(self, event):
        """パン実行"""
        dx = event.x - self.pan_start_x
        dy = event.y - self.pan_start_y
        
        self.pan_x += dx / self.zoom_level
        self.pan_y += dy / self.zoom_level
        
        self.pan_start_x = event.x
        self.pan_start_y = event.y
        
        self.draw_graph()
    
    def select_node(self, node_id):
        """ノードを選択"""
        self.selected_node = node_id
        
        if node_id and node_id in self.nodes:
            # ノード情報更新
            node = self.nodes[node_id]
            info_text = f"ID: {node_id}\n"
            info_text += f"エイリアス: {node['alias']}\n"
            info_text += f"チャンネル数: {len(node['channels'])}\n"
            info_text += f"座標: ({node['x']:.0f}, {node['y']:.0f})\n"
            
            self.node_info_text.delete(1.0, tk.END)
            self.node_info_text.insert(1.0, info_text)
            
            # チャンネル情報更新
            for item in self.channel_tree.get_children():
                self.channel_tree.delete(item)
            
            for edge_id in node['channels']:
                edge = self.edges[edge_id]
                other_id = edge['node2'] if edge['node1'] == node_id else edge['node1']
                other_alias = self.nodes[other_id]['alias'] if other_id in self.nodes else other_id
                capacity = self.format_capacity(edge['capacity'])
                state = edge['state']
                
                self.channel_tree.insert('', 'end', values=(other_alias, capacity, state))
        else:
            self.node_info_text.delete(1.0, tk.END)
            for item in self.channel_tree.get_children():
                self.channel_tree.delete(item)
        
        self.draw_graph()
    
    # ツールバーアクション
    def zoom_in(self):
        """ズームイン"""
        self.zoom_level *= 1.2
        self.zoom_label.config(text=f"ズーム: {self.zoom_level*100:.0f}%")
        self.draw_graph()
    
    def zoom_out(self):
        """ズームアウト"""
        self.zoom_level /= 1.2
        self.zoom_label.config(text=f"ズーム: {self.zoom_level*100:.0f}%")
        self.draw_graph()
    
    def reset_view(self):
        """ビューリセット"""
        self.zoom_level = 1.0
        self.pan_x = 0
        self.pan_y = 0
        self.zoom_label.config(text="ズーム: 100%")
        self.center_graph()
    
    def toggle_labels(self):
        """ラベル表示切り替え"""
        self.show_labels = self.labels_var.get()
        self.draw_graph()
    
    def toggle_capacity(self):
        """容量表示切り替え"""
        self.show_capacity = self.capacity_var.get()
        self.draw_graph()
    
    def toggle_animation(self):
        """アニメーション切り替え"""
        self.animation_enabled = self.animation_var.get()
        if self.animation_enabled:
            self.animate_graph()
    
    def refresh_graph(self):
        """グラフ更新"""
        self.update_status("グラフ更新中...")
        
        def refresh_in_background():
            try:
                # Lightning ノードから実際のデータを取得（実装）
                # ここではサンプルデータを再生成
                self.nodes.clear()
                self.edges.clear()
                self.generate_sample_network()
                
                self.window.after(0, self.auto_layout)
                self.window.after(0, self.update_statistics)
                
                self.update_status("グラフ更新完了")
                
            except Exception as e:
                self.update_status(f"更新エラー: {str(e)}")
        
        threading.Thread(target=refresh_in_background, daemon=True).start()
    
    def export_graph(self):
        """グラフをエクスポート"""
        from tkinter import filedialog
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if file_path:
            graph_data = {
                'nodes': self.nodes,
                'edges': self.edges,
                'timestamp': datetime.now().isoformat()
            }
            
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(graph_data, f, indent=2)
            
            messagebox.showinfo("エクスポート完了", f"グラフをエクスポートしました:\n{file_path}")
    
    def take_screenshot(self):
        """スクリーンショット"""
        from tkinter import filedialog
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".ps",
            filetypes=[("PostScript files", "*.ps"), ("All files", "*.*")]
        )
        
        if file_path:
            self.canvas.postscript(file=file_path)
            messagebox.showinfo("スクリーンショット", f"スクリーンショットを保存しました:\n{file_path}")
    
    # コントロールパネルアクション
    def apply_filters(self, event=None):
        """フィルター適用"""
        # フィルター処理実装
        self.draw_graph()
        self.update_status("フィルター適用完了")
    
    def update_node_size(self, value):
        """ノードサイズ更新"""
        for node in self.nodes.values():
            base_size = 20 if node != self.nodes.get('self') else 30
            node['size'] = base_size * (float(value) / 20)
        self.draw_graph()
    
    def update_edge_width(self, value):
        """エッジ幅更新"""
        self.draw_graph()
    
    def open_color_settings(self):
        """カラー設定を開く"""
        color_window = tk.Toplevel(self.window)
        color_window.title("カラースキーム設定")
        color_window.geometry("400x300")
        
        for i, (key, color) in enumerate(self.color_scheme.items()):
            frame = ttk.Frame(color_window)
            frame.pack(fill='x', padx=10, pady=2)
            
            ttk.Label(frame, text=key.replace('_', ' ').title() + ":").pack(side='left')
            
            color_label = tk.Label(frame, bg=color, width=10)
            color_label.pack(side='right', padx=(0, 10))
            
            ttk.Button(frame, text="変更",
                      command=lambda k=key, l=color_label: self.change_color(k, l)).pack(side='right')
    
    def change_color(self, key, label):
        """カラー変更"""
        color = colorchooser.askcolor(initialcolor=self.color_scheme[key])[1]
        if color:
            self.color_scheme[key] = color
            label.config(bg=color)
            
            # キャンバス背景色の場合は即座に適用
            if key == 'background':
                self.canvas.config(bg=color)
            
            self.draw_graph()
    
    def update_statistics(self):
        """統計情報更新"""
        total_capacity = sum(edge['capacity'] for edge in self.edges.values())
        avg_connections = sum(len(node['channels']) for node in self.nodes.values()) / len(self.nodes) if self.nodes else 0
        
        self.stats_labels['ノード数'].config(text=str(len(self.nodes)))
        self.stats_labels['エッジ数'].config(text=str(len(self.edges)))
        self.stats_labels['総容量'].config(text=self.format_capacity(total_capacity))
        self.stats_labels['平均接続数'].config(text=f"{avg_connections:.1f}")
    
    # ダイアログ
    def open_channel_dialog(self):
        """チャンネル開設ダイアログ"""
        if not self.selected_node:
            messagebox.showinfo("情報", "チャンネルを開設するノードを選択してください")
            return
        
        messagebox.showinfo("チャンネル開設", f"ノード '{self.nodes[self.selected_node]['alias']}' とチャンネルを開設します")
    
    def find_route_dialog(self):
        """ルート探索ダイアログ"""
        if not self.selected_node:
            messagebox.showinfo("情報", "ルート探索の起点となるノードを選択してください")
            return
        
        messagebox.showinfo("ルート探索", f"ノード '{self.nodes[self.selected_node]['alias']}' からのルートを探索します")
    
    def update_status(self, message):
        """ステータス更新"""
        if hasattr(self, 'status_label'):
            self.status_label.config(text=message)
    
    def run(self):
        """ビジュアライザーを実行"""
        try:
            # マウス座標更新
            def update_coords(event):
                graph_x = event.x / self.zoom_level - self.pan_x
                graph_y = event.y / self.zoom_level - self.pan_y
                self.coord_label.config(text=f"X: {graph_x:.0f}, Y: {graph_y:.0f}")
            
            self.canvas.bind('<Motion>', update_coords)
            
            self.window.mainloop()
        except KeyboardInterrupt:
            print("\n👋 ネットワークグラフビジュアライザーが中断されました")


def main():
    """メイン関数"""
    try:
        visualizer = NetworkGraphVisualizer()
        visualizer.run()
    except Exception as e:
        print(f"❌ ネットワークグラフビジュアライザー起動エラー: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()