#!/usr/bin/env python3
"""
BLNCS Plugin Manager - プラグイン管理システム
Extensible plugin system for BLNCS functionality.
"""

import os
import json
import importlib
import inspect
import sys
import threading
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional, Callable
import logging
import traceback

try:
    from .config_manager import get_config_manager
    from ..lightning.client_simple import get_lightning_client
except ImportError:
    sys.path.append(str(Path(__file__).parent.parent))
    from config_manager import get_config_manager
    from lightning.client_simple import get_lightning_client


class PluginBase:
    """プラグインベースクラス"""
    
    def __init__(self):
        self.name = self.__class__.__name__
        self.version = "1.0.0"
        self.description = "BLNCS Plugin"
        self.author = "Unknown"
        self.dependencies = []
        self.enabled = True
        
        self.lightning_client = None
        self.config = None
        self.logger = None
    
    def initialize(self, plugin_manager):
        """プラグイン初期化"""
        self.lightning_client = plugin_manager.lightning_client
        self.config = plugin_manager.config
        self.logger = plugin_manager.get_plugin_logger(self.name)
        
        # プラグイン固有の初期化処理
        self.on_initialize()
    
    def on_initialize(self):
        """プラグイン固有の初期化処理（オーバーライド用）"""
        pass
    
    def on_enable(self):
        """プラグイン有効化時の処理"""
        pass
    
    def on_disable(self):
        """プラグイン無効化時の処理"""
        pass
    
    def on_unload(self):
        """プラグインアンロード時の処理"""
        pass
    
    def get_metadata(self):
        """プラグインメタデータ取得"""
        return {
            'name': self.name,
            'version': self.version,
            'description': self.description,
            'author': self.author,
            'dependencies': self.dependencies,
            'enabled': self.enabled
        }


class EventHook:
    """イベントフック"""
    
    def __init__(self, event_name: str, priority: int = 100):
        self.event_name = event_name
        self.priority = priority
    
    def __call__(self, func):
        func._event_hook = self
        return func


class CommandHandler:
    """コマンドハンドラー"""
    
    def __init__(self, command: str, description: str = "", usage: str = ""):
        self.command = command
        self.description = description
        self.usage = usage
    
    def __call__(self, func):
        func._command_handler = self
        return func


class PluginManager:
    """プラグイン管理システム"""
    
    def __init__(self, config_manager=None):
        self.config = config_manager or get_config_manager()
        self.lightning_client = get_lightning_client()
        
        # プラグイン管理
        self.plugins: Dict[str, PluginBase] = {}
        self.plugin_metadata: Dict[str, dict] = {}
        self.event_handlers: Dict[str, List[tuple]] = {}  # event_name -> [(priority, plugin, handler)]
        self.command_handlers: Dict[str, tuple] = {}  # command -> (plugin, handler)
        
        # プラグインディレクトリ
        self.plugin_dir = Path(self.config.get_data_dir()) / "plugins"
        self.plugin_dir.mkdir(exist_ok=True, parents=True)
        
        # 内蔵プラグインディレクトリ
        self.builtin_plugin_dir = Path(__file__).parent.parent / "plugins"
        
        # ロギング設定
        self.setup_logging()
        
        # プラグイン設定ファイル
        self.plugin_config_file = self.plugin_dir / "plugins.json"
        self.load_plugin_config()
        
        # ロックオブジェクト
        self.plugin_lock = threading.RLock()
    
    def setup_logging(self):
        """ロギング設定"""
        log_dir = self.plugin_dir / "logs"
        log_dir.mkdir(exist_ok=True)
        
        log_file = log_dir / f"plugins_{datetime.now().strftime('%Y%m%d')}.log"
        
        self.logger = logging.getLogger('blncs_plugins')
        self.logger.setLevel(logging.INFO)
        
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(logging.INFO)
        
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        
        self.logger.addHandler(file_handler)
    
    def get_plugin_logger(self, plugin_name: str):
        """プラグイン専用ロガー取得"""
        logger = logging.getLogger(f'blncs_plugins.{plugin_name}')
        logger.setLevel(logging.INFO)
        
        if not logger.handlers:
            handler = logging.FileHandler(
                self.plugin_dir / "logs" / f"{plugin_name}_{datetime.now().strftime('%Y%m%d')}.log",
                encoding='utf-8'
            )
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
        return logger
    
    def load_plugin_config(self):
        """プラグイン設定読み込み"""
        if self.plugin_config_file.exists():
            try:
                with open(self.plugin_config_file, 'r', encoding='utf-8') as f:
                    self.plugin_settings = json.load(f)
            except Exception as e:
                self.logger.error(f"プラグイン設定読み込みエラー: {e}")
                self.plugin_settings = {}
        else:
            self.plugin_settings = {}
    
    def save_plugin_config(self):
        """プラグイン設定保存"""
        try:
            with open(self.plugin_config_file, 'w', encoding='utf-8') as f:
                json.dump(self.plugin_settings, f, indent=2, ensure_ascii=False)
        except Exception as e:
            self.logger.error(f"プラグイン設定保存エラー: {e}")
    
    def discover_plugins(self):
        """プラグイン発見"""
        plugin_paths = []
        
        # 内蔵プラグインを検索
        if self.builtin_plugin_dir.exists():
            plugin_paths.extend(self.builtin_plugin_dir.glob("*.py"))
        
        # ユーザープラグインを検索
        plugin_paths.extend(self.plugin_dir.glob("*.py"))
        plugin_paths.extend(self.plugin_dir.glob("*/plugin.py"))
        
        discovered = []
        for plugin_path in plugin_paths:
            if plugin_path.stem.startswith('__'):
                continue
                
            try:
                metadata = self.extract_plugin_metadata(plugin_path)
                if metadata:
                    discovered.append({
                        'path': str(plugin_path),
                        'metadata': metadata
                    })
            except Exception as e:
                self.logger.error(f"プラグインメタデータ抽出エラー ({plugin_path}): {e}")
        
        return discovered
    
    def extract_plugin_metadata(self, plugin_path: Path):
        """プラグインメタデータ抽出"""
        try:
            # プラグインファイルから基本情報を読み取り
            with open(plugin_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # クラス定義を探す
            import ast
            
            tree = ast.parse(content)
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    # PluginBaseを継承しているクラスを探す
                    for base in node.bases:
                        if isinstance(base, ast.Name) and base.id == 'PluginBase':
                            return {
                                'name': node.name,
                                'path': str(plugin_path),
                                'file_name': plugin_path.name
                            }
            
            return None
            
        except Exception as e:
            self.logger.error(f"メタデータ抽出エラー ({plugin_path}): {e}")
            return None
    
    def load_plugin(self, plugin_path: str):
        """プラグイン読み込み"""
        with self.plugin_lock:
            try:
                plugin_path = Path(plugin_path)
                
                # モジュール名生成
                if plugin_path.parent.name == "plugins" and plugin_path.name != "plugin.py":
                    module_name = plugin_path.stem
                else:
                    module_name = f"{plugin_path.parent.name}.plugin"
                
                # sys.pathに追加
                plugin_dir = str(plugin_path.parent)
                if plugin_dir not in sys.path:
                    sys.path.insert(0, plugin_dir)
                
                # モジュール読み込み
                spec = importlib.util.spec_from_file_location(module_name, plugin_path)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                
                # PluginBaseを継承したクラスを探す
                plugin_class = None
                for name, obj in inspect.getmembers(module):
                    if inspect.isclass(obj) and issubclass(obj, PluginBase) and obj != PluginBase:
                        plugin_class = obj
                        break
                
                if not plugin_class:
                    raise ValueError("PluginBaseを継承したクラスが見つかりません")
                
                # プラグインインスタンス作成
                plugin = plugin_class()
                
                # 依存関係チェック
                if not self.check_dependencies(plugin):
                    raise ValueError(f"依存関係が満たされていません: {plugin.dependencies}")
                
                # プラグイン初期化
                plugin.initialize(self)
                
                # プラグイン登録
                self.plugins[plugin.name] = plugin
                self.plugin_metadata[plugin.name] = plugin.get_metadata()
                
                # イベントハンドラーとコマンドハンドラーを登録
                self.register_plugin_handlers(plugin)
                
                # プラグイン有効化
                if self.plugin_settings.get(plugin.name, {}).get('enabled', True):
                    plugin.enabled = True
                    plugin.on_enable()
                else:
                    plugin.enabled = False
                
                self.logger.info(f"プラグインを読み込みました: {plugin.name} v{plugin.version}")
                
                return {
                    'success': True,
                    'plugin_name': plugin.name,
                    'plugin_version': plugin.version
                }
                
            except Exception as e:
                self.logger.error(f"プラグイン読み込みエラー ({plugin_path}): {e}")
                self.logger.error(traceback.format_exc())
                return {
                    'success': False,
                    'error': str(e)
                }
    
    def unload_plugin(self, plugin_name: str):
        """プラグインアンロード"""
        with self.plugin_lock:
            try:
                if plugin_name not in self.plugins:
                    return {'success': False, 'error': 'プラグインが見つかりません'}
                
                plugin = self.plugins[plugin_name]
                
                # プラグインアンロード処理
                plugin.on_unload()
                
                # ハンドラー削除
                self.unregister_plugin_handlers(plugin)
                
                # プラグイン削除
                del self.plugins[plugin_name]
                del self.plugin_metadata[plugin_name]
                
                self.logger.info(f"プラグインをアンロードしました: {plugin_name}")
                
                return {'success': True}
                
            except Exception as e:
                self.logger.error(f"プラグインアンロードエラー ({plugin_name}): {e}")
                return {'success': False, 'error': str(e)}
    
    def enable_plugin(self, plugin_name: str):
        """プラグイン有効化"""
        with self.plugin_lock:
            if plugin_name in self.plugins:
                plugin = self.plugins[plugin_name]
                if not plugin.enabled:
                    plugin.enabled = True
                    plugin.on_enable()
                    
                    # 設定保存
                    if plugin_name not in self.plugin_settings:
                        self.plugin_settings[plugin_name] = {}
                    self.plugin_settings[plugin_name]['enabled'] = True
                    self.save_plugin_config()
                    
                    self.logger.info(f"プラグインを有効化しました: {plugin_name}")
                    return {'success': True}
                else:
                    return {'success': False, 'error': 'プラグインは既に有効です'}
            else:
                return {'success': False, 'error': 'プラグインが見つかりません'}
    
    def disable_plugin(self, plugin_name: str):
        """プラグイン無効化"""
        with self.plugin_lock:
            if plugin_name in self.plugins:
                plugin = self.plugins[plugin_name]
                if plugin.enabled:
                    plugin.enabled = False
                    plugin.on_disable()
                    
                    # 設定保存
                    if plugin_name not in self.plugin_settings:
                        self.plugin_settings[plugin_name] = {}
                    self.plugin_settings[plugin_name]['enabled'] = False
                    self.save_plugin_config()
                    
                    self.logger.info(f"プラグインを無効化しました: {plugin_name}")
                    return {'success': True}
                else:
                    return {'success': False, 'error': 'プラグインは既に無効です'}
            else:
                return {'success': False, 'error': 'プラグインが見つかりません'}
    
    def check_dependencies(self, plugin: PluginBase):
        """依存関係チェック"""
        for dependency in plugin.dependencies:
            if dependency not in self.plugins:
                return False
        return True
    
    def register_plugin_handlers(self, plugin: PluginBase):
        """プラグインハンドラー登録"""
        try:
            # クラスのメソッドを調査
            for method_name, method in inspect.getmembers(plugin, predicate=inspect.ismethod):
                # イベントハンドラーチェック
                if hasattr(method, '_event_hook'):
                    hook = method._event_hook
                    if hook.event_name not in self.event_handlers:
                        self.event_handlers[hook.event_name] = []
                    
                    self.event_handlers[hook.event_name].append((hook.priority, plugin, method))
                    # 優先度でソート
                    self.event_handlers[hook.event_name].sort(key=lambda x: x[0])
                
                # コマンドハンドラーチェック
                if hasattr(method, '_command_handler'):
                    handler = method._command_handler
                    self.command_handlers[handler.command] = (plugin, method, handler)
            
        except Exception as e:
            self.logger.error(f"ハンドラー登録エラー ({plugin.name}): {e}")
    
    def unregister_plugin_handlers(self, plugin: PluginBase):
        """プラグインハンドラー削除"""
        try:
            # イベントハンドラー削除
            for event_name, handlers in self.event_handlers.items():
                self.event_handlers[event_name] = [(p, pl, h) for p, pl, h in handlers if pl != plugin]
            
            # コマンドハンドラー削除
            commands_to_remove = []
            for command, (pl, handler, info) in self.command_handlers.items():
                if pl == plugin:
                    commands_to_remove.append(command)
            
            for command in commands_to_remove:
                del self.command_handlers[command]
                
        except Exception as e:
            self.logger.error(f"ハンドラー削除エラー ({plugin.name}): {e}")
    
    # イベントシステム
    def emit_event(self, event_name: str, *args, **kwargs):
        """イベント発火"""
        if event_name in self.event_handlers:
            results = []
            for priority, plugin, handler in self.event_handlers[event_name]:
                if plugin.enabled:
                    try:
                        result = handler(*args, **kwargs)
                        results.append({
                            'plugin': plugin.name,
                            'result': result
                        })
                    except Exception as e:
                        self.logger.error(f"イベントハンドラーエラー ({plugin.name}.{handler.__name__}): {e}")
                        results.append({
                            'plugin': plugin.name,
                            'error': str(e)
                        })
            return results
        return []
    
    def handle_command(self, command: str, *args, **kwargs):
        """コマンド処理"""
        if command in self.command_handlers:
            plugin, handler, info = self.command_handlers[command]
            if plugin.enabled:
                try:
                    return {
                        'success': True,
                        'plugin': plugin.name,
                        'result': handler(*args, **kwargs)
                    }
                except Exception as e:
                    self.logger.error(f"コマンドハンドラーエラー ({plugin.name}.{handler.__name__}): {e}")
                    return {
                        'success': False,
                        'plugin': plugin.name,
                        'error': str(e)
                    }
            else:
                return {
                    'success': False,
                    'error': 'プラグインが無効です'
                }
        else:
            return {
                'success': False,
                'error': 'コマンドが見つかりません'
            }
    
    # 情報取得
    def get_loaded_plugins(self):
        """読み込まれたプラグイン一覧取得"""
        return list(self.plugin_metadata.values())
    
    def get_plugin_info(self, plugin_name: str):
        """プラグイン詳細情報取得"""
        if plugin_name in self.plugins:
            plugin = self.plugins[plugin_name]
            metadata = plugin.get_metadata()
            
            # 追加情報
            metadata.update({
                'event_handlers': [name for name in self.event_handlers.keys() 
                                 if any(pl == plugin for _, pl, _ in self.event_handlers[name])],
                'command_handlers': [cmd for cmd, (pl, _, _) in self.command_handlers.items() 
                                   if pl == plugin],
                'loaded_at': getattr(plugin, '_loaded_at', None),
                'last_error': getattr(plugin, '_last_error', None)
            })
            
            return metadata
        return None
    
    def get_available_commands(self):
        """利用可能コマンド一覧取得"""
        commands = []
        for command, (plugin, handler, info) in self.command_handlers.items():
            commands.append({
                'command': command,
                'plugin': plugin.name,
                'description': info.description,
                'usage': info.usage,
                'enabled': plugin.enabled
            })
        return commands
    
    def get_event_handlers(self):
        """イベントハンドラー一覧取得"""
        handlers = {}
        for event_name, handler_list in self.event_handlers.items():
            handlers[event_name] = []
            for priority, plugin, handler in handler_list:
                handlers[event_name].append({
                    'plugin': plugin.name,
                    'priority': priority,
                    'handler': handler.__name__,
                    'enabled': plugin.enabled
                })
        return handlers
    
    def install_plugin_from_file(self, file_path: str):
        """ファイルからプラグインインストール"""
        try:
            source_path = Path(file_path)
            if not source_path.exists():
                return {'success': False, 'error': 'ファイルが見つかりません'}
            
            # プラグインディレクトリにコピー
            target_path = self.plugin_dir / source_path.name
            
            import shutil
            shutil.copy2(source_path, target_path)
            
            # プラグイン読み込み
            result = self.load_plugin(str(target_path))
            
            if result['success']:
                self.logger.info(f"プラグインをインストールしました: {source_path.name}")
                return {
                    'success': True,
                    'plugin_name': result['plugin_name'],
                    'installed_path': str(target_path)
                }
            else:
                # インストール失敗時はファイルを削除
                target_path.unlink()
                return result
                
        except Exception as e:
            self.logger.error(f"プラグインインストールエラー: {e}")
            return {'success': False, 'error': str(e)}


def get_plugin_manager():
    """プラグインマネージャーのシングルトンインスタンス取得"""
    if not hasattr(get_plugin_manager, '_instance'):
        get_plugin_manager._instance = PluginManager()
    return get_plugin_manager._instance


# サンプルプラグイン
class SamplePlugin(PluginBase):
    """サンプルプラグイン"""
    
    def __init__(self):
        super().__init__()
        self.name = "SamplePlugin"
        self.version = "1.0.0"
        self.description = "BLNCSサンプルプラグイン"
        self.author = "BLNCS Team"
    
    def on_initialize(self):
        """初期化処理"""
        self.logger.info(f"{self.name} が初期化されました")
    
    def on_enable(self):
        """有効化処理"""
        self.logger.info(f"{self.name} が有効化されました")
    
    def on_disable(self):
        """無効化処理"""
        self.logger.info(f"{self.name} が無効化されました")
    
    @EventHook('payment_received', priority=50)
    def on_payment_received(self, payment_info):
        """支払い受信イベントハンドラー"""
        self.logger.info(f"支払いを受信しました: {payment_info}")
        return f"SamplePlugin processed payment: {payment_info.get('amount', 0)} sats"
    
    @CommandHandler('sample', description='サンプルコマンド', usage='sample [message]')
    def sample_command(self, message="Hello from SamplePlugin!"):
        """サンプルコマンドハンドラー"""
        self.logger.info(f"サンプルコマンド実行: {message}")
        return {'message': message, 'timestamp': datetime.now().isoformat()}


def main():
    """テスト用メイン関数"""
    manager = PluginManager()
    
    print("=== BLNCS プラグインマネージャー テスト ===")
    
    # サンプルプラグインを手動登録
    sample_plugin = SamplePlugin()
    sample_plugin.initialize(manager)
    manager.plugins[sample_plugin.name] = sample_plugin
    manager.plugin_metadata[sample_plugin.name] = sample_plugin.get_metadata()
    manager.register_plugin_handlers(sample_plugin)
    sample_plugin.on_enable()
    
    # プラグイン一覧表示
    print("\n1. 読み込まれたプラグイン:")
    for plugin in manager.get_loaded_plugins():
        print(f"  - {plugin['name']} v{plugin['version']}: {plugin['description']}")
    
    # イベント発火テスト
    print("\n2. イベント発火テスト:")
    results = manager.emit_event('payment_received', {'amount': 50000, 'sender': 'test_node'})
    for result in results:
        print(f"  {result['plugin']}: {result.get('result', result.get('error'))}")
    
    # コマンド実行テスト
    print("\n3. コマンド実行テスト:")
    result = manager.handle_command('sample', 'テストメッセージ')
    print(f"  結果: {result}")
    
    # 利用可能コマンド表示
    print("\n4. 利用可能コマンド:")
    commands = manager.get_available_commands()
    for cmd in commands:
        print(f"  - {cmd['command']}: {cmd['description']} (プラグイン: {cmd['plugin']})")


if __name__ == "__main__":
    main()