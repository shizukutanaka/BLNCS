"""
BLNCS セットアップユーティリティ
設定ファイルの自動生成とプロジェクト初期化を行う。
"""

import os
import yaml
from pathlib import Path
from typing import Dict, Any, Optional

from .logger import get_logger
from .config import get_config


def create_default_config(config_path: Optional[str] = None) -> Path:
    """デフォルト設定ファイルを生成"""
    if config_path is None:
        config_path = "config/config.yaml"
    
    config_file = Path(config_path)
    config_file.parent.mkdir(parents=True, exist_ok=True)
    
    logger = get_logger(__name__)
    
    if config_file.exists():
        logger.info(f"設定ファイルは既に存在します: {config_file}")
        return config_file
    
    # デフォルト設定を作成
    default_config = {
        'lightning': {
            'host': 'localhost',
            'port': 8080,
            'network': 'testnet',
            'timeout': 30,
            'cert_path': '~/.lnd/tls.cert',
            'macaroon_path': '~/.lnd/data/chain/bitcoin/testnet/readonly.macaroon'
        },
        'system': {
            'name': 'BLNCS',
            'environment': 'development',
            'log_level': 'info',
            'data_dir': './data'
        },
        'features': {
            'enable_history': True,
            'enable_cache': True,
            'max_history_entries': 1000
        }
    }
    
    # YAML ファイルとして保存
    with open(config_file, 'w', encoding='utf-8') as f:
        yaml.dump(default_config, f, default_flow_style=False, allow_unicode=True, indent=2)
    
    logger.info(f"デフォルト設定ファイルを作成しました: {config_file}")
    return config_file


def initialize_project_directories() -> None:
    """プロジェクトに必要なディレクトリを作成"""
    logger = get_logger(__name__)
    
    directories = [
        'config',
        'data',
        'logs'
    ]
    
    created_dirs = []
    for dir_name in directories:
        dir_path = Path(dir_name)
        if not dir_path.exists():
            dir_path.mkdir(parents=True, exist_ok=True)
            created_dirs.append(dir_name)
            logger.info(f"ディレクトリを作成しました: {dir_name}")
    
    return created_dirs


def setup_environment() -> None:
    """環境変数をチェックし、必要に応じて設定を提案"""
    logger = get_logger(__name__)
    
    env_vars = {
        'LN_HOST': 'Lightning ノードのホスト名',
        'LN_PORT': 'Lightning ノードのポート番号',
        'LN_NETWORK': 'ネットワークタイプ (mainnet/testnet)',
        'LOG_LEVEL': 'ログレベル (debug/info/warning/error)',
        'BLNCS_ENV': '実行環境 (development/production)'
    }
    
    suggestions = []
    for var_name, description in env_vars.items():
        if not os.getenv(var_name):
            suggestions.append(f"export {var_name}=<値>  # {description}")
    
    if suggestions:
        logger.info("以下の環境変数の設定を推奨します:")
        for suggestion in suggestions:
            logger.info(f"  {suggestion}")
    
    return suggestions


def validate_setup() -> Dict[str, bool]:
    """セットアップ状況を検証"""
    logger = get_logger(__name__)
    results = {}
    
    # 設定ファイルの存在確認
    config_exists = Path("config/config.yaml").exists()
    results['config_file'] = config_exists
    
    # ディレクトリの存在確認
    required_dirs = ['config', 'data', 'logs']
    for dir_name in required_dirs:
        exists = Path(dir_name).exists()
        results[f'{dir_name}_dir'] = exists
    
    # 設定ファイルの有効性確認
    if config_exists:
        try:
            config = get_config()
            results['config_valid'] = True
            logger.info("設定ファイルは有効です")
        except Exception as e:
            results['config_valid'] = False
            logger.error(f"設定ファイルにエラーがあります: {e}")
    else:
        results['config_valid'] = False
    
    return results


def run_full_setup() -> Dict[str, Any]:
    """フルセットアップを実行"""
    logger = get_logger(__name__)
    logger.info("BLNCS セットアップを開始します...")
    
    setup_results = {
        'created_dirs': [],
        'config_file': None,
        'env_suggestions': [],
        'validation': {}
    }
    
    try:
        # ディレクトリ作成
        created_dirs = initialize_project_directories()
        setup_results['created_dirs'] = created_dirs
        
        # 設定ファイル作成
        config_file = create_default_config()
        setup_results['config_file'] = str(config_file)
        
        # 環境変数の確認
        env_suggestions = setup_environment()
        setup_results['env_suggestions'] = env_suggestions
        
        # セットアップ検証
        validation_results = validate_setup()
        setup_results['validation'] = validation_results
        
        # 結果サマリー
        all_valid = all(validation_results.values())
        if all_valid:
            logger.info("✅ セットアップが正常に完了しました!")
        else:
            failed_items = [k for k, v in validation_results.items() if not v]
            logger.warning(f"⚠️  一部のセットアップ項目で問題があります: {failed_items}")
        
        setup_results['success'] = all_valid
        
    except Exception as e:
        logger.error(f"セットアップ中にエラーが発生しました: {e}")
        setup_results['success'] = False
        setup_results['error'] = str(e)
    
    return setup_results


if __name__ == "__main__":
    result = run_full_setup()
    print("セットアップ結果:", result)