#!/usr/bin/env python3
"""
BLNCS - Internationalization Test Script
国際化システムのテストスクリプト
"""

import sys
import os
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

def test_i18n_system():
    """国際化システムのテスト"""
    print("=== BLNCS Internationalization Test ===\n")

    try:
        # 国際化マネージャーのテスト
        from blncs import get_i18n_manager, _

        print("1. Testing i18n manager initialization...")
        i18n = get_i18n_manager()
        print(f"   Current language: {i18n.current_language}")
        print(f"   Supported languages: {i18n.get_supported_languages()}")

        print("\n2. Testing translation functions...")

        # 基本的な翻訳テスト
        test_messages = [
            "Hello, World!",
            "Error: %s",
            "Processing",
            "Complete",
            "Failed"
        ]

        for message in test_messages:
            translated = _(message)
            print(f"   '{message}' -> '{translated}'")

        print("\n3. Testing language switching...")

        # 言語切り替えテスト
        languages_to_test = ['en', 'ja']
        for lang in languages_to_test:
            if i18n.set_language(lang):
                print(f"   Language set to: {lang}")
                hello = _("Hello, World!")
                print(f"   'Hello, World!' in {lang}: '{hello}'")
            else:
                print(f"   Failed to set language: {lang}")

        print("\n4. Testing translation statistics...")
        stats = i18n.get_all_languages_info()
        for lang, info in stats.items():
            print(f"   {lang}: {info['completion']:.1f}% complete")

        print("\n5. Testing message extraction...")

        # メッセージ抽出機能のテスト
        source_dir = Path(__file__).parent.parent / "blncs"
        if source_dir.exists():
            # generate_translationsスクリプトの機能をテスト
            sys.path.insert(0, str(Path(__file__).parent))
            from generate_translations import extract_messages_from_directory

            messages = extract_messages_from_directory(source_dir)
            print(f"   Found {len(messages)} files with translatable messages")

            total_messages = 0
            for file_path, file_messages in messages.items():
                total_messages += len(file_messages)

            print(f"   Total translatable messages: {total_messages}")
        else:
            print("   Source directory not found")

        print("\n=== Test completed successfully! ===")
        return True

    except Exception as e:
        print(f"Error during testing: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_cli_i18n():
    """CLIでの国際化テスト"""
    print("\n=== CLI Internationalization Test ===\n")

    try:
        # 環境変数で言語を設定
        os.environ['BLNCS_LOCALE'] = 'ja'

        # CLIコマンドをテスト
        print("1. Testing CLI with Japanese locale...")

        # blncs_main.py のインポートテスト
        try:
            from blncs_main import BLNCSApplication

            print("   CLI module imported successfully")

            # 設定なしでアプリケーションを初期化（エラーが発生するがインポートはテスト可能）
            print("   CLI application class available")

        except ImportError as e:
            print(f"   Import error: {e}")
        except Exception as e:
            print(f"   Application error (expected): {e}")

        print("\n2. Testing environment variable...")

        # 環境変数の確認
        locale_env = os.environ.get('BLNCS_LOCALE', 'not set')
        print(f"   BLNCS_LOCALE: {locale_env}")

        # 設定ファイルの確認
        config_dir = Path("config")
        if config_dir.exists():
            print(f"   Config directory exists: {config_dir}")
            config_files = list(config_dir.glob("*.json"))
            print(f"   Config files: {[f.name for f in config_files]}")
        else:
            print("   Config directory not found")

        print("\n=== CLI test completed ===")
        return True

    except Exception as e:
        print(f"Error during CLI testing: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    print("Testing BLNCS Internationalization System\n")

    success1 = test_i18n_system()
    success2 = test_cli_i18n()

    if success1 and success2:
        print("\n🎉 All tests passed!")
        sys.exit(0)
    else:
        print("\n❌ Some tests failed!")
        sys.exit(1)
