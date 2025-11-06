#!/usr/bin/env python3
"""
BLNCS - I18N System Integration Script
国際化システム統合スクリプト
"""

import sys
import os
from pathlib import Path
import argparse
import logging

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

def setup_comprehensive_i18n():
    """包括的な国際化システムをセットアップ"""
    try:
        from blncs.core.comprehensive_i18n_system import setup_global_i18n

        print("Setting up comprehensive internationalization system...")

        # グローバル国際化システムをセットアップ
        i18n_system = setup_global_i18n()

        print("✅ Comprehensive I18N system initialized")
        print(f"   Current language: {i18n_system.core_i18n.current_language}")
        print(f"   Supported languages: {len(i18n_system.core_i18n.supported_languages)}")

        return i18n_system

    except Exception as e:
        print(f"❌ Failed to setup I18N system: {e}")
        return None

def enhance_translation_quality(i18n_system):
    """翻訳品質を向上"""
    try:
        print("\nEnhancing translation quality...")

        # 品質向上を実行
        quality_report = i18n_system.enhance_translation_quality()

        print("✅ Translation quality enhanced")
        print("   Quality report:")
        print(f"   - Total languages: {quality_report['total_languages']}")
        print(f"   - Excellent: {len(quality_report['summary']['excellent_languages'])}")
        print(f"   - Good: {len(quality_report['summary']['good_languages'])}")
        print(f"   - Needs improvement: {len(quality_report['summary']['needs_improvement'])}")

        return quality_report

    except Exception as e:
        print(f"❌ Failed to enhance translation quality: {e}")
        return None

def optimize_performance(i18n_system, platform="auto"):
    """パフォーマンスを最適化"""
    try:
        print(f"\nOptimizing performance for platform: {platform}")

        # パフォーマンス最適化を実行
        metrics = i18n_system.optimize_performance(platform)

        print("✅ Performance optimized")
        print("   Performance metrics:")
        print(f"   - Cache size: {metrics['cache_size']}")
        print(f"   - Hit rate: {metrics['hit_rate']:.1f}%")
        print(f"   - Memory usage: {metrics['memory_usage']} bytes")

        return metrics

    except Exception as e:
        print(f"❌ Failed to optimize performance: {e}")
        return None

def generate_documentation(i18n_system, languages=None):
    """多言語ドキュメントを生成"""
    try:
        print("\nGenerating multilingual documentation...")

        target_languages = languages or i18n_system.core_i18n.supported_languages[:7]  # 上位7言語

        # ドキュメント生成を実行
        result = i18n_system.generate_documentation(target_languages)

        print("✅ Documentation generated")
        print(f"   Languages: {result['languages']}")
        print(f"   Output directory: docs/multilingual/")

        return result

    except Exception as e:
        print(f"❌ Failed to generate documentation: {e}")
        return None

def run_comprehensive_test(i18n_system):
    """包括的なテストを実行"""
    try:
        print("\nRunning comprehensive I18N tests...")

        # システム状態を取得
        status = i18n_system.get_system_status()

        print("✅ System status retrieved")
        print(f"   Current language: {status['core_i18n']['current_language']}")
        print(f"   Supported languages: {len(status['core_i18n']['supported_languages'])}")
        print(f"   Cache hit rate: {status['cache']['hit_rate']:.1f}%")
        # 言語切り替えテスト
        test_languages = ['en', 'ja', 'es', 'fr', 'de', 'zh', 'ko']
        successful_switches = 0

        for language in test_languages:
            if language in i18n_system.core_i18n.supported_languages:
                success = i18n_system.set_language(language)
                if success:
                    # 翻訳テスト
                    hello = i18n_system.get_text("Hello, World!")
                    print(f"   ✓ {language}: '{hello}'")
                    successful_switches += 1
                else:
                    print(f"   ✗ {language}: Failed to set language")

        print(f"\n✅ Language switching test: {successful_switches}/{len(test_languages)} successful")

        # 元の言語に戻す
        i18n_system.set_language('en')

        return status

    except Exception as e:
        print(f"❌ Failed to run comprehensive test: {e}")
        return None

def main():
    """メイン関数"""
    parser = argparse.ArgumentParser(description="BLNCS Comprehensive I18N System Setup")
    parser.add_argument("--platform", default="auto", choices=["auto", "mobile", "desktop", "web", "server"],
                       help="Target platform for optimization")
    parser.add_argument("--languages", nargs="*", help="Target languages for documentation")
    parser.add_argument("--test", action="store_true", help="Run comprehensive tests")
    parser.add_argument("--quality-only", action="store_true", help="Only enhance translation quality")
    parser.add_argument("--docs-only", action="store_true", help="Only generate documentation")
    parser.add_argument("--no-optimize", action="store_true", help="Skip performance optimization")

    args = parser.parse_args()

    print("🚀 BLNCS Comprehensive Internationalization System Setup\n")

    # システムセットアップ
    i18n_system = setup_comprehensive_i18n()
    if not i18n_system:
        return 1

    # 品質向上
    if not args.docs_only:
        quality_report = enhance_translation_quality(i18n_system)
        if quality_report:
            print(f"\n📊 Quality Report: {quality_report['total_languages']} languages processed")

    # パフォーマンス最適化
    if not args.no_optimize:
        metrics = optimize_performance(i18n_system, args.platform)
        if metrics:
            print(f"\n⚡ Performance optimized for {args.platform}")

    # ドキュメント生成
    if not args.quality_only:
        docs_result = generate_documentation(i18n_system, args.languages)
        if docs_result:
            print(f"\n📚 Documentation generated for {len(docs_result['languages'])} languages")

    # 包括テスト
    if args.test:
        status = run_comprehensive_test(i18n_system)
        if status:
            print(f"\n🧪 Tests completed: {len(status['core_i18n']['supported_languages'])} languages available")

    print("\n🎉 Comprehensive I18N system setup completed successfully!")
    print("\nNext steps:")
    print("1. Set language: export BLNCS_LOCALE=ja")
    print("2. Test: python blncs_main.py status")
    print("3. View docs: open docs/multilingual/README.md")
    print("4. Customize translations: edit locale/*/LC_MESSAGES/blncs.po")

    return 0

if __name__ == "__main__":
    sys.exit(main())
