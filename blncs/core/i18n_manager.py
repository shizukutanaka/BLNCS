#!/usr/bin/env python3
"""
BLNCS - Internationalization (i18n) System
国際化システム基盤
"""

import os
import gettext
import locale
from pathlib import Path
from typing import Optional, Dict, Any
import logging

class I18NManager:
    """
    国際化マネージャー
    多言語対応システムを管理
    """

    def __init__(self, domain: str = "blncs", localedir: Optional[str] = None):
        """
        初期化

        Args:
            domain: 翻訳ドメイン名
            localedir: 翻訳ファイルディレクトリ
        """
        self.domain = domain
        self.logger = logging.getLogger("blncs.i18n")

        # デフォルトのロケールディレクトリ設定
        if localedir is None:
            # プロジェクトルートからの相対パス
            project_root = Path(__file__).parent.parent.parent
            self.localedir = project_root / "locale"
        else:
            self.localedir = Path(localedir)

        # 翻訳オブジェクト
        self._translation = None
        self._current_locale = None

        # フォールバック言語設定
        self.fallback_languages = ['en', 'ja']
        self.current_language = self._detect_system_locale()

        # 翻訳ファイルの自動作成ディレクトリ
        self._ensure_locale_structure()

    def _detect_system_locale(self) -> str:
        """システムロケールを検出"""
        try:
            system_locale = locale.getlocale()[0]
            if system_locale:
                # 言語コード部分を抽出 (例: 'ja_JP' -> 'ja')
                lang = system_locale.split('_')[0]
                return lang if self._is_supported_language(lang) else 'en'
        except Exception as e:
            self.logger.warning(f"Failed to detect system locale: {e}")

        return 'en'

    def _is_supported_language(self, lang: str) -> bool:
        """言語がサポートされているかチェック"""
        supported = self.get_supported_languages()
        return lang in supported

    def get_supported_languages(self) -> list:
        """サポートされている言語一覧を取得"""
        languages = []

        if self.localedir.exists():
            for item in self.localedir.iterdir():
                if item.is_dir():
                    # LC_MESSAGESディレクトリがあるかチェック
                    lc_messages = item / "LC_MESSAGES"
                    if lc_messages.exists() and (lc_messages / f"{self.domain}.mo").exists():
                        languages.append(item.name)

        # フォールバックとして基本言語を追加
        for lang in self.fallback_languages:
            if lang not in languages:
                languages.append(lang)

        return sorted(languages)

    def _ensure_locale_structure(self):
        """ロケールディレクトリ構造を確保"""
        if not self.localedir.exists():
            self.localedir.mkdir(parents=True, exist_ok=True)
            self.logger.info(f"Created locale directory: {self.localedir}")

        # 各言語のディレクトリ構造を作成
        for lang in self.fallback_languages + ['es', 'fr', 'de', 'zh', 'ko', 'pt', 'ru', 'ar']:
            lang_dir = self.localedir / lang / "LC_MESSAGES"
            lang_dir.mkdir(parents=True, exist_ok=True)

            # .poファイルが存在しなければ作成
            po_file = lang_dir / f"{self.domain}.po"
            if not po_file.exists():
                self._create_po_template(lang_dir)

    def _create_po_template(self, lang_dir: Path):
        """POテンプレートファイルを作成"""
        po_file = lang_dir / f"{self.domain}.po"

        template_content = f'''# {self.domain} translation file
# Copyright (C) 2025 BLNCS
# This file is distributed under the same license as the BLNCS package.
#
#, fuzzy
msgid ""
msgstr ""
"Project-Id-Version: {self.domain} 2.0.0\\n"
"Report-Msgid-Bugs-To: \\n"
"POT-Creation-Date: 2025-01-01 00:00+0000\\n"
"PO-Revision-Date: YEAR-MO-DA HO:MI+ZONE\\n"
"Last-Translator: FULL NAME <EMAIL@ADDRESS>\\n"
"Language-Team: LANGUAGE <LL@li.org>\\n"
"MIME-Version: 1.0\\n"
"Content-Type: text/plain; charset=UTF-8\\n"
"Content-Transfer-Encoding: 8bit\\n"
"Language: {lang_dir.parent.name}\\n"

# Core messages
msgid "Initializing BLNCS Application"
msgstr ""

msgid "Database connected"
msgstr ""

msgid "Database connection failed"
msgstr ""

msgid "Cache initialized"
msgstr ""

msgid "Performance optimizer initialized"
msgstr ""

msgid "Security manager initialized"
msgstr ""

msgid "Lightning Network client connected"
msgstr ""

msgid "Lightning Network client connection failed"
msgstr ""

msgid "System initialization completed successfully"
msgstr ""

msgid "System initialization failed: %s"
msgstr ""

msgid "Starting server on %s:%s"
msgstr ""

msgid "Shutdown signal received"
msgstr ""

msgid "Server error: %s"
msgstr ""

msgid "Overall Status: %s"
msgstr ""

msgid "Lightning Network:"
msgstr ""

msgid "Performance Metrics:"
msgstr ""

msgid "Health Status: %s"
msgstr ""

msgid "Usage: invoice <amount>"
msgstr ""

msgid "Error getting balance: %s"
msgstr ""

msgid "No channels found"
msgstr ""

msgid "Error getting channels: %s"
msgstr ""

msgid "Error getting node info: %s"
msgstr ""

msgid "Error getting performance metrics: %s"
msgstr ""

msgid "Error getting security status: %s"
msgstr ""

msgid "Creating Invoice for %s sats"
msgstr ""

msgid "Payment Hash: %s"
msgstr ""

msgid "Payment Request: %s"
msgstr ""

msgid "Amount: %s"
msgstr ""

msgid "Status: %s"
msgstr ""

msgid "Error creating invoice: %s"
msgstr ""

msgid "Running System Optimization"
msgstr ""

msgid "Optimization completed:"
msgstr ""

msgid "Cache Optimization:"
msgstr ""

msgid "Database Recommendations:"
msgstr ""

msgid "Error during optimization: %s"
msgstr ""

msgid "Shutting down BLNCS Application"
msgstr ""

msgid "BLNCS Application shutdown completed"
msgstr ""

msgid "Received signal %s, shutting down..."
msgstr ""

msgid "Shutdown requested"
msgstr ""

msgid "Application failed: %s"
msgstr ""

# Interactive CLI messages
msgid "BLNCS v%s - Interactive Mode"
msgstr ""

msgid "Type 'help' for commands or 'quit' to exit"
msgstr ""

msgid "Unknown command: %s"
msgstr ""

msgid "Use 'quit' to exit"
msgstr ""

msgid "Error: %s"
msgstr ""

# Help messages
msgid "Available Commands:"
msgstr ""

msgid "Show this help"
msgstr ""

msgid "Show system status"
msgstr ""

msgid "Show health check"
msgstr ""

msgid "Show wallet balance"
msgstr ""

msgid "Show Lightning channels"
msgstr ""

msgid "Show node information"
msgstr ""

msgid "Show performance metrics"
msgstr ""

msgid "Show security status"
msgstr ""

msgid "Run system optimization"
msgstr ""

msgid "Create Lightning invoice"
msgstr ""

msgid "Exit application"
msgstr ""

# Balance display
msgid "--- Wallet Balance ---"
msgstr ""

msgid "confirmed"
msgstr ""

msgid "pending"
msgstr ""

# Channels display
msgid "--- Lightning Channels ---"
msgstr ""

msgid "Channel ID: %s"
msgstr ""

msgid "Peer: %s"
msgstr ""

msgid "Capacity: %s"
msgstr ""

msgid "Local: %s"
msgstr ""

msgid "Remote: %s"
msgstr ""

msgid "Active: %s"
msgstr ""

# Node info display
msgid "--- Node Information ---"
msgstr ""

# Performance display
msgid "--- Performance Metrics ---"
msgstr ""

msgid "CPU Usage: %s%%"
msgstr ""

msgid "Memory Usage: %s%%"
msgstr ""

msgid "Disk Usage: %s%%"
msgstr ""

msgid "Memory Available: %s GB"
msgstr ""

msgid "Operation Statistics:"
msgstr ""

msgid "calls, avg %ss"
msgstr ""

# Security display
msgid "--- Security Status ---"
msgstr ""

msgid "Active Tokens: %s"
msgstr ""

msgid "Locked Accounts: %s"
msgstr ""

msgid "Failed Login Attempts: %s"
msgstr ""

msgid "Recent Security Events:"
msgstr ""

# Configuration messages
msgid "Creating configuration template at %s"
msgstr ""

msgid "Configuration template created successfully"
msgstr ""

msgid "Configuration sections:"
msgstr ""

msgid "Edit %s to customize settings"
msgstr ""

msgid "Configuration file not found: %s"
msgstr ""

msgid "Creating configuration with default settings..."
msgstr ""

msgid "Configuration file created: %s"
msgstr ""

msgid "Configuration integrity warning: checksum mismatch for %s"
msgstr ""

# Authentication messages
msgid "Authentication token required. Provide --auth-token or set BLNCS_CLI_TOKEN."
msgstr ""

msgid "Authentication failed. Verify the provided token."
msgstr ""

msgid "Access denied. '%s' permission required for this command."
msgstr ""

# Progress messages
msgid "Processing"
msgstr ""

msgid "Complete"
msgstr ""

msgid "Failed"
msgstr ""

# Language names
msgid "English"
msgstr ""

msgid "Japanese"
msgstr ""

msgid "Spanish"
msgstr ""

msgid "French"
msgstr ""

msgid "German"
msgstr ""

msgid "Chinese"
msgstr ""

msgid "Korean"
msgstr ""

msgid "Portuguese"
msgstr ""

msgid "Russian"
msgstr ""

msgid "Arabic"
msgstr ""
'''

        with open(po_file, 'w', encoding='utf-8') as f:
            f.write(template_content)

        self.logger.info(f"Created PO template: {po_file}")

    def set_language(self, language: str) -> bool:
        """
        言語を設定

        Args:
            language: 言語コード (例: 'ja', 'en')

        Returns:
            bool: 設定成功の場合True
        """
        if not self._is_supported_language(language):
            self.logger.warning(f"Unsupported language: {language}")
            return False

        try:
            # 翻訳オブジェクトを再作成
            self._translation = gettext.translation(
                domain=self.domain,
                localedir=self.localedir,
                languages=[language],
                fallback=True
            )

            self._current_locale = language
            self.current_language = language

            # 翻訳関数をインストール
            if self._translation:
                self._translation.install()
            else:
                # フォールバックとしてnull翻訳を使用
                gettext.install(self.domain, fallback=True)

            self.logger.info(f"Language set to: {language}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to set language {language}: {e}")
            return False

    def get_text(self, message: str, *args) -> str:
        """
        翻訳されたテキストを取得

        Args:
            message: 翻訳元のメッセージ
            *args: フォーマット引数

        Returns:
            str: 翻訳されたテキスト
        """
        try:
            if self._translation:
                translated = self._translation.gettext(message)
            else:
                translated = gettext.gettext(message)

            if args:
                translated = translated % args

            return translated
        except Exception as e:
            self.logger.warning(f"Translation error for '{message}': {e}")
            return message % args if args else message

    def get_plural(self, singular: str, plural: str, n: int) -> str:
        """
        複数形の翻訳を取得

        Args:
            singular: 単数形メッセージ
            plural: 複数形メッセージ
            n: 数値

        Returns:
            str: 適切な翻訳
        """
        try:
            if self._translation:
                translated = self._translation.ngettext(singular, plural, n)
            else:
                translated = gettext.ngettext(singular, plural, n)
            return translated
        except Exception as e:
            self.logger.warning(f"Plural translation error: {e}")
            return singular if n == 1 else plural

    def update_translation(self, language: str, key: str, value: str):
        """
        翻訳を更新

        Args:
            language: 言語コード
            key: 翻訳キー
            value: 翻訳値
        """
        po_file = self.localedir / language / "LC_MESSAGES" / f"{self.domain}.po"

        if not po_file.exists():
            self.logger.error(f"PO file not found: {po_file}")
            return

        try:
            # POファイルを更新
            content = po_file.read_text(encoding='utf-8')

            # 既存の翻訳を更新、または新しい翻訳を追加
            if f'msgid "{key}"' in content:
                # 既存の翻訳を更新
                import re
                pattern = f'(msgid "{re.escape(key)}"\\nmsgstr ")(\\"\\".*?"|".*?")'
                replacement = f'\\1"{value}"'
                content = re.sub(pattern, replacement, content)
            else:
                # 新しい翻訳を追加
                new_entry = f'''

msgid "{key}"
msgstr "{value}"
'''
                content += new_entry

            po_file.write_text(content, encoding='utf-8')

            # .moファイルを更新
            self._compile_translation(language)

            self.logger.info(f"Updated translation: {language}/{key}")

        except Exception as e:
            self.logger.error(f"Failed to update translation: {e}")

    def _compile_translation(self, language: str):
        """
        POファイルをMOファイルにコンパイル

        Args:
            language: 言語コード
        """
        try:
            po_file = self.localedir / language / "LC_MESSAGES" / f"{self.domain}.po"
            mo_file = self.localedir / language / "LC_MESSAGES" / f"{self.domain}.mo"

            # msgfmtコマンドを使用（利用可能なら）
            import subprocess
            try:
                result = subprocess.run(
                    ['msgfmt', str(po_file), '-o', str(mo_file)],
                    capture_output=True,
                    text=True
                )
                if result.returncode != 0:
                    self.logger.warning(f"msgfmt failed: {result.stderr}")
            except FileNotFoundError:
                # msgfmtが利用できない場合はPythonで簡易コンパイル
                self._simple_compile_po(po_file, mo_file)

        except Exception as e:
            self.logger.error(f"Failed to compile translation: {e}")

    def _simple_compile_po(self, po_file: Path, mo_file: Path):
        """
        簡易POコンパイラ（Python実装）
        """
        try:
            import re

            content = po_file.read_text(encoding='utf-8')
            translations = {}

            # 翻訳エントリを解析
            entries = re.findall(r'msgid\s+"([^"]*)"\s+msgstr\s+"([^"]*)"', content)

            for msgid, msgstr in entries:
                if msgid and msgstr:
                    translations[msgid] = msgstr

            # 簡易MO形式で保存（実際にはGNUTranslationsで読み込み）
            import struct
            import pickle

            # 簡易的なバイナリ形式で保存
            with open(mo_file, 'wb') as f:
                pickle.dump(translations, f)

        except Exception as e:
            self.logger.error(f"Simple PO compilation failed: {e}")

    def get_language_info(self, language: str) -> Dict[str, Any]:
        """
        言語情報を取得

        Args:
            language: 言語コード

        Returns:
            dict: 言語情報
        """
        info = {
            'code': language,
            'name': self.get_text(f"{language}_name").replace('_name', ''),
            'supported': self._is_supported_language(language),
            'completion': 0
        }

        # 翻訳完了率を計算
        po_file = self.localedir / language / "LC_MESSAGES" / f"{self.domain}.po"
        if po_file.exists():
            try:
                content = po_file.read_text(encoding='utf-8')
                total_entries = len(re.findall(r'msgid\s+"[^"]*"\s+msgstr', content))
                translated_entries = len(re.findall(r'msgid\s+"[^"]*"\s+msgstr\s+"[^"]+"', content))

                if total_entries > 0:
                    info['completion'] = int((translated_entries / total_entries) * 100)
            except Exception as e:
                self.logger.warning(f"Failed to calculate completion for {language}: {e}")

        return info

    def get_all_languages_info(self) -> Dict[str, Dict[str, Any]]:
        """
        すべての言語情報を取得

        Returns:
            dict: 言語コードをキーとした言語情報
        """
        languages = self.get_supported_languages()
        return {lang: self.get_language_info(lang) for lang in languages}

    def export_to_json(self, output_path: str):
        """
        翻訳をJSON形式でエクスポート

        Args:
            output_path: 出力ファイルパス
        """
        try:
            translations = {}

            for language in self.get_supported_languages():
                lang_translations = {}

                po_file = self.localedir / language / "LC_MESSAGES" / f"{self.domain}.po"
                if po_file.exists():
                    try:
                        import re
                        content = po_file.read_text(encoding='utf-8')
                        entries = re.findall(r'msgid\s+"([^"]*)"\s+msgstr\s+"([^"]*)"', content)

                        for msgid, msgstr in entries:
                            if msgid and msgstr:
                                lang_translations[msgid] = msgstr
                    except Exception as e:
                        self.logger.warning(f"Failed to read translations for {language}: {e}")

                translations[language] = lang_translations

            import json
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(translations, f, ensure_ascii=False, indent=2)

            self.logger.info(f"Exported translations to: {output_path}")

        except Exception as e:
            self.logger.error(f"Failed to export translations: {e}")


# グローバルインスタンス
_i18n_manager: Optional[I18NManager] = None

def get_i18n_manager() -> I18NManager:
    """国際化マネージャーのインスタンスを取得"""
    global _i18n_manager
    if _i18n_manager is None:
        _i18n_manager = I18NManager()
    return _i18n_manager

def _(message: str, *args) -> str:
    """
    翻訳関数（gettext._のエイリアス）

    Args:
        message: 翻訳元のメッセージ
        *args: フォーマット引数

    Returns:
        str: 翻訳されたテキスト
    """
    manager = get_i18n_manager()
    return manager.get_text(message, *args)

def ngettext(singular: str, plural: str, n: int) -> str:
    """
    複数形翻訳関数

    Args:
        singular: 単数形メッセージ
        plural: 複数形メッセージ
        n: 数値

    Returns:
        str: 適切な翻訳
    """
    manager = get_i18n_manager()
    return manager.get_plural(singular, plural, n)

# 便利な翻訳関数
def tr(text: str, *args) -> str:
    """翻訳の別名"""
    return _(text, *args)

def translate(text: str, *args) -> str:
    """翻訳の別名"""
    return _(text, *args)
