"""
国際化システム for BLNCS
50言語に対応した多言語サポート機能を提供
"""

import json
import os
from typing import Dict, Optional, Any
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


class LanguageCode:
    """言語コード定数"""
    # 主要言語
    ENGLISH = "en"
    JAPANESE = "ja"
    CHINESE_SIMPLIFIED = "zh_CN"
    CHINESE_TRADITIONAL = "zh_TW"
    KOREAN = "ko"
    SPANISH = "es"
    FRENCH = "fr"
    GERMAN = "de"
    ITALIAN = "it"
    PORTUGUESE = "pt"
    RUSSIAN = "ru"
    ARABIC = "ar"
    HINDI = "hi"
    BENGALI = "bn"
    URDU = "ur"
    INDONESIAN = "id"
    THAI = "th"
    VIETNAMESE = "vi"
    TURKISH = "tr"
    POLISH = "pl"
    DUTCH = "nl"
    SWEDISH = "sv"
    NORWEGIAN = "no"
    DANISH = "da"
    FINNISH = "fi"
    GREEK = "el"
    CZECH = "cs"
    HUNGARIAN = "hu"
    ROMANIAN = "ro"
    BULGARIAN = "bg"
    CROATIAN = "hr"
    SERBIAN = "sr"
    SLOVENIAN = "sl"
    SLOVAK = "sk"
    ESTONIAN = "et"
    LATVIAN = "lv"
    LITHUANIAN = "lt"
    MALTESE = "mt"
    ICELANDIC = "is"
    ALBANIAN = "sq"
    MACEDONIAN = "mk"
    BOSNIAN = "bs"
    MONTENEGRIN = "me"
    LUXEMBOURGISH = "lb"
    IRISH = "ga"
    WELSH = "cy"
    SCOTTISH_GAELIC = "gd"
    BASQUE = "eu"
    CATALAN = "ca"
    GALICIAN = "gl"
    ASTURIAN = "ast"

    # 言語リスト
    SUPPORTED_LANGUAGES = [
        ENGLISH, JAPANESE, CHINESE_SIMPLIFIED, CHINESE_TRADITIONAL, KOREAN,
        SPANISH, FRENCH, GERMAN, ITALIAN, PORTUGUESE, RUSSIAN, ARABIC,
        HINDI, BENGALI, URDU, INDONESIAN, THAI, VIETNAMESE, TURKISH, POLISH,
        DUTCH, SWEDISH, NORWEGIAN, DANISH, FINNISH, GREEK, CZECH, HUNGARIAN,
        ROMANIAN, BULGARIAN, CROATIAN, SERBIAN, SLOVENIAN, SLOVAK, ESTONIAN,
        LATVIAN, LITHUANIAN, MALTESE, ICELANDIC, ALBANIAN, MACEDONIAN,
        BOSNIAN, MONTENEGRIN, LUXEMBOURGISH, IRISH, WELSH, SCOTTISH_GAELIC,
        BASQUE, CATALAN, GALICIAN, ASTURIAN
    ]


class TranslationManager:
    """翻訳マネージャー"""

    def __init__(self, translations_dir: str = "translations"):
        """
        初期化
        Args:
            translations_dir: 翻訳ファイルディレクトリ
        """
        self.translations_dir = Path(translations_dir)
        self.translations_dir.mkdir(exist_ok=True)
        self.translations: Dict[str, Dict[str, str]] = {}
        self.current_language = LanguageCode.ENGLISH
        self.fallback_language = LanguageCode.ENGLISH

    def set_language(self, language_code: str):
        """
        言語を設定
        Args:
            language_code: 言語コード
        """
        if language_code not in LanguageCode.SUPPORTED_LANGUAGES:
            raise ValueError(f"サポートされていない言語です: {language_code}")

        if language_code != self.current_language:
            self.current_language = language_code
            self._load_translations(language_code)

    def _load_translations(self, language_code: str):
        """翻訳ファイルを読み込み"""
        try:
            file_path = self.translations_dir / f"{language_code}.json"
            if file_path.exists():
                with open(file_path, 'r', encoding='utf-8') as f:
                    self.translations[language_code] = json.load(f)
            else:
                logger.warning(f"翻訳ファイルが存在しません: {file_path}")
                self.translations[language_code] = {}
        except Exception as e:
            logger.error(f"翻訳ファイル読み込みエラー: {e}")
            self.translations[language_code] = {}

    def translate(self, key: str, **kwargs) -> str:
        """
        翻訳を取得
        Args:
            key: 翻訳キー
            **kwargs: フォーマットパラメータ
        Returns:
            翻訳文字列
        """
        # 現在の言語から翻訳を取得
        if self.current_language in self.translations:
            translation = self.translations[self.current_language].get(key)
            if translation:
                if kwargs:
                    try:
                        return translation.format(**kwargs)
                    except KeyError as e:
                        logger.warning(f"翻訳フォーマットエラー: {e}")
                        return translation
                return translation

        # フォールバック言語から取得
        if self.fallback_language in self.translations:
            translation = self.translations[self.fallback_language].get(key)
            if translation:
                if kwargs:
                    try:
                        return translation.format(**kwargs)
                    except KeyError as e:
                        logger.warning(f"フォールバック翻訳フォーマットエラー: {e}")
                        return translation
                return translation

        # 翻訳が見つからない場合はキーをそのまま返す
        logger.warning(f"翻訳が見つかりません: {key} (言語: {self.current_language})")
        return key

    def add_translation(self, language_code: str, key: str, value: str):
        """
        翻訳を追加
        Args:
            language_code: 言語コード
            key: 翻訳キー
            value: 翻訳値
        """
        if language_code not in self.translations:
            self.translations[language_code] = {}
        self.translations[language_code][key] = value
        self._save_translations(language_code)

    def _save_translations(self, language_code: str):
        """翻訳ファイルを保存"""
        try:
            file_path = self.translations_dir / f"{language_code}.json"
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(self.translations[language_code], f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error(f"翻訳ファイル保存エラー: {e}")

    def get_available_languages(self) -> list:
        """利用可能な言語リストを取得"""
        return [lang for lang in LanguageCode.SUPPORTED_LANGUAGES
                if (self.translations_dir / f"{lang}.json").exists()]

    def create_language_template(self, language_code: str):
        """
        新しい言語のテンプレートを作成
        Args:
            language_code: 言語コード
        """
        template_path = self.translations_dir / f"{language_code}.json"
        if template_path.exists():
            logger.warning(f"言語ファイルが既に存在します: {template_path}")
            return

        # 英語の翻訳をベースにテンプレートを作成
        if self.fallback_language in self.translations:
            template_data = self.translations[self.fallback_language].copy()
            # キーを言語名に変更（例: "Hello" -> "こんにちは"）
            with open(template_path, 'w', encoding='utf-8') as f:
                json.dump(template_data, f, ensure_ascii=False, indent=2)

            logger.info(f"言語テンプレートを作成しました: {template_path}")


class LocalizedFormatter:
    """ローカライズされたフォーマッター"""

    def __init__(self, translation_manager: TranslationManager):
        """
        初期化
        Args:
            translation_manager: 翻訳マネージャー
        """
        self.translator = translation_manager

    def format_message(self, key: str, **kwargs) -> str:
        """
        メッセージをフォーマット
        Args:
            key: メッセージキー
            **kwargs: フォーマットパラメータ
        Returns:
            フォーマットされたメッセージ
        """
        return self.translator.translate(key, **kwargs)

    def format_number(self, number: float, decimals: int = 2) -> str:
        """
        数値をローカライズしてフォーマット
        Args:
            number: 数値
            decimals: 小数点以下の桁数
        Returns:
            フォーマットされた文字列
        """
        # 言語によるフォーマットの違いを実装（簡易版）
        if self.translator.current_language in ['ja', 'zh_CN', 'zh_TW', 'ko']:
            return f"{number:.{decimals}f}"
        else:
            return f"{number:,.{decimals}f}"

    def format_date(self, timestamp: float) -> str:
        """
        日付をローカライズしてフォーマット
        Args:
            timestamp: タイムスタンプ
        Returns:
            フォーマットされた日付文字列
        """
        # 言語による日付フォーマットの違いを実装（簡易版）
        from datetime import datetime
        dt = datetime.fromtimestamp(timestamp)

        if self.translator.current_language == 'ja':
            return dt.strftime("%Y年%m月%d日 %H:%M:%S")
        elif self.translator.current_language in ['zh_CN', 'zh_TW']:
            return dt.strftime("%Y年%m月%d日 %H:%M:%S")
        elif self.translator.current_language == 'ko':
            return dt.strftime("%Y년 %m월 %d일 %H:%M:%S")
        else:
            return dt.strftime("%Y-%m-%d %H:%M:%S")

    def format_currency(self, amount: float, currency: str = "USD") -> str:
        """
        通貨をローカライズしてフォーマット
        Args:
            amount: 金額
            currency: 通貨コード
        Returns:
            フォーマットされた通貨文字列
        """
        # 通貨記号のマッピング
        currency_symbols = {
            "USD": "$", "EUR": "€", "JPY": "¥", "GBP": "£",
            "CNY": "¥", "KRW": "₩", "INR": "₹", "RUB": "₽"
        }

        symbol = currency_symbols.get(currency, currency)

        if self.translator.current_language == 'ja':
            return f"{symbol}{amount:,}"
        elif self.translator.current_language in ['zh_CN', 'zh_TW']:
            return f"{symbol}{amount:,}"
        elif self.translator.current_language == 'ko':
            return f"{symbol}{amount:,}"
        else:
            return f"{symbol}{amount:,.2f}"


# 使用例
def example_usage():
    # 翻訳マネージャーの初期化
    tm = TranslationManager()
    tm.set_language(LanguageCode.JAPANESE)

    # 翻訳の追加
    tm.add_translation(LanguageCode.JAPANESE, "greeting", "こんにちは、{name}さん！")
    tm.add_translation(LanguageCode.ENGLISH, "greeting", "Hello, {name}!")

    # 翻訳の取得
    greeting_ja = tm.translate("greeting", name="田中")
    greeting_en = tm.translate("greeting", name="Tanaka")

    print(f"日本語: {greeting_ja}")
    print(f"英語: {greeting_en}")

    # フォーマッターの使用
    formatter = LocalizedFormatter(tm)

    # 言語を変更
    tm.set_language(LanguageCode.ENGLISH)

    number = formatter.format_number(12345.67)
    date = formatter.format_date(1640995200)  # 2022-01-01 00:00:00
    currency = formatter.format_currency(1000.50, "JPY")

    print(f"数値: {number}")
    print(f"日付: {date}")
    print(f"通貨: {currency}")


if __name__ == "__main__":
    example_usage()
