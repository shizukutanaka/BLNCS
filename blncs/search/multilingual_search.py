"""
多言語検索システム for BLNCS
言語検出、翻訳、国際化対応検索機能
"""

import re
import json
import logging
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

logger = logging.getLogger(__name__)


class Language(Enum):
    """対応言語"""
    AUTO = "auto"
    JA = "ja"  # 日本語
    EN = "en"  # 英語
    ZH = "zh"  # 中国語
    KO = "ko"  # 韓国語
    FR = "fr"  # フランス語
    DE = "de"  # ドイツ語
    ES = "es"  # スペイン語
    PT = "pt"  # ポルトガル語
    RU = "ru"  # ロシア語
    AR = "ar"  # アラビア語
    HI = "hi"  # ヒンディー語
    TH = "th"  # タイ語
    VI = "vi"  # ベトナム語
    ID = "id"  # インドネシア語


@dataclass
class LanguageInfo:
    """言語情報"""
    code: str
    name: str
    native_name: str
    script: str
    direction: str  # 'ltr' or 'rtl'


class LanguageDetector:
    """言語検出システム"""

    def __init__(self):
        """初期化"""
        self.language_profiles = self._load_language_profiles()
        self.char_ranges = self._load_character_ranges()

    def _load_language_profiles(self) -> Dict[str, LanguageInfo]:
        """言語プロファイルを読み込み"""
        return {
            "ja": LanguageInfo("ja", "Japanese", "日本語", "Han,Hiragana,Katakana", "ltr"),
            "en": LanguageInfo("en", "English", "English", "Latin", "ltr"),
            "zh": LanguageInfo("zh", "Chinese", "中文", "Han", "ltr"),
            "ko": LanguageInfo("ko", "Korean", "한국어", "Hangul", "ltr"),
            "fr": LanguageInfo("fr", "French", "Français", "Latin", "ltr"),
            "de": LanguageInfo("de", "German", "Deutsch", "Latin", "ltr"),
            "es": LanguageInfo("es", "Spanish", "Español", "Latin", "ltr"),
            "pt": LanguageInfo("pt", "Portuguese", "Português", "Latin", "ltr"),
            "ru": LanguageInfo("ru", "Russian", "Русский", "Cyrillic", "ltr"),
            "ar": LanguageInfo("ar", "Arabic", "العربية", "Arabic", "rtl"),
            "hi": LanguageInfo("hi", "Hindi", "हिन्दी", "Devanagari", "ltr"),
            "th": LanguageInfo("th", "Thai", "ไทย", "Thai", "ltr"),
            "vi": LanguageInfo("vi", "Vietnamese", "Tiếng Việt", "Latin", "ltr"),
            "id": LanguageInfo("id", "Indonesian", "Bahasa Indonesia", "Latin", "ltr")
        }

    def _load_character_ranges(self) -> Dict[str, List[Tuple[int, int]]]:
        """文字範囲を読み込み"""
        return {
            "ja": [
                (0x3040, 0x309F),  # ひらがな
                (0x30A0, 0x30FF),  # カタカナ
                (0x4E00, 0x9FAF),  # 漢字 (CJK統合漢字)
                (0x3400, 0x4DBF),  # 漢字拡張A
                (0x20000, 0x2A6DF),  # 漢字拡張B,C,D,E
                (0x2A700, 0x2B73F),  # 漢字拡張F,G
            ],
            "zh": [
                (0x4E00, 0x9FFF),  # CJK統合漢字
                (0x3400, 0x4DBF),  # 漢字拡張A
                (0x20000, 0x2A6DF),  # 漢字拡張B,C,D,E
                (0x2A700, 0x2B73F),  # 漢字拡張F,G
            ],
            "ko": [
                (0xAC00, 0xD7AF),  # ハングル音節
                (0x1100, 0x11FF),  # ハングル字母
                (0x3130, 0x318F),  # ハングル互換字母
            ],
            "ru": [
                (0x0400, 0x04FF),  # キリル文字
                (0x0500, 0x052F),  # キリル文字補助
            ],
            "ar": [
                (0x0600, 0x06FF),  # アラビア文字
                (0x0750, 0x077F),  # アラビア文字補助
                (0x08A0, 0x08FF),  # アラビア文字拡張A
                (0x0870, 0x089F),  # アラビア文字拡張B
            ],
            "hi": [
                (0x0900, 0x097F),  # デーバナーガリー文字
                (0x0980, 0x09FF),  # ベンガル文字
                (0x0A00, 0x0A7F),  # グルムキー文字
                (0x0A80, 0x0AFF),  # グジャラート文字
            ],
            "th": [
                (0x0E00, 0x0E7F),  # タイ文字
            ]
        }

    def detect_language(self, text: str) -> Language:
        """
        テキストの言語を検出
        Args:
            text: 検出対象テキスト
        Returns:
            検出された言語
        """
        if not text or not text.strip():
            return Language.EN

        # 文字コードポイントを分析
        char_scores = {}

        for char in text:
            code = ord(char)

            for lang_code, ranges in self.char_ranges.items():
                for start, end in ranges:
                    if start <= code <= end:
                        char_scores[lang_code] = char_scores.get(lang_code, 0) + 1
                        break

        if char_scores:
            # 最もスコアの高い言語を選択
            detected_lang = max(char_scores.items(), key=lambda x: x[1])[0]

            # 信頼度チェック（テキスト長に対する文字数の割合）
            total_chars = len([c for c in text if ord(c) > 127])
            if total_chars > 0:
                ratio = char_scores[detected_lang] / total_chars
                if ratio > 0.3:  # 30%以上の文字が該当言語の場合
                    return Language(detected_lang)

        # デフォルトの検出アルゴリズム（簡易版）
        return self._detect_by_patterns(text)

    def _detect_by_patterns(self, text: str) -> Language:
        """パターンによる言語検出"""
        # 日本語のパターン
        if re.search(r'[\u3040-\u309f\u30a0-\u30ff]', text):
            return Language.JA

        # 中国語のパターン
        if re.search(r'[\u4e00-\u9faf]', text):
            return Language.ZH

        # 韓国語のパターン
        if re.search(r'[\uac00-\ud7af]', text):
            return Language.KO

        # ロシア語のパターン
        if re.search(r'[\u0400-\u04ff]', text):
            return Language.RU

        # アラビア語のパターン
        if re.search(r'[\u0600-\u06ff]', text):
            return Language.AR

        # ヒンディー語のパターン
        if re.search(r'[\u0900-\u097f]', text):
            return Language.HI

        # タイ語のパターン
        if re.search(r'[\u0e00-\u0e7f]', text):
            return Language.TH

        # 英語がデフォルト
        return Language.EN

    def get_language_info(self, language: Language) -> Optional[LanguageInfo]:
        """言語情報を取得"""
        return self.language_profiles.get(language.value)

    def get_supported_languages(self) -> List[LanguageInfo]:
        """対応言語一覧を取得"""
        return list(self.language_profiles.values())


class TranslationService:
    """翻訳サービス"""

    def __init__(self):
        """初期化"""
        self.translation_cache: Dict[str, str] = {}
        self.cache_file = Path("cache/translation_cache.json")

        # 簡易的な翻訳辞書（実際にはAPIを使用）
        self.translation_dict = self._load_translation_dict()

    def _load_translation_dict(self) -> Dict[str, Dict[str, str]]:
        """翻訳辞書を読み込み"""
        dict_file = Path(__file__).parent / "translation_dict.json"

        if dict_file.exists():
            try:
                with open(dict_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except:
                pass

        # デフォルトの簡易辞書
        return {
            "technology": {
                "ja": "技術",
                "en": "technology",
                "zh": "技术",
                "ko": "기술"
            },
            "search": {
                "ja": "検索",
                "en": "search",
                "zh": "搜索",
                "ko": "검색"
            },
            "artificial intelligence": {
                "ja": "人工知能",
                "en": "artificial intelligence",
                "zh": "人工智能",
                "ko": "인공 지능"
            },
            "machine learning": {
                "ja": "機械学習",
                "en": "machine learning",
                "zh": "机器学习",
                "ko": "기계 학습"
            },
            "blockchain": {
                "ja": "ブロックチェーン",
                "en": "blockchain",
                "zh": "区块链",
                "ko": "블록체인"
            }
        }

    def translate_text(self, text: str, target_lang: Language, source_lang: Language = Language.AUTO) -> str:
        """
        テキストを翻訳
        Args:
            text: 翻訳対象テキスト
            target_lang: 翻訳先言語
            source_lang: 翻訳元言語
        Returns:
            翻訳されたテキスト
        """
        if target_lang == source_lang or target_lang == Language.AUTO:
            return text

        # キャッシュチェック
        cache_key = f"{text}:{source_lang.value}:{target_lang.value}"
        if cache_key in self.translation_cache:
            return self.translation_cache[cache_key]

        # 簡易翻訳（実際にはGoogle Translate APIなどを使用）
        translated = self._simple_translate(text, source_lang, target_lang)

        # キャッシュに保存
        self.translation_cache[cache_key] = translated

        return translated

    def _simple_translate(self, text: str, source_lang: Language, target_lang: Language) -> str:
        """簡易翻訳"""
        if source_lang == Language.AUTO:
            source_lang = LanguageDetector().detect_language(text)

        # 完全一致の翻訳を検索
        for key, translations in self.translation_dict.items():
            if key.lower() in text.lower():
                if target_lang.value in translations:
                    return text.replace(key, translations[target_lang.value])

        # 単語単位の翻訳
        words = text.split()
        translated_words = []

        for word in words:
            # 句読点などを保持
            punctuation = ""
            if word.endswith(('.', ',', '!', '?', ':', ';')):
                punctuation = word[-1]
                word = word[:-1]

            translated_word = word

            # 翻訳辞書から検索
            for key, translations in self.translation_dict.items():
                if word.lower() == key.lower() and target_lang.value in translations:
                    translated_word = translations[target_lang.value]
                    break

            translated_words.append(translated_word + punctuation)

        return " ".join(translated_words)

    def save_cache(self):
        """キャッシュを保存"""
        try:
            cache_dir = self.cache_file.parent
            cache_dir.mkdir(exist_ok=True)

            with open(self.cache_file, 'w', encoding='utf-8') as f:
                json.dump(self.translation_cache, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error(f"Error saving translation cache: {e}")

    def load_cache(self):
        """キャッシュを読み込み"""
        if self.cache_file.exists():
            try:
                with open(self.cache_file, 'r', encoding='utf-8') as f:
                    self.translation_cache = json.load(f)
            except Exception as e:
                logger.error(f"Error loading translation cache: {e}")


class MultilingualSearchEngine:
    """多言語検索エンジン"""

    def __init__(self):
        """初期化"""
        self.detector = LanguageDetector()
        self.translator = TranslationService()

        # 言語別ストップワード
        self.stopwords = self._load_stopwords()

    def _load_stopwords(self) -> Dict[str, Set[str]]:
        """ストップワードを読み込み"""
        stopwords_file = Path(__file__).parent / "stopwords.json"

        if stopwords_file.exists():
            try:
                with open(stopwords_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except:
                pass

        # デフォルトのストップワード
        return {
            "en": {"the", "a", "an", "and", "or", "but", "in", "on", "at", "to", "for", "of", "with", "by", "is", "are", "was", "were"},
            "ja": {"の", "は", "を", "が", "で", "に", "と", "から", "まで", "も", "か", "だ", "です", "ます"},
            "zh": {"的", "一", "是", "在", "不", "了", "有", "和", "人", "这", "中", "大", "为", "上", "个", "国"},
            "ko": {"의", "가", "이", "은", "를", "는", "에", "와", "과", "도", "다", "하다", "이다"}
        }

    def preprocess_text(self, text: str, language: Language) -> str:
        """
        テキストを前処理
        Args:
            text: 前処理対象テキスト
            language: 言語
        Returns:
            前処理されたテキスト
        """
        # 小文字化（英語のみ）
        if language == Language.EN:
            text = text.lower()

        # ストップワード除去
        if language.value in self.stopwords:
            words = text.split()
            filtered_words = [
                word for word in words
                if word not in self.stopwords[language.value]
            ]
            text = " ".join(filtered_words)

        # 特殊文字の正規化
        text = re.sub(r'[^\w\s\u4e00-\u9faf\u3040-\u309f\u30a0-\u30ff\uac00-\ud7af]', ' ', text)

        return text.strip()

    def translate_search_terms(self, terms: List[str], target_language: Language) -> List[str]:
        """
        検索語を翻訳
        Args:
            terms: 検索語リスト
            target_language: 翻訳先言語
        Returns:
            翻訳された検索語リスト
        """
        translated_terms = []

        for term in terms:
            translated = self.translator.translate_text(term, target_language)
            if translated != term:  # 翻訳された場合
                translated_terms.append(translated)

        return translated_terms

    def get_search_languages(self, query: str) -> List[Tuple[Language, float]]:
        """
        検索クエリに適した言語を取得
        Args:
            query: 検索クエリ
        Returns:
            (言語, 信頼度)のリスト
        """
        detected = self.detector.detect_language(query)

        # 検出された言語を優先
        languages = [(detected, 1.0)]

        # 英語をセカンダリとして追加
        if detected != Language.EN:
            languages.append((Language.EN, 0.8))

        return languages

    def normalize_query(self, query: str, target_languages: List[Language]) -> Dict[Language, str]:
        """
        クエリを正規化
        Args:
            query: 検索クエリ
            target_languages: 対象言語リスト
        Returns:
            言語別正規化クエリ
        """
        normalized = {}

        for lang in target_languages:
            # 前処理
            processed = self.preprocess_text(query, lang)

            # 翻訳（必要に応じて）
            if self.detector.detect_language(query) != lang:
                processed = self.translator.translate_text(processed, lang)

            normalized[lang] = processed

        return normalized


# Global instances
_language_detector = None
_translation_service = None
_multilingual_search_engine = None


def get_language_detector() -> LanguageDetector:
    """グローバル言語検出器を取得"""
    global _language_detector
    if _language_detector is None:
        _language_detector = LanguageDetector()
    return _language_detector


def get_translation_service() -> TranslationService:
    """グローバル翻訳サービスを取得"""
    global _translation_service
    if _translation_service is None:
        _translation_service = TranslationService()
    return _translation_service


def get_multilingual_search_engine() -> MultilingualSearchEngine:
    """グローバル多言語検索エンジンを取得"""
    global _multilingual_search_engine
    if _multilingual_search_engine is None:
        _multilingual_search_engine = MultilingualSearchEngine()
    return _multilingual_search_engine


def detect_text_language(text: str) -> Language:
    """テキストの言語を検出（簡易関数）"""
    return get_language_detector().detect_language(text)


def translate_text(text: str, target_lang: Language, source_lang: Language = Language.AUTO) -> str:
    """テキストを翻訳（簡易関数）"""
    return get_translation_service().translate_text(text, target_lang, source_lang)


if __name__ == "__main__":
    # テスト実行
    detector = get_language_detector()
    translator = get_translation_service()
    engine = get_multilingual_search_engine()

    # 言語検出テスト
    test_texts = [
        "Hello world",
        "こんにちは世界",
        "你好世界",
        "안녕하세요 세계",
        "Привет мир"
    ]

    print("Language Detection Test:")
    for text in test_texts:
        detected = detector.detect_language(text)
        info = detector.get_language_info(detected)
        print(f"'{text}' -> {detected.value} ({info.name if info else 'Unknown'})")

    # 翻訳テスト
    print("\nTranslation Test:")
    text = "artificial intelligence"
    for lang in [Language.JA, Language.ZH, Language.KO]:
        translated = translator.translate_text(text, lang)
        print(f"'{text}' -> {lang.value}: '{translated}'")

    # 検索クエリ正規化テスト
    print("\nQuery Normalization Test:")
    query = "machine learning technology"
    languages = engine.get_search_languages(query)
    print(f"Query: '{query}'")
    print(f"Suggested languages: {[(lang.value, score) for lang, score in languages]}")

    normalized = engine.normalize_query(query, [lang for lang, score in languages])
    for lang, processed in normalized.items():
        print(f"  {lang.value}: '{processed}'")
