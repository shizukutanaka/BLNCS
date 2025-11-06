#!/usr/bin/env python3
"""
BLNCS - Global Language Detection and Auto-Translation System
グローバル言語検出・自動翻訳システム
"""

import os
import locale
import json
import threading
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple
import logging
import time
import re

class GlobalLanguageDetector:
    """
    グローバル言語検出システム
    複数のソースから言語を自動検出
    """

    def __init__(self):
        """初期化"""
        self.logger = logging.getLogger("blncs.lang_detector")

        # 言語検出ソース
        self.detection_sources = [
            'environment_variables',
            'system_locale',
            'user_preferences',
            'geolocation',
            'browser_settings',
            'application_settings'
        ]

        # 言語信頼度スコア
        self.language_confidence = {}

        # 検出履歴
        self.detection_history = []

    def detect_language(self, context: Dict[str, Any] = None) -> Tuple[str, float]:
        """
        複数のソースから言語を検出

        Args:
            context: 検出文脈情報

        Returns:
            tuple: (言語コード, 信頼度スコア)
        """
        context = context or {}
        scores = {}

        # 各ソースから言語を検出
        for source in self.detection_sources:
            try:
                score = getattr(self, f'_detect_from_{source}')(context)
                if score:
                    for language, confidence in score.items():
                        if language not in scores:
                            scores[language] = []
                        scores[language].append(confidence)
            except Exception as e:
                self.logger.debug(f"Language detection failed for source {source}: {e}")

        # スコアを統合
        final_scores = {}
        for language, confidence_list in scores.items():
            avg_confidence = sum(confidence_list) / len(confidence_list)
            final_scores[language] = avg_confidence

        # 最高スコアの言語を選択
        if final_scores:
            best_language = max(final_scores.items(), key=lambda x: x[1])
            return best_language

        # デフォルト言語
        return ('en', 0.5)

    def _detect_from_environment_variables(self, context: Dict[str, Any]) -> Dict[str, float]:
        """環境変数から言語を検出"""
        scores = {}

        # 標準的な環境変数をチェック
        env_vars = [
            'BLNCS_LOCALE', 'LANG', 'LANGUAGE', 'LC_ALL', 'LC_MESSAGES'
        ]

        for env_var in env_vars:
            lang_value = os.environ.get(env_var)
            if lang_value:
                # 言語コードを抽出 (例: 'ja_JP.UTF-8' -> 'ja')
                lang_code = lang_value.split('_')[0].split('-')[0].lower()

                if self._is_valid_language(lang_code):
                    scores[lang_code] = 0.9  # 環境変数は高信頼度
                    break

        return scores

    def _detect_from_system_locale(self, context: Dict[str, Any]) -> Dict[str, float]:
        """システムロケールから言語を検出"""
        scores = {}

        try:
            system_locale = locale.getlocale()[0]
            if system_locale:
                lang_code = system_locale.split('_')[0].lower()
                if self._is_valid_language(lang_code):
                    scores[lang_code] = 0.8
        except Exception:
            pass

        return scores

    def _detect_from_user_preferences(self, context: Dict[str, Any]) -> Dict[str, float]:
        """ユーザープリファレンスから言語を検出"""
        scores = {}

        user_id = context.get('user_id')
        if user_id:
            # ユーザー設定ファイルから言語を取得
            prefs_file = Path.home() / '.blncs' / 'preferences.json'
            if prefs_file.exists():
                try:
                    with open(prefs_file, 'r', encoding='utf-8') as f:
                        prefs = json.load(f)

                    user_lang = prefs.get('language')
                    if user_lang and self._is_valid_language(user_lang):
                        scores[user_lang] = 0.95  # ユーザープリファレンスは最高信頼度
                except Exception as e:
                    self.logger.debug(f"Failed to read user preferences: {e}")

        return scores

    def _detect_from_geolocation(self, context: Dict[str, Any]) -> Dict[str, float]:
        """位置情報から言語を検出"""
        scores = {}

        # IPアドレスやGPS情報から地域を推定
        # 実際の実装ではIPアドレスによる地域検出APIを使用
        region = context.get('region') or self._infer_region_from_ip()

        if region:
            # 地域別主要言語
            region_languages = {
                'asia': ['zh', 'ja', 'ko'],
                'europe': ['de', 'fr', 'es', 'it'],
                'americas': ['es', 'pt', 'fr', 'en']
            }

            if region in region_languages:
                for lang in region_languages[region]:
                    scores[lang] = 0.6  # 地域推定は中程度の信頼度

        return scores

    def _detect_from_browser_settings(self, context: Dict[str, Any]) -> Dict[str, float]:
        """ブラウザ設定から言語を検出"""
        scores = {}

        # HTTP Accept-Languageヘッダー
        accept_language = context.get('accept_language', '')
        if accept_language:
            detected_lang = self._parse_accept_language(accept_language)
            if detected_lang:
                scores[detected_lang] = 0.7

        return scores

    def _detect_from_application_settings(self, context: Dict[str, Any]) -> Dict[str, float]:
        """アプリケーション設定から言語を検出"""
        scores = {}

        # 設定ファイルから言語を取得
        config_paths = [
            Path.cwd() / 'config' / 'blncs.json',
            Path.home() / '.blncs' / 'config.json',
            Path('/etc/blncs/config.json')
        ]

        for config_path in config_paths:
            if config_path.exists():
                try:
                    with open(config_path, 'r', encoding='utf-8') as f:
                        config = json.load(f)

                    i18n_config = config.get('i18n', {})
                    language = i18n_config.get('locale') or i18n_config.get('language')

                    if language and self._is_valid_language(language):
                        scores[language] = 0.85
                        break
                except Exception:
                    continue

        return scores

    def _parse_accept_language(self, accept_language: str) -> Optional[str]:
        """Accept-Languageヘッダーを解析"""
        if not accept_language:
            return None

        try:
            languages = []
            for lang_spec in accept_language.split(','):
                lang_spec = lang_spec.strip()
                if ';' in lang_spec:
                    lang, qvalue = lang_spec.split(';', 1)
                    qvalue = float(qvalue.split('=')[1])
                else:
                    lang = lang_spec
                    qvalue = 1.0

                lang = lang.split('-')[0]
                languages.append((lang, qvalue))

            # 優先度順にソート
            languages.sort(key=lambda x: x[1], reverse=True)

            # 有効な言語を検索
            for lang, _ in languages:
                if self._is_valid_language(lang):
                    return lang

        except Exception:
            pass

        return None

    def _infer_region_from_ip(self) -> Optional[str]:
        """IPアドレスから地域を推定"""
        # 実際の実装ではIPアドレスによる地域検出APIを使用
        # ここでは簡易的な推定
        try:
            import socket
            # ローカルIPアドレスを取得
            local_ip = socket.gethostbyname(socket.gethostname())

            # プライベートIPアドレスの場合
            if local_ip.startswith(('10.', '192.168.', '172.')):
                return 'americas'  # デフォルト

            # 実際にはIPアドレスによる地域検出APIを呼び出す
            return None

        except Exception:
            return None

    def _is_valid_language(self, language: str) -> bool:
        """言語コードが有効かチェック"""
        valid_languages = [
            'en', 'ja', 'es', 'fr', 'de', 'zh', 'ko', 'pt', 'ru', 'ar',
            'hi', 'th', 'vi', 'id', 'tr', 'it', 'nl', 'sv', 'da', 'no'
        ]
        return language.lower() in valid_languages

    def update_confidence_scores(self, language: str, actual_usage: bool):
        """
        言語信頼度スコアを更新

        Args:
            language: 言語コード
            actual_usage: 実際に使用されたか
        """
        if language not in self.language_confidence:
            self.language_confidence[language] = {'correct': 0, 'total': 0}

        self.language_confidence[language]['total'] += 1
        if actual_usage:
            self.language_confidence[language]['correct'] += 1

    def get_detection_accuracy(self) -> Dict[str, float]:
        """検出精度を取得"""
        accuracy = {}

        for language, stats in self.language_confidence.items():
            if stats['total'] > 0:
                accuracy[language] = stats['correct'] / stats['total']

        return accuracy

class AutoTranslationProvider:
    """
    自動翻訳プロバイダー統合
    複数の翻訳APIを統合管理
    """

    def __init__(self):
        """初期化"""
        self.logger = logging.getLogger("blncs.auto_translate")

        # API設定
        self.api_providers = {
            'google': {'enabled': False, 'api_key': None, 'rate_limit': 100},
            'deepl': {'enabled': False, 'api_key': None, 'rate_limit': 50},
            'azure': {'enabled': False, 'api_key': None, 'rate_limit': 200},
            'aws': {'enabled': False, 'api_key': None, 'rate_limit': 100}
        }

        # 使用統計
        self.usage_stats = {provider: {'requests': 0, 'errors': 0} for provider in self.api_providers}

        # レート制限管理
        self.rate_limiters = {}

    def configure_provider(self, provider: str, api_key: str, enabled: bool = True):
        """
        翻訳プロバイダーを設定

        Args:
            provider: プロバイダー名
            api_key: APIキー
            enabled: 有効化
        """
        if provider not in self.api_providers:
            self.logger.warning(f"Unknown provider: {provider}")
            return False

        self.api_providers[provider]['api_key'] = api_key
        self.api_providers[provider]['enabled'] = enabled

        self.logger.info(f"Translation provider {provider} configured")
        return True

    def translate_text(self, text: str, target_language: str, source_language: str = 'auto') -> Optional[str]:
        """
        テキストを自動翻訳

        Args:
            text: 翻訳元テキスト
            target_language: 対象言語
            source_language: 翻訳元言語

        Returns:
            Optional[str]: 翻訳結果
        """
        # 利用可能なプロバイダーを検索
        available_providers = [p for p, config in self.api_providers.items() if config['enabled']]

        if not available_providers:
            self.logger.warning("No translation providers available")
            return None

        # 各プロバイダーで翻訳を試行
        for provider in available_providers:
            try:
                translation = self._translate_with_provider(provider, text, target_language, source_language)
                if translation:
                    self.usage_stats[provider]['requests'] += 1
                    return translation
            except Exception as e:
                self.logger.warning(f"Translation failed with {provider}: {e}")
                self.usage_stats[provider]['errors'] += 1

        return None

    def _translate_with_provider(self, provider: str, text: str, target_language: str, source_language: str) -> Optional[str]:
        """指定プロバイダーで翻訳"""
        if provider == 'google':
            return self._translate_with_google(text, target_language, source_language)
        elif provider == 'deepl':
            return self._translate_with_deepl(text, target_language, source_language)
        elif provider == 'azure':
            return self._translate_with_azure(text, target_language, source_language)
        elif provider == 'aws':
            return self._translate_with_aws(text, target_language, source_language)

        return None

    def _translate_with_google(self, text: str, target_language: str, source_language: str) -> Optional[str]:
        """Google Translate API"""
        try:
            from googletrans import Translator
            translator = Translator()
            result = translator.translate(text, src=source_language, dest=target_language)
            return result.text if result else None
        except ImportError:
            self.logger.warning("googletrans not installed")
            return None
        except Exception as e:
            self.logger.error(f"Google translation error: {e}")
            return None

    def _translate_with_deepl(self, text: str, target_language: str, source_language: str) -> Optional[str]:
        """DeepL API"""
        try:
            import deepl
            translator = deepl.Translator(self.api_providers['deepl']['api_key'])
            result = translator.translate_text(text, target_lang=target_language.upper())
            return result.text if result else None
        except ImportError:
            self.logger.warning("deepl not installed")
            return None
        except Exception as e:
            self.logger.error(f"DeepL translation error: {e}")
            return None

    def _translate_with_azure(self, text: str, target_language: str, source_language: str) -> Optional[str]:
        """Azure Translator API"""
        # Azure Translatorの実装
        return None

    def _translate_with_aws(self, text: str, target_language: str, source_language: str) -> Optional[str]:
        """AWS Translate API"""
        # AWS Translateの実装
        return None

    def get_usage_report(self) -> Dict[str, Any]:
        """使用状況レポートを取得"""
        return {
            'providers': self.api_providers,
            'usage_stats': self.usage_stats,
            'total_requests': sum(stats['requests'] for stats in self.usage_stats.values()),
            'total_errors': sum(stats['errors'] for stats in self.usage_stats.values())
        }

class TranslationQualityValidator:
    """
    翻訳品質検証システム
    翻訳の正確性と適切性を自動検証
    """

    def __init__(self):
        """初期化"""
        self.logger = logging.getLogger("blncs.translation_validator")

        # 品質チェックルール
        self.quality_rules = {
            'length_consistency': True,
            'placeholder_preservation': True,
            'terminology_consistency': True,
            'grammar_check': True,
            'cultural_adaptation': True
        }

        # 用語集
        self.terminology = self._load_terminology()

    def _load_terminology(self) -> Dict[str, Dict[str, str]]:
        """用語集を読み込み"""
        terminology_path = Path(__file__).parent.parent / "config" / "terminology.json"

        if terminology_path.exists():
            try:
                with open(terminology_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                self.logger.warning(f"Failed to load terminology: {e}")

        # デフォルト用語集
        return {
            'en': {
                'Lightning Network': 'Lightning Network',
                'Bitcoin': 'Bitcoin',
                'Node': 'Node',
                'Channel': 'Channel',
                'Invoice': 'Invoice',
                'Payment': 'Payment',
                'Wallet': 'Wallet',
                'Balance': 'Balance',
                'Transaction': 'Transaction',
                'Error': 'Error',
                'Warning': 'Warning',
                'Success': 'Success',
                'Failed': 'Failed'
            },
            'ja': {
                'Lightning Network': 'ライトニングネットワーク',
                'Bitcoin': 'ビットコイン',
                'Node': 'ノード',
                'Channel': 'チャネル',
                'Invoice': 'インボイス',
                'Payment': '決済',
                'Wallet': 'ウォレット',
                'Balance': '残高',
                'Transaction': 'トランザクション',
                'Error': 'エラー',
                'Warning': '警告',
                'Success': '成功',
                'Failed': '失敗'
            }
        }

    def validate_translation(self, source_text: str, translation: str, source_lang: str, target_lang: str) -> Dict[str, Any]:
        """
        翻訳を検証

        Args:
            source_text: 翻訳元テキスト
            translation: 翻訳テキスト
            source_lang: 翻訳元言語
            target_lang: 対象言語

        Returns:
            dict: 検証結果
        """
        validation_result = {
            'valid': True,
            'score': 1.0,
            'issues': [],
            'suggestions': []
        }

        # 各ルールで検証
        if self.quality_rules['length_consistency']:
            self._check_length_consistency(source_text, translation, validation_result)

        if self.quality_rules['placeholder_preservation']:
            self._check_placeholder_preservation(source_text, translation, validation_result)

        if self.quality_rules['terminology_consistency']:
            self._check_terminology_consistency(translation, target_lang, validation_result)

        if self.quality_rules['grammar_check']:
            self._check_grammar(translation, target_lang, validation_result)

        # 総合スコアを計算
        validation_result['score'] = self._calculate_overall_score(validation_result)

        return validation_result

    def _check_length_consistency(self, source: str, translation: str, result: Dict[str, Any]):
        """長さの一貫性をチェック"""
        source_len = len(source)
        translation_len = len(translation)

        # 長さが極端に異なる場合
        ratio = min(source_len, translation_len) / max(source_len, translation_len)

        if ratio < 0.3:  # 30%未満
            result['issues'].append(f"Length mismatch: {ratio:.2%}")
".2%"            result['suggestions'].append("Consider reviewing translation length")

    def _check_placeholder_preservation(self, source: str, translation: str, result: Dict[str, Any]):
        """プレースホルダーの保存をチェック"""
        # %s, %d, {} などのプレースホルダーをチェック
        placeholders = re.findall(r'%[sdifg]|\{[^}]+\}', source)

        for placeholder in placeholders:
            if placeholder not in translation:
                result['issues'].append(f"Missing placeholder: {placeholder}")
                result['valid'] = False

    def _check_terminology_consistency(self, translation: str, language: str, result: Dict[str, Any]):
        """用語の一貫性をチェック"""
        if language not in self.terminology:
            return

        # 用語集の用語が正しく使用されているかチェック
        for source_term, correct_translation in self.terminology[language].items():
            if source_term.lower() in translation.lower():
                # 正しい用語が使用されているかチェック
                if correct_translation.lower() not in translation.lower():
                    result['suggestions'].append(f"Consider using standard term: {correct_translation}")

    def _check_grammar(self, translation: str, language: str, result: Dict[str, Any]):
        """文法をチェック"""
        # 基本的な文法チェック
        issues = []

        # 日本語の場合
        if language == 'ja':
            # 句点のチェック
            if not translation.endswith(('。', '！', '？', '…')):
                issues.append("Missing Japanese punctuation")

        # 英語の場合
        elif language == 'en':
            # 大文字のチェック
            if translation and not translation[0].isupper():
                issues.append("First letter should be capitalized")

        if issues:
            result['issues'].extend(issues)
            result['suggestions'].append("Review grammar and punctuation")

    def _calculate_overall_score(self, result: Dict[str, Any]) -> float:
        """総合スコアを計算"""
        base_score = 1.0

        # 問題点ごとにスコアを減点
        for issue in result['issues']:
            if 'placeholder' in issue.lower():
                base_score -= 0.3  # プレースホルダー欠落は重大
            elif 'length' in issue.lower():
                base_score -= 0.2  # 長さ不一致
            elif 'grammar' in issue.lower():
                base_score -= 0.1  # 文法問題

        return max(0.0, base_score)

class SmartLanguageManager:
    """
    スマート言語マネージャー
    機械学習による最適言語選択
    """

    def __init__(self, detector: GlobalLanguageDetector, auto_translator: AutoTranslationProvider):
        """初期化"""
        self.detector = detector
        self.auto_translator = auto_translator
        self.logger = logging.getLogger("blncs.smart_lang")

        # 学習データ
        self.user_language_history = {}
        self.context_language_mapping = {}

        # 適応学習
        self.learning_enabled = True
        self.min_confidence_threshold = 0.7

    def get_optimal_language(self, user_id: str, context: Dict[str, Any]) -> str:
        """
        最適言語を取得

        Args:
            user_id: ユーザーID
            context: 文脈情報

        Returns:
            str: 最適言語コード
        """
        # ユーザーの言語履歴を取得
        user_history = self.user_language_history.get(user_id, [])

        # 過去の使用言語を分析
        if user_history and self.learning_enabled:
            preferred_language = self._analyze_user_language_preference(user_history)
            if preferred_language:
                return preferred_language

        # 自動検出
        detected_language, confidence = self.detector.detect_language(context)

        # 信頼度が低い場合はフォールバック
        if confidence < self.min_confidence_threshold:
            detected_language = self._get_fallback_language(context)

        # 言語履歴を更新
        if user_id:
            if user_id not in self.user_language_history:
                self.user_language_history[user_id] = []

            self.user_language_history[user_id].append({
                'language': detected_language,
                'confidence': confidence,
                'context': context,
                'timestamp': time.time()
            })

            # 履歴を制限（最新50件）
            if len(self.user_language_history[user_id]) > 50:
                self.user_language_history[user_id] = self.user_language_history[user_id][-50:]

        return detected_language

    def _analyze_user_language_preference(self, history: List[Dict[str, Any]]) -> Optional[str]:
        """ユーザーの言語プリファレンスを分析"""
        if not history:
            return None

        # 言語使用頻度をカウント
        language_count = {}
        total_confidence = {}

        for entry in history:
            language = entry['language']
            confidence = entry['confidence']

            language_count[language] = language_count.get(language, 0) + 1
            total_confidence[language] = total_confidence.get(language, 0) + confidence

        # 最も使用頻度の高い言語を選択
        if language_count:
            best_language = max(language_count.items(), key=lambda x: x[1])
            avg_confidence = total_confidence[best_language[0]] / best_language[1]

            if avg_confidence >= 0.8:  # 80%以上の信頼度
                return best_language[0]

        return None

    def _get_fallback_language(self, context: Dict[str, Any]) -> str:
        """フォールバック言語を取得"""
        # プラットフォーム別フォールバック
        platform = context.get('platform', 'desktop')

        fallbacks = {
            'mobile': ['en', 'ja', 'es', 'fr', 'de'],
            'desktop': ['en', 'ja', 'de', 'fr', 'es'],
            'web': ['en', 'ja', 'es', 'fr', 'de']
        }

        available_langs = fallbacks.get(platform, ['en'])

        # 利用可能な言語から選択
        for lang in available_langs:
            if self._is_language_available(lang):
                return lang

        return 'en'

    def _is_language_available(self, language: str) -> bool:
        """言語が利用可能かチェック"""
        # 実際には国際化マネージャーの利用可能言語をチェック
        return True  # 仮実装

    def update_user_preference(self, user_id: str, language: str, feedback: str):
        """
        ユーザーの言語プリファレンスを更新

        Args:
            user_id: ユーザーID
            language: 言語
            feedback: フィードバック ('positive', 'negative', 'neutral')
        """
        if user_id not in self.user_language_history:
            self.user_language_history[user_id] = []

        self.user_language_history[user_id].append({
            'language': language,
            'feedback': feedback,
            'timestamp': time.time()
        })

    def get_language_recommendations(self, user_id: str) -> List[str]:
        """
        言語推奨を取得

        Args:
            user_id: ユーザーID

        Returns:
            list: 推奨言語リスト
        """
        if user_id not in self.user_language_history:
            return ['en', 'ja', 'es']

        # ユーザーの使用履歴に基づいて推奨
        user_history = self.user_language_history[user_id]
        language_scores = {}

        for entry in user_history:
            language = entry['language']
            feedback = entry['feedback']

            if language not in language_scores:
                language_scores[language] = 0

            if feedback == 'positive':
                language_scores[language] += 1
            elif feedback == 'negative':
                language_scores[language] -= 0.5

        # スコア順にソート
        sorted_languages = sorted(language_scores.items(), key=lambda x: x[1], reverse=True)

        return [lang for lang, score in sorted_languages[:5]]
