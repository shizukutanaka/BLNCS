#!/usr/bin/env python3
"""
BLNCS - Language Quality Enhancement System
言語品質向上システム
"""

import re
import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import logging

class LanguageQualityEnhancer:
    """
    言語品質向上システム
    各言語の翻訳品質を向上させる機能を提供
    """

    def __init__(self, i18n_manager):
        """
        初期化

        Args:
            i18n_manager: 国際化マネージャー
        """
        self.i18n_manager = i18n_manager
        self.logger = logging.getLogger("blncs.i18n_quality")

        # 品質チェックルール
        self.quality_rules = self._load_quality_rules()

        # 言語別品質メトリクス
        self.quality_metrics = {}

    def _load_quality_rules(self) -> Dict[str, Dict[str, Any]]:
        """品質チェックルールを読み込み"""
        rules_path = Path(__file__).parent.parent / "config" / "i18n_quality_rules.json"

        if rules_path.exists():
            try:
                with open(rules_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                self.logger.warning(f"Failed to load quality rules: {e}")

        # デフォルトの品質ルール
        return {
            'common': {
                'min_length': 3,
                'max_length': 100,
                'no_empty_translations': True,
                'no_untranslated_placeholders': True,
                'consistent_terminology': True
            },
            'ja': {
                'check_honorifics': True,
                'check_particle_usage': True,
                'preferred_script': 'mixed',
                'avoid_roman_letters': False
            },
            'zh': {
                'check_traditional_simplified': False,
                'check_tone_marks': False,
                'preferred_encoding': 'utf-8'
            },
            'ko': {
                'check_hangul_only': False,
                'check_hanja_usage': False,
                'honorifics_level': 'standard'
            },
            'de': {
                'check_gender_neutral': False,
                'check_compound_words': True,
                'formal_address': True
            },
            'fr': {
                'check_gender_agreement': False,
                'check_contractions': True,
                'formal_address': True
            },
            'es': {
                'check_regional_variants': False,
                'check_subjunctive_mood': False,
                'formal_address': True
            }
        }

    def enhance_asian_languages(self):
        """アジア言語の翻訳品質を向上"""
        asian_languages = ['ja', 'zh', 'ko']

        for language in asian_languages:
            if language in self.i18n_manager.supported_languages:
                self.logger.info(f"Enhancing {language} translations...")

                # 日本語の品質向上
                if language == 'ja':
                    self._enhance_japanese_quality()

                # 中国語の品質向上
                elif language == 'zh':
                    self._enhance_chinese_quality()

                # 韓国語の品質向上
                elif language == 'ko':
                    self._enhance_korean_quality()

    def _enhance_japanese_quality(self):
        """日本語翻訳の品質を向上"""
        po_file = self.i18n_manager.localedir / 'ja' / 'LC_MESSAGES' / f"{self.i18n_manager.domain}.po"

        if not po_file.exists():
            return

        try:
            content = po_file.read_text(encoding='utf-8')
            lines = content.split('\n')
            updated_lines = []

            for i, line in enumerate(lines):
                if line.startswith('msgstr "'):
                    # 日本語特有の品質改善
                    translated_text = self._improve_japanese_translation(line)
                    updated_lines.append(f'msgstr "{translated_text}"')
                else:
                    updated_lines.append(line)

            # ファイルを更新
            updated_content = '\n'.join(updated_lines)
            po_file.write_text(updated_content, encoding='utf-8')

            # 翻訳をコンパイル
            self.i18n_manager._compile_translation('ja')

            self.logger.info("Japanese translation quality enhanced")

        except Exception as e:
            self.logger.error(f"Failed to enhance Japanese translations: {e}")

    def _improve_japanese_translation(self, msgstr_line: str) -> str:
        """日本語翻訳を改善"""
        # msgstr "..." の部分を抽出
        match = re.search(r'msgstr "(.+)"', msgstr_line)
        if not match:
            return msgstr_line

        text = match.group(1)

        # 改善ルール
        improvements = [
            # 英語の用語を適切な日本語に置換
            (r'Lightning Network', 'ライトニングネットワーク'),
            (r'Bitcoin', 'ビットコイン'),
            (r'Node', 'ノード'),
            (r'Channel', 'チャネル'),
            (r'Invoice', 'インボイス'),
            (r'Payment', '決済'),
            (r'Wallet', 'ウォレット'),
            (r'Balance', '残高'),
            (r'Transaction', 'トランザクション'),
            (r'Error', 'エラー'),
            (r'Warning', '警告'),
            (r'Success', '成功'),
            (r'Failed', '失敗'),
            (r'Connected', '接続済み'),
            (r'Disconnected', '切断'),
            (r'Configuration', '設定'),
            (r'Authentication', '認証'),
            (r'Security', 'セキュリティ'),
            (r'Performance', 'パフォーマンス'),
            (r'Metrics', 'メトリクス'),
            (r'Status', 'ステータス'),
            (r'Database', 'データベース'),
            (r'Cache', 'キャッシュ'),
            (r'Server', 'サーバー'),
            (r'Client', 'クライアント'),
            (r'API', 'API'),
            (r'JSON', 'JSON'),
            (r'HTTP', 'HTTP'),
            (r'HTTPS', 'HTTPS'),
            (r'TLS', 'TLS'),
            (r'SSL', 'SSL'),
            (r'Timeout', 'タイムアウト'),
            (r'Backup', 'バックアップ'),
            (r'Restore', '復元'),
            (r'Migration', 'マイグレーション'),
            (r'Update', '更新'),
            (r'Deploy', 'デプロイ'),
            (r'Monitor', '監視'),
            (r'Log', 'ログ'),
            (r'Audit', '監査'),
            (r'Compliance', 'コンプライアンス'),
            (r'GDPR', 'GDPR'),
            (r'SOC 2', 'SOC 2'),
            (r'PCI-DSS', 'PCI-DSS')
        ]

        improved_text = text
        for pattern, replacement in improvements:
            improved_text = re.sub(pattern, replacement, improved_text)

        # 丁寧語の改善
        if not any(word in improved_text for word in ['です', 'ます', 'ございます']):
            # 必要に応じて丁寧語を追加
            if '完了' in improved_text or '成功' in improved_text:
                improved_text = improved_text.replace('完了', '完了しました').replace('成功', '成功しました')

        return improved_text

    def _enhance_chinese_quality(self):
        """中国語翻訳の品質を向上"""
        po_file = self.i18n_manager.localedir / 'zh' / 'LC_MESSAGES' / f"{self.i18n_manager.domain}.po"

        if not po_file.exists():
            return

        try:
            content = po_file.read_text(encoding='utf-8')
            lines = content.split('\n')
            updated_lines = []

            for i, line in enumerate(lines):
                if line.startswith('msgstr "'):
                    translated_text = self._improve_chinese_translation(line)
                    updated_lines.append(f'msgstr "{translated_text}"')
                else:
                    updated_lines.append(line)

            updated_content = '\n'.join(updated_lines)
            po_file.write_text(updated_content, encoding='utf-8')

            self.i18n_manager._compile_translation('zh')
            self.logger.info("Chinese translation quality enhanced")

        except Exception as e:
            self.logger.error(f"Failed to enhance Chinese translations: {e}")

    def _improve_chinese_translation(self, msgstr_line: str) -> str:
        """中国語翻訳を改善"""
        match = re.search(r'msgstr "(.+)"', msgstr_line)
        if not match:
            return msgstr_line

        text = match.group(1)

        # 中国語特有の用語改善
        improvements = [
            (r'Lightning Network', '闪电网络'),
            (r'Bitcoin', '比特币'),
            (r'Node', '节点'),
            (r'Channel', '通道'),
            (r'Invoice', '发票'),
            (r'Payment', '支付'),
            (r'Wallet', '钱包'),
            (r'Balance', '余额'),
            (r'Transaction', '交易'),
            (r'Error', '错误'),
            (r'Warning', '警告'),
            (r'Success', '成功'),
            (r'Failed', '失败'),
            (r'Connected', '已连接'),
            (r'Disconnected', '已断开'),
            (r'Configuration', '配置'),
            (r'Authentication', '认证'),
            (r'Security', '安全'),
            (r'Performance', '性能'),
            (r'Metrics', '指标'),
            (r'Status', '状态'),
            (r'Database', '数据库'),
            (r'Cache', '缓存'),
            (r'Server', '服务器'),
            (r'Client', '客户端'),
            (r'API', 'API'),
            (r'HTTP', 'HTTP'),
            (r'HTTPS', 'HTTPS'),
            (r'Backup', '备份'),
            (r'Restore', '恢复'),
            (r'Monitor', '监控'),
            (r'Log', '日志'),
            (r'Audit', '审计')
        ]

        improved_text = text
        for pattern, replacement in improvements:
            improved_text = re.sub(pattern, replacement, improved_text)

        return improved_text

    def _enhance_korean_quality(self):
        """韓国語翻訳の品質を向上"""
        po_file = self.i18n_manager.localedir / 'ko' / 'LC_MESSAGES' / f"{self.i18n_manager.domain}.po"

        if not po_file.exists():
            return

        try:
            content = po_file.read_text(encoding='utf-8')
            lines = content.split('\n')
            updated_lines = []

            for i, line in enumerate(lines):
                if line.startswith('msgstr "'):
                    translated_text = self._improve_korean_translation(line)
                    updated_lines.append(f'msgstr "{translated_text}"')
                else:
                    updated_lines.append(line)

            updated_content = '\n'.join(updated_lines)
            po_file.write_text(updated_content, encoding='utf-8')

            self.i18n_manager._compile_translation('ko')
            self.logger.info("Korean translation quality enhanced")

        except Exception as e:
            self.logger.error(f"Failed to enhance Korean translations: {e}")

    def _improve_korean_translation(self, msgstr_line: str) -> str:
        """韓国語翻訳を改善"""
        match = re.search(r'msgstr "(.+)"', msgstr_line)
        if not match:
            return msgstr_line

        text = match.group(1)

        # 韓国語特有の用語改善
        improvements = [
            (r'Lightning Network', '라이트닝 네트워크'),
            (r'Bitcoin', '비트코인'),
            (r'Node', '노드'),
            (r'Channel', '채널'),
            (r'Invoice', '인보이스'),
            (r'Payment', '결제'),
            (r'Wallet', '지갑'),
            (r'Balance', '잔액'),
            (r'Transaction', '거래'),
            (r'Error', '오류'),
            (r'Warning', '경고'),
            (r'Success', '성공'),
            (r'Failed', '실패'),
            (r'Connected', '연결됨'),
            (r'Disconnected', '연결 끊김'),
            (r'Configuration', '설정'),
            (r'Authentication', '인증'),
            (r'Security', '보안'),
            (r'Performance', '성능'),
            (r'Metrics', '메트릭'),
            (r'Status', '상태'),
            (r'Database', '데이터베이스'),
            (r'Cache', '캐시'),
            (r'Server', '서버'),
            (r'Client', '클라이언트'),
            (r'API', 'API'),
            (r'HTTP', 'HTTP'),
            (r'HTTPS', 'HTTPS'),
            (r'Backup', '백업'),
            (r'Restore', '복원'),
            (r'Monitor', '모니터링'),
            (r'Log', '로그'),
            (r'Audit', '감사')
        ]

        improved_text = text
        for pattern, replacement in improvements:
            improved_text = re.sub(pattern, replacement, improved_text)

        return improved_text

    def enhance_european_languages(self):
        """欧州言語の翻訳品質を向上"""
        european_languages = ['de', 'fr', 'es', 'it', 'nl', 'sv', 'da', 'no', 'fi']

        for language in european_languages:
            if language in self.i18n_manager.supported_languages:
                self.logger.info(f"Enhancing {language} translations...")

                # ドイツ語の品質向上
                if language == 'de':
                    self._enhance_german_quality()

                # フランス語の品質向上
                elif language == 'fr':
                    self._enhance_french_quality()

                # スペイン語の品質向上
                elif language == 'es':
                    self._enhance_spanish_quality()

    def _enhance_german_quality(self):
        """ドイツ語翻訳の品質を向上"""
        po_file = self.i18n_manager.localedir / 'de' / 'LC_MESSAGES' / f"{self.i18n_manager.domain}.po"

        if not po_file.exists():
            return

        try:
            content = po_file.read_text(encoding='utf-8')
            lines = content.split('\n')
            updated_lines = []

            for i, line in enumerate(lines):
                if line.startswith('msgstr "'):
                    translated_text = self._improve_german_translation(line)
                    updated_lines.append(f'msgstr "{translated_text}"')
                else:
                    updated_lines.append(line)

            updated_content = '\n'.join(updated_lines)
            po_file.write_text(updated_content, encoding='utf-8')

            self.i18n_manager._compile_translation('de')
            self.logger.info("German translation quality enhanced")

        except Exception as e:
            self.logger.error(f"Failed to enhance German translations: {e}")

    def _improve_german_translation(self, msgstr_line: str) -> str:
        """ドイツ語翻訳を改善"""
        match = re.search(r'msgstr "(.+)"', msgstr_line)
        if not match:
            return msgstr_line

        text = match.group(1)

        # ドイツ語特有の用語改善
        improvements = [
            (r'Lightning Network', 'Lightning-Netzwerk'),
            (r'Bitcoin', 'Bitcoin'),
            (r'Node', 'Knoten'),
            (r'Channel', 'Kanal'),
            (r'Invoice', 'Rechnung'),
            (r'Payment', 'Zahlung'),
            (r'Wallet', 'Geldbörse'),
            (r'Balance', 'Guthaben'),
            (r'Transaction', 'Transaktion'),
            (r'Error', 'Fehler'),
            (r'Warning', 'Warnung'),
            (r'Success', 'Erfolg'),
            (r'Failed', 'Fehlgeschlagen'),
            (r'Connected', 'Verbunden'),
            (r'Disconnected', 'Getrennt'),
            (r'Configuration', 'Konfiguration'),
            (r'Authentication', 'Authentifizierung'),
            (r'Security', 'Sicherheit'),
            (r'Performance', 'Leistung'),
            (r'Metrics', 'Metriken'),
            (r'Status', 'Status'),
            (r'Database', 'Datenbank'),
            (r'Cache', 'Cache'),
            (r'Server', 'Server'),
            (r'Client', 'Client'),
            (r'API', 'API'),
            (r'HTTP', 'HTTP'),
            (r'HTTPS', 'HTTPS'),
            (r'Backup', 'Sicherung'),
            (r'Restore', 'Wiederherstellung'),
            (r'Monitor', 'Überwachung'),
            (r'Log', 'Protokoll'),
            (r'Audit', 'Audit')
        ]

        improved_text = text
        for pattern, replacement in improvements:
            improved_text = re.sub(pattern, replacement, improved_text)

        return improved_text

    def _enhance_french_quality(self):
        """フランス語翻訳の品質を向上"""
        po_file = self.i18n_manager.localedir / 'fr' / 'LC_MESSAGES' / f"{self.i18n_manager.domain}.po"

        if not po_file.exists():
            return

        try:
            content = po_file.read_text(encoding='utf-8')
            lines = content.split('\n')
            updated_lines = []

            for i, line in enumerate(lines):
                if line.startswith('msgstr "'):
                    translated_text = self._improve_french_translation(line)
                    updated_lines.append(f'msgstr "{translated_text}"')
                else:
                    updated_lines.append(line)

            updated_content = '\n'.join(updated_lines)
            po_file.write_text(updated_content, encoding='utf-8')

            self.i18n_manager._compile_translation('fr')
            self.logger.info("French translation quality enhanced")

        except Exception as e:
            self.logger.error(f"Failed to enhance French translations: {e}")

    def _improve_french_translation(self, msgstr_line: str) -> str:
        """フランス語翻訳を改善"""
        match = re.search(r'msgstr "(.+)"', msgstr_line)
        if not match:
            return msgstr_line

        text = match.group(1)

        # フランス語特有の用語改善
        improvements = [
            (r'Lightning Network', 'Réseau Lightning'),
            (r'Bitcoin', 'Bitcoin'),
            (r'Node', 'Nœud'),
            (r'Channel', 'Canal'),
            (r'Invoice', 'Facture'),
            (r'Payment', 'Paiement'),
            (r'Wallet', 'Portefeuille'),
            (r'Balance', 'Solde'),
            (r'Transaction', 'Transaction'),
            (r'Error', 'Erreur'),
            (r'Warning', 'Avertissement'),
            (r'Success', 'Succès'),
            (r'Failed', 'Échoué'),
            (r'Connected', 'Connecté'),
            (r'Disconnected', 'Déconnecté'),
            (r'Configuration', 'Configuration'),
            (r'Authentication', 'Authentification'),
            (r'Security', 'Sécurité'),
            (r'Performance', 'Performance'),
            (r'Metrics', 'Métriques'),
            (r'Status', 'Statut'),
            (r'Database', 'Base de données'),
            (r'Cache', 'Cache'),
            (r'Server', 'Serveur'),
            (r'Client', 'Client'),
            (r'API', 'API'),
            (r'HTTP', 'HTTP'),
            (r'HTTPS', 'HTTPS'),
            (r'Backup', 'Sauvegarde'),
            (r'Restore', 'Restaurer'),
            (r'Monitor', 'Surveillance'),
            (r'Log', 'Journal'),
            (r'Audit', 'Audit')
        ]

        improved_text = text
        for pattern, replacement in improvements:
            improved_text = re.sub(pattern, replacement, improved_text)

        return improved_text

    def _enhance_spanish_quality(self):
        """スペイン語翻訳の品質を向上"""
        po_file = self.i18n_manager.localedir / 'es' / 'LC_MESSAGES' / f"{self.i18n_manager.domain}.po"

        if not po_file.exists():
            return

        try:
            content = po_file.read_text(encoding='utf-8')
            lines = content.split('\n')
            updated_lines = []

            for i, line in enumerate(lines):
                if line.startswith('msgstr "'):
                    translated_text = self._improve_spanish_translation(line)
                    updated_lines.append(f'msgstr "{translated_text}"')
                else:
                    updated_lines.append(line)

            updated_content = '\n'.join(updated_lines)
            po_file.write_text(updated_content, encoding='utf-8')

            self.i18n_manager._compile_translation('es')
            self.logger.info("Spanish translation quality enhanced")

        except Exception as e:
            self.logger.error(f"Failed to enhance Spanish translations: {e}")

    def _improve_spanish_translation(self, msgstr_line: str) -> str:
        """スペイン語翻訳を改善"""
        match = re.search(r'msgstr "(.+)"', msgstr_line)
        if not match:
            return msgstr_line

        text = match.group(1)

        # スペイン語特有の用語改善
        improvements = [
            (r'Lightning Network', 'Red Lightning'),
            (r'Bitcoin', 'Bitcoin'),
            (r'Node', 'Nodo'),
            (r'Channel', 'Canal'),
            (r'Invoice', 'Factura'),
            (r'Payment', 'Pago'),
            (r'Wallet', 'Billetera'),
            (r'Balance', 'Saldo'),
            (r'Transaction', 'Transacción'),
            (r'Error', 'Error'),
            (r'Warning', 'Advertencia'),
            (r'Success', 'Éxito'),
            (r'Failed', 'Falló'),
            (r'Connected', 'Conectado'),
            (r'Disconnected', 'Desconectado'),
            (r'Configuration', 'Configuración'),
            (r'Authentication', 'Autenticación'),
            (r'Security', 'Seguridad'),
            (r'Performance', 'Rendimiento'),
            (r'Metrics', 'Métricas'),
            (r'Status', 'Estado'),
            (r'Database', 'Base de datos'),
            (r'Cache', 'Caché'),
            (r'Server', 'Servidor'),
            (r'Client', 'Cliente'),
            (r'API', 'API'),
            (r'HTTP', 'HTTP'),
            (r'HTTPS', 'HTTPS'),
            (r'Backup', 'Respaldo'),
            (r'Restore', 'Restaurar'),
            (r'Monitor', 'Monitoreo'),
            (r'Log', 'Registro'),
            (r'Audit', 'Auditoría')
        ]

        improved_text = text
        for pattern, replacement in improvements:
            improved_text = re.sub(pattern, replacement, improved_text)

        return improved_text

    def validate_translation_quality(self, language: str) -> Dict[str, Any]:
        """
        翻訳品質を検証

        Args:
            language: 検証対象言語

        Returns:
            dict: 品質検証結果
        """
        validation_result = {
            'language': language,
            'total_entries': 0,
            'translated_entries': 0,
            'empty_translations': 0,
            'placeholder_translations': 0,
            'quality_score': 0,
            'issues': [],
            'recommendations': []
        }

        po_file = self.i18n_manager.localedir / language / 'LC_MESSAGES' / f"{self.i18n_manager.domain}.po"
        if not po_file.exists():
            validation_result['issues'].append(f"PO file not found for {language}")
            return validation_result

        try:
            content = po_file.read_text(encoding='utf-8')
            lines = content.split('\n')

            i = 0
            while i < len(lines):
                line = lines[i]

                if line.startswith('msgid "'):
                    validation_result['total_entries'] += 1

                    # 次の行がmsgstrかチェック
                    if (i + 1) < len(lines):
                        msgstr_line = lines[i + 1]

                        if msgstr_line.startswith('msgstr "'):
                            validation_result['translated_entries'] += 1

                            # 翻訳内容の検証
                            msgstr_match = re.search(r'msgstr "(.+)"', msgstr_line)
                            if msgstr_match:
                                translation = msgstr_match.group(1)

                                # 空翻訳チェック
                                if not translation.strip():
                                    validation_result['empty_translations'] += 1
                                    validation_result['issues'].append(f"Empty translation for msgid at line {i+1}")

                                # プレースホルダーチェック
                                if '%' in translation and not re.search(r'%[sd]', translation):
                                    validation_result['placeholder_translations'] += 1
                                    validation_result['issues'].append(f"Invalid placeholder in translation at line {i+1}")

                i += 1

            # 品質スコアを計算
            if validation_result['total_entries'] > 0:
                translation_rate = validation_result['translated_entries'] / validation_result['total_entries']
                validation_result['quality_score'] = translation_rate * 100

                if validation_result['empty_translations'] > 0:
                    validation_result['quality_score'] -= validation_result['empty_translations'] * 10

                if validation_result['placeholder_translations'] > 0:
                    validation_result['quality_score'] -= validation_result['placeholder_translations'] * 5

                validation_result['quality_score'] = max(0, validation_result['quality_score'])

            # 推奨事項を追加
            if validation_result['empty_translations'] > 0:
                validation_result['recommendations'].append(f"Translate {validation_result['empty_translations']} empty entries")

            if validation_result['quality_score'] < 80:
                validation_result['recommendations'].append("Review translation quality and completeness")

        except Exception as e:
            validation_result['issues'].append(f"Validation error: {e}")

        return validation_result

    def generate_quality_report(self) -> Dict[str, Any]:
        """
        翻訳品質レポートを生成

        Returns:
            dict: 包括的な品質レポート
        """
        report = {
            'timestamp': self.i18n_manager.datetime.now().isoformat(),
            'total_languages': len(self.i18n_manager.supported_languages),
            'validation_results': {},
            'summary': {
                'excellent_languages': [],
                'good_languages': [],
                'needs_improvement': [],
                'poor_quality': []
            }
        }

        for language in self.i18n_manager.supported_languages:
            validation = self.validate_translation_quality(language)
            report['validation_results'][language] = validation

            score = validation['quality_score']
            if score >= 90:
                report['summary']['excellent_languages'].append(language)
            elif score >= 70:
                report['summary']['good_languages'].append(language)
            elif score >= 50:
                report['summary']['needs_improvement'].append(language)
            else:
                report['summary']['poor_quality'].append(language)

        return report
