#!/usr/bin/env python3
"""
BLNCS - Multilingual Documentation Generator
多言語ドキュメント生成システム
"""

import os
import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Any
import logging
from datetime import datetime

class MultilingualDocumentationGenerator:
    """
    多言語ドキュメント生成システム
    ソースから多言語ドキュメントを自動生成
    """

    def __init__(self, i18n_manager, output_dir: str = "docs/multilingual"):
        """
        初期化

        Args:
            i18n_manager: 国際化マネージャー
            output_dir: 出力ディレクトリ
        """
        self.i18n_manager = i18n_manager
        self.output_dir = Path(output_dir)
        self.logger = logging.getLogger("blncs.i18n_docs")

        # ドキュメントテンプレート
        self.templates = self._load_document_templates()

        # サポート言語
        self.target_languages = [
            'en', 'ja', 'es', 'fr', 'de', 'zh', 'ko'
        ]

    def _load_document_templates(self) -> Dict[str, str]:
        """ドキュメントテンプレートを読み込み"""
        templates_dir = Path(__file__).parent.parent / "templates" / "docs"

        if not templates_dir.exists():
            templates_dir.mkdir(parents=True, exist_ok=True)

        # デフォルトテンプレート
        return {
            'readme': '''# {title}

{description}

## インストール / Installation

{installation}

## 設定 / Configuration

{configuration}

## 使用方法 / Usage

{usage}

## サポート / Support

{support}
''',
            'api_guide': '''# {title}

{description}

## API エンドポイント / API Endpoints

{endpoints}

## 認証 / Authentication

{authentication}

## エラーハンドリング / Error Handling

{error_handling}
''',
            'troubleshooting': '''# {title}

{description}

## よくある問題 / Common Issues

{issues}

## トラブルシューティング / Troubleshooting

{troubleshooting}

## サポート / Support

{support}
'''
        }

    def generate_multilingual_readme(self):
        """多言語READMEを生成"""
        self.logger.info("Generating multilingual README files...")

        # 各言語のREADMEを生成
        for language in self.target_languages:
            self.i18n_manager.set_language(language)

            readme_content = self._generate_readme_content(language)
            output_file = self.output_dir / f"README_{language.upper()}.md"

            self.output_dir.mkdir(parents=True, exist_ok=True)

            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(readme_content)

            self.logger.info(f"Generated README for {language}: {output_file}")

        # 元の言語に戻す
        self.i18n_manager.set_language(self.i18n_manager.current_language)

    def _generate_readme_content(self, language: str) -> str:
        """READMEコンテンツを生成"""
        title = self.i18n_manager.get_text("BLNCS – Bitcoin Lightning Network Control System")
        description = self.i18n_manager.get_text("BLNCS is an integrated control system for Bitcoin Lightning Network infrastructure.")

        installation = f'''
```bash
# Clone repository
git clone https://github.com/yourusername/BLNCS.git
cd BLNCS

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\\Scripts\\activate

# Install dependencies
pip install -r requirements.txt

# Set language
export BLNCS_LOCALE={language}

# Verify installation
python blncs_main.py --version
```
'''

        configuration = f'''
```json
{{
  "i18n": {{
    "locale": "{language}",
    "fallback_locale": "en"
  }},
  "lightning": {{
    "network": "mainnet"
  }},
  "api": {{
    "port": 3000
  }}
}}
```
'''

        usage = f'''
```bash
# Start server
python blncs_main.py server

# Check status
python blncs_main.py status

# Interactive mode
python blncs_main.py --interactive
```
'''

        support = self.i18n_manager.get_text("For support, please visit our GitHub repository or join our community discussions.")

        return self.templates['readme'].format(
            title=title,
            description=description,
            installation=installation,
            configuration=configuration,
            usage=usage,
            support=support
        )

    def generate_multilingual_api_docs(self):
        """多言語APIドキュメントを生成"""
        self.logger.info("Generating multilingual API documentation...")

        for language in self.target_languages:
            self.i18n_manager.set_language(language)

            api_content = self._generate_api_documentation(language)
            output_file = self.output_dir / f"API_GUIDE_{language.upper()}.md"

            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(api_content)

            self.logger.info(f"Generated API docs for {language}: {output_file}")

        self.i18n_manager.set_language(self.i18n_manager.current_language)

    def _generate_api_documentation(self, language: str) -> str:
        """APIドキュメントを生成"""
        title = self.i18n_manager.get_text("BLNCS API Documentation")
        description = self.i18n_manager.get_text("Complete API reference for BLNCS Lightning Network Control System")

        endpoints = f'''
### Lightning Network Operations

#### Get Node Information
```
GET /api/lightning/info
```

#### Get Balance
```
GET /api/lightning/balance
```

#### Create Invoice
```
POST /api/lightning/invoice
{{
  "amount": 1000,
  "memo": "{self.i18n_manager.get_text("Payment description")}"
}}
```

#### Pay Invoice
```
POST /api/lightning/pay
{{
  "payment_request": "lnbc..."
}}
```
'''

        authentication = f'''
{self.i18n_manager.get_text("All API endpoints require JWT authentication:")}

```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \\
     http://localhost:3000/api/lightning/info
```
'''

        error_handling = f'''
### {self.i18n_manager.get_text("Error Response Format")}

```json
{{
  "error": "{self.i18n_manager.get_text("Error message")}",
  "code": 400,
  "details": {{}}
}}
```

### {self.i18n_manager.get_text("Common Error Codes")}

- `400`: {self.i18n_manager.get_text("Bad Request")}
- `401`: {self.i18n_manager.get_text("Unauthorized")}
- `404`: {self.i18n_manager.get_text("Not Found")}
- `500`: {self.i18n_manager.get_text("Internal Server Error")}
'''

        return self.templates['api_guide'].format(
            title=title,
            description=description,
            endpoints=endpoints,
            authentication=authentication,
            error_handling=error_handling
        )

    def generate_multilingual_troubleshooting(self):
        """多言語トラブルシューティングガイドを生成"""
        self.logger.info("Generating multilingual troubleshooting guides...")

        for language in self.target_languages:
            self.i18n_manager.set_language(language)

            troubleshooting_content = self._generate_troubleshooting_content(language)
            output_file = self.output_dir / f"TROUBLESHOOTING_{language.upper()}.md"

            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(troubleshooting_content)

            self.logger.info(f"Generated troubleshooting guide for {language}: {output_file}")

        self.i18n_manager.set_language(self.i18n_manager.current_language)

    def _generate_troubleshooting_content(self, language: str) -> str:
        """トラブルシューティングコンテンツを生成"""
        title = self.i18n_manager.get_text("BLNCS Troubleshooting Guide")
        description = self.i18n_manager.get_text("Common issues and solutions for BLNCS")

        issues = f'''
## {self.i18n_manager.get_text("Connection Issues")}

### {self.i18n_manager.get_text("Connection Refused")}
```bash
# Check if service is running
systemctl status blncs

# Check logs
journalctl -u blncs -f

# Verify port
netstat -tlnp | grep 3000
```

### {self.i18n_manager.get_text("Database Connection Failed")}
```bash
# Test database connection
python -c "from blncs.core.unified_database import UnifiedDatabase; db = UnifiedDatabase(); print('Connected')"

# Check credentials
echo $BLNCS_DATABASE_URL

# Run migrations
python blncs_main.py db migrate
```
'''

        troubleshooting = f'''
## {self.i18n_manager.get_text("Performance Issues")}

### {self.i18n_manager.get_text("High Memory Usage")}
```bash
# Check resource usage
python blncs_main.py system status

# Optimize database
python blncs_main.py db optimize

# Clear cache
curl -X POST -H "Authorization: Bearer YOUR_TOKEN" \\
  http://localhost:3000/api/cache/clear
```

### {self.i18n_manager.get_text("Slow Response Times")}
- {self.i18n_manager.get_text("Check network connectivity")}
- {self.i18n_manager.get_text("Review server logs for errors")}
- {self.i18n_manager.get_text("Consider upgrading hardware resources")}
'''

        support = f'''
## {self.i18n_manager.get_text("Getting Help")}

- {self.i18n_manager.get_text("Check the documentation")}: [docs/](docs/)
- {self.i18n_manager.get_text("Search existing issues")}: [GitHub Issues](https://github.com/yourusername/BLNCS/issues)
- {self.i18n_manager.get_text("Join community discussions")}: [GitHub Discussions](https://github.com/yourusername/BLNCS/discussions)
'''

        return self.templates['troubleshooting'].format(
            title=title,
            description=description,
            issues=issues,
            troubleshooting=troubleshooting,
            support=support
        )

    def generate_language_specific_guides(self):
        """言語別ガイドを生成"""
        self.logger.info("Generating language-specific guides...")

        for language in self.target_languages:
            if language != 'en':  # 英語以外の場合
                self.i18n_manager.set_language(language)

                guide_content = self._generate_language_specific_guide(language)
                output_file = self.output_dir / f"{language.upper()}_USER_GUIDE.md"

                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(guide_content)

                self.logger.info(f"Generated language guide for {language}: {output_file}")

        self.i18n_manager.set_language(self.i18n_manager.current_language)

    def _generate_language_specific_guide(self, language: str) -> str:
        """言語別ガイドを生成"""
        title = self.i18n_manager.get_text(f"{language.upper()} User Guide")
        description = self.i18n_manager.get_text("BLNCS user guide in") + f" {self.i18n_manager._get_language_name(language)}"

        content = f'''# {title}

{description}

## 言語設定 / Language Setup

```bash
export BLNCS_LOCALE={language}
```

## 基本操作 / Basic Operations

### システムステータス確認 / Check System Status
```bash
python blncs_main.py status
```

### サーバー起動 / Start Server
```bash
python blncs_main.py server --port 3000
```

### 設定確認 / Check Configuration
```bash
python blncs_main.py config
```

## Lightning Network操作 / Lightning Network Operations

### 残高確認 / Check Balance
```bash
python blncs_main.py balance
```

### インボイス作成 / Create Invoice
```bash
python blncs_main.py invoice 10000 "Payment description"
```

### チャネル情報 / Channel Information
```bash
python blncs_main.py channels
```

## トラブルシューティング / Troubleshooting

### 言語が表示されない / Language Not Displaying
1. 環境変数を確認: `echo $BLNCS_LOCALE`
2. 翻訳ファイルを更新: `python scripts/generate_translations.py --update`
3. アプリケーションを再起動

### 翻訳が不完全 / Incomplete Translations
- 翻訳ファイルの完了率を確認
- 不足している翻訳を追加
- 翻訳をコンパイル: `python scripts/generate_translations.py --update`

## 地域別設定 / Regional Settings

### 通貨フォーマット / Currency Format
{self.i18n_manager.get_regional_format('currency', language)}

### 日付フォーマット / Date Format
{self.i18n_manager.get_regional_format('date', language)}

## サポート / Support

- ドキュメント: [docs/](docs/)
- コミュニティ: [GitHub Discussions](https://github.com/yourusername/BLNCS/discussions)
'''

        return content

    def generate_documentation_index(self):
        """ドキュメントインデックスを生成"""
        self.logger.info("Generating documentation index...")

        index_content = f'''# BLNCS Multilingual Documentation

{self.i18n_manager.get_text("Complete documentation for BLNCS in multiple languages")}

## 対応言語 / Supported Languages

'''

        for language in self.target_languages:
            lang_name = self.i18n_manager._get_language_name(language)
            index_content += f"- **{lang_name}** ({language.upper()})\n"

        index_content += f'''

## ドキュメント一覧 / Documentation List

### README Files
'''

        for language in self.target_languages:
            index_content += f"- [README_{language.upper()}.md](README_{language.upper()}.md) - {self.i18n_manager._get_language_name(language)}\n"

        index_content += f'''

### API Documentation
'''

        for language in self.target_languages:
            index_content += f"- [API_GUIDE_{language.upper()}.md](API_GUIDE_{language.upper()}.md) - {self.i18n_manager._get_language_name(language)}\n"

        index_content += f'''

### Troubleshooting Guides
'''

        for language in self.target_languages:
            index_content += f"- [TROUBLESHOOTING_{language.upper()}.md](TROUBLESHOOTING_{language.upper()}.md) - {self.i18n_manager._get_language_name(language)}\n"

        index_content += f'''

### Language-Specific Guides
'''

        for language in self.target_languages:
            if language != 'en':
                index_content += f"- [{language.upper()}_USER_GUIDE.md]({language.upper()}_USER_GUIDE.md) - {self.i18n_manager._get_language_name(language)}\n"

        index_content += f'''

## 翻訳統計 / Translation Statistics

{self._generate_translation_statistics()}

## 貢献方法 / Contributing

翻訳の改善に貢献する方法：

1. 各言語のPOファイルを編集: `locale/[言語コード]/LC_MESSAGES/blncs.po`
2. 翻訳を更新: `python scripts/generate_translations.py --update`
3. プルリクエストを送信

詳細は [`docs/I18N_GUIDE.md`](../I18N_GUIDE.md) を参照してください。

---
{self.i18n_manager.get_text("Generated on")} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
'''

        index_file = self.output_dir / "README.md"
        with open(index_file, 'w', encoding='utf-8') as f:
            f.write(index_content)

        self.logger.info(f"Generated documentation index: {index_file}")

    def _generate_translation_statistics(self) -> str:
        """翻訳統計を生成"""
        stats = self.i18n_manager.update_translation_progress()
        result = "\n"

        for language, language_stats in stats.items():
            lang_name = self.i18n_manager._get_language_name(language)
            completion = language_stats['completion_rate']
            status = "🟢" if completion >= 90 else "🟡" if completion >= 70 else "🔴"
            result += f"- {status} {lang_name}: {completion:.1f}% ({language_stats['translated_entries']}/{language_stats['total_entries']} entries)\n"

        return result

    def generate_all_documentation(self):
        """すべてのドキュメントを生成"""
        self.logger.info("Generating all multilingual documentation...")

        # 各言語のドキュメントを生成
        self.generate_multilingual_readme()
        self.generate_multilingual_api_docs()
        self.generate_multilingual_troubleshooting()
        self.generate_language_specific_guides()

        # インデックスを生成
        self.generate_documentation_index()

        self.logger.info("All multilingual documentation generated successfully")
