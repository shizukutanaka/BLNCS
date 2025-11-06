# BLNCS 国際化 (i18n) ガイド

BLNCSは多言語対応をサポートしており、50言語以上の翻訳に対応する設計となっています。

## 概要

BLNCSの国際化システムは以下のコンポーネントで構成されています：

- **gettextベースの翻訳システム**: Python標準のgettextライブラリを使用
- **動的言語切り替え**: 実行時に言語を変更可能
- **翻訳テンプレート自動生成**: ソースコードから翻訳メッセージを自動抽出
- **言語別ファイル管理**: 各言語の翻訳を独立して管理

## 対応言語

現在サポートされている言語：

- 日本語 (ja)
- 英語 (en) - デフォルト
- スペイン語 (es)
- フランス語 (fr)
- ドイツ語 (de)
- 中国語 (zh)
- 韓国語 (ko)
- ポルトガル語 (pt)
- ロシア語 (ru)
- アラビア語 (ar)

## 基本的な使用方法

### 1. 翻訳関数の使用

Pythonコードでは、以下の方法で翻訳を使用します：

```python
from blncs import _

# シンプルなメッセージ
message = _("Hello, World!")

# パラメータを含むメッセージ
error_msg = _("Error: %s") % error_code

# 複数形
count_msg = _("Found %d item") if count == 1 else _("Found %d items") % count
```

### 2. 言語の設定

```python
from blncs import get_i18n_manager

# 国際化マネージャーを取得
i18n = get_i18n_manager()

# 言語を設定
i18n.set_language('ja')  # 日本語
i18n.set_language('en')  # 英語
i18n.set_language('es')  # スペイン語
```

### 3. 翻訳ファイルの場所

翻訳ファイルは以下の構造で配置されます：

```
locale/
├── en/
│   └── LC_MESSAGES/
│       ├── blncs.po
│       └── blncs.mo
├── ja/
│   └── LC_MESSAGES/
│       ├── blncs.po
│       └── blncs.mo
├── es/
│   └── LC_MESSAGES/
│       ├── blncs.po
│       └── blncs.mo
└── ...
```

## 翻訳ファイルの管理

### 翻訳テンプレートの生成

ソースコードから翻訳メッセージを自動抽出してPOテンプレートを生成します：

```bash
# プロジェクトルートで実行
python scripts/generate_translations.py --init  # ロケール構造の初期化
python scripts/generate_translations.py --update  # 翻訳ファイルの更新
```

### 翻訳の編集

各言語のPOファイルを編集して翻訳を追加・更新します：

```bash
# 日本語翻訳の編集
vim locale/ja/LC_MESSAGES/blncs.po

# 英語翻訳の編集
vim locale/en/LC_MESSAGES/blncs.po
```

POファイルのフォーマット：

```po
msgid "Hello, World!"
msgstr "こんにちは、世界！"

msgid "Error: %s"
msgstr "エラー: %s"

msgid "Found %d item"
msgid_plural "Found %d items"
msgstr[0] "%d個の項目が見つかりました"
msgstr[1] "%d個の項目が見つかりました"
```

### 翻訳のコンパイル

POファイルを編集したら、MOファイルにコンパイルします：

```bash
python scripts/generate_translations.py --update
```

または、直接msgfmtコマンドを使用：

```bash
msgfmt locale/ja/LC_MESSAGES/blncs.po -o locale/ja/LC_MESSAGES/blncs.mo
```

## CLIでの言語設定

### 環境変数による設定

```bash
export BLNCS_LOCALE=ja
python blncs_main.py status
```

### 設定ファイルによる設定

`config/production.json` に以下を追加：

```json
{
  "i18n": {
    "locale": "ja",
    "fallback_locale": "en"
  }
}
```

## APIでの言語設定

### リクエストヘッダーによる設定

```bash
curl -H "Accept-Language: ja" http://localhost:3000/api/lightning/info
```

### クエリパラメータによる設定

```bash
curl "http://localhost:3000/api/lightning/info?lang=ja"
```

## 開発者向けガイド

### 新しいメッセージの追加

1. ソースコードに翻訳関数を使用：

```python
# 悪い例
print("Hello, World!")

# 良い例
print(_("Hello, World!"))
```

2. 翻訳テンプレートを更新：

```bash
python scripts/generate_translations.py --update
```

3. 各言語の翻訳を追加

4. 翻訳をコンパイル

### 言語の追加

1. `scripts/generate_translations.py` の `languages` リストに新しい言語を追加
2. 初期化スクリプトを実行：

```bash
python scripts/generate_translations.py --init
```

3. 新しい言語のPOファイルを編集して翻訳を追加

### 翻訳のテスト

```bash
# 日本語でテスト
BLNCS_LOCALE=ja python blncs_main.py status

# スペイン語でテスト
BLNCS_LOCALE=es python blncs_main.py status
```

## 高度な機能

### 翻訳の統計情報

```python
from blncs import get_i18n_manager

i18n = get_i18n_manager()
stats = i18n.get_all_languages_info()

for lang, info in stats.items():
    print(f"{lang}: {info['completion']:.1f}% complete")
```

### 翻訳のエクスポート

```python
# JSON形式でエクスポート
i18n.export_to_json("translations.json")
```

### カスタム翻訳ドメイン

```python
from blncs.core.i18n_manager import I18NManager

# カスタムドメインで国際化マネージャーを作成
i18n = I18NManager(domain="myapp", localedir="my_locale")
```

## 注意事項

1. **翻訳メッセージの更新**: ソースコードを変更したら必ず翻訳テンプレートを更新してください
2. **言語フォールバック**: 翻訳が見つからない場合、英語にフォールバックします
3. **パフォーマンス**: 初回読み込み時に翻訳ファイルをキャッシュします
4. **文字エンコーディング**: すべての翻訳ファイルはUTF-8で保存してください

## トラブルシューティング

### 翻訳が表示されない

1. 翻訳ファイルが正しくコンパイルされているか確認：

```bash
ls -la locale/ja/LC_MESSAGES/blncs.mo
```

2. 言語設定が正しいか確認：

```python
from blncs import get_i18n_manager
print(get_i18n_manager().current_language)
```

3. 翻訳ファイルの構文を確認：

```bash
msgfmt --check locale/ja/LC_MESSAGES/blncs.po
```

### 翻訳が更新されない

1. ブラウザキャッシュをクリア（Webインターフェースの場合）
2. アプリケーションを再起動
3. 翻訳ファイルを再コンパイル

### 文字化けが発生する

1. POファイルがUTF-8で保存されているか確認
2. システムロケールが適切に設定されているか確認：

```bash
echo $LANG
```

## 貢献方法

翻訳の改善に貢献する方法：

1. GitHubで翻訳Issueを作成
2. 各言語のPOファイルを編集
3. プルリクエストを送信

詳細は `CONTRIBUTING.md` を参照してください。
