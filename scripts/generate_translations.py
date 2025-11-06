#!/usr/bin/env python3
"""
BLNCS - Translation Template Generator
翻訳テンプレート生成スクリプト
"""

import os
import sys
from pathlib import Path
import argparse

def extract_messages_from_file(file_path: Path) -> set:
    """
    ファイルから翻訳が必要なメッセージを抽出

    Args:
        file_path: 解析するファイルパス

    Returns:
        set: 翻訳メッセージのセット
    """
    messages = set()

    try:
        content = file_path.read_text(encoding='utf-8')

        # _("message") パターンを検索
        import re
        pattern = r'_\("([^"]+)"\)'
        matches = re.findall(pattern, content)
        messages.update(matches)

        # _("message: %s") パターンも検索
        pattern_with_args = r'_\("([^"]+%[^"]+)"\)'
        matches_with_args = re.findall(pattern_with_args, content)
        messages.update(matches_with_args)

        # ログメッセージも検索
        log_patterns = [
            r'logger\.info\(["\']([^"\']+)["\']',
            r'logger\.warning\(["\']([^"\']+)["\']',
            r'logger\.error\(["\']([^"\']+)["\']',
            r'logger\.critical\(["\']([^"\']+)["\']'
        ]

        for pattern in log_patterns:
            matches = re.findall(pattern, content)
            messages.update(matches)

        # print(_("message")) パターンも検索
        print_pattern = r'print\(_\("([^"]+)"\)'
        print_matches = re.findall(print_pattern, content)
        messages.update(print_matches)

    except Exception as e:
        print(f"Warning: Could not parse {file_path}: {e}")

    return messages

def extract_messages_from_directory(directory: Path) -> dict:
    """
    ディレクトリからすべての翻訳メッセージを抽出

    Args:
        directory: 解析するディレクトリ

    Returns:
        dict: ファイルごとのメッセージセット
    """
    all_messages = {}

    # Pythonファイルのみを対象
    python_files = list(directory.rglob("*.py"))

    for file_path in python_files:
        messages = extract_messages_from_file(file_path)
        if messages:
            relative_path = file_path.relative_to(directory)
            all_messages[str(relative_path)] = messages

    return all_messages

def generate_po_template(output_path: Path, messages: dict, domain: str = "blncs"):
    """
    POテンプレートファイルを生成

    Args:
        output_path: 出力ファイルパス
        messages: メッセージ辞書
        domain: 翻訳ドメイン
    """
    template_content = f'''# {domain} translation file
# Copyright (C) 2025 BLNCS
# This file is distributed under the same license as the BLNCS package.
#
#, fuzzy
msgid ""
msgstr ""
"Project-Id-Version: {domain} 2.0.0\\n"
"Report-Msgid-Bugs-To: \\n"
"POT-Creation-Date: 2025-01-01 00:00+0000\\n"
"PO-Revision-Date: YEAR-MO-DA HO:MI+ZONE\\n"
"Last-Translator: FULL NAME <EMAIL@ADDRESS>\\n"
"Language-Team: LANGUAGE <LL@li.org>\\n"
"MIME-Version: 1.0\\n"
"Content-Type: text/plain; charset=UTF-8\\n"
"Content-Transfer-Encoding: 8bit\\n"
"Language: {output_path.parent.parent.name}\\n"

'''

    # すべてのメッセージを統合
    all_unique_messages = set()
    for file_messages in messages.values():
        all_unique_messages.update(file_messages)

    # メッセージをアルファベット順にソート
    sorted_messages = sorted(all_unique_messages)

    # 各メッセージのPOエントリを生成
    for message in sorted_messages:
        if message.strip():  # 空文字列を除外
            template_content += f'''msgid "{message}"
msgstr ""

'''

    # ファイルに書き込み
    output_path.write_text(template_content, encoding='utf-8')
    print(f"Generated PO template: {output_path}")
    print(f"Total messages: {len(sorted_messages)}")

def generate_mo_file(po_file: Path):
    """
    POファイルをMOファイルにコンパイル

    Args:
        po_file: 入力POファイル
    """
    mo_file = po_file.with_suffix('.mo')

    try:
        # msgfmtコマンドを試す
        import subprocess
        result = subprocess.run([
            'msgfmt', str(po_file), '-o', str(mo_file)
        ], capture_output=True, text=True)

        if result.returncode == 0:
            print(f"Compiled {po_file} -> {mo_file}")
        else:
            print(f"Warning: msgfmt failed for {po_file}: {result.stderr}")
            # フォールバックとしてPythonで簡易コンパイル
            compile_po_with_python(po_file, mo_file)

    except FileNotFoundError:
        print(f"Warning: msgfmt not found, using Python fallback for {po_file}")
        compile_po_with_python(po_file, mo_file)

def compile_po_with_python(po_file: Path, mo_file: Path):
    """
    PythonでPOファイルを簡易コンパイル

    Args:
        po_file: 入力POファイル
        mo_file: 出力MOファイル
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

        # 簡易バイナリ形式で保存
        import pickle
        with open(mo_file, 'wb') as f:
            pickle.dump(translations, f)

        print(f"Compiled with Python fallback: {mo_file}")

    except Exception as e:
        print(f"Error compiling {po_file}: {e}")

def initialize_locale_structure(project_root: Path, domain: str = "blncs"):
    """
    ロケールディレクトリ構造を初期化

    Args:
        project_root: プロジェクトルートディレクトリ
        domain: 翻訳ドメイン
    """
    locale_dir = project_root / "locale"

    if not locale_dir.exists():
        locale_dir.mkdir(parents=True, exist_ok=True)
        print(f"Created locale directory: {locale_dir}")

    # 各言語のディレクトリを作成
    languages = ['en', 'ja', 'es', 'fr', 'de', 'zh', 'ko', 'pt', 'ru', 'ar']

    for lang in languages:
        lang_dir = locale_dir / lang / "LC_MESSAGES"
        lang_dir.mkdir(parents=True, exist_ok=True)

        # POファイルが存在しなければ作成
        po_file = lang_dir / f"{domain}.po"
        if not po_file.exists():
            print(f"Creating PO template for {lang}")
            generate_po_template(po_file, {}, domain)
            generate_mo_file(po_file)

def update_translations(project_root: Path, domain: str = "blncs"):
    """
    翻訳ファイルを更新

    Args:
        project_root: プロジェクトルートディレクトリ
        domain: 翻訳ドメイン
    """
    print("Extracting messages from source code...")

    # ソースコードからメッセージを抽出
    source_dir = project_root / "blncs"
    messages = extract_messages_from_directory(source_dir)

    print(f"Found messages in {len(messages)} files")

    # 各言語の翻訳ファイルを更新
    locale_dir = project_root / "locale"

    for lang_dir in locale_dir.iterdir():
        if lang_dir.is_dir():
            po_file = lang_dir / "LC_MESSAGES" / f"{domain}.po"
            if po_file.exists():
                print(f"Updating {lang_dir.name} translations...")
                generate_po_template(po_file, messages, domain)
                generate_mo_file(po_file)

def main():
    """メイン関数"""
    parser = argparse.ArgumentParser(description="BLNCS Translation Management")
    parser.add_argument("--init", action="store_true", help="Initialize locale structure")
    parser.add_argument("--update", action="store_true", help="Update translation files")
    parser.add_argument("--extract", action="store_true", help="Extract messages only")
    parser.add_argument("--domain", default="blncs", help="Translation domain")
    parser.add_argument("--project-root", type=Path, default=Path.cwd(),
                       help="Project root directory")

    args = parser.parse_args()

    if args.init:
        print("Initializing locale structure...")
        initialize_locale_structure(args.project_root, args.domain)

    if args.update or args.extract:
        if args.extract:
            # メッセージ抽出のみ
            source_dir = args.project_root / "blncs"
            messages = extract_messages_from_directory(source_dir)

            print(f"Found {len(messages)} files with translatable messages:")
            for file_path, file_messages in messages.items():
                print(f"  {file_path}: {len(file_messages)} messages")

        if args.update:
            update_translations(args.project_root, args.domain)

    if not (args.init or args.update or args.extract):
        parser.print_help()

if __name__ == "__main__":
    main()
