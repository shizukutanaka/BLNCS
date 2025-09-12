#!/usr/bin/env python3
"""
BLNCS Internationalization CLI Commands
Command-line interface for managing multi-language support.
"""

import click
import json
import sys
from pathlib import Path
from typing import Dict, Any

try:
    from ...i18n import (
        get_translator, get_language_manager, set_language, 
        get_current_language, get_system_locale
    )
except ImportError:
    # For standalone testing
    sys.path.append(str(Path(__file__).parent.parent.parent))
    from i18n import (
        get_translator, get_language_manager, set_language,
        get_current_language, get_system_locale
    )


@click.group()
def i18n():
    """Internationalization and localization commands"""
    pass


@i18n.command()
@click.option('--format', 'output_format', default='table', type=click.Choice(['table', 'json']))
def list_languages(output_format: str):
    """List all available languages"""
    click.echo("Available Languages:")
    
    language_manager = get_language_manager()
    current_language = language_manager.get_current_language()
    
    if output_format == 'json':
        languages_data = []
        for code, name in language_manager.get_available_languages().items():
            completion = language_manager.get_language_completion_percentage(code)
            language_info = {
                'code': code,
                'name': name,
                'completion': completion,
                'is_current': code == current_language
            }
            languages_data.append(language_info)
        
        click.echo(json.dumps(languages_data, indent=2))
    else:
        # Table format
        click.echo("-" * 60)
        click.echo(f"{'Code':<6} {'Name':<20} {'Completion':<12} {'Status'}")
        click.echo("-" * 60)
        
        selector_data = language_manager.create_language_selector_data()
        for lang_data in selector_data:
            status = "✅ Current" if lang_data['is_current'] else ""
            click.echo(f"{lang_data['code']:<6} {lang_data['name']:<20} {lang_data['completion']:>8.1f}%   {status}")


@i18n.command()
@click.argument('language_code')
def set_language_cmd(language_code: str):
    """Set the current language"""
    language_manager = get_language_manager()
    
    # Check if language is available
    available_languages = language_manager.get_available_languages()
    if language_code not in available_languages:
        click.echo(f"❌ Language '{language_code}' not available", err=True)
        click.echo(f"Available languages: {', '.join(available_languages.keys())}")
        return 1
    
    # Set language
    success = language_manager.set_language(language_code)
    if success:
        language_name = available_languages[language_code]
        click.echo(f"✅ Language set to {language_name} ({language_code})")
        
        # Show sample translations
        translator = get_translator()
        sample_keys = ['app.title', 'action.connect', 'lightning.balance']
        
        click.echo("\nSample translations:")
        for key in sample_keys:
            translated = translator.translate(key)
            click.echo(f"  {key}: {translated}")
        
        return 0
    else:
        click.echo(f"❌ Failed to set language to {language_code}", err=True)
        return 1


@i18n.command()
def current():
    """Show current language information"""
    language_manager = get_language_manager()
    current_language = language_manager.get_current_language()
    
    language_info = language_manager.get_language_info(current_language)
    if language_info:
        click.echo(f"Current Language: {language_info['name']} ({language_info['code']})")
        click.echo(f"Translation count: {language_info['translation_count']}")
        
        completion = language_manager.get_language_completion_percentage(current_language)
        click.echo(f"Completion: {completion:.1f}%")
        
        if completion < 100:
            missing_count = len(language_manager.get_missing_translations(current_language))
            click.echo(f"Missing translations: {missing_count}")
    else:
        click.echo(f"Current language: {current_language}")


@i18n.command()
@click.argument('language_code')
@click.option('--show-keys', is_flag=True, help='Show missing translation keys')
def validate(language_code: str, show_keys: bool):
    """Validate translations for a language"""
    language_manager = get_language_manager()
    
    # Check if language exists
    available_languages = language_manager.get_available_languages()
    if language_code not in available_languages:
        click.echo(f"❌ Language '{language_code}' not available", err=True)
        return 1
    
    # Run validation
    validation_results = language_manager.validate_translations(language_code)
    
    language_name = available_languages[language_code]
    click.echo(f"Validation Results for {language_name} ({language_code}):")
    click.echo("-" * 50)
    
    # Show results
    for category, issues in validation_results.items():
        if issues:
            click.echo(f"\n{category.upper()} ({len(issues)}):")
            
            if show_keys or category != 'missing':
                for issue in issues[:10]:  # Show first 10
                    click.echo(f"  • {issue}")
                
                if len(issues) > 10:
                    click.echo(f"  ... and {len(issues) - 10} more")
            else:
                click.echo(f"  {len(issues)} missing translations (use --show-keys to view)")
    
    # Summary
    total_issues = sum(len(issues) for issues in validation_results.values())
    if total_issues == 0:
        click.echo("\n✅ No issues found")
        return 0
    else:
        click.echo(f"\n⚠️ Total issues: {total_issues}")
        return 1


@i18n.command()
@click.argument('language_code')
@click.argument('output_file')
def export_template(language_code: str, output_file: str):
    """Export translation template for a new language"""
    language_manager = get_language_manager()
    
    try:
        language_manager.export_translation_template(language_code, output_file)
        click.echo(f"✅ Translation template exported to {output_file}")
        click.echo(f"Language code: {language_code}")
        
        # Show instructions
        click.echo("\nInstructions for translators:")
        click.echo("1. Edit the exported JSON file")
        click.echo("2. Replace 'TODO: Translate...' with actual translations")
        click.echo("3. Update the _metadata section with translator info")
        click.echo("4. Save the file as {language_code}.json in the translations directory")
        
        return 0
        
    except Exception as e:
        click.echo(f"❌ Failed to export template: {e}", err=True)
        return 1


@i18n.command()
@click.argument('translation_file')
def import_translation(translation_file: str):
    """Import a new translation file"""
    translator = get_translator()
    
    translation_path = Path(translation_file)
    if not translation_path.exists():
        click.echo(f"❌ Translation file not found: {translation_file}", err=True)
        return 1
    
    try:
        # Extract language code from filename or load from file
        language_code = translation_path.stem
        
        # Load the translation
        translator.load_translation(language_code)
        
        # Validate the imported translation
        language_manager = get_language_manager()
        validation_results = language_manager.validate_translations(language_code)
        
        click.echo(f"✅ Translation imported for language: {language_code}")
        
        # Show validation summary
        total_issues = sum(len(issues) for issues in validation_results.values())
        if total_issues > 0:
            click.echo(f"⚠️ Found {total_issues} validation issues")
            click.echo("Run 'blncs i18n validate {language_code}' for details")
        else:
            click.echo("✅ No validation issues found")
        
        return 0
        
    except Exception as e:
        click.echo(f"❌ Failed to import translation: {e}", err=True)
        return 1


@i18n.command()
@click.option('--key', help='Translation key to test')
@click.option('--text', help='Text to translate to all languages')
def test(key: str, text: str):
    """Test translation functionality"""
    translator = get_translator()
    language_manager = get_language_manager()
    
    if key:
        # Test specific key translation
        click.echo(f"Testing translation key: {key}")
        click.echo("-" * 40)
        
        for lang_code, lang_name in language_manager.get_available_languages().items():
            translator.set_language(lang_code)
            translated = translator.translate(key)
            click.echo(f"{lang_code} ({lang_name}): {translated}")
    
    elif text:
        # Add temporary translation for testing
        click.echo(f"Testing text translation: {text}")
        click.echo("-" * 40)
        
        test_key = "test.message"
        
        # Add to all languages (just for testing)
        for lang_code in language_manager.get_available_languages():
            translator.add_translation(lang_code, test_key, f"[{lang_code}] {text}")
        
        # Show results
        for lang_code, lang_name in language_manager.get_available_languages().items():
            translator.set_language(lang_code)
            translated = translator.translate(test_key)
            click.echo(f"{lang_code} ({lang_name}): {translated}")
    
    else:
        # General translation test
        click.echo("Translation System Test")
        click.echo("-" * 30)
        
        # Test common keys
        test_keys = [
            'app.title',
            'action.start',
            'action.stop', 
            'lightning.balance',
            'success.connected'
        ]
        
        original_language = language_manager.get_current_language()
        
        for lang_code, lang_name in language_manager.get_available_languages().items():
            click.echo(f"\n{lang_name} ({lang_code}):")
            translator.set_language(lang_code)
            
            for test_key in test_keys:
                translated = translator.translate(test_key)
                click.echo(f"  {test_key}: {translated}")
        
        # Restore original language
        translator.set_language(original_language)


@i18n.command()
def detect():
    """Detect system language and locale information"""
    click.echo("System Language Detection:")
    click.echo("-" * 30)
    
    # System locale
    system_locale = get_system_locale()
    click.echo(f"System locale: {system_locale or 'Not detected'}")
    
    # Language manager detection
    language_manager = get_language_manager()
    detected_language = language_manager.detect_system_language()
    click.echo(f"Detected language: {detected_language}")
    
    # Current language
    current_language = language_manager.get_current_language()
    click.echo(f"Current language: {current_language}")
    
    # Available languages
    available_languages = language_manager.get_available_languages()
    click.echo(f"Available languages: {', '.join(available_languages.keys())}")
    
    # Auto-detection recommendation
    if detected_language != current_language and detected_language in available_languages:
        click.echo(f"\n💡 Recommendation: Switch to {detected_language} for better localization")
        click.echo(f"   Run: blncs i18n set-language {detected_language}")


@i18n.command()
def status():
    """Show internationalization status and statistics"""
    language_manager = get_language_manager()
    translator = get_translator()
    
    click.echo("🌍 BLNCS Internationalization Status")
    click.echo("=" * 50)
    
    # Current status
    current_language = language_manager.get_current_language()
    current_name = language_manager.get_available_languages().get(current_language, current_language)
    click.echo(f"Current Language: {current_name} ({current_language})")
    
    # System information
    system_locale = get_system_locale()
    detected_language = language_manager.detect_system_language()
    click.echo(f"System Locale: {system_locale or 'Unknown'}")
    click.echo(f"Detected Language: {detected_language}")
    
    # Translation statistics
    click.echo(f"\nTranslation Statistics:")
    click.echo("-" * 30)
    
    english_count = 0
    if 'en' in translator.translations:
        english_count = len(translator.translations['en'].translations)
        click.echo(f"Base translations (English): {english_count}")
    
    for lang_code, lang_name in language_manager.get_available_languages().items():
        if lang_code == 'en':
            continue
        
        completion = language_manager.get_language_completion_percentage(lang_code)
        translation_count = len(translator.translations[lang_code].translations)
        missing_count = len(language_manager.get_missing_translations(lang_code))
        
        status_icon = "✅" if completion >= 95 else "⚠️" if completion >= 75 else "❌"
        click.echo(f"{status_icon} {lang_name} ({lang_code}): {completion:.1f}% ({translation_count}/{english_count}, {missing_count} missing)")
    
    # Configuration
    click.echo(f"\nConfiguration:")
    preferences = language_manager.preferences
    click.echo(f"Auto-detect: {'✅' if preferences.auto_detect else '❌'}")
    click.echo(f"Save preferences: {'✅' if preferences.save_preference else '❌'}")
    click.echo(f"Fallback languages: {', '.join(preferences.fallback_languages)}")


if __name__ == '__main__':
    i18n()