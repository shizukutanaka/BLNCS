import re
import json
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple, Union
from dataclasses import dataclass
from enum import Enum
import logging
import ipaddress
import email_validator

logger = logging.getLogger(__name__)

class ValidationType(Enum):
    """検証タイプ"""
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    LDAP_INJECTION = "ldap_injection"
    XXE = "xxe"
    SSRF = "ssrf"
    OPEN_REDIRECT = "open_redirect"

@dataclass
class ValidationRule:
    """検証ルール"""
    field_name: str
    required: bool = False
    data_type: type = str
    min_length: Optional[int] = None
    max_length: Optional[int] = None
    min_value: Optional[Union[int, float]] = None
    max_value: Optional[Union[int, float]] = None
    pattern: Optional[str] = None
    allowed_values: Optional[List[Any]] = None
    custom_validator: Optional[callable] = None

class InputValidator:
    """統一入力検証システム"""
    
    def __init__(self):
        # SQLインジェクション検出パターン
        self.sql_patterns = [
            r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|CREATE|ALTER|EXEC|EXECUTE)\b)",
            r"(--|#|\/\*|\*\/|@@|@)",
            r"(\bOR\b.*?=.*?)",
            r"(\bAND\b.*?=.*?)",
            r"(\'|\"|;|\\x00|\\n|\\r|\\x1a)",
            r"(\bHAVING\b|\bGROUP\s+BY\b)",
            r"(xp_cmdshell|sp_executesql|OPENROWSET)",
        ]
        
        # XSS検出パターン
        self.xss_patterns = [
            r"<script[^>]*>.*?</script>",
            r"javascript\s*:",
            r"on\w+\s*=",
            r"<iframe[^>]*>",
            r"<object[^>]*>",
            r"<embed[^>]*>",
            r"<applet[^>]*>",
            r"<meta[^>]*http-equiv",
            r"<img[^>]*src[^>]*=",
            r"<svg[^>]*onload[^>]*=",
            r"eval\s*\(",
            r"expression\s*\(",
            r"vbscript\s*:",
            r"data\s*:\s*text\/html",
        ]
        
        # コマンドインジェクション検出パターン
        self.command_patterns = [
            r"[;&|`$]",
            r"\$\([^)]*\)",
            r"`[^`]*`",
            r">\s*/dev/null",
            r"2>&1",
            r"&&|\|\|",
        ]
        
        # パストラバーサル検出パターン
        self.path_patterns = [
            r"\.\./",
            r"\.\\/",
            r"%2e%2e[/\\]",
            r"\.\.%2f",
            r"\.\.%5c",
            r"/etc/passwd",
            r"c:\\windows",
            r"c:\\winnt",
        ]
        
    def validate_input(self, data: Any, rules: Union[ValidationRule, List[ValidationRule]]) -> Tuple[bool, List[str]]:
        """包括的入力検証"""
        errors = []
        
        if isinstance(rules, ValidationRule):
            rules = [rules]
            
        for rule in rules:
            field_errors = self._validate_field(data, rule)
            errors.extend(field_errors)
            
        # セキュリティチェック
        if isinstance(data, str):
            security_errors = self._security_validation(data)
            errors.extend(security_errors)
            
        return len(errors) == 0, errors
        
    def _validate_field(self, value: Any, rule: ValidationRule) -> List[str]:
        """フィールド検証"""
        errors = []
        field = rule.field_name
        
        # 必須チェック
        if rule.required and (value is None or value == ""):
            errors.append(f"{field}: Required field is missing")
            return errors
            
        if value is None:
            return errors
            
        # 型チェック
        if rule.data_type and not isinstance(value, rule.data_type):
            try:
                # 型変換を試みる
                value = rule.data_type(value)
            except (ValueError, TypeError):
                errors.append(f"{field}: Invalid type, expected {rule.data_type.__name__}")
                return errors
                
        # 文字列検証
        if isinstance(value, str):
            if rule.min_length and len(value) < rule.min_length:
                errors.append(f"{field}: Too short, minimum {rule.min_length} characters")
                
            if rule.max_length and len(value) > rule.max_length:
                errors.append(f"{field}: Too long, maximum {rule.max_length} characters")
                
            if rule.pattern and not re.match(rule.pattern, value):
                errors.append(f"{field}: Does not match required pattern")
                
        # 数値検証
        if isinstance(value, (int, float)):
            if rule.min_value is not None and value < rule.min_value:
                errors.append(f"{field}: Value too small, minimum {rule.min_value}")
                
            if rule.max_value is not None and value > rule.max_value:
                errors.append(f"{field}: Value too large, maximum {rule.max_value}")
                
        # 許可値チェック
        if rule.allowed_values and value not in rule.allowed_values:
            errors.append(f"{field}: Value not in allowed list")
            
        # カスタム検証
        if rule.custom_validator:
            try:
                result = rule.custom_validator(value)
                if result is False:
                    errors.append(f"{field}: Custom validation failed")
                elif isinstance(result, str):
                    errors.append(f"{field}: {result}")
            except Exception as e:
                errors.append(f"{field}: Validation error - {str(e)}")
                
        return errors
        
    def _security_validation(self, value: str) -> List[str]:
        """セキュリティ検証"""
        errors = []
        
        # SQLインジェクション検査
        for pattern in self.sql_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                errors.append("Potential SQL injection detected - input rejected")
                # SQLインジェクション攻撃を完全に防止
                return errors
                
        # XSS検査
        for pattern in self.xss_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                errors.append("Potential XSS attack detected - input rejected")
                # XSS攻撃を完全に防止
                return errors
                
        # コマンドインジェクション検査
        for pattern in self.command_patterns:
            if re.search(pattern, value):
                errors.append("Potential command injection detected")
                break
                
        # パストラバーサル検査
        for pattern in self.path_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                errors.append("Potential path traversal detected")
                break
                
        return errors
        
    def sanitize_html(self, html: str) -> str:
        """HTML sanitization"""
        # 危険なタグを除去
        dangerous_tags = [
            'script', 'iframe', 'object', 'embed', 'applet',
            'form', 'input', 'button', 'select', 'textarea',
            'style', 'link', 'meta', 'base'
        ]
        
        for tag in dangerous_tags:
            # 開始タグと終了タグを除去
            html = re.sub(f'<{tag}[^>]*>.*?</{tag}>', '', html, flags=re.IGNORECASE | re.DOTALL)
            # 自己閉じタグを除去
            html = re.sub(f'<{tag}[^>]*/>', '', html, flags=re.IGNORECASE)
            
        # イベントハンドラを除去
        html = re.sub(r'\s*on\w+\s*=\s*["\'][^"\']*["\']', '', html, flags=re.IGNORECASE)
        html = re.sub(r'\s*on\w+\s*=\s*[^\s>]+', '', html, flags=re.IGNORECASE)
        
        # JavaScriptプロトコルを除去
        html = re.sub(r'javascript\s*:', '', html, flags=re.IGNORECASE)
        html = re.sub(r'vbscript\s*:', '', html, flags=re.IGNORECASE)
        
        return html
        
    def validate_email(self, email: str) -> Tuple[bool, str]:
        """メールアドレス検証"""
        try:
            # email-validatorライブラリを使用
            validation = email_validator.validate_email(email)
            return True, validation.email
        except email_validator.EmailNotValidError as e:
            return False, str(e)
            
    def validate_url(self, url: str, allowed_schemes: List[str] = None) -> Tuple[bool, str]:
        """URL検証"""
        if allowed_schemes is None:
            allowed_schemes = ['http', 'https']
            
        try:
            parsed = urllib.parse.urlparse(url)
            
            # スキーム検証
            if parsed.scheme not in allowed_schemes:
                return False, f"Invalid URL scheme: {parsed.scheme}"
                
            # ホスト検証
            if not parsed.netloc:
                return False, "Missing host in URL"
                
            # オープンリダイレクト防止
            if parsed.netloc.startswith('@'):
                return False, "Potential open redirect detected"
                
            return True, url
            
        except Exception as e:
            return False, f"Invalid URL: {str(e)}"
            
    def validate_ip_address(self, ip: str, version: Optional[int] = None) -> Tuple[bool, str]:
        """IPアドレス検証"""
        try:
            if version == 4:
                ipaddress.IPv4Address(ip)
            elif version == 6:
                ipaddress.IPv6Address(ip)
            else:
                ipaddress.ip_address(ip)
                
            return True, ip
            
        except ValueError as e:
            return False, f"Invalid IP address: {str(e)}"
            
    def validate_json(self, json_str: str) -> Tuple[bool, Any]:
        """JSON検証"""
        try:
            data = json.loads(json_str)
            return True, data
        except json.JSONDecodeError as e:
            return False, f"Invalid JSON: {str(e)}"
            
    def escape_sql(self, value: str) -> str:
        """SQL エスケープ（最終手段として使用）"""
        # パラメータ化クエリが推奨
        value = value.replace("'", "''")
        value = value.replace("\\", "\\\\")
        value = value.replace("\0", "\\0")
        value = value.replace("\n", "\\n")
        value = value.replace("\r", "\\r")
        value = value.replace("\x1a", "\\Z")
        return value
        
    def escape_shell(self, value: str) -> str:
        """シェルコマンドエスケープ"""
        # 危険な文字をエスケープ
        dangerous_chars = ['&', '|', ';', '$', '>', '<', '`', '\\', '!', '\n', '\r']
        for char in dangerous_chars:
            value = value.replace(char, f'\\{char}')
        return value