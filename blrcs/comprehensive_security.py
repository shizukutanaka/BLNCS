"""包括的セキュリティ強化システム"""

import re
import hmac
import hashlib
import secrets
import time
import ipaddress
import logging
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import asyncio
from pathlib import Path
import json

logger = logging.getLogger(__name__)

class ThreatLevel(Enum):
    """脅威レベル"""
    LOW = "low"
    MEDIUM = "medium" 
    HIGH = "high"
    CRITICAL = "critical"

class AttackType(Enum):
    """攻撃タイプ"""
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    CSRF = "csrf"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    BRUTE_FORCE = "brute_force"
    DDOS = "ddos"
    MALFORMED_REQUEST = "malformed_request"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_EXFILTRATION = "data_exfiltration"

@dataclass
class SecurityIncident:
    """セキュリティインシデント"""
    id: str
    timestamp: float
    source_ip: str
    attack_type: AttackType
    threat_level: ThreatLevel
    payload: str
    user_agent: str
    endpoint: str
    blocked: bool
    details: Dict[str, Any] = field(default_factory=dict)

class AdvancedInputSanitizer:
    """高度な入力サニタイゼーション"""
    
    def __init__(self):
        # 拡張SQLインジェクションパターン
        self.sql_patterns = [
            r'(\bselect\b|\binsert\b|\bupdate\b|\bdelete\b|\bdrop\b|\bunion\b|\balter\b)',
            r'(\bor\b|\band\b)\s+\d+\s*=\s*\d+',
            r'[\'";]\s*(\bor\b|\band\b)',
            r'\b(exec|execute|sp_)\w*\b',
            r'@@\w+',
            r'\bxp_\w+',
            r'\bsp_\w+',
            r'(\bhaving\b|\bgroup\s+by\b)',
            r'\b(information_schema|sysobjects|syscolumns)\b',
            r'(cast|convert|substring|ascii|char)\s*\(',
            r'(waitfor\s+delay|benchmark\s*\()',
            r'(\binto\s+outfile\b|\bload_file\b)',
            r'(pg_sleep|sleep\s*\()',
            r'(0x[0-9a-f]+|char\s*\(\d+\))',
            r'(concat\s*\(|group_concat\s*\()',
        ]
        
        # 拡張XSSパターン  
        self.xss_patterns = [
            r'<script[^>]*>.*?</script>',
            r'javascript\s*:',
            r'vbscript\s*:',
            r'on\w+\s*=',
            r'<iframe[^>]*>',
            r'<object[^>]*>',
            r'<embed[^>]*>',
            r'<applet[^>]*>',
            r'<form[^>]*>',
            r'<link[^>]*>',
            r'<meta[^>]*>',
            r'<style[^>]*>',
            r'eval\s*\(',
            r'expression\s*\(',
            r'String\.fromCharCode',
            r'document\.(cookie|domain|write)',
            r'window\.(location|open)',
            r'alert\s*\(',
            r'confirm\s*\(',
            r'prompt\s*\(',
            r'data\s*:\s*text/html',
            r'\\x[0-9a-f]{2}',
            r'&#x?[0-9a-f]+;?',
        ]
        
        # コマンドインジェクションパターン
        self.command_patterns = [
            r'[;&|`$]',
            r'\b(cat|ls|ps|id|whoami|uname|pwd)\b',
            r'\b(rm|mv|cp|chmod|chown)\b',
            r'\b(wget|curl|nc|netcat)\b',
            r'\b(python|perl|ruby|php|bash|sh)\b',
            r'\.\./+',
            r'/etc/(passwd|shadow|hosts)',
            r'/proc/',
            r'/dev/',
            r'\\x[0-9a-f]{2}',
        ]
        
        # パストラバーサルパターン
        self.path_patterns = [
            r'\.\./+',
            r'\.\.\\+',
            r'/etc/',
            r'/proc/',
            r'/sys/',
            r'\\windows\\',
            r'\\system32\\',
            r'%2e%2e%2f',
            r'%2e%2e\\',
            r'..%252f',
            r'..%255c',
        ]

    def sanitize_strict(self, value: str, field_name: str = "") -> str:
        """厳格なサニタイゼーション"""
        if not isinstance(value, str):
            value = str(value)
            
        original_value = value
        
        # 1. 基本的な制御文字除去
        value = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', value)
        
        # 2. 危険なパターンチェック
        for pattern in self.sql_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                logger.warning(f"SQL injection attempt blocked: {field_name} = {original_value[:100]}")
                raise ValueError(f"Input contains SQL injection pattern in field '{field_name}'")
                
        for pattern in self.xss_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                logger.warning(f"XSS attempt blocked: {field_name} = {original_value[:100]}")
                raise ValueError(f"Input contains XSS pattern in field '{field_name}'")
                
        for pattern in self.command_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                logger.warning(f"Command injection attempt blocked: {field_name} = {original_value[:100]}")
                raise ValueError(f"Input contains command injection pattern in field '{field_name}'")
                
        for pattern in self.path_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                logger.warning(f"Path traversal attempt blocked: {field_name} = {original_value[:100]}")
                raise ValueError(f"Input contains path traversal pattern in field '{field_name}'")
        
        # 3. HTMLエンコーディング（XSS防止）
        html_chars = {
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#x27;',
            '&': '&amp;',
            '/': '&#x2F;',
        }
        
        for char, encoded in html_chars.items():
            value = value.replace(char, encoded)
            
        # 4. SQLメタ文字エスケープ
        sql_chars = {
            "'": "''",
            '"': '""',
            '\\': '\\\\',
            '%': '\\%',
            '_': '\\_',
        }
        
        for char, escaped in sql_chars.items():
            value = value.replace(char, escaped)
            
        return value

    def sanitize_permissive(self, value: str, allowed_tags: List[str] = None) -> str:
        """許可的なサニタイゼーション（一部HTMLタグを許可）"""
        if not isinstance(value, str):
            value = str(value)
            
        allowed_tags = allowed_tags or ['b', 'i', 'u', 'strong', 'em', 'p', 'br']
        
        # 危険なパターンは引き続きブロック
        for pattern in self.sql_patterns[:5]:  # 最も危険なSQLパターンのみ
            if re.search(pattern, value, re.IGNORECASE):
                raise ValueError("Input contains dangerous SQL pattern")
                
        for pattern in self.xss_patterns[:10]:  # 最も危険なXSSパターンのみ  
            if re.search(pattern, value, re.IGNORECASE):
                raise ValueError("Input contains dangerous XSS pattern")
        
        # 許可されていないHTMLタグを除去
        def replace_tag(match):
            tag_name = match.group(1).lower()
            if tag_name in allowed_tags:
                return match.group(0)
            else:
                return ''
                
        value = re.sub(r'<(/?)(\w+)[^>]*>', replace_tag, value)
        
        return value

class ThreatDetectionEngine:
    """脅威検出エンジン"""
    
    def __init__(self):
        self.failed_attempts = {}  # IP -> [timestamps]
        self.blocked_ips = set()
        self.suspicious_patterns = {}
        self.incident_history = []
        self.max_incidents = 10000
        
        # 脅威検出しきい値
        self.thresholds = {
            "failed_login_attempts": 5,
            "requests_per_minute": 100,
            "suspicious_patterns": 3,
            "block_duration": 3600,  # 1時間
        }

    def detect_brute_force(self, ip: str, success: bool = False) -> bool:
        """ブルートフォース攻撃検出"""
        current_time = time.time()
        
        if ip not in self.failed_attempts:
            self.failed_attempts[ip] = []
            
        if not success:
            self.failed_attempts[ip].append(current_time)
            
            # 1時間以内の失敗回数をカウント
            recent_failures = [
                t for t in self.failed_attempts[ip] 
                if current_time - t < 3600
            ]
            self.failed_attempts[ip] = recent_failures
            
            if len(recent_failures) >= self.thresholds["failed_login_attempts"]:
                self._block_ip(ip, "brute_force")
                return True
        else:
            # ログイン成功時は失敗回数をリセット
            self.failed_attempts[ip] = []
            
        return False

    def detect_ddos(self, ip: str) -> bool:
        """DDoS攻撃検出"""
        current_time = time.time()
        
        # 1分間のリクエスト数をチェック
        if ip not in self.failed_attempts:
            self.failed_attempts[ip] = []
            
        self.failed_attempts[ip].append(current_time)
        
        # 1分以内のリクエスト数をカウント
        recent_requests = [
            t for t in self.failed_attempts[ip]
            if current_time - t < 60
        ]
        self.failed_attempts[ip] = recent_requests
        
        if len(recent_requests) > self.thresholds["requests_per_minute"]:
            self._block_ip(ip, "ddos")
            return True
            
        return False

    def detect_anomalous_behavior(self, ip: str, user_agent: str, endpoint: str) -> bool:
        """異常な行動パターン検出"""
        # 異常なUser-Agentパターン
        suspicious_agents = [
            r'sqlmap',
            r'nikto',
            r'nmap',
            r'masscan',
            r'nessus',
            r'burp',
            r'python-requests',
            r'curl/\d+\.\d+',
            r'wget/\d+\.\d+',
        ]
        
        for pattern in suspicious_agents:
            if re.search(pattern, user_agent, re.IGNORECASE):
                return True
                
        # 異常なエンドポイントアクセスパターン
        suspicious_endpoints = [
            r'/admin',
            r'/wp-admin',
            r'/phpmyadmin',
            r'/config',
            r'/backup',
            r'/test',
            r'/debug',
            r'\.php$',
            r'\.asp$',
            r'\.jsp$',
        ]
        
        for pattern in suspicious_endpoints:
            if re.search(pattern, endpoint, re.IGNORECASE):
                return True
                
        return False

    def _block_ip(self, ip: str, reason: str):
        """IP一時ブロック"""
        self.blocked_ips.add(ip)
        logger.warning(f"IP {ip} blocked for {reason}")
        
        # 一定時間後に自動解除
        async def unblock_later():
            await asyncio.sleep(self.thresholds["block_duration"])
            self.blocked_ips.discard(ip)
            logger.info(f"IP {ip} unblocked")
            
        asyncio.create_task(unblock_later())

    def is_blocked(self, ip: str) -> bool:
        """IPブロック状態確認"""
        return ip in self.blocked_ips

    def record_incident(self, incident: SecurityIncident):
        """セキュリティインシデント記録"""
        self.incident_history.append(incident)
        
        # 履歴サイズ制限
        if len(self.incident_history) > self.max_incidents:
            self.incident_history = self.incident_history[-self.max_incidents:]
            
        # Critical/Highレベルの場合は即座にログ出力
        if incident.threat_level in [ThreatLevel.CRITICAL, ThreatLevel.HIGH]:
            logger.error(f"Security incident: {incident.attack_type.value} from {incident.source_ip}")

class CSRFProtectionAdvanced:
    """高度なCSRF保護"""
    
    def __init__(self):
        self.tokens = {}  # session_id -> {token, timestamp, used}
        self.token_lifetime = 3600  # 1時間
        self.secret_key = secrets.token_bytes(32)

    def generate_token(self, session_id: str, action: str = "default") -> str:
        """CSRFトークン生成"""
        timestamp = int(time.time())
        nonce = secrets.token_urlsafe(16)
        
        # トークンにアクション情報を含める
        payload = f"{session_id}:{action}:{timestamp}:{nonce}"
        
        # HMAC署名
        signature = hmac.new(
            self.secret_key,
            payload.encode(),
            hashlib.sha256
        ).hexdigest()
        
        token = f"{payload}:{signature}"
        
        # トークンを保存
        self.tokens[session_id] = {
            'token': token,
            'timestamp': timestamp,
            'used': False,
            'action': action
        }
        
        return token

    def validate_token(self, session_id: str, token: str, action: str = "default") -> Tuple[bool, str]:
        """CSRFトークン検証"""
        try:
            # トークン形式チェック
            parts = token.split(':')
            if len(parts) != 5:
                return False, "Invalid token format"
                
            payload = ':'.join(parts[:-1])
            provided_signature = parts[-1]
            
            # 署名検証
            expected_signature = hmac.new(
                self.secret_key,
                payload.encode(),
                hashlib.sha256
            ).hexdigest()
            
            if not secrets.compare_digest(provided_signature, expected_signature):
                return False, "Invalid token signature"
                
            # セッション・アクション・タイムスタンプ検証
            token_session, token_action, timestamp, nonce = parts[:-1]
            
            if token_session != session_id:
                return False, "Token session mismatch"
                
            if token_action != action:
                return False, "Token action mismatch"
                
            # タイムスタンプ検証
            if time.time() - int(timestamp) > self.token_lifetime:
                return False, "Token expired"
                
            # ワンタイム使用チェック
            if session_id in self.tokens:
                token_info = self.tokens[session_id]
                if token_info['used']:
                    return False, "Token already used"
                    
                # トークンを使用済みにマーク
                token_info['used'] = True
                
            return True, "Token valid"
            
        except Exception as e:
            logger.error(f"CSRF token validation error: {e}")
            return False, "Token validation failed"

class ComprehensiveSecurityManager:
    """包括的セキュリティマネージャー"""
    
    def __init__(self):
        self.sanitizer = AdvancedInputSanitizer()
        self.threat_detector = ThreatDetectionEngine()
        self.csrf_protection = CSRFProtectionAdvanced()
        self.security_headers = self._get_security_headers()
        
    def _get_security_headers(self) -> Dict[str, str]:
        """セキュリティヘッダー取得"""
        return {
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
            'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; media-src 'self'; frame-src 'none';",
            'X-Frame-Options': 'DENY',
            'X-Content-Type-Options': 'nosniff',
            'X-XSS-Protection': '1; mode=block',
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
            'Cross-Origin-Embedder-Policy': 'require-corp',
            'Cross-Origin-Opener-Policy': 'same-origin',
            'Cross-Origin-Resource-Policy': 'same-origin',
        }

    async def process_request(self, 
                            ip: str, 
                            user_agent: str, 
                            endpoint: str, 
                            data: Dict[str, Any] = None) -> Tuple[bool, Dict[str, Any]]:
        """リクエスト処理とセキュリティチェック"""
        
        # 1. IPブロックチェック
        if self.threat_detector.is_blocked(ip):
            incident = SecurityIncident(
                id=secrets.token_urlsafe(8),
                timestamp=time.time(),
                source_ip=ip,
                attack_type=AttackType.DDOS,
                threat_level=ThreatLevel.HIGH,
                payload="",
                user_agent=user_agent,
                endpoint=endpoint,
                blocked=True
            )
            self.threat_detector.record_incident(incident)
            return False, {"error": "Access denied", "reason": "IP blocked"}
            
        # 2. DDoS検出
        if self.threat_detector.detect_ddos(ip):
            return False, {"error": "Too many requests", "reason": "Rate limit exceeded"}
            
        # 3. 異常行動検出
        if self.threat_detector.detect_anomalous_behavior(ip, user_agent, endpoint):
            incident = SecurityIncident(
                id=secrets.token_urlsafe(8),
                timestamp=time.time(),
                source_ip=ip,
                attack_type=AttackType.MALFORMED_REQUEST,
                threat_level=ThreatLevel.MEDIUM,
                payload=user_agent,
                user_agent=user_agent,
                endpoint=endpoint,
                blocked=True
            )
            self.threat_detector.record_incident(incident)
            return False, {"error": "Suspicious behavior detected", "reason": "Anomalous pattern"}
        
        # 4. 入力データサニタイゼーション
        if data:
            try:
                sanitized_data = {}
                for key, value in data.items():
                    if isinstance(value, str):
                        sanitized_data[key] = self.sanitizer.sanitize_strict(value, key)
                    else:
                        sanitized_data[key] = value
                        
                return True, {
                    "sanitized_data": sanitized_data,
                    "security_headers": self.security_headers
                }
                
            except ValueError as e:
                # 悪意のある入力を検出
                incident = SecurityIncident(
                    id=secrets.token_urlsafe(8),
                    timestamp=time.time(),
                    source_ip=ip,
                    attack_type=AttackType.SQL_INJECTION if "SQL" in str(e) else AttackType.XSS,
                    threat_level=ThreatLevel.HIGH,
                    payload=str(data)[:1000],
                    user_agent=user_agent,
                    endpoint=endpoint,
                    blocked=True
                )
                self.threat_detector.record_incident(incident)
                return False, {"error": "Invalid input", "reason": str(e)}
        
        return True, {"security_headers": self.security_headers}

    def get_security_report(self) -> Dict[str, Any]:
        """セキュリティレポート生成"""
        recent_incidents = [
            incident for incident in self.threat_detector.incident_history
            if time.time() - incident.timestamp < 86400  # 24時間以内
        ]
        
        attack_counts = {}
        for incident in recent_incidents:
            attack_type = incident.attack_type.value
            attack_counts[attack_type] = attack_counts.get(attack_type, 0) + 1
            
        return {
            "total_incidents": len(recent_incidents),
            "blocked_ips": len(self.threat_detector.blocked_ips),
            "attack_breakdown": attack_counts,
            "threat_levels": {
                level.value: len([i for i in recent_incidents if i.threat_level == level])
                for level in ThreatLevel
            },
            "top_attacking_ips": self._get_top_attacking_ips(recent_incidents),
            "generated_at": datetime.now().isoformat()
        }

    def _get_top_attacking_ips(self, incidents: List[SecurityIncident]) -> List[Dict[str, Any]]:
        """攻撃元IP上位取得"""
        ip_counts = {}
        for incident in incidents:
            ip = incident.source_ip
            if ip not in ip_counts:
                ip_counts[ip] = {"count": 0, "attacks": []}
            ip_counts[ip]["count"] += 1
            ip_counts[ip]["attacks"].append(incident.attack_type.value)
            
        sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1]["count"], reverse=True)
        
        return [
            {
                "ip": ip,
                "attack_count": data["count"],
                "attack_types": list(set(data["attacks"]))
            }
            for ip, data in sorted_ips[:10]
        ]

# グローバルインスタンス
comprehensive_security = ComprehensiveSecurityManager()