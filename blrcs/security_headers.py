from typing import Dict, List, Optional
from dataclasses import dataclass
import hashlib
import secrets
import logging

logger = logging.getLogger(__name__)

@dataclass
class SecurityHeaderConfig:
    """セキュリティヘッダー設定"""
    enable_hsts: bool = True
    hsts_max_age: int = 31536000  # 1年
    hsts_include_subdomains: bool = True
    hsts_preload: bool = True
    
    enable_csp: bool = True
    csp_default_src: List[str] = None
    csp_script_src: List[str] = None
    csp_style_src: List[str] = None
    csp_img_src: List[str] = None
    csp_connect_src: List[str] = None
    csp_font_src: List[str] = None
    csp_object_src: List[str] = None
    csp_media_src: List[str] = None
    csp_frame_src: List[str] = None
    csp_report_uri: str = None
    
    enable_x_frame_options: bool = True
    x_frame_options: str = "DENY"  # DENY, SAMEORIGIN, ALLOW-FROM
    
    enable_x_content_type_options: bool = True
    enable_x_xss_protection: bool = True
    enable_referrer_policy: bool = True
    referrer_policy: str = "strict-origin-when-cross-origin"
    
    enable_permissions_policy: bool = True
    permissions_policy: Dict[str, List[str]] = None
    
    enable_expect_ct: bool = True
    expect_ct_max_age: int = 86400
    expect_ct_enforce: bool = True
    expect_ct_report_uri: str = None
    
    def __post_init__(self):
        if self.csp_default_src is None:
            self.csp_default_src = ["'self'"]
        if self.csp_script_src is None:
            self.csp_script_src = ["'self'", "'unsafe-inline'"]
        if self.csp_style_src is None:
            self.csp_style_src = ["'self'", "'unsafe-inline'"]
        if self.csp_img_src is None:
            self.csp_img_src = ["'self'", "data:", "https:"]
        if self.csp_connect_src is None:
            self.csp_connect_src = ["'self'"]
        if self.csp_font_src is None:
            self.csp_font_src = ["'self'", "data:"]
        if self.csp_object_src is None:
            self.csp_object_src = ["'none'"]
        if self.csp_media_src is None:
            self.csp_media_src = ["'self'"]
        if self.csp_frame_src is None:
            self.csp_frame_src = ["'none'"]
        if self.permissions_policy is None:
            self.permissions_policy = {
                "accelerometer": [],
                "camera": [],
                "geolocation": [],
                "gyroscope": [],
                "magnetometer": [],
                "microphone": [],
                "payment": [],
                "usb": []
            }

class SecurityHeaders:
    """包括的セキュリティヘッダー管理"""
    
    def __init__(self, config: SecurityHeaderConfig = None):
        self.config = config or SecurityHeaderConfig()
        self.nonce_cache = {}
        
    def get_headers(self, request_context: Optional[Dict] = None) -> Dict[str, str]:
        """セキュリティヘッダー生成"""
        headers = {}
        
        # HSTS (HTTP Strict Transport Security)
        if self.config.enable_hsts:
            headers["Strict-Transport-Security"] = self._build_hsts_header()
            
        # CSP (Content Security Policy)
        if self.config.enable_csp:
            headers["Content-Security-Policy"] = self._build_csp_header(request_context)
            
        # X-Frame-Options
        if self.config.enable_x_frame_options:
            headers["X-Frame-Options"] = self.config.x_frame_options
            
        # X-Content-Type-Options
        if self.config.enable_x_content_type_options:
            headers["X-Content-Type-Options"] = "nosniff"
            
        # X-XSS-Protection (レガシーブラウザ向け)
        if self.config.enable_x_xss_protection:
            headers["X-XSS-Protection"] = "1; mode=block"
            
        # Referrer-Policy
        if self.config.enable_referrer_policy:
            headers["Referrer-Policy"] = self.config.referrer_policy
            
        # Permissions-Policy (Feature-Policy の後継)
        if self.config.enable_permissions_policy:
            headers["Permissions-Policy"] = self._build_permissions_policy()
            
        # Expect-CT
        if self.config.enable_expect_ct:
            headers["Expect-CT"] = self._build_expect_ct_header()
            
        # Cross-Origin headers
        headers.update(self._get_cors_headers(request_context))
        
        # Cache-Control for sensitive data
        if request_context and request_context.get("sensitive_data"):
            headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
            headers["Pragma"] = "no-cache"
            headers["Expires"] = "0"
            
        return headers
        
    def _build_hsts_header(self) -> str:
        """HSTS ヘッダー構築"""
        parts = [f"max-age={self.config.hsts_max_age}"]
        
        if self.config.hsts_include_subdomains:
            parts.append("includeSubDomains")
            
        if self.config.hsts_preload:
            parts.append("preload")
            
        return "; ".join(parts)
        
    def _build_csp_header(self, request_context: Optional[Dict] = None) -> str:
        """CSP ヘッダー構築"""
        directives = []
        
        # Nonce生成（インラインスクリプト用）
        nonce = self._generate_nonce()
        if request_context:
            request_context["csp_nonce"] = nonce
            
        # Default-src
        if self.config.csp_default_src:
            directives.append(f"default-src {' '.join(self.config.csp_default_src)}")
            
        # Script-src
        script_sources = self.config.csp_script_src.copy()
        script_sources.append(f"'nonce-{nonce}'")
        directives.append(f"script-src {' '.join(script_sources)}")
        
        # Style-src
        style_sources = self.config.csp_style_src.copy()
        style_sources.append(f"'nonce-{nonce}'")
        directives.append(f"style-src {' '.join(style_sources)}")
        
        # Other directives
        if self.config.csp_img_src:
            directives.append(f"img-src {' '.join(self.config.csp_img_src)}")
            
        if self.config.csp_connect_src:
            directives.append(f"connect-src {' '.join(self.config.csp_connect_src)}")
            
        if self.config.csp_font_src:
            directives.append(f"font-src {' '.join(self.config.csp_font_src)}")
            
        if self.config.csp_object_src:
            directives.append(f"object-src {' '.join(self.config.csp_object_src)}")
            
        if self.config.csp_media_src:
            directives.append(f"media-src {' '.join(self.config.csp_media_src)}")
            
        if self.config.csp_frame_src:
            directives.append(f"frame-src {' '.join(self.config.csp_frame_src)}")
            
        # Security directives
        directives.extend([
            "base-uri 'self'",
            "form-action 'self'",
            "frame-ancestors 'none'",
            "block-all-mixed-content",
            "upgrade-insecure-requests"
        ])
        
        # Report-URI
        if self.config.csp_report_uri:
            directives.append(f"report-uri {self.config.csp_report_uri}")
            
        return "; ".join(directives)
        
    def _build_permissions_policy(self) -> str:
        """Permissions-Policy ヘッダー構築"""
        policies = []
        
        for feature, origins in self.config.permissions_policy.items():
            if not origins:
                policies.append(f"{feature}=()")
            else:
                origin_list = " ".join(f'"{origin}"' for origin in origins)
                policies.append(f"{feature}=({origin_list})")
                
        return ", ".join(policies)
        
    def _build_expect_ct_header(self) -> str:
        """Expect-CT ヘッダー構築"""
        parts = [f"max-age={self.config.expect_ct_max_age}"]
        
        if self.config.expect_ct_enforce:
            parts.append("enforce")
            
        if self.config.expect_ct_report_uri:
            parts.append(f'report-uri="{self.config.expect_ct_report_uri}"')
            
        return ", ".join(parts)
        
    def _get_cors_headers(self, request_context: Optional[Dict] = None) -> Dict[str, str]:
        """CORS ヘッダー生成"""
        headers = {}
        
        if not request_context:
            return headers
            
        origin = request_context.get("origin")
        if not origin:
            return headers
            
        # 許可されたオリジンチェック
        allowed_origins = request_context.get("allowed_origins", [])
        if origin in allowed_origins or "*" in allowed_origins:
            headers["Access-Control-Allow-Origin"] = origin
            headers["Access-Control-Allow-Credentials"] = "true"
            
            # Preflight request
            if request_context.get("method") == "OPTIONS":
                headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
                headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-CSRF-Token"
                headers["Access-Control-Max-Age"] = "86400"
                
        return headers
        
    def _generate_nonce(self) -> str:
        """CSP nonce 生成"""
        return secrets.token_urlsafe(16)
        
    def validate_csp_report(self, report: Dict) -> bool:
        """CSP 違反レポート検証"""
        required_fields = ["document-uri", "violated-directive", "blocked-uri"]
        
        for field in required_fields:
            if field not in report:
                return False
                
        # 既知の false positive をフィルタ
        blocked_uri = report.get("blocked-uri", "")
        if blocked_uri.startswith("chrome-extension://"):
            return False
        if blocked_uri.startswith("moz-extension://"):
            return False
            
        return True
        
    def get_report_only_headers(self) -> Dict[str, str]:
        """レポートのみモードのヘッダー（テスト用）"""
        headers = self.get_headers()
        
        # CSP をレポートのみモードに変更
        if "Content-Security-Policy" in headers:
            csp = headers.pop("Content-Security-Policy")
            headers["Content-Security-Policy-Report-Only"] = csp
            
        return headers

class SecureResponseWrapper:
    """レスポンスラッパー（自動セキュリティヘッダー付与）"""
    
    def __init__(self, security_headers: SecurityHeaders):
        self.security_headers = security_headers
        
    def wrap_response(self, response, request_context: Optional[Dict] = None):
        """レスポンスにセキュリティヘッダーを追加"""
        headers = self.security_headers.get_headers(request_context)
        
        for header_name, header_value in headers.items():
            response.headers[header_name] = header_value
            
        # セキュアクッキー設定
        if hasattr(response, "set_cookie"):
            self._secure_cookies(response)
            
        return response
        
    def _secure_cookies(self, response):
        """クッキーのセキュリティ属性設定"""
        # Set-Cookie ヘッダーを解析して再設定
        if "Set-Cookie" in response.headers:
            cookies = response.headers.getlist("Set-Cookie")
            response.headers.pop("Set-Cookie")
            
            for cookie in cookies:
                # セキュリティ属性を追加
                if "Secure" not in cookie:
                    cookie += "; Secure"
                if "HttpOnly" not in cookie:
                    cookie += "; HttpOnly"
                if "SameSite" not in cookie:
                    cookie += "; SameSite=Strict"
                    
                response.headers.add("Set-Cookie", cookie)