import re
import hashlib
import secrets
from typing import List, Tuple, Optional, Dict
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)

@dataclass
class PasswordPolicyConfig:
    """パスワードポリシー設定"""
    min_length: int = 12
    max_length: int = 128
    require_uppercase: bool = True
    require_lowercase: bool = True
    require_numbers: bool = True
    require_special: bool = True
    min_uppercase: int = 1
    min_lowercase: int = 1
    min_numbers: int = 1
    min_special: int = 1
    max_repeated_chars: int = 3
    max_sequential_chars: int = 3
    password_history_size: int = 5
    min_password_age_days: int = 1
    max_password_age_days: int = 90
    min_entropy_bits: int = 60

class PasswordPolicy:
    """エンタープライズグレードパスワードポリシー"""
    
    def __init__(self, config: PasswordPolicyConfig = None):
        self.config = config or PasswordPolicyConfig()
        self.password_history: Dict[str, List[Dict]] = {}
        self.common_passwords = self._load_common_passwords()
        self.keyboard_patterns = self._load_keyboard_patterns()
        
    def _load_common_passwords(self) -> set:
        """一般的な弱いパスワードリスト"""
        return {
            "password", "123456", "password123", "admin", "letmein",
            "qwerty", "monkey", "1234567890", "password1", "123456789",
            "qwertyuiop", "1234", "12345", "abc123", "Password1",
            "password!", "welcome", "welcome123", "admin123", "root",
            "toor", "pass", "test", "guest", "master", "dragon",
            "baseball", "football", "iloveyou", "trustno1", "1234567",
            "sunshine", "princess", "starwars", "whatever", "shadow",
            "cheese", "computer", "michelle", "111111", "123123",
            "freedom", "hello", "ninja", "azerty", "solo", "monday",
            "flower", "password1!", "passw0rd", "p@ssw0rd", "P@ssw0rd"
        }
        
    def _load_keyboard_patterns(self) -> List[str]:
        """キーボードパターン"""
        return [
            "qwerty", "asdfgh", "zxcvbn", "qwertz", "azerty",
            "qweasd", "qaz", "wsx", "edc", "rfv", "tgb", "yhn",
            "ujm", "ikl", "1234567890", "0987654321",
            "abcdefgh", "zyxwvuts"
        ]
        
    def validate_password(self, password: str, username: str = "", 
                         old_password: str = "") -> Tuple[bool, List[str]]:
        """包括的パスワード検証"""
        errors = []
        
        # 基本チェック
        if not password:
            errors.append("Password cannot be empty")
            return False, errors
            
        # 長さチェック
        if len(password) < self.config.min_length:
            errors.append(f"Password must be at least {self.config.min_length} characters")
            
        if len(password) > self.config.max_length:
            errors.append(f"Password must not exceed {self.config.max_length} characters")
            
        # 文字種チェック
        uppercase_count = sum(1 for c in password if c.isupper())
        lowercase_count = sum(1 for c in password if c.islower())
        number_count = sum(1 for c in password if c.isdigit())
        special_count = sum(1 for c in password if not c.isalnum())
        
        if self.config.require_uppercase and uppercase_count < self.config.min_uppercase:
            errors.append(f"Password must contain at least {self.config.min_uppercase} uppercase letter(s)")
            
        if self.config.require_lowercase and lowercase_count < self.config.min_lowercase:
            errors.append(f"Password must contain at least {self.config.min_lowercase} lowercase letter(s)")
            
        if self.config.require_numbers and number_count < self.config.min_numbers:
            errors.append(f"Password must contain at least {self.config.min_numbers} number(s)")
            
        if self.config.require_special and special_count < self.config.min_special:
            errors.append(f"Password must contain at least {self.config.min_special} special character(s)")
            
        # 連続文字チェック
        if self._has_repeated_chars(password):
            errors.append(f"Password cannot contain more than {self.config.max_repeated_chars - 1} repeated characters")
            
        # 連番チェック
        if self._has_sequential_chars(password):
            errors.append(f"Password cannot contain more than {self.config.max_sequential_chars - 1} sequential characters")
            
        # ユーザー名チェック
        if username and username.lower() in password.lower():
            errors.append("Password cannot contain username")
            
        # 一般的なパスワードチェック
        if password.lower() in self.common_passwords:
            errors.append("Password is too common")
            
        # キーボードパターンチェック
        if self._contains_keyboard_pattern(password):
            errors.append("Password contains keyboard pattern")
            
        # 辞書語チェック
        if self._is_dictionary_word(password):
            errors.append("Password is a dictionary word or too simple")
            
        # エントロピーチェック
        entropy = self._calculate_entropy(password)
        if entropy < self.config.min_entropy_bits:
            errors.append(f"Password is too weak (entropy: {entropy:.1f} bits, required: {self.config.min_entropy_bits})")
            
        # 前のパスワードとの類似性チェック
        if old_password and self._is_similar_to_old(password, old_password):
            errors.append("New password is too similar to the old password")
            
        return len(errors) == 0, errors
        
    def _has_repeated_chars(self, password: str) -> bool:
        """連続同一文字チェック"""
        for i in range(len(password) - self.config.max_repeated_chars + 1):
            if password[i:i+self.config.max_repeated_chars] == password[i] * self.config.max_repeated_chars:
                return True
        return False
        
    def _has_sequential_chars(self, password: str) -> bool:
        """連番文字チェック"""
        for i in range(len(password) - self.config.max_sequential_chars + 1):
            chunk = password[i:i+self.config.max_sequential_chars]
            if self._is_sequential(chunk):
                return True
        return False
        
    def _is_sequential(self, chunk: str) -> bool:
        """文字列が連番かチェック"""
        # 数字の連番
        if chunk.isdigit():
            for i in range(len(chunk) - 1):
                if int(chunk[i+1]) - int(chunk[i]) != 1:
                    return False
            return True
            
        # アルファベットの連番
        if chunk.isalpha():
            for i in range(len(chunk) - 1):
                if ord(chunk[i+1]) - ord(chunk[i]) != 1:
                    return False
            return True
            
        return False
        
    def _contains_keyboard_pattern(self, password: str) -> bool:
        """キーボードパターン検出"""
        password_lower = password.lower()
        for pattern in self.keyboard_patterns:
            if pattern in password_lower:
                return True
        return False
        
    def _is_dictionary_word(self, password: str) -> bool:
        """辞書語チェック（簡易版）"""
        # 数字や記号を除去
        alpha_only = re.sub(r'[^a-zA-Z]', '', password)
        
        # 長い英単語のようなパターン
        if len(alpha_only) >= 6 and alpha_only.isalpha():
            # 母音と子音のバランスチェック
            vowels = sum(1 for c in alpha_only.lower() if c in 'aeiou')
            consonants = len(alpha_only) - vowels
            
            # 極端に母音または子音に偏っていない
            if 0.2 < vowels / len(alpha_only) < 0.8:
                return True
                
        return False
        
    def _calculate_entropy(self, password: str) -> float:
        """パスワードエントロピー計算"""
        import math
        
        charset_size = 0
        
        # 使用文字種のカウント
        if any(c.islower() for c in password):
            charset_size += 26
        if any(c.isupper() for c in password):
            charset_size += 26
        if any(c.isdigit() for c in password):
            charset_size += 10
        if any(not c.isalnum() for c in password):
            charset_size += 32  # 一般的な特殊文字
            
        if charset_size == 0:
            return 0
            
        # エントロピー = log2(charset_size^length)
        entropy = len(password) * math.log2(charset_size)
        
        # パターンや辞書語によるペナルティ
        if self._contains_keyboard_pattern(password):
            entropy *= 0.5
        if password.lower() in self.common_passwords:
            entropy *= 0.1
            
        return entropy
        
    def _is_similar_to_old(self, new_password: str, old_password: str) -> bool:
        """新旧パスワードの類似性チェック"""
        # レーベンシュタイン距離を使用
        distance = self._levenshtein_distance(new_password, old_password)
        
        # 変更が30%未満なら類似とみなす
        max_len = max(len(new_password), len(old_password))
        similarity_ratio = 1 - (distance / max_len)
        
        return similarity_ratio > 0.7
        
    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """レーベンシュタイン距離計算"""
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
            
        if len(s2) == 0:
            return len(s1)
            
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
            
        return previous_row[-1]
        
    def generate_strong_password(self, length: int = 16) -> str:
        """強力なパスワード生成"""
        if length < self.config.min_length:
            length = self.config.min_length
            
        # 文字セット定義
        uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        lowercase = "abcdefghijklmnopqrstuvwxyz"
        numbers = "0123456789"
        special = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        # 必須文字を確保
        password_chars = []
        
        if self.config.require_uppercase:
            for _ in range(self.config.min_uppercase):
                password_chars.append(secrets.choice(uppercase))
                
        if self.config.require_lowercase:
            for _ in range(self.config.min_lowercase):
                password_chars.append(secrets.choice(lowercase))
                
        if self.config.require_numbers:
            for _ in range(self.config.min_numbers):
                password_chars.append(secrets.choice(numbers))
                
        if self.config.require_special:
            for _ in range(self.config.min_special):
                password_chars.append(secrets.choice(special))
                
        # 残りの文字をランダムに追加
        all_chars = uppercase + lowercase + numbers + special
        while len(password_chars) < length:
            password_chars.append(secrets.choice(all_chars))
            
        # シャッフル
        secrets.SystemRandom().shuffle(password_chars)
        
        return ''.join(password_chars)
        
    def check_password_history(self, user_id: str, password_hash: str) -> Tuple[bool, str]:
        """パスワード履歴チェック"""
        if user_id not in self.password_history:
            self.password_history[user_id] = []
            
        # 履歴チェック
        for history_entry in self.password_history[user_id][-self.config.password_history_size:]:
            if history_entry['hash'] == password_hash:
                return False, f"Password was used recently. Please choose a different password."
                
        return True, "Password not in history"
        
    def add_to_history(self, user_id: str, password_hash: str):
        """パスワード履歴に追加"""
        if user_id not in self.password_history:
            self.password_history[user_id] = []
            
        import time
        self.password_history[user_id].append({
            'hash': password_hash,
            'timestamp': time.time()
        })
        
        # 履歴サイズ制限
        if len(self.password_history[user_id]) > self.config.password_history_size * 2:
            self.password_history[user_id] = self.password_history[user_id][-self.config.password_history_size:]