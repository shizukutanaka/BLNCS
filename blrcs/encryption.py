# BLRCS Encryption Module
# AES-256-GCM encryption for sensitive data
import os
import json
import base64
from pathlib import Path
from typing import Optional, Union, Dict, Any
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
from cryptography.hazmat.backends import default_backend
import secrets

class DataEncryptor:
    """
    Secure data encryption using AES-256-GCM.
    Following security best practices.
    """
    
    def __init__(self, key: Optional[bytes] = None, password: Optional[str] = None):
        """
        Initialize encryptor with key or password.
        
        Args:
            key: 32-byte encryption key
            password: Password to derive key from
        """
        if key:
            self.key = key
        elif password:
            self.key = self._derive_key(password)
        else:
            # Generate random key
            self.key = secrets.token_bytes(32)
        
        self.backend = default_backend()
    
    def _derive_key(self, password: str, salt: Optional[bytes] = None) -> bytes:
        """Derive encryption key from password using PBKDF2"""
        if salt is None:
            salt = secrets.token_bytes(16)
        
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=self.backend
        )
        
        return kdf.derive(password.encode())
    
    def encrypt(self, data: Union[str, bytes, dict]) -> Dict[str, str]:
        """
        Encrypt data using AES-256-GCM.
        
        Args:
            data: Data to encrypt (string, bytes, or dict)
            
        Returns:
            Dictionary with encrypted data and metadata
        """
        # Convert data to bytes
        if isinstance(data, str):
            plaintext = data.encode('utf-8')
        elif isinstance(data, dict):
            plaintext = json.dumps(data).encode('utf-8')
        else:
            plaintext = data
        
        # Generate nonce
        nonce = secrets.token_bytes(12)
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.GCM(nonce),
            backend=self.backend
        )
        
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        
        # Return encrypted data with metadata
        return {
            'ciphertext': base64.b64encode(ciphertext).decode('ascii'),
            'nonce': base64.b64encode(nonce).decode('ascii'),
            'tag': base64.b64encode(encryptor.tag).decode('ascii'),
            'algorithm': 'AES-256-GCM'
        }
    
    def decrypt(self, encrypted_data: Dict[str, str]) -> Union[str, bytes]:
        """
        Decrypt data encrypted with AES-256-GCM.
        
        Args:
            encrypted_data: Dictionary with encrypted data and metadata
            
        Returns:
            Decrypted data
        """
        # Decode from base64
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])
        nonce = base64.b64decode(encrypted_data['nonce'])
        tag = base64.b64decode(encrypted_data['tag'])
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.GCM(nonce, tag),
            backend=self.backend
        )
        
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Try to decode as UTF-8 string
        try:
            return plaintext.decode('utf-8')
        except UnicodeDecodeError:
            return plaintext
    
    def encrypt_file(self, file_path: Path, output_path: Optional[Path] = None) -> Path:
        """Encrypt a file"""
        file_path = Path(file_path)
        
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        # Read file
        with open(file_path, 'rb') as f:
            data = f.read()
        
        # Encrypt
        encrypted = self.encrypt(data)
        
        # Save encrypted file
        if output_path is None:
            output_path = file_path.with_suffix(file_path.suffix + '.enc')
        
        with open(output_path, 'w') as f:
            json.dump(encrypted, f)
        
        return output_path
    
    def decrypt_file(self, file_path: Path, output_path: Optional[Path] = None) -> Path:
        """Decrypt a file"""
        file_path = Path(file_path)
        
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        # Read encrypted file
        with open(file_path, 'r') as f:
            encrypted = json.load(f)
        
        # Decrypt
        data = self.decrypt(encrypted)
        
        # Save decrypted file
        if output_path is None:
            output_path = file_path.with_suffix('')
        
        mode = 'wb' if isinstance(data, bytes) else 'w'
        with open(output_path, mode) as f:
            f.write(data)
        
        return output_path
    
    def save_key(self, key_path: Path):
        """Save encryption key to file (be careful with this!)"""
        key_path = Path(key_path)
        key_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Save with restricted permissions
        with open(key_path, 'wb') as f:
            f.write(self.key)
        
        # Set file permissions to 600 (owner read/write only)
        if os.name != 'nt':  # Unix-like systems
            os.chmod(key_path, 0o600)
    
    @classmethod
    def load_key(cls, key_path: Path) -> 'DataEncryptor':
        """Load encryption key from file"""
        key_path = Path(key_path)
        
        if not key_path.exists():
            raise FileNotFoundError(f"Key file not found: {key_path}")
        
        with open(key_path, 'rb') as f:
            key = f.read()
        
        return cls(key=key)

class SecureStorage:
    """
    Secure storage for sensitive configuration and data.
    Encrypts data at rest.
    """
    
    def __init__(self, storage_path: Path = Path("data/secure"), 
                 password: Optional[str] = None):
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)
        
        # Initialize encryptor
        key_file = self.storage_path / '.key'
        
        if key_file.exists():
            self.encryptor = DataEncryptor.load_key(key_file)
        else:
            self.encryptor = DataEncryptor(password=password)
            self.encryptor.save_key(key_file)
    
    def store(self, key: str, value: Any) -> bool:
        """Store encrypted value"""
        try:
            # Encrypt value
            encrypted = self.encryptor.encrypt(value)
            
            # Save to file
            file_path = self.storage_path / f"{key}.enc"
            with open(file_path, 'w') as f:
                json.dump(encrypted, f)
            
            return True
        except Exception:
            return False
    
    def retrieve(self, key: str) -> Optional[Any]:
        """Retrieve and decrypt value"""
        file_path = self.storage_path / f"{key}.enc"
        
        if not file_path.exists():
            return None
        
        try:
            # Read encrypted file
            with open(file_path, 'r') as f:
                encrypted = json.load(f)
            
            # Decrypt
            value = self.encryptor.decrypt(encrypted)
            
            # Try to parse as JSON
            try:
                return json.loads(value)
            except (json.JSONDecodeError, TypeError):
                return value
        
        except Exception:
            return None
    
    def delete(self, key: str) -> bool:
        """Delete stored value"""
        file_path = self.storage_path / f"{key}.enc"
        
        if file_path.exists():
            file_path.unlink()
            return True
        
        return False
    
    def list_keys(self) -> list:
        """List all stored keys"""
        keys = []
        
        for file_path in self.storage_path.glob("*.enc"):
            key = file_path.stem
            if not key.startswith('.'):
                keys.append(key)
        
        return keys

# Global secure storage instance
_secure_storage: Optional[SecureStorage] = None

def get_secure_storage(password: Optional[str] = None) -> SecureStorage:
    """Get global secure storage instance"""
    global _secure_storage
    
    if _secure_storage is None:
        # Try to get password from environment if not provided
        if password is None:
            password = os.environ.get('BLRCS_ENCRYPTION_PASSWORD')
        
        _secure_storage = SecureStorage(password=password)
    
    return _secure_storage

# Utility functions
def encrypt_string(text: str, password: str) -> str:
    """Quick function to encrypt a string"""
    encryptor = DataEncryptor(password=password)
    encrypted = encryptor.encrypt(text)
    return base64.b64encode(json.dumps(encrypted).encode()).decode()

def decrypt_string(encrypted_text: str, password: str) -> str:
    """Quick function to decrypt a string"""
    encryptor = DataEncryptor(password=password)
    encrypted = json.loads(base64.b64decode(encrypted_text))
    return encryptor.decrypt(encrypted)