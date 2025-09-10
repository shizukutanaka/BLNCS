"""
Enhanced QR Code Generation and Processing Module
Provides QR code functionality with fallback support for missing dependencies.
"""

import base64
import logging
from typing import Optional, Union, Dict, Any, Tuple
from io import BytesIO
from pathlib import Path

# Try to import QR code libraries with fallback
try:
    import qrcode
    from qrcode.image.styledpil import StyledPilImage
    from qrcode.image.styles.moduledrawers import RoundedModuleDrawer, CircleModuleDrawer, SquareModuleDrawer
    from qrcode.image.styles.colorfills import SolidFillColorMask
    QRCODE_AVAILABLE = True
except ImportError:
    QRCODE_AVAILABLE = False

try:
    from PIL import Image, ImageDraw, ImageFont
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

logger = logging.getLogger(__name__)


class QRCodeError(Exception):
    """Custom QR code processing error"""
    pass


class EnhancedQRGenerator:
    """
    Enhanced QR code generator with fallback ASCII representation
    """
    
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # QR code configuration
        self.default_version = 1
        self.default_error_correction = qrcode.constants.ERROR_CORRECT_L if QRCODE_AVAILABLE else 'L'
        self.default_box_size = 10
        self.default_border = 4
        
        self.logger.info(f"QR Generator initialized (qrcode available: {QRCODE_AVAILABLE}, PIL available: {PIL_AVAILABLE})")
    
    def generate_qr_code(self, data: str, format: str = 'PNG', **kwargs) -> Union[bytes, str]:
        """
        Generate QR code for given data
        
        Args:
            data: Data to encode in QR code
            format: Output format ('PNG', 'JPEG', 'ASCII')
            **kwargs: Additional options for QR code generation
        
        Returns:
            QR code as bytes (for image formats) or string (for ASCII)
        """
        if format.upper() == 'ASCII':
            return self._generate_ascii_qr(data, **kwargs)
        
        if not QRCODE_AVAILABLE:
            self.logger.warning("qrcode library not available, falling back to ASCII")
            return self._generate_ascii_qr(data, **kwargs)
        
        try:
            return self._generate_image_qr(data, format, **kwargs)
        except Exception as e:
            self.logger.error(f"Failed to generate image QR code: {e}")
            self.logger.info("Falling back to ASCII QR code")
            return self._generate_ascii_qr(data, **kwargs)
    
    def _generate_image_qr(self, data: str, format: str = 'PNG', **kwargs) -> bytes:
        """Generate QR code as image using qrcode library"""
        # QR code parameters
        version = kwargs.get('version', self.default_version)
        error_correction = kwargs.get('error_correction', self.default_error_correction)
        box_size = kwargs.get('box_size', self.default_box_size)
        border = kwargs.get('border', self.default_border)
        
        # Style parameters
        fill_color = kwargs.get('fill_color', 'black')
        back_color = kwargs.get('back_color', 'white')
        style = kwargs.get('style', 'square')  # square, rounded, circle
        
        # Create QR code instance
        qr = qrcode.QRCode(
            version=version,
            error_correction=error_correction,
            box_size=box_size,
            border=border,
        )
        
        qr.add_data(data)
        qr.make(fit=True)
        
        # Generate image with style
        if style == 'styled' and PIL_AVAILABLE:
            img = self._create_styled_qr(qr, fill_color, back_color, **kwargs)
        else:
            img = qr.make_image(fill_color=fill_color, back_color=back_color)
        
        # Convert to bytes
        buffer = BytesIO()
        img.save(buffer, format=format.upper())
        return buffer.getvalue()
    
    def _create_styled_qr(self, qr, fill_color: str, back_color: str, **kwargs) -> Image.Image:
        """Create styled QR code with custom appearance"""
        style_type = kwargs.get('module_style', 'square')
        
        # Module drawer styles
        module_drawer = SquareModuleDrawer()
        if style_type == 'rounded':
            module_drawer = RoundedModuleDrawer()
        elif style_type == 'circle':
            module_drawer = CircleModuleDrawer()
        
        # Color mask
        color_mask = SolidFillColorMask(
            back_color=back_color,
            front_color=fill_color
        )
        
        img = qr.make_image(
            image_factory=StyledPilImage,
            module_drawer=module_drawer,
            color_mask=color_mask
        )
        
        return img
    
    def _generate_ascii_qr(self, data: str, **kwargs) -> str:
        """Generate ASCII representation of QR code (fallback)"""
        if QRCODE_AVAILABLE:
            try:
                qr = qrcode.QRCode(
                    version=kwargs.get('version', 1),
                    error_correction=kwargs.get('error_correction', qrcode.constants.ERROR_CORRECT_L),
                    box_size=1,
                    border=kwargs.get('border', 2),
                )
                qr.add_data(data)
                qr.make(fit=True)
                
                # Get ASCII representation
                return qr.get_matrix_as_ascii()
            except Exception as e:
                self.logger.error(f"Failed to generate ASCII QR with qrcode: {e}")
        
        # Ultra-simple fallback ASCII representation
        return self._simple_ascii_qr(data, **kwargs)
    
    def _simple_ascii_qr(self, data: str, **kwargs) -> str:
        """Simple ASCII QR code representation (minimal fallback)"""
        width = kwargs.get('width', 25)
        height = kwargs.get('height', 25)
        
        # Create simple pattern based on data hash
        import hashlib
        data_hash = hashlib.md5(data.encode()).hexdigest()
        
        ascii_qr = []
        ascii_qr.append("█" * (width + 4))  # Top border
        ascii_qr.append("█" + " " * (width + 2) + "█")  # Top padding
        
        for i in range(height):
            row = "█ "
            for j in range(width):
                # Use hash to determine pattern
                char_idx = (i * width + j) % len(data_hash)
                if int(data_hash[char_idx], 16) > 7:
                    row += "█"
                else:
                    row += " "
            row += " █"
            ascii_qr.append(row)
        
        ascii_qr.append("█" + " " * (width + 2) + "█")  # Bottom padding
        ascii_qr.append("█" * (width + 4))  # Bottom border
        
        # Add data info
        ascii_qr.append("")
        ascii_qr.append(f"QR Data: {data[:50]}{'...' if len(data) > 50 else ''}")
        ascii_qr.append("Note: Install 'qrcode[pil]' for proper QR codes")
        
        return "\n".join(ascii_qr)
    
    def generate_lightning_invoice_qr(self, invoice: str, **kwargs) -> Union[bytes, str]:
        """Generate QR code for Lightning Network invoice"""
        # Validate invoice format (basic check)
        if not invoice.lower().startswith(('lnbc', 'lntb', 'lnbcrt')):
            raise QRCodeError(f"Invalid Lightning invoice format: {invoice}")
        
        # Add Lightning-specific styling
        kwargs.setdefault('fill_color', '#FF9500')  # Lightning orange
        kwargs.setdefault('back_color', 'white')
        kwargs.setdefault('error_correction', qrcode.constants.ERROR_CORRECT_M if QRCODE_AVAILABLE else 'M')
        
        return self.generate_qr_code(invoice, **kwargs)
    
    def generate_bitcoin_address_qr(self, address: str, amount: Optional[float] = None, 
                                  message: Optional[str] = None, **kwargs) -> Union[bytes, str]:
        """Generate QR code for Bitcoin address (BIP21 format)"""
        # Validate Bitcoin address (basic check)
        if not (address.startswith(('1', '3', 'bc1', 'tb1'))):
            raise QRCodeError(f"Invalid Bitcoin address format: {address}")
        
        # Create BIP21 URI
        uri = f"bitcoin:{address}"
        params = []
        
        if amount is not None:
            params.append(f"amount={amount}")
        if message:
            params.append(f"message={message}")
        
        if params:
            uri += "?" + "&".join(params)
        
        # Bitcoin-specific styling
        kwargs.setdefault('fill_color', '#F7931A')  # Bitcoin orange
        kwargs.setdefault('back_color', 'white')
        kwargs.setdefault('error_correction', qrcode.constants.ERROR_CORRECT_M if QRCODE_AVAILABLE else 'M')
        
        return self.generate_qr_code(uri, **kwargs)
    
    def save_qr_to_file(self, data: str, file_path: Union[str, Path], format: str = 'PNG', **kwargs) -> bool:
        """Save QR code to file"""
        try:
            file_path = Path(file_path)
            file_path.parent.mkdir(parents=True, exist_ok=True)
            
            qr_data = self.generate_qr_code(data, format=format, **kwargs)
            
            if format.upper() == 'ASCII':
                # Save ASCII as text file
                with open(file_path, 'w') as f:
                    f.write(qr_data)
            else:
                # Save image as binary
                with open(file_path, 'wb') as f:
                    f.write(qr_data)
            
            self.logger.info(f"QR code saved to {file_path}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to save QR code to {file_path}: {e}")
            return False
    
    def get_qr_as_base64(self, data: str, format: str = 'PNG', **kwargs) -> str:
        """Get QR code as base64 encoded string"""
        try:
            if format.upper() == 'ASCII':
                # For ASCII, just return the string
                return self.generate_qr_code(data, format=format, **kwargs)
            
            qr_bytes = self.generate_qr_code(data, format=format, **kwargs)
            return base64.b64encode(qr_bytes).decode('utf-8')
        except Exception as e:
            self.logger.error(f"Failed to generate base64 QR code: {e}")
            return f"QR generation failed: {e}"
    
    def create_batch_qr_codes(self, data_list: list, output_dir: Union[str, Path], 
                            format: str = 'PNG', **kwargs) -> Dict[str, bool]:
        """Create multiple QR codes in batch"""
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        results = {}
        
        for i, data in enumerate(data_list):
            try:
                # Generate filename
                safe_data = data.replace('/', '_').replace(':', '_')[:30]
                filename = f"qr_{i:03d}_{safe_data}.{format.lower()}"
                file_path = output_dir / filename
                
                # Generate and save QR code
                success = self.save_qr_to_file(data, file_path, format=format, **kwargs)
                results[data] = success
                
            except Exception as e:
                self.logger.error(f"Failed to create QR code for {data}: {e}")
                results[data] = False
        
        return results
    
    def get_qr_info(self, data: str) -> Dict[str, Any]:
        """Get information about what QR code would be generated"""
        info = {
            'data': data,
            'data_length': len(data),
            'data_type': self._detect_data_type(data),
            'qrcode_available': QRCODE_AVAILABLE,
            'pil_available': PIL_AVAILABLE
        }
        
        if QRCODE_AVAILABLE:
            try:
                # Determine optimal QR version
                qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_L)
                qr.add_data(data)
                qr.make(fit=True)
                
                info.update({
                    'qr_version': qr.version,
                    'error_correction': 'L',
                    'estimated_size': f"{21 + (qr.version - 1) * 4}x{21 + (qr.version - 1) * 4}",
                    'capacity_used_percent': (len(data) / 2953) * 100  # Approximate for version 40
                })
            except Exception as e:
                info['qr_error'] = str(e)
        
        return info
    
    def _detect_data_type(self, data: str) -> str:
        """Detect the type of data for QR code optimization"""
        data_lower = data.lower()
        
        if data_lower.startswith(('http://', 'https://')):
            return 'url'
        elif data_lower.startswith(('lnbc', 'lntb', 'lnbcrt')):
            return 'lightning_invoice'
        elif data_lower.startswith('bitcoin:'):
            return 'bitcoin_uri'
        elif data_lower.startswith(('1', '3', 'bc1', 'tb1')):
            return 'bitcoin_address'
        elif '@' in data and '.' in data:
            return 'email'
        elif data.startswith('tel:'):
            return 'telephone'
        elif data.startswith('sms:'):
            return 'sms'
        elif data.startswith('wifi:'):
            return 'wifi'
        else:
            return 'text'


# Global QR generator instance
_qr_generator = None

def get_qr_generator() -> EnhancedQRGenerator:
    """Get global QR generator instance"""
    global _qr_generator
    if _qr_generator is None:
        _qr_generator = EnhancedQRGenerator()
    return _qr_generator


# Convenience functions
def generate_qr_code(data: str, format: str = 'PNG', **kwargs) -> Union[bytes, str]:
    """Generate QR code (convenience function)"""
    return get_qr_generator().generate_qr_code(data, format, **kwargs)

def generate_lightning_qr(invoice: str, **kwargs) -> Union[bytes, str]:
    """Generate Lightning invoice QR code (convenience function)"""
    return get_qr_generator().generate_lightning_invoice_qr(invoice, **kwargs)

def generate_bitcoin_qr(address: str, amount: Optional[float] = None, **kwargs) -> Union[bytes, str]:
    """Generate Bitcoin address QR code (convenience function)"""
    return get_qr_generator().generate_bitcoin_address_qr(address, amount, **kwargs)

def save_qr_to_file(data: str, file_path: Union[str, Path], **kwargs) -> bool:
    """Save QR code to file (convenience function)"""
    return get_qr_generator().save_qr_to_file(data, file_path, **kwargs)


# Export commonly used functions
__all__ = [
    'EnhancedQRGenerator',
    'QRCodeError',
    'get_qr_generator',
    'generate_qr_code',
    'generate_lightning_qr',
    'generate_bitcoin_qr',
    'save_qr_to_file',
    'QRCODE_AVAILABLE',
    'PIL_AVAILABLE'
]