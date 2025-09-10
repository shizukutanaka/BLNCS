"""
QR Code Payment System
Handles QR code generation and reading for Lightning Network payments.
"""

import os
import io
import base64
import tempfile
from pathlib import Path
from typing import Dict, Optional, Union, Any
from dataclasses import dataclass
import logging

from .logger import get_logger
from .config_manager import get_config_manager


@dataclass
class QRCodeResult:
    """Result of QR code operation"""
    success: bool
    data: Optional[str] = None
    file_path: Optional[str] = None
    error: Optional[str] = None
    payment_info: Optional[Dict[str, Any]] = None


class QRPaymentManager:
    """QR code payment functionality for Lightning invoices"""
    
    def __init__(self):
        self.logger = get_logger(__name__)
        self.config_manager = get_config_manager()
        
        # Check for required dependencies
        self._qr_available = self._check_qr_dependencies()
        
        # QR code settings
        self.qr_settings = {
            'box_size': 10,
            'border': 4,
            'error_correction': 'M',  # M = ~15% error correction
            'background_color': 'white',
            'fill_color': 'black'
        }
    
    def _check_qr_dependencies(self) -> bool:
        """Check if QR code dependencies are available"""
        try:
            import qrcode
            from PIL import Image
            return True
        except ImportError:
            self.logger.warning("QR code dependencies not available. Install with: pip install qrcode[pil]")
            return False
    
    def generate_invoice_qr(self, 
                          invoice: str, 
                          save_to_file: bool = True,
                          file_path: Optional[str] = None) -> QRCodeResult:
        """
        Generate QR code for Lightning invoice
        
        Args:
            invoice: Lightning invoice string (bolt11)
            save_to_file: Whether to save QR code to file
            file_path: Optional custom file path
            
        Returns:
            QRCodeResult with success status and file information
        """
        if not self._qr_available:
            return self._generate_ascii_qr(invoice, save_to_file, file_path)
        
        try:
            import qrcode
            from qrcode.constants import ERROR_CORRECT_M
            
            # Create QR code instance
            qr = qrcode.QRCode(
                version=1,  # Auto-size
                error_correction=ERROR_CORRECT_M,
                box_size=self.qr_settings['box_size'],
                border=self.qr_settings['border'],
            )
            
            # Add invoice data
            qr.add_data(invoice.upper())  # BOLT11 should be uppercase
            qr.make(fit=True)
            
            # Create image
            qr_image = qr.make_image(
                fill_color=self.qr_settings['fill_color'],
                back_color=self.qr_settings['background_color']
            )
            
            if save_to_file:
                # Determine file path
                if not file_path:
                    timestamp = int(self._get_current_timestamp())
                    filename = f"invoice_qr_{timestamp}.png"
                    qr_dir = Path.home() / ".blncs" / "qr_codes"
                    qr_dir.mkdir(parents=True, exist_ok=True)
                    file_path = str(qr_dir / filename)
                
                # Save image
                qr_image.save(file_path)
                
                self.logger.info(f"QR code saved to: {file_path}")
                return QRCodeResult(
                    success=True,
                    data=invoice,
                    file_path=file_path
                )
            else:
                # Return image data as base64
                img_buffer = io.BytesIO()
                qr_image.save(img_buffer, format='PNG')
                img_data = base64.b64encode(img_buffer.getvalue()).decode()
                
                return QRCodeResult(
                    success=True,
                    data=img_data
                )
                
        except Exception as e:
            self.logger.error(f"Failed to generate QR code: {e}")
            return QRCodeResult(
                success=False,
                error=str(e)
            )
    
    def _generate_ascii_qr(self, 
                          invoice: str, 
                          save_to_file: bool = True,
                          file_path: Optional[str] = None) -> QRCodeResult:
        """Fallback ASCII QR code generation"""
        try:
            import qrcode
            
            qr = qrcode.QRCode()
            qr.add_data(invoice.upper())
            qr.make()
            
            # Generate ASCII art
            ascii_qr = qr.get_matrix()
            ascii_lines = []
            
            for row in ascii_qr:
                line = ''.join('██' if cell else '  ' for cell in row)
                ascii_lines.append(line)
            
            ascii_content = '\n'.join(ascii_lines)
            
            if save_to_file:
                if not file_path:
                    timestamp = int(self._get_current_timestamp())
                    filename = f"invoice_qr_{timestamp}.txt"
                    qr_dir = Path.home() / ".blncs" / "qr_codes"
                    qr_dir.mkdir(parents=True, exist_ok=True)
                    file_path = str(qr_dir / filename)
                
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(ascii_content)
                
                return QRCodeResult(
                    success=True,
                    data=ascii_content,
                    file_path=file_path
                )
            else:
                return QRCodeResult(
                    success=True,
                    data=ascii_content
                )
                
        except Exception as e:
            self.logger.error(f"Failed to generate ASCII QR: {e}")
            return QRCodeResult(
                success=False,
                error=str(e)
            )
    
    def read_qr_code(self, image_path: str) -> QRCodeResult:
        """
        Read QR code from image file
        
        Args:
            image_path: Path to image file containing QR code
            
        Returns:
            QRCodeResult with decoded data and payment information
        """
        if not self._qr_available:
            return QRCodeResult(
                success=False,
                error="QR code reading requires PIL and pyzbar. Install with: pip install qrcode[pil] pyzbar"
            )
        
        try:
            from PIL import Image
            from pyzbar import pyzbar
            
            # Open and process image
            image = Image.open(image_path)
            
            # Decode QR codes
            decoded_objects = pyzbar.decode(image)
            
            if not decoded_objects:
                return QRCodeResult(
                    success=False,
                    error="No QR code found in image"
                )
            
            # Get first QR code
            qr_data = decoded_objects[0].data.decode('utf-8')
            
            # Parse payment information
            payment_info = self._parse_payment_data(qr_data)
            
            return QRCodeResult(
                success=True,
                data=qr_data,
                payment_info=payment_info
            )
            
        except ImportError:
            return QRCodeResult(
                success=False,
                error="QR code reading requires pyzbar. Install with: pip install pyzbar"
            )
        except Exception as e:
            self.logger.error(f"Failed to read QR code: {e}")
            return QRCodeResult(
                success=False,
                error=str(e)
            )
    
    def _parse_payment_data(self, data: str) -> Dict[str, Any]:
        """Parse payment data from QR code"""
        payment_info = {}
        
        # Check if it's a Lightning invoice (BOLT11)
        if data.lower().startswith('ln'):
            payment_info['type'] = 'lightning_invoice'
            payment_info['invoice'] = data
            
            # Try to decode basic invoice information
            try:
                # Simple BOLT11 parsing for amount
                if 'm' in data.lower():
                    # Extract amount in millisats
                    parts = data.lower().split('ln')[1]
                    if 'm' in parts:
                        amount_part = parts.split('m')[0]
                        # Extract numeric part
                        amount_str = ''.join(filter(str.isdigit, amount_part[-10:]))
                        if amount_str:
                            payment_info['amount_msat'] = int(amount_str)
                            payment_info['amount_sat'] = int(amount_str) // 1000
            except Exception:
                pass
        
        # Check if it's a Bitcoin address
        elif len(data) >= 26 and len(data) <= 62:
            # Basic Bitcoin address validation
            if data.startswith(('1', '3', 'bc1', 'tb1')):
                payment_info['type'] = 'bitcoin_address'
                payment_info['address'] = data
        
        # Check if it's a BIP21 URI
        elif data.startswith('bitcoin:'):
            payment_info['type'] = 'bip21_uri'
            payment_info['uri'] = data
            
            # Parse BIP21 URI
            try:
                from urllib.parse import urlparse, parse_qs
                parsed = urlparse(data)
                payment_info['address'] = parsed.path
                
                query_params = parse_qs(parsed.query)
                if 'amount' in query_params:
                    payment_info['amount_btc'] = float(query_params['amount'][0])
                if 'label' in query_params:
                    payment_info['label'] = query_params['label'][0]
                if 'message' in query_params:
                    payment_info['message'] = query_params['message'][0]
            except Exception:
                pass
        
        else:
            payment_info['type'] = 'unknown'
            payment_info['raw_data'] = data
        
        return payment_info
    
    def scan_from_camera(self, timeout: int = 30) -> QRCodeResult:
        """
        Scan QR code from camera (if available)
        
        Args:
            timeout: Timeout in seconds
            
        Returns:
            QRCodeResult with scanned data
        """
        try:
            import cv2
            from pyzbar import pyzbar
            
            # Initialize camera
            cap = cv2.VideoCapture(0)
            if not cap.isOpened():
                return QRCodeResult(
                    success=False,
                    error="Cannot access camera"
                )
            
            self.logger.info("Camera scanning started. Press 'q' to quit.")
            
            import time
            start_time = time.time()
            
            while True:
                # Check timeout
                if time.time() - start_time > timeout:
                    cap.release()
                    cv2.destroyAllWindows()
                    return QRCodeResult(
                        success=False,
                        error="Scan timeout"
                    )
                
                # Capture frame
                ret, frame = cap.read()
                if not ret:
                    continue
                
                # Decode QR codes
                decoded_objects = pyzbar.decode(frame)
                
                for obj in decoded_objects:
                    qr_data = obj.data.decode('utf-8')
                    payment_info = self._parse_payment_data(qr_data)
                    
                    cap.release()
                    cv2.destroyAllWindows()
                    
                    return QRCodeResult(
                        success=True,
                        data=qr_data,
                        payment_info=payment_info
                    )
                
                # Display frame (optional)
                cv2.imshow('QR Code Scanner - Press q to quit', frame)
                
                # Check for quit key
                if cv2.waitKey(1) & 0xFF == ord('q'):
                    break
            
            cap.release()
            cv2.destroyAllWindows()
            
            return QRCodeResult(
                success=False,
                error="Scan cancelled by user"
            )
            
        except ImportError:
            return QRCodeResult(
                success=False,
                error="Camera scanning requires opencv and pyzbar. Install with: pip install opencv-python pyzbar"
            )
        except Exception as e:
            return QRCodeResult(
                success=False,
                error=str(e)
            )
    
    def create_payment_qr(self, 
                         amount_sat: int,
                         memo: str = "",
                         client=None) -> QRCodeResult:
        """
        Create Lightning invoice and generate QR code
        
        Args:
            amount_sat: Amount in satoshis
            memo: Invoice memo/description
            client: Lightning client instance
            
        Returns:
            QRCodeResult with invoice and QR code
        """
        try:
            if not client:
                from ..lightning.client import LightningClient
                client = LightningClient()
            
            # Create invoice
            invoice = client.create_invoice(amount_sat, memo)
            
            if not invoice:
                return QRCodeResult(
                    success=False,
                    error="Failed to create invoice"
                )
            
            # Generate QR code
            qr_result = self.generate_invoice_qr(invoice)
            
            if qr_result.success:
                qr_result.payment_info = {
                    'type': 'lightning_invoice',
                    'invoice': invoice,
                    'amount_sat': amount_sat,
                    'memo': memo
                }
            
            return qr_result
            
        except Exception as e:
            self.logger.error(f"Failed to create payment QR: {e}")
            return QRCodeResult(
                success=False,
                error=str(e)
            )
    
    def _get_current_timestamp(self) -> float:
        """Get current timestamp"""
        import time
        return time.time()
    
    def list_qr_codes(self) -> list:
        """List saved QR code files"""
        try:
            qr_dir = Path.home() / ".blncs" / "qr_codes"
            if not qr_dir.exists():
                return []
            
            qr_files = []
            for file_path in qr_dir.glob("*.png"):
                qr_files.append({
                    'path': str(file_path),
                    'name': file_path.name,
                    'size': file_path.stat().st_size,
                    'created': file_path.stat().st_ctime
                })
            
            # Sort by creation time (newest first)
            qr_files.sort(key=lambda x: x['created'], reverse=True)
            return qr_files
            
        except Exception as e:
            self.logger.error(f"Failed to list QR codes: {e}")
            return []
    
    def cleanup_old_qr_codes(self, max_age_days: int = 7) -> int:
        """Clean up old QR code files"""
        try:
            qr_dir = Path.home() / ".blncs" / "qr_codes"
            if not qr_dir.exists():
                return 0
            
            import time
            current_time = time.time()
            max_age_seconds = max_age_days * 24 * 3600
            
            cleaned_count = 0
            for file_path in qr_dir.glob("*.png"):
                if current_time - file_path.stat().st_ctime > max_age_seconds:
                    file_path.unlink()
                    cleaned_count += 1
            
            self.logger.info(f"Cleaned up {cleaned_count} old QR code files")
            return cleaned_count
            
        except Exception as e:
            self.logger.error(f"Failed to cleanup QR codes: {e}")
            return 0


def get_qr_payment_manager() -> QRPaymentManager:
    """Get singleton QRPaymentManager instance"""
    return QRPaymentManager()