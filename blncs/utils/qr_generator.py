"""
BLNCS QRコード生成モジュール
Lightning Networkインボイス用のQRコード生成（軽量実装）。
"""

from typing import Optional
from pathlib import Path

from ..core.logger import get_logger


class QRGenerator:
    """QRコード生成（ASCII実装）"""
    
    def __init__(self):
        self.logger = get_logger(__name__)
        self.qrcode_available = False
        
        # オプション依存関係をチェック
        try:
            import qrcode
            self.qrcode_available = True
            self.qrcode = qrcode
            self.logger.debug("qrcodeライブラリが利用可能")
        except ImportError:
            self.logger.warning("qrcodeライブラリが見つかりません。ASCII QRコードを使用します")
    
    def generate_ascii_qr(self, data: str) -> str:
        """ASCII文字でQRコードを生成（簡易版）"""
        # 簡易的なASCII表現（実際のQRコードではない）
        border = "█" * (len(data) // 2 + 4)
        padding = "█" + " " * (len(data) // 2 + 2) + "█"
        
        lines = []
        lines.append(border)
        lines.append(padding)
        
        # データを複数行に分割
        chunk_size = max(10, len(data) // 5)
        for i in range(0, len(data), chunk_size):
            chunk = data[i:i+chunk_size]
            # 簡易的なパターン化
            pattern = ""
            for char in chunk:
                if ord(char) % 2 == 0:
                    pattern += "▓"
                else:
                    pattern += "░"
            
            line = "█ " + pattern.center(len(data) // 2) + " █"
            lines.append(line)
        
        lines.append(padding)
        lines.append(border)
        
        # データ表示
        lines.append("")
        lines.append("Lightning Invoice:")
        lines.append(data[:50] + "..." if len(data) > 50 else data)
        
        return "\n".join(lines)
    
    def generate_qr_code(self, data: str, output_file: Optional[str] = None) -> str:
        """QRコードを生成"""
        if self.qrcode_available:
            try:
                # qrcodeライブラリを使用
                qr = self.qrcode.QRCode(
                    version=1,
                    error_correction=self.qrcode.constants.ERROR_CORRECT_L,
                    box_size=10,
                    border=4,
                )
                qr.add_data(data)
                qr.make(fit=True)
                
                if output_file:
                    # 画像ファイルとして保存
                    img = qr.make_image(fill_color="black", back_color="white")
                    img.save(output_file)
                    self.logger.info(f"QRコード画像を保存: {output_file}")
                    return f"QRコード画像: {output_file}"
                else:
                    # ASCII表現を返す
                    import io
                    f = io.StringIO()
                    qr.print_ascii(out=f)
                    f.seek(0)
                    ascii_qr = f.read()
                    return ascii_qr
                    
            except Exception as e:
                self.logger.warning(f"QRコード生成エラー: {e}")
                return self.generate_ascii_qr(data)
        else:
            # フォールバック: ASCII QRコード
            return self.generate_ascii_qr(data)
    
    def generate_invoice_qr(self, invoice: str, save_to_file: bool = False) -> str:
        """Lightning Networkインボイス用QRコード生成"""
        # Lightningインボイスは通常 "lightning:" プレフィックスを付ける
        if not invoice.startswith("lightning:"):
            invoice = f"lightning:{invoice}"
        
        if save_to_file:
            # ファイル名を生成
            from datetime import datetime
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_dir = Path("./qr_codes")
            output_dir.mkdir(exist_ok=True)
            output_file = output_dir / f"invoice_{timestamp}.png"
            
            return self.generate_qr_code(invoice, str(output_file))
        else:
            return self.generate_qr_code(invoice)


# グローバルインスタンス
_global_qr_generator = None

def get_qr_generator() -> QRGenerator:
    """グローバルQRジェネレーターを取得"""
    global _global_qr_generator
    if _global_qr_generator is None:
        _global_qr_generator = QRGenerator()
    return _global_qr_generator

def generate_invoice_qr(invoice: str, save_to_file: bool = False) -> str:
    """インボイスQRコードを生成（簡易インターフェース）"""
    generator = get_qr_generator()
    return generator.generate_invoice_qr(invoice, save_to_file)