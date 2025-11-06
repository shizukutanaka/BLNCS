"""
Lightning Payment Manager
実用的な支払い管理機能
"""

import time
import json
import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class PaymentRecord:
    """支払い記録"""
    payment_hash: str
    payment_request: str
    amount: int
    status: str  # 'pending', 'succeeded', 'failed'
    type: str    # 'invoice', 'payment'
    memo: str = ""
    fees: int = 0
    created_at: float = 0
    settled_at: Optional[float] = None

    def __post_init__(self):
        if self.created_at == 0:
            self.created_at = time.time()


class PaymentManager:
    """支払い管理システム"""

    def __init__(self, data_dir: str = "data"):
        self.data_dir = data_dir
        self.payments: Dict[str, PaymentRecord] = {}
        self.load_payments()

    def load_payments(self):
        """支払い履歴読み込み"""
        try:
            import os
            payments_file = os.path.join(self.data_dir, "payments.json")
            if os.path.exists(payments_file):
                with open(payments_file, 'r') as f:
                    data = json.load(f)
                    for payment_hash, payment_data in data.items():
                        self.payments[payment_hash] = PaymentRecord(**payment_data)
                logger.info(f"Loaded {len(self.payments)} payments")
        except Exception as e:
            logger.error(f"Failed to load payments: {e}")

    def save_payments(self):
        """支払い履歴保存"""
        try:
            import os
            os.makedirs(self.data_dir, exist_ok=True)
            payments_file = os.path.join(self.data_dir, "payments.json")
            data = {hash: asdict(payment) for hash, payment in self.payments.items()}
            with open(payments_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save payments: {e}")

    def add_payment(self, payment: PaymentRecord):
        """支払い記録追加"""
        self.payments[payment.payment_hash] = payment
        self.save_payments()
        logger.info(f"Added payment: {payment.payment_hash[:8]}...")

    def get_payment(self, payment_hash: str) -> Optional[PaymentRecord]:
        """支払い記録取得"""
        return self.payments.get(payment_hash)

    def list_payments(self, limit: int = 100, payment_type: Optional[str] = None) -> List[PaymentRecord]:
        """支払い一覧取得"""
        payments = list(self.payments.values())

        if payment_type:
            payments = [p for p in payments if p.type == payment_type]

        # Sort by created_at descending
        payments.sort(key=lambda x: x.created_at, reverse=True)

        return payments[:limit]

    def get_payment_stats(self) -> Dict[str, Any]:
        """支払い統計取得"""
        total_count = len(self.payments)
        invoices = [p for p in self.payments.values() if p.type == 'invoice']
        payments = [p for p in self.payments.values() if p.type == 'payment']

        succeeded_payments = [p for p in payments if p.status == 'succeeded']
        total_sent = sum(p.amount for p in succeeded_payments)
        total_fees = sum(p.fees for p in succeeded_payments)

        succeeded_invoices = [p for p in invoices if p.status == 'succeeded']
        total_received = sum(p.amount for p in succeeded_invoices)

        return {
            'total_payments': total_count,
            'total_invoices': len(invoices),
            'total_sent': len(payments),
            'total_sent_amount': total_sent,
            'total_received_amount': total_received,
            'total_fees_paid': total_fees,
            'success_rate': len(succeeded_payments) / len(payments) if payments else 0
        }

    def search_payments(self, query: str) -> List[PaymentRecord]:
        """支払い検索"""
        results = []
        query_lower = query.lower()

        for payment in self.payments.values():
            if (query_lower in payment.memo.lower() or
                query_lower in payment.payment_hash.lower() or
                query_lower in payment.payment_request.lower()):
                results.append(payment)

        return sorted(results, key=lambda x: x.created_at, reverse=True)


# Global instance
_payment_manager = None

def get_payment_manager() -> PaymentManager:
    """Get global payment manager instance"""
    global _payment_manager
    if _payment_manager is None:
        _payment_manager = PaymentManager()
    return _payment_manager