"""
Advanced Security Framework for BLNCS Enterprise
Practical zero-trust enforcement, key rotation, and adaptive anomaly detection
"""

import base64
import binascii
import hashlib
import hmac
import json
import logging
import secrets
import threading
import time
from collections import defaultdict, deque
from statistics import StatisticsError, mean, pstdev
from typing import Any, Deque, Dict, Iterable, List, Optional, Tuple

logger = logging.getLogger(__name__)


class KeyRotationManager:
    """Lightweight HMAC key rotation utility for token signing."""

    def __init__(self, rotation_interval: int = 86400, history_size: int = 5):
        self.rotation_interval = max(300, rotation_interval)
        self.history_size = max(1, history_size)
        self._active_key = self._generate_key()
        self._previous_keys: Deque[bytes] = deque(maxlen=self.history_size)
        self._last_rotation = time.time()
        self._lock = threading.Lock()

    def _generate_key(self) -> bytes:
        return secrets.token_bytes(32)

    def _rotate_if_needed(self) -> None:
        if time.time() - self._last_rotation < self.rotation_interval:
            return
        with self._lock:
            if time.time() - self._last_rotation < self.rotation_interval:
                return
            self._previous_keys.appendleft(self._active_key)
            self._active_key = self._generate_key()
            self._last_rotation = time.time()
            logger.info("Rotated HMAC signing key", extra={"extra_fields": {"previous_keys": len(self._previous_keys)}})

    def sign(self, payload: Dict[str, Any]) -> str:
        self._rotate_if_needed()
        body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        signature = hmac.new(self._active_key, body, hashlib.sha256).digest()
        return base64.urlsafe_b64encode(signature).decode("ascii")

    def verify(self, payload: Dict[str, Any], signature: str) -> bool:
        try:
            provided = base64.urlsafe_b64decode(signature.encode("ascii"))
        except (ValueError, binascii.Error):
            return False

        body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")

        def _compare(candidate_key: bytes) -> bool:
            expected = hmac.new(candidate_key, body, hashlib.sha256).digest()
            return hmac.compare_digest(expected, provided)

        if _compare(self._active_key):
            return True

        for key in self._previous_keys:
            if _compare(key):
                return True

        return False


class ZeroTrustManager:
    """Baseline zero-trust decisioning with explicit policy hooks."""

    def __init__(self):
        self.identity_store: Dict[str, Dict[str, Any]] = {}
        self.policies: Dict[str, Dict[str, Any]] = {}
        self.lock = threading.Lock()

    def register_identity(self, user_id: str, attributes: Dict[str, Any]) -> None:
        with self.lock:
            self.identity_store[user_id] = {
                "attributes": attributes,
                "trust_score": 0.5,
                "last_seen": time.time()
            }

    def upsert_policy(self, resource: str, policy: Dict[str, Any]) -> None:
        with self.lock:
            self.policies[resource] = policy

    def evaluate(self, user_id: str, resource: str, action: str, context: Dict[str, Any]) -> Tuple[bool, str]:
        with self.lock:
            identity = self.identity_store.get(user_id)
            if not identity:
                return False, "Identity not registered"

            policy = self.policies.get(resource, {})

            required_scopes: Iterable[str] = policy.get("required_scopes", [])
            user_scopes = identity["attributes"].get("scopes", [])
            missing_scopes = [scope for scope in required_scopes if scope not in user_scopes]
            if missing_scopes:
                return False, f"Missing scopes: {', '.join(missing_scopes)}"

            mfa_required = policy.get("mfa", False)
            if mfa_required and not context.get("mfa_verified", False):
                return False, "MFA verification required"

            ip_allowlist = policy.get("ip_allowlist")
            if ip_allowlist and context.get("ip_address") not in ip_allowlist:
                return False, "Source IP not allowed"

            identity["trust_score"] = min(1.0, identity["trust_score"] + 0.01)
            identity["last_seen"] = time.time()

            return True, "Access granted"


class AdaptiveAnomalyDetector:
    """Statistical anomaly detection without external ML dependencies."""

    METRICS = {
        "request_frequency": {"threshold_multiplier": 3.0, "default": 0.0},
        "error_rate": {"threshold_multiplier": 2.5, "default": 0.0},
        "authentication_failures": {"threshold_multiplier": 2.0, "default": 0.0},
        "payload_size": {"threshold_multiplier": 2.5, "default": 0.0},
        "latency_ms": {"threshold_multiplier": 2.5, "default": 50.0},
    }

    def __init__(self, history: int = 200):
        self.history = max(20, history)
        self.metric_windows: Dict[str, Deque[float]] = {metric: deque(maxlen=self.history) for metric in self.METRICS}
        self.lock = threading.Lock()

    def score_event(self, event: Dict[str, Any]) -> Tuple[float, List[str]]:
        anomalies: List[str] = []
        cumulative_score = 0.0

        with self.lock:
            for metric, config in self.METRICS.items():
                value = float(event.get(metric, config["default"]))
                window = self.metric_windows[metric]

                if window:
                    try:
                        current_mean = mean(window)
                        current_stdev = pstdev(window)
                    except StatisticsError:
                        current_mean = window[-1]
                        current_stdev = 0.0
                else:
                    current_mean = value
                    current_stdev = 0.0

                window.append(value)

                if current_stdev == 0.0:
                    continue

                z_score = abs(value - current_mean) / max(current_stdev, 1e-9)
                threshold = config["threshold_multiplier"]
                if z_score >= threshold:
                    anomalies.append(metric)
                    cumulative_score += min(1.0, z_score / (threshold * 2))

        final_score = min(1.0, cumulative_score)
        return final_score, anomalies


class AdvancedSecurityManager:
    """Coordinated security controls for runtime enforcement."""

    def __init__(self):
        self.key_manager = KeyRotationManager()
        self.zero_trust = ZeroTrustManager()
        self.anomaly_detector = AdaptiveAnomalyDetector()
        self.security_events: Deque[Dict[str, Any]] = deque(maxlen=50000)
        self.lock = threading.Lock()

    def initialize_security(self, config: Optional[Dict[str, Any]] = None) -> None:
        if not config:
            config = {}

        rotation = int(config.get("key_rotation_seconds", 86400))
        history = int(config.get("key_history", 5))
        self.key_manager = KeyRotationManager(rotation_interval=rotation, history_size=history)

        for identity in config.get("bootstrap_identities", []):
            user_id = identity.get("user_id")
            attrs = identity.get("attributes", {})
            if user_id:
                self.zero_trust.register_identity(user_id, attrs)

        for policy in config.get("policies", []):
            resource = policy.get("resource")
            rules = policy.get("rules", {})
            if resource:
                self.zero_trust.upsert_policy(resource, rules)

        logger.info("Advanced security controls initialised", extra={"extra_fields": {"identities": len(self.zero_trust.identity_store), "policies": len(self.zero_trust.policies)}})

    def process_security_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        event = dict(event)
        event.setdefault("timestamp", time.time())

        anomaly_score, anomaly_metrics = self.anomaly_detector.score_event(event)

        access_granted = True
        access_reason = "No policy evaluation"
        if all(key in event for key in ("user_id", "resource", "action")):
            access_granted, access_reason = self.zero_trust.evaluate(
                event["user_id"], event["resource"], event["action"], event
            )

        risk_score = self._calculate_risk_score(event, anomaly_score, anomaly_metrics, access_granted)
        recommendations = self._generate_recommendations(event, anomaly_score, anomaly_metrics, access_granted)

        assessment = {
            "event_id": f"sec_{int(time.time())}_{secrets.token_hex(4)}",
            "timestamp": event["timestamp"],
            "anomaly_score": anomaly_score,
            "anomaly_metrics": anomaly_metrics,
            "access_granted": access_granted,
            "access_reason": access_reason,
            "risk_score": risk_score,
            "recommendations": recommendations,
        }

        with self.lock:
            self.security_events.append({**event, **assessment})

        if risk_score >= 0.7:
            logger.warning(
                "High risk event detected",
                extra={"extra_fields": {"event_id": assessment["event_id"], "metrics": anomaly_metrics, "risk_score": risk_score}}
            )

        return assessment

    def sign_payload(self, payload: Dict[str, Any]) -> str:
        return self.key_manager.sign(payload)

    def verify_payload(self, payload: Dict[str, Any], signature: str) -> bool:
        return self.key_manager.verify(payload, signature)

    def get_security_dashboard(self) -> Dict[str, Any]:
        with self.lock:
            recent_events = list(self.security_events)[-200:]

        total_events = len(recent_events)
        high_risk_events = sum(1 for e in recent_events if e.get("risk_score", 0.0) >= 0.7)
        denied_events = sum(1 for e in recent_events if not e.get("access_granted", True))

        metric_counts: Dict[str, int] = defaultdict(int)
        for event in recent_events:
            for metric in event.get("anomaly_metrics", []):
                metric_counts[metric] += 1

        return {
            "summary": {
                "total_events": total_events,
                "high_risk_events": high_risk_events,
                "denied_events": denied_events,
            },
            "frequent_anomalies": dict(sorted(metric_counts.items(), key=lambda item: item[1], reverse=True)),
            "recent_events": recent_events[-10:],
        }

    def _calculate_risk_score(
        self,
        event: Dict[str, Any],
        anomaly_score: float,
        anomaly_metrics: List[str],
        access_granted: bool,
    ) -> float:
        score = anomaly_score * 0.6

        severity_weights = {
            "authentication_failures": 0.2,
            "error_rate": 0.2,
            "payload_size": 0.15,
            "request_frequency": 0.25,
            "latency_ms": 0.1,
        }

        for metric in anomaly_metrics:
            score += severity_weights.get(metric, 0.05)

        if not access_granted:
            score += 0.2

        event_type_weights = {
            "authentication_failure": 0.25,
            "privilege_escalation": 0.3,
            "data_access": 0.15,
        }
        score += event_type_weights.get(event.get("event_type"), 0.0)

        return min(1.0, score)

    def _generate_recommendations(
        self,
        event: Dict[str, Any],
        anomaly_score: float,
        anomaly_metrics: List[str],
        access_granted: bool,
    ) -> List[str]:
        recommendations: List[str] = []

        if anomaly_score >= 0.7:
            recommendations.append("Initiate incident response workflow")
        elif anomaly_score >= 0.4:
            recommendations.append("Increase monitoring for source identity")

        if "authentication_failures" in anomaly_metrics or event.get("authentication_failures", 0) >= 5:
            recommendations.append("Evaluate account lockout policies")

        if "request_frequency" in anomaly_metrics:
            recommendations.append("Review rate limiting configuration")

        if not access_granted:
            recommendations.append("Notify security team of denied access attempt")

        if not recommendations:
            recommendations.append("No immediate action required")

        return recommendations


advanced_security = AdvancedSecurityManager()


def init_advanced_security(config: Optional[Dict[str, Any]] = None) -> None:
    advanced_security.initialize_security(config)


def process_security_event(event: Dict[str, Any]) -> Dict[str, Any]:
    return advanced_security.process_security_event(event)


def get_security_dashboard() -> Dict[str, Any]:
    return advanced_security.get_security_dashboard()
