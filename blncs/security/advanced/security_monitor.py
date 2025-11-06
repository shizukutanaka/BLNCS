"""
Advanced Security Monitoring System for BLNCS

This module provides comprehensive security monitoring including:
- Threat detection and analysis
- Compliance evaluation and reporting
- Risk assessment and mitigation
- Real-time security alerting
"""

import time
import json
import logging
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import threading
import hashlib
import hmac
from collections import defaultdict, deque
import ipaddress
import re
from datetime import datetime, timedelta

class SecurityLevel(Enum):
    """Security threat levels."""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

class ThreatType(Enum):
    """Types of security threats."""
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    MALWARE_DETECTION = "malware_detection"
    DATA_BREACH = "data_breach"
    NETWORK_ATTACK = "network_attack"
    CONFIGURATION_DRIFT = "configuration_drift"
    COMPLIANCE_VIOLATION = "compliance_violation"

@dataclass
class SecurityAlert:
    """Security alert data structure."""
    id: str
    timestamp: float
    threat_type: ThreatType
    severity: SecurityLevel
    title: str
    description: str
    source_ip: str
    affected_systems: List[str]
    indicators: Dict[str, Any]
    recommendations: List[str]
    status: str = "active"  # active, investigating, resolved, false_positive
    assigned_to: Optional[str] = None
    resolved_at: Optional[float] = None
    resolution_notes: Optional[str] = None

@dataclass
class ComplianceRule:
    """Compliance rule definition."""
    id: str
    name: str
    description: str
    category: str  # GDPR, HIPAA, PCI-DSS, etc.
    requirements: List[str]
    automated_checks: List[str]
    manual_checks: List[str]
    remediation_steps: List[str]
    last_evaluation: Optional[float] = None
    compliance_status: str = "unknown"  # compliant, non_compliant, partial, unknown

@dataclass
class RiskAssessment:
    """Risk assessment data structure."""
    id: str
    timestamp: float
    assessment_type: str  # vulnerability, threat, impact, likelihood
    target_system: str
    risk_score: float  # 0.0 to 1.0
    risk_factors: Dict[str, float]
    mitigation_strategies: List[str]
    next_review_date: Optional[float] = None

class ThreatDetector:
    """Advanced threat detection engine."""

    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.ThreatDetector")
        self.detection_rules = {}
        self.threat_patterns = {}
        self.suspicious_activities = defaultdict(list)
        self._load_detection_rules()

    def _load_detection_rules(self):
        """Load threat detection rules."""
        self.detection_rules = {
            'brute_force': {
                'pattern': r'Failed login attempts: (\d+)',
                'threshold': 5,
                'window': 300,  # 5 minutes
                'severity': SecurityLevel.HIGH
            },
            'unusual_access': {
                'pattern': r'Access from unusual location',
                'threshold': 1,
                'window': 60,
                'severity': SecurityLevel.MEDIUM
            },
            'data_exfiltration': {
                'pattern': r'Large data transfer to external IP',
                'threshold': 1000000,  # 1MB
                'window': 60,
                'severity': SecurityLevel.CRITICAL
            }
        }

    def analyze_log_entry(self, log_entry: Dict[str, Any]) -> Optional[SecurityAlert]:
        """Analyze a log entry for threats."""
        message = log_entry.get('message', '')
        source_ip = log_entry.get('source_ip', 'unknown')
        timestamp = log_entry.get('timestamp', time.time())

        for rule_name, rule in self.detection_rules.items():
            if self._matches_rule(message, rule):
                if self._exceeds_threshold(source_ip, rule_name, timestamp, rule):
                    return self._create_alert(rule_name, rule, log_entry)

        return None

    def _matches_rule(self, message: str, rule: Dict[str, Any]) -> bool:
        """Check if message matches detection rule."""
        pattern = rule.get('pattern', '')
        try:
            return bool(re.search(pattern, message, re.IGNORECASE))
        except re.error:
            return False

    def _exceeds_threshold(self, source_ip: str, rule_name: str, timestamp: float, rule: Dict[str, Any]) -> bool:
        """Check if activity exceeds threshold."""
        threshold = rule.get('threshold', 1)
        window = rule.get('window', 60)

        # Clean old entries
        current_time = time.time()
        self.suspicious_activities[rule_name] = [
            (ip, ts) for ip, ts in self.suspicious_activities[rule_name]
            if current_time - ts < window
        ]

        # Count recent activities for this IP and rule
        count = sum(1 for ip, ts in self.suspicious_activities[rule_name]
                   if ip == source_ip and current_time - ts < window)

        return count >= threshold

    def _create_alert(self, rule_name: str, rule: Dict[str, Any], log_entry: Dict[str, Any]) -> SecurityAlert:
        """Create a security alert."""
        alert_id = f"alert_{int(time.time())}_{hashlib.md5(rule_name.encode()).hexdigest()[:8]}"

        return SecurityAlert(
            id=alert_id,
            timestamp=time.time(),
            threat_type=ThreatType.SUSPICIOUS_ACTIVITY,
            severity=rule.get('severity', SecurityLevel.MEDIUM),
            title=f"Security Alert: {rule_name.replace('_', ' ').title()}",
            description=f"Detected {rule_name} activity in log entry",
            source_ip=log_entry.get('source_ip', 'unknown'),
            affected_systems=[log_entry.get('system', 'unknown')],
            indicators={'rule': rule_name, 'log_entry': log_entry},
            recommendations=self._get_recommendations(rule_name)
        )

    def _get_recommendations(self, rule_name: str) -> List[str]:
        """Get remediation recommendations for threat."""
        recommendations = {
            'brute_force': [
                'Block the source IP address',
                'Implement rate limiting',
                'Review authentication mechanisms',
                'Enable two-factor authentication'
            ],
            'unusual_access': [
                'Verify user identity and location',
                'Check for VPN or proxy usage',
                'Review access logs for patterns',
                'Update geo-blocking rules'
            ],
            'data_exfiltration': [
                'Isolate affected systems',
                'Review data access logs',
                'Implement data loss prevention (DLP)',
                'Conduct forensic analysis'
            ]
        }
        return recommendations.get(rule_name, ['Review and investigate the activity'])

class ComplianceEvaluator:
    """Compliance evaluation and reporting system."""

    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.ComplianceEvaluator")
        self.compliance_rules = []
        self.evaluation_history = deque(maxlen=1000)
        self._load_compliance_rules()

    def _load_compliance_rules(self):
        """Load compliance rules and requirements."""
        self.compliance_rules = [
            ComplianceRule(
                id="gdpr_data_protection",
                name="GDPR Data Protection",
                description="Ensure compliance with GDPR data protection requirements",
                category="GDPR",
                requirements=[
                    "Data encryption at rest and in transit",
                    "Data minimization principles",
                    "User consent management",
                    "Data subject rights implementation"
                ],
                automated_checks=[
                    "Check encryption status",
                    "Validate data retention policies",
                    "Audit consent records"
                ],
                manual_checks=[
                    "Privacy impact assessment",
                    "Data processing agreement review"
                ],
                remediation_steps=[
                    "Implement end-to-end encryption",
                    "Update data retention schedules",
                    "Train staff on GDPR compliance"
                ]
            ),
            ComplianceRule(
                id="pci_dss_security",
                name="PCI DSS Security Standards",
                description="Payment Card Industry Data Security Standard compliance",
                category="PCI-DSS",
                requirements=[
                    "Network security controls",
                    "Vulnerability management",
                    "Access control measures",
                    "Regular security testing"
                ],
                automated_checks=[
                    "Firewall configuration validation",
                    "Vulnerability scan execution",
                    "Access log analysis"
                ],
                manual_checks=[
                    "Annual penetration testing",
                    "Security policy review"
                ],
                remediation_steps=[
                    "Update firewall rules",
                    "Patch management implementation",
                    "Access control audit"
                ]
            )
        ]

    def evaluate_compliance(self, rule_id: str = None) -> Dict[str, Any]:
        """Evaluate compliance status."""
        evaluation_results = {}

        rules_to_check = [self.compliance_rules] if rule_id is None else [
            rule for rule in self.compliance_rules if rule.id == rule_id
        ]

        for rule in rules_to_check:
            evaluation = self._evaluate_single_rule(rule)
            evaluation_results[rule.id] = evaluation

            # Store evaluation history
            self.evaluation_history.append({
                'rule_id': rule.id,
                'timestamp': time.time(),
                'result': evaluation
            })

        return evaluation_results

    def _evaluate_single_rule(self, rule: ComplianceRule) -> Dict[str, Any]:
        """Evaluate a single compliance rule."""
        # Simulate compliance evaluation
        # In a real system, this would perform actual checks

        automated_checks_passed = 0
        automated_checks_total = len(rule.automated_checks)

        # Simulate automated checks (replace with actual implementation)
        for check in rule.automated_checks:
            # Simulate check result (80% pass rate for demo)
            if hash(check) % 10 < 8:  # Pseudo-random pass/fail
                automated_checks_passed += 1

        compliance_score = (automated_checks_passed / automated_checks_total) if automated_checks_total > 0 else 0

        if compliance_score >= 0.9:
            status = "compliant"
        elif compliance_score >= 0.7:
            status = "partial"
        else:
            status = "non_compliant"

        return {
            'rule_id': rule.id,
            'rule_name': rule.name,
            'compliance_status': status,
            'compliance_score': compliance_score,
            'automated_checks_passed': automated_checks_passed,
            'automated_checks_total': automated_checks_total,
            'manual_checks_required': len(rule.manual_checks),
            'last_evaluation': time.time(),
            'remediation_required': status != "compliant"
        }

class RiskAssessor:
    """Risk assessment and mitigation system."""

    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.RiskAssessor")
        self.risk_factors = {}
        self.assessment_history = deque(maxlen=1000)
        self._load_risk_factors()

    def _load_risk_factors(self):
        """Load risk assessment factors."""
        self.risk_factors = {
            'authentication_strength': {
                'weight': 0.25,
                'description': 'Strength of authentication mechanisms'
            },
            'network_security': {
                'weight': 0.20,
                'description': 'Network security controls'
            },
            'data_protection': {
                'weight': 0.20,
                'description': 'Data protection measures'
            },
            'access_control': {
                'weight': 0.15,
                'description': 'Access control effectiveness'
            },
            'monitoring_coverage': {
                'weight': 0.10,
                'description': 'Security monitoring coverage'
            },
            'incident_response': {
                'weight': 0.10,
                'description': 'Incident response capabilities'
            }
        }

    def assess_system_risk(self, system_name: str) -> RiskAssessment:
        """Perform comprehensive risk assessment for a system."""
        # Simulate risk assessment
        risk_factors = {}

        for factor_name, factor_info in self.risk_factors.items():
            # Simulate factor score (0.0 to 1.0, higher is better security)
            base_score = 0.8  # Assume good baseline security
            variance = (hash(f"{system_name}_{factor_name}") % 100) / 100.0 * 0.4  # ±20% variance
            score = max(0.0, min(1.0, base_score + variance - 0.2))

            # Convert to risk (lower score = higher risk)
            risk_score = 1.0 - score
            risk_factors[factor_name] = risk_score

        # Calculate overall risk score (weighted average)
        total_weight = sum(factor['weight'] for factor in self.risk_factors.values())
        overall_risk = sum(
            risk_factors[factor] * self.risk_factors[factor]['weight']
            for factor in risk_factors
        ) / total_weight

        # Generate mitigation strategies
        mitigation_strategies = self._generate_mitigation_strategies(risk_factors)

        assessment = RiskAssessment(
            id=f"assessment_{int(time.time())}_{system_name}",
            timestamp=time.time(),
            assessment_type="comprehensive",
            target_system=system_name,
            risk_score=overall_risk,
            risk_factors=risk_factors,
            mitigation_strategies=mitigation_strategies,
            next_review_date=time.time() + (30 * 24 * 60 * 60)  # 30 days
        )

        # Store assessment history
        self.assessment_history.append(asdict(assessment))

        return assessment

    def _generate_mitigation_strategies(self, risk_factors: Dict[str, float]) -> List[str]:
        """Generate risk mitigation strategies."""
        strategies = []

        for factor, risk_score in risk_factors.items():
            if risk_score > 0.7:  # High risk
                if factor == 'authentication_strength':
                    strategies.extend([
                        'Implement multi-factor authentication',
                        'Review and strengthen password policies',
                        'Implement biometric authentication where applicable'
                    ])
                elif factor == 'network_security':
                    strategies.extend([
                        'Deploy next-generation firewalls',
                        'Implement network segmentation',
                        'Regular security audits and penetration testing'
                    ])
                elif factor == 'data_protection':
                    strategies.extend([
                        'Implement end-to-end encryption',
                        'Deploy data loss prevention (DLP) systems',
                        'Regular data classification and handling training'
                    ])

        return strategies if strategies else ['Continue current security practices']

class SecurityMonitor:
    """Main security monitoring system."""

    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.SecurityMonitor")
        self.threat_detector = ThreatDetector()
        self.compliance_evaluator = ComplianceEvaluator()
        self.risk_assessor = RiskAssessor()

        self.alerts: List[SecurityAlert] = []
        self.alert_history = deque(maxlen=10000)
        self.monitoring_active = False
        self.monitoring_thread = None

        # Alert subscribers
        self.alert_subscribers = []

    def start_monitoring(self):
        """Start the security monitoring system."""
        if self.monitoring_active:
            return

        self.monitoring_active = True
        self.monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitoring_thread.start()
        self.logger.info("Security monitoring system started")

    def stop_monitoring(self):
        """Stop the security monitoring system."""
        self.monitoring_active = False
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=5)
        self.logger.info("Security monitoring system stopped")

    def _monitoring_loop(self):
        """Main monitoring loop."""
        while self.monitoring_active:
            try:
                # Perform periodic checks
                self._perform_periodic_checks()

                # Process any queued log entries
                self._process_log_queue()

                time.sleep(60)  # Check every minute

            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}")
                time.sleep(60)

    def _perform_periodic_checks(self):
        """Perform periodic security checks."""
        # Compliance evaluation
        compliance_results = self.compliance_evaluator.evaluate_compliance()

        for rule_id, result in compliance_results.items():
            if result['compliance_status'] == 'non_compliant':
                alert = SecurityAlert(
                    id=f"compliance_{int(time.time())}_{rule_id}",
                    timestamp=time.time(),
                    threat_type=ThreatType.COMPLIANCE_VIOLATION,
                    severity=SecurityLevel.HIGH,
                    title=f"Compliance Violation: {result['rule_name']}",
                    description=f"Compliance score: {result['compliance_score']:.2%}",
                    source_ip='internal',
                    affected_systems=['compliance_system'],
                    indicators={'rule_id': rule_id, 'result': result},
                    recommendations=self.compliance_evaluator.compliance_rules[
                        next(i for i, r in enumerate(self.compliance_evaluator.compliance_rules) if r.id == rule_id)
                    ].remediation_steps
                )
                self._add_alert(alert)

    def _process_log_queue(self):
        """Process queued log entries for threat detection."""
        # In a real system, this would process logs from a queue
        # For demo, we'll simulate log processing
        pass

    def _add_alert(self, alert: SecurityAlert):
        """Add a security alert."""
        self.alerts.append(alert)
        self.alert_history.append(asdict(alert))

        # Notify subscribers
        self._notify_subscribers(alert)

        self.logger.warning(f"Security alert raised: {alert.title}")

    def _notify_subscribers(self, alert: SecurityAlert):
        """Notify alert subscribers."""
        for subscriber in self.alert_subscribers:
            try:
                subscriber(alert)
            except Exception as e:
                self.logger.error(f"Error notifying subscriber: {e}")

    def subscribe_to_alerts(self, callback):
        """Subscribe to security alerts."""
        self.alert_subscribers.append(callback)

    def unsubscribe_from_alerts(self, callback):
        """Unsubscribe from security alerts."""
        if callback in self.alert_subscribers:
            self.alert_subscribers.remove(callback)

    def get_recent_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent security alerts."""
        return [asdict(alert) for alert in self.alerts[-limit:]]

    def resolve_alert(self, alert_id: str, resolution_notes: str, assigned_to: str = None):
        """Resolve a security alert."""
        for alert in self.alerts:
            if alert.id == alert_id:
                alert.status = "resolved"
                alert.resolved_at = time.time()
                alert.resolution_notes = resolution_notes
                alert.assigned_to = assigned_to
                break

    def perform_risk_assessment(self, system_name: str) -> Dict[str, Any]:
        """Perform risk assessment for a system."""
        assessment = self.risk_assessor.assess_system_risk(system_name)
        return asdict(assessment)

    def get_compliance_report(self) -> Dict[str, Any]:
        """Get comprehensive compliance report."""
        return self.compliance_evaluator.evaluate_compliance()

    def get_security_dashboard_data(self) -> Dict[str, Any]:
        """Get data for security dashboard."""
        return {
            'active_alerts': len([a for a in self.alerts if a.status == 'active']),
            'total_alerts': len(self.alerts),
            'threat_types': self._count_threat_types(),
            'severity_distribution': self._count_severity_levels(),
            'recent_activity': self._get_recent_activity(),
            'compliance_status': self._get_compliance_summary(),
            'risk_assessments': len(self.risk_assessor.assessment_history)
        }

    def _count_threat_types(self) -> Dict[str, int]:
        """Count alerts by threat type."""
        counts = defaultdict(int)
        for alert in self.alerts:
            counts[alert.threat_type.value] += 1
        return dict(counts)

    def _count_severity_levels(self) -> Dict[str, int]:
        """Count alerts by severity level."""
        counts = defaultdict(int)
        for alert in self.alerts:
            counts[alert.severity.name] += 1
        return dict(counts)

    def _get_recent_activity(self) -> List[Dict[str, Any]]:
        """Get recent security activity."""
        return [asdict(alert) for alert in self.alerts[-10:]]  # Last 10 alerts

    def _get_compliance_summary(self) -> Dict[str, Any]:
        """Get compliance summary."""
        compliant = 0
        partial = 0
        non_compliant = 0

        for rule in self.compliance_evaluator.compliance_rules:
            status = rule.compliance_status
            if status == 'compliant':
                compliant += 1
            elif status == 'partial':
                partial += 1
            else:
                non_compliant += 1

        return {
            'compliant': compliant,
            'partial': partial,
            'non_compliant': non_compliant,
            'total_rules': len(self.compliance_evaluator.compliance_rules)
        }

def create_security_monitor() -> SecurityMonitor:
    """Factory function to create security monitor."""
    return SecurityMonitor()

# Integration with existing systems
def integrate_security_monitoring(app_or_service):
    """Integrate security monitoring with existing application."""
    monitor = create_security_monitor()

    # Start monitoring
    monitor.start_monitoring()

    # Add alert subscription for logging or notification
    def log_alert(alert: SecurityAlert):
        logger.warning(f"Security Alert: {alert.title} - {alert.description}")

    monitor.subscribe_to_alerts(log_alert)

    return monitor
