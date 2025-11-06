"""
Real-time Threat Intelligence Framework for BLNCS Enterprise
Provides global threat information sharing, real-time threat detection, and collaborative defense
"""

import time
import threading
import asyncio
from typing import Dict, List, Optional, Any, Callable
from collections import defaultdict, deque
from datetime import datetime, timedelta
import json
import logging
import hashlib
import secrets
import requests
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)

class ThreatType(Enum):
    """Types of security threats"""
    MALWARE = "malware"
    PHISHING = "phishing"
    DDoS = "ddos"
    DATA_BREACH = "data_breach"
    INSIDER_THREAT = "insider_threat"
    SUPPLY_CHAIN = "supply_chain"
    ZERO_DAY = "zero_day"
    APT = "apt"

class ThreatSeverity(Enum):
    """Threat severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class ThreatIntelligence:
    """Threat intelligence data structure"""
    threat_id: str
    threat_type: ThreatType
    severity: ThreatSeverity
    title: str
    description: str
    indicators: List[str]
    affected_systems: List[str]
    mitigation_steps: List[str]
    confidence_score: float
    source: str
    timestamp: float
    expiry_time: float
    tags: List[str]

class ThreatIntelligenceFeed:
    """Threat intelligence feed management"""

    def __init__(self):
        self.feeds = {}
        self.intelligence_data = deque(maxlen=100000)
        self.feed_health = {}
        self.lock = threading.Lock()

    def register_feed(self, feed_name: str, feed_config: Dict[str, Any]):
        """Register threat intelligence feed"""
        self.feeds[feed_name] = {
            'name': feed_name,
            'url': feed_config.get('url', ''),
            'api_key': feed_config.get('api_key', ''),
            'update_interval': feed_config.get('update_interval', 300),  # 5 minutes
            'format': feed_config.get('format', 'json'),
            'last_update': 0,
            'is_active': True
        }

    def update_feeds(self):
        """Update all threat intelligence feeds"""
        for feed_name, feed_config in self.feeds.items():
            if not feed_config['is_active']:
                continue

            current_time = time.time()
            if current_time - feed_config['last_update'] >= feed_config['update_interval']:
                try:
                    self._fetch_feed_data(feed_name, feed_config)
                    feed_config['last_update'] = current_time
                except Exception as e:
                    logger.error(f"Failed to update feed {feed_name}: {e}")
                    self.feed_health[feed_name] = {'status': 'error', 'last_error': str(e)}

    def _fetch_feed_data(self, feed_name: str, feed_config: Dict[str, Any]):
        """Fetch data from threat intelligence feed"""
        try:
            # Simulate API call to threat intelligence feed
            # In production, make actual HTTP requests

            # Mock threat intelligence data
            mock_threats = [
                {
                    'threat_id': f"threat_{secrets.token_hex(8)}",
                    'threat_type': 'malware',
                    'severity': 'high',
                    'title': 'New Ransomware Variant Detected',
                    'description': 'Sophisticated ransomware targeting enterprise systems',
                    'indicators': ['hash:abc123', 'domain:malicious.com'],
                    'affected_systems': ['windows', 'linux'],
                    'mitigation_steps': ['update_signatures', 'backup_data'],
                    'confidence_score': 0.85,
                    'source': feed_name,
                    'timestamp': time.time(),
                    'expiry_time': time.time() + 86400,  # 24 hours
                    'tags': ['ransomware', 'enterprise']
                }
            ]

            with self.lock:
                for threat_data in mock_threats:
                    threat_intel = ThreatIntelligence(
                        threat_id=threat_data['threat_id'],
                        threat_type=ThreatType(threat_data['threat_type']),
                        severity=ThreatSeverity(threat_data['severity']),
                        title=threat_data['title'],
                        description=threat_data['description'],
                        indicators=threat_data['indicators'],
                        affected_systems=threat_data['affected_systems'],
                        mitigation_steps=threat_data['mitigation_steps'],
                        confidence_score=threat_data['confidence_score'],
                        source=threat_data['source'],
                        timestamp=threat_data['timestamp'],
                        expiry_time=threat_data['expiry_time'],
                        tags=threat_data['tags']
                    )

                    self.intelligence_data.append(threat_intel)

            logger.info(f"Updated threat intelligence feed: {feed_name}")

        except Exception as e:
            logger.error(f"Error fetching feed data for {feed_name}: {e}")
            raise

    def query_threats(self, filters: Dict[str, Any] = None) -> List[ThreatIntelligence]:
        """Query threat intelligence data"""
        with self.lock:
            current_time = time.time()
            valid_threats = [
                threat for threat in self.intelligence_data
                if threat.timestamp <= current_time <= threat.expiry_time
            ]

        if not filters:
            return valid_threats

        # Apply filters
        filtered_threats = []

        for threat in valid_threats:
            match = True

            if 'threat_type' in filters and threat.threat_type != ThreatType(filters['threat_type']):
                match = False

            if 'severity' in filters and threat.severity != ThreatSeverity(filters['severity']):
                match = False

            if 'min_confidence' in filters and threat.confidence_score < filters['min_confidence']:
                match = False

            if 'tags' in filters:
                if not any(tag in threat.tags for tag in filters['tags']):
                    match = False

            if match:
                filtered_threats.append(threat)

        return filtered_threats

class CollaborativeThreatSharing:
    """Collaborative threat intelligence sharing"""

    def __init__(self):
        self.sharing_partners = {}
        self.shared_intelligence = deque(maxlen=50000)
        self.sharing_policies = {}
        self.lock = threading.Lock()

    def register_sharing_partner(self, partner_id: str, partner_config: Dict[str, Any]):
        """Register threat intelligence sharing partner"""
        self.sharing_partners[partner_id] = {
            'partner_id': partner_id,
            'name': partner_config.get('name', ''),
            'api_endpoint': partner_config.get('api_endpoint', ''),
            'api_key': partner_config.get('api_key', ''),
            'sharing_level': partner_config.get('sharing_level', 'basic'),  # basic, detailed, restricted
            'is_active': True,
            'last_sync': 0
        }

    def share_threat_intelligence(self, threat_data: ThreatIntelligence,
                                 target_partners: List[str] = None) -> bool:
        """Share threat intelligence with partners"""
        try:
            partners_to_share = target_partners or list(self.sharing_partners.keys())

            shared_count = 0

            for partner_id in partners_to_share:
                if partner_id not in self.sharing_partners:
                    continue

                partner = self.sharing_partners[partner_id]

                if not partner['is_active']:
                    continue

                # Check sharing policy
                if not self._can_share_with_partner(threat_data, partner):
                    continue

                # Share intelligence (simplified)
                shared_entry = {
                    'threat_id': threat_data.threat_id,
                    'shared_with': partner_id,
                    'shared_at': time.time(),
                    'threat_summary': {
                        'type': threat_data.threat_type.value,
                        'severity': threat_data.severity.value,
                        'title': threat_data.title,
                        'indicators_count': len(threat_data.indicators)
                    }
                }

                with self.lock:
                    self.shared_intelligence.append(shared_entry)

                shared_count += 1

            logger.info(f"Shared threat intelligence with {shared_count} partners")
            return True

        except Exception as e:
            logger.error(f"Failed to share threat intelligence: {e}")
            return False

    def _can_share_with_partner(self, threat_data: ThreatIntelligence, partner: Dict[str, Any]) -> bool:
        """Check if threat can be shared with partner"""
        sharing_level = partner['sharing_level']

        if sharing_level == 'basic':
            return threat_data.confidence_score >= 0.6
        elif sharing_level == 'detailed':
            return threat_data.confidence_score >= 0.4
        elif sharing_level == 'restricted':
            return threat_data.severity == ThreatSeverity.CRITICAL

        return True

    def receive_shared_intelligence(self, partner_id: str, intelligence_data: Dict[str, Any]) -> bool:
        """Receive threat intelligence from partner"""
        try:
            with self.lock:
                self.shared_intelligence.append({
                    'threat_id': intelligence_data.get('threat_id', ''),
                    'received_from': partner_id,
                    'received_at': time.time(),
                    'intelligence_data': intelligence_data
                })

            logger.info(f"Received threat intelligence from partner {partner_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to receive threat intelligence: {e}")
            return False

class ThreatCorrelationEngine:
    """Threat correlation and analysis engine"""

    def __init__(self):
        self.correlation_rules = {}
        self.threat_clusters = defaultdict(list)
        self.correlation_history = deque(maxlen=10000)
        self.lock = threading.Lock()

    def define_correlation_rule(self, rule_name: str, rule_config: Dict[str, Any]):
        """Define threat correlation rule"""
        self.correlation_rules[rule_name] = {
            'name': rule_name,
            'trigger_conditions': rule_config.get('trigger_conditions', []),
            'correlation_window': rule_config.get('correlation_window', 3600),  # 1 hour
            'minimum_matches': rule_config.get('minimum_matches', 2),
            'action': rule_config.get('action', 'alert')
        }

    def correlate_threats(self, new_threat: ThreatIntelligence) -> List[Dict[str, Any]]:
        """Correlate new threat with existing threats"""
        correlated_threats = []

        with self.lock:
            # Check correlation rules
            for rule_name, rule_config in self.correlation_rules.items():
                if self._matches_correlation_rule(new_threat, rule_config):
                    # Find correlated threats
                    correlated = self._find_correlated_threats(new_threat, rule_config)
                    if len(correlated) >= rule_config['minimum_matches'] - 1:  # -1 because new_threat is included
                        correlated_threats.append({
                            'rule_name': rule_name,
                            'correlated_threats': correlated,
                            'correlation_score': len(correlated) / rule_config['minimum_matches'],
                            'action_required': rule_config['action']
                        })

            # Record correlation
            if correlated_threats:
                self.correlation_history.append({
                    'timestamp': time.time(),
                    'threat_id': new_threat.threat_id,
                    'correlations': correlated_threats
                })

        return correlated_threats

    def _matches_correlation_rule(self, threat: ThreatIntelligence, rule: Dict[str, Any]) -> bool:
        """Check if threat matches correlation rule"""
        conditions = rule['trigger_conditions']

        for condition in conditions:
            field = condition.get('field')
            operator = condition.get('operator')
            value = condition.get('value')

            threat_value = getattr(threat, field, None)

            if operator == 'equals' and threat_value != value:
                return False
            elif operator == 'contains' and value not in str(threat_value):
                return False
            elif operator == 'greater_than' and threat_value <= value:
                return False

        return True

    def _find_correlated_threats(self, new_threat: ThreatIntelligence,
                               rule: Dict[str, Any]) -> List[ThreatIntelligence]:
        """Find threats correlated with new threat"""
        correlated = []
        window_start = time.time() - rule['correlation_window']

        with self.lock:
            for threat in list(self.threat_clusters.get(new_threat.threat_type.value, [])):
                if threat.timestamp >= window_start and threat.threat_id != new_threat.threat_id:
                    # Check similarity
                    similarity = self._calculate_threat_similarity(new_threat, threat)
                    if similarity > 0.6:  # 60% similarity threshold
                        correlated.append(threat)

        return correlated

    def _calculate_threat_similarity(self, threat1: ThreatIntelligence, threat2: ThreatIntelligence) -> float:
        """Calculate similarity between two threats"""
        # Simplified similarity calculation
        similarity_factors = []

        # Type similarity
        if threat1.threat_type == threat2.threat_type:
            similarity_factors.append(1.0)
        else:
            similarity_factors.append(0.0)

        # Indicator overlap
        indicators1 = set(threat1.indicators)
        indicators2 = set(threat2.indicators)
        if indicators1 or indicators2:
            overlap = len(indicators1 & indicators2)
            total = len(indicators1 | indicators2)
            similarity_factors.append(overlap / total if total > 0 else 0)

        # Tag overlap
        tags1 = set(threat1.tags)
        tags2 = set(threat2.tags)
        if tags1 or tags2:
            overlap = len(tags1 & tags2)
            total = len(tags1 | tags2)
            similarity_factors.append(overlap / total if total > 0 else 0)

        return sum(similarity_factors) / len(similarity_factors) if similarity_factors else 0.0

class AutomatedThreatResponse:
    """Automated threat response system"""

    def __init__(self):
        self.response_playbooks = {}
        self.incident_responses = deque(maxlen=5000)
        self.response_effectiveness = {}
        self.lock = threading.Lock()

    def define_response_playbook(self, playbook_name: str, playbook_config: Dict[str, Any]):
        """Define automated response playbook"""
        self.response_playbooks[playbook_name] = {
            'name': playbook_name,
            'trigger_conditions': playbook_config.get('trigger_conditions', []),
            'response_actions': playbook_config.get('response_actions', []),
            'rollback_actions': playbook_config.get('rollback_actions', []),
            'approval_required': playbook_config.get('approval_required', False),
            'execution_timeout': playbook_config.get('execution_timeout', 300)
        }

    def execute_automated_response(self, threat: ThreatIntelligence,
                                 playbook_name: str = 'default') -> Dict[str, Any]:
        """Execute automated response to threat"""
        if playbook_name not in self.response_playbooks:
            return {'error': 'Response playbook not found'}

        playbook = self.response_playbooks[playbook_name]

        # Check if playbook should be triggered
        if not self._should_trigger_playbook(threat, playbook):
            return {'triggered': False, 'reason': 'Trigger conditions not met'}

        try:
            # Execute response actions
            execution_results = []

            for action in playbook['response_actions']:
                result = self._execute_response_action(action, threat)
                execution_results.append(result)

            # Record response
            with self.lock:
                self.incident_responses.append({
                    'timestamp': time.time(),
                    'threat_id': threat.threat_id,
                    'playbook': playbook_name,
                    'execution_results': execution_results,
                    'overall_success': all(r['success'] for r in execution_results)
                })

            return {
                'playbook_executed': playbook_name,
                'actions_executed': len(playbook['response_actions']),
                'execution_results': execution_results,
                'response_time': time.time()
            }

        except Exception as e:
            logger.error(f"Automated response execution failed: {e}")
            return {'error': str(e)}

    def _should_trigger_playbook(self, threat: ThreatIntelligence, playbook: Dict[str, Any]) -> bool:
        """Check if playbook should be triggered"""
        conditions = playbook['trigger_conditions']

        for condition in conditions:
            field = condition.get('field')
            operator = condition.get('operator')
            value = condition.get('value')

            threat_value = getattr(threat, field, None)

            if operator == 'equals' and threat_value != value:
                return False
            elif operator == 'greater_than' and threat_value <= value:
                return False

        return True

    def _execute_response_action(self, action: Dict[str, Any], threat: ThreatIntelligence) -> Dict[str, Any]:
        """Execute specific response action"""
        action_type = action.get('type')
        action_params = action.get('params', {})

        try:
            if action_type == 'block_ip':
                # Block malicious IP addresses
                return {'success': True, 'action': 'IP blocked', 'details': action_params}

            elif action_type == 'update_firewall':
                # Update firewall rules
                return {'success': True, 'action': 'Firewall updated', 'details': action_params}

            elif action_type == 'isolate_system':
                # Isolate compromised system
                return {'success': True, 'action': 'System isolated', 'details': action_params}

            elif action_type == 'notify_admin':
                # Notify security administrators
                return {'success': True, 'action': 'Admin notified', 'details': action_params}

            else:
                return {'success': False, 'error': f'Unknown action type: {action_type}'}

        except Exception as e:
            return {'success': False, 'error': str(e)}

class ThreatIntelligenceManager:
    """Main threat intelligence management system"""

    def __init__(self):
        self.threat_feeds = ThreatIntelligenceFeed()
        self.collaborative_sharing = CollaborativeThreatSharing()
        self.correlation_engine = ThreatCorrelationEngine()
        self.automated_response = AutomatedThreatResponse()
        self.threat_intelligence_db = {}
        self.lock = threading.Lock()

    def initialize_threat_intelligence(self, config: Dict[str, Any]):
        """Initialize threat intelligence system"""
        logger.info("Initializing threat intelligence system")

        # Register threat intelligence feeds
        feeds = [
            {
                'name': 'alienvault_otx',
                'url': 'https://otx.alienvault.com/api/v1/indicators/export',
                'api_key': config.get('alienvault_api_key', ''),
                'update_interval': 300
            },
            {
                'name': 'abuseipdb',
                'url': 'https://api.abuseipdb.com/api/v2/blacklist',
                'api_key': config.get('abuseipdb_api_key', ''),
                'update_interval': 600
            },
            {
                'name': 'virus_total',
                'url': 'https://www.virustotal.com/vtapi/v2/file/report',
                'api_key': config.get('virustotal_api_key', ''),
                'update_interval': 1800
            }
        ]

        for feed in feeds:
            self.threat_feeds.register_feed(feed['name'], feed)

        # Register sharing partners
        partners = [
            {
                'partner_id': 'partner_1',
                'name': 'Security Partner A',
                'api_endpoint': 'https://partner1.com/api/threats',
                'sharing_level': 'detailed'
            },
            {
                'partner_id': 'partner_2',
                'name': 'Security Partner B',
                'api_endpoint': 'https://partner2.com/api/threats',
                'sharing_level': 'basic'
            }
        ]

        for partner in partners:
            self.collaborative_sharing.register_sharing_partner(partner['partner_id'], partner)

        # Define correlation rules
        self.correlation_engine.define_correlation_rule('malware_outbreak', {
            'trigger_conditions': [
                {'field': 'threat_type', 'operator': 'equals', 'value': ThreatType.MALWARE}
            ],
            'correlation_window': 3600,
            'minimum_matches': 3,
            'action': 'escalate'
        })

        self.correlation_engine.define_correlation_rule('coordinated_attack', {
            'trigger_conditions': [
                {'field': 'severity', 'operator': 'equals', 'value': ThreatSeverity.HIGH}
            ],
            'correlation_window': 1800,
            'minimum_matches': 5,
            'action': 'immediate_response'
        })

        # Define response playbooks
        self.automated_response.define_response_playbook('malware_containment', {
            'trigger_conditions': [
                {'field': 'threat_type', 'operator': 'equals', 'value': ThreatType.MALWARE},
                {'field': 'severity', 'operator': 'greater_than', 'value': ThreatSeverity.MEDIUM}
            ],
            'response_actions': [
                {'type': 'update_firewall', 'params': {'action': 'block_malicious_domains'}},
                {'type': 'scan_systems', 'params': {'scan_type': 'malware'}},
                {'type': 'notify_admin', 'params': {'urgency': 'high'}}
            ]
        })

        self.automated_response.define_response_playbook('ddos_mitigation', {
            'trigger_conditions': [
                {'field': 'threat_type', 'operator': 'equals', 'value': ThreatType.DDoS}
            ],
            'response_actions': [
                {'type': 'enable_ddos_protection', 'params': {'threshold': 1000}},
                {'type': 'route_traffic', 'params': {'strategy': 'load_balanced'}},
                {'type': 'notify_admin', 'params': {'urgency': 'critical'}}
            ]
        })

        logger.info("Threat intelligence system initialized")

    def process_new_threat(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process new threat intelligence"""
        try:
            # Create threat intelligence object
            threat = ThreatIntelligence(
                threat_id=threat_data['threat_id'],
                threat_type=ThreatType(threat_data['threat_type']),
                severity=ThreatSeverity(threat_data['severity']),
                title=threat_data['title'],
                description=threat_data['description'],
                indicators=threat_data['indicators'],
                affected_systems=threat_data['affected_systems'],
                mitigation_steps=threat_data['mitigation_steps'],
                confidence_score=threat_data['confidence_score'],
                source=threat_data['source'],
                timestamp=time.time(),
                expiry_time=time.time() + 86400,
                tags=threat_data.get('tags', [])
            )

            # Add to feeds
            with self.lock:
                self.threat_feeds.intelligence_data.append(threat)

            # Perform correlation analysis
            correlations = self.correlation_engine.correlate_threats(threat)

            # Execute automated response if needed
            response_results = {}
            for correlation in correlations:
                if correlation['action_required'] in ['immediate_response', 'escalate']:
                    playbook_name = f"{threat.threat_type.value}_response"
                    response = self.automated_response.execute_automated_response(threat, playbook_name)
                    response_results[playbook_name] = response

            # Share with partners if high confidence
            if threat.confidence_score > 0.8:
                self.collaborative_sharing.share_threat_intelligence(threat)

            return {
                'threat_processed': threat.threat_id,
                'correlations_found': len(correlations),
                'automated_responses': len(response_results),
                'shared_with_partners': threat.confidence_score > 0.8
            }

        except Exception as e:
            logger.error(f"Threat processing failed: {e}")
            return {'error': str(e)}

    def query_threat_intelligence(self, query_params: Dict[str, Any]) -> List[ThreatIntelligence]:
        """Query threat intelligence database"""
        return self.threat_feeds.query_threats(query_params)

    def get_threat_intelligence_status(self) -> Dict[str, Any]:
        """Get threat intelligence system status"""
        with self.lock:
            active_feeds = len([f for f in self.threat_feeds.feeds.values() if f['is_active']])
            total_intelligence = len(self.threat_feeds.intelligence_data)
            active_partners = len([p for p in self.collaborative_sharing.sharing_partners.values() if p['is_active']])

        return {
            'threat_feeds': {
                'total_feeds': len(self.threat_feeds.feeds),
                'active_feeds': active_feeds,
                'total_intelligence_entries': total_intelligence
            },
            'collaborative_sharing': {
                'total_partners': len(self.collaborative_sharing.sharing_partners),
                'active_partners': active_partners,
                'shared_intelligence_count': len(self.collaborative_sharing.shared_intelligence)
            },
            'correlation_engine': {
                'correlation_rules': len(self.correlation_engine.correlation_rules),
                'recent_correlations': len(self.correlation_engine.correlation_history)
            },
            'automated_response': {
                'response_playbooks': len(self.automated_response.response_playbooks),
                'incident_responses': len(self.automated_response.incident_responses)
            }
        }

# Global threat intelligence instances
threat_intelligence_manager = ThreatIntelligenceManager()

def init_threat_intelligence():
    """Initialize threat intelligence system"""
    threat_intelligence_manager.initialize_threat_intelligence({})

def process_threat_intelligence(threat_data: Dict[str, Any]) -> Dict[str, Any]:
    """Process new threat intelligence"""
    return threat_intelligence_manager.process_new_threat(threat_data)

def query_threats(**filters) -> List[ThreatIntelligence]:
    """Query threat intelligence"""
    return threat_intelligence_manager.query_threat_intelligence(filters)

def get_threat_intelligence_status() -> Dict[str, Any]:
    """Get threat intelligence system status"""
    return threat_intelligence_manager.get_threat_intelligence_status()
