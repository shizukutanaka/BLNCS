# BLRCS Threat Intelligence System
# Advanced threat intelligence collection, analysis, and sharing

import os
import json
import time
import hashlib
import logging
import threading
import requests
import asyncio
from typing import Dict, List, Any, Optional, Set, Tuple, Union
from dataclasses import dataclass, field, asdict
from enum import Enum
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict, deque
import ipaddress
import re
try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False
import socket

logger = logging.getLogger(__name__)

class ThreatType(Enum):
    """Types of threats"""
    MALWARE = "malware"
    PHISHING = "phishing"
    BOTNET = "botnet"
    APT = "apt"
    RANSOMWARE = "ransomware"
    CRYPTOMINING = "cryptomining"
    C2_SERVER = "c2_server"
    SUSPICIOUS_DOMAIN = "suspicious_domain"
    MALICIOUS_IP = "malicious_ip"
    VULNERABILITY = "vulnerability"
    IOC = "ioc"

class ConfidenceLevel(Enum):
    """Confidence levels for threat intelligence"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CONFIRMED = 4

class ThreatSource(Enum):
    """Sources of threat intelligence"""
    OSINT = "osint"
    COMMERCIAL = "commercial"
    GOVERNMENT = "government"
    COMMUNITY = "community"
    INTERNAL = "internal"
    HONEYPOT = "honeypot"

@dataclass
class ThreatIndicator:
    """Threat indicator/IOC"""
    id: str
    indicator_type: str  # ip, domain, hash, url, email
    value: str
    threat_types: List[ThreatType] = field(default_factory=list)
    confidence: ConfidenceLevel = ConfidenceLevel.MEDIUM
    source: ThreatSource = ThreatSource.OSINT
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    tags: Set[str] = field(default_factory=set)
    description: str = ""
    context: Dict[str, Any] = field(default_factory=dict)
    ttl: Optional[datetime] = None
    active: bool = True

@dataclass
class ThreatReport:
    """Comprehensive threat report"""
    id: str
    title: str
    threat_types: List[ThreatType]
    indicators: List[ThreatIndicator]
    description: str
    analysis: str
    recommendations: List[str]
    severity: str
    published_date: datetime
    source: ThreatSource
    confidence: ConfidenceLevel
    tags: Set[str] = field(default_factory=set)
    references: List[str] = field(default_factory=list)

class ThreatFeedParser:
    """Parse various threat intelligence feed formats"""
    
    def __init__(self):
        self.parsers = {
            'stix': self._parse_stix,
            'json': self._parse_json,
            'csv': self._parse_csv,
            'xml': self._parse_xml,
            'misp': self._parse_misp
        }
    
    def parse_feed(self, data: str, format_type: str) -> List[ThreatIndicator]:
        """Parse threat feed data"""
        parser = self.parsers.get(format_type.lower())
        if not parser:
            raise ValueError(f"Unsupported feed format: {format_type}")
        
        return parser(data)
    
    def _parse_json(self, data: str) -> List[ThreatIndicator]:
        """Parse JSON format threat feed"""
        indicators = []
        
        try:
            feed_data = json.loads(data)
            
            for item in feed_data.get('indicators', []):
                indicator = ThreatIndicator(
                    id=item.get('id', f"json_{int(time.time())}_{len(indicators)}"),
                    indicator_type=item.get('type', 'unknown'),
                    value=item.get('value', ''),
                    confidence=ConfidenceLevel(item.get('confidence', 2)),
                    description=item.get('description', ''),
                    tags=set(item.get('tags', [])),
                    context=item.get('context', {})
                )
                
                # Parse threat types
                for threat_type in item.get('threat_types', []):
                    try:
                        indicator.threat_types.append(ThreatType(threat_type))
                    except ValueError:
                        pass
                
                indicators.append(indicator)
                
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON feed: {e}")
        
        return indicators
    
    def _parse_csv(self, data: str) -> List[ThreatIndicator]:
        """Parse CSV format threat feed"""
        indicators = []
        lines = data.strip().split('\n')
        
        if not lines:
            return indicators
        
        # Assume first line is header
        headers = [h.strip().lower() for h in lines[0].split(',')]
        
        for i, line in enumerate(lines[1:], 1):
            try:
                values = [v.strip() for v in line.split(',')]
                if len(values) != len(headers):
                    continue
                
                row_data = dict(zip(headers, values))
                
                indicator = ThreatIndicator(
                    id=f"csv_{int(time.time())}_{i}",
                    indicator_type=row_data.get('type', 'unknown'),
                    value=row_data.get('indicator', row_data.get('value', '')),
                    description=row_data.get('description', ''),
                    confidence=ConfidenceLevel(int(row_data.get('confidence', 2)))
                )
                
                indicators.append(indicator)
                
            except (ValueError, IndexError) as e:
                logger.warning(f"Failed to parse CSV line {i}: {e}")
                continue
        
        return indicators
    
    def _parse_stix(self, data: str) -> List[ThreatIndicator]:
        """Parse STIX format threat feed (simplified)"""
        # This would integrate with python-stix2 library in production
        indicators = []
        
        try:
            stix_data = json.loads(data)
            
            for obj in stix_data.get('objects', []):
                if obj.get('type') == 'indicator':
                    pattern = obj.get('pattern', '')
                    
                    # Extract indicator value from pattern
                    indicator_value = self._extract_from_stix_pattern(pattern)
                    
                    if indicator_value:
                        indicator = ThreatIndicator(
                            id=obj.get('id', f"stix_{int(time.time())}_{len(indicators)}"),
                            indicator_type=self._get_indicator_type_from_pattern(pattern),
                            value=indicator_value,
                            description=obj.get('description', ''),
                            tags=set(obj.get('labels', [])),
                            source=ThreatSource.OSINT
                        )
                        
                        indicators.append(indicator)
                        
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse STIX feed: {e}")
        
        return indicators
    
    def _parse_xml(self, data: str) -> List[ThreatIndicator]:
        """Parse XML format threat feed"""
        indicators = []
        
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(data)
            
            for indicator_elem in root.findall('.//indicator'):
                indicator = ThreatIndicator(
                    id=indicator_elem.get('id', f"xml_{int(time.time())}_{len(indicators)}"),
                    indicator_type=indicator_elem.get('type', 'unknown'),
                    value=indicator_elem.text or '',
                    description=indicator_elem.get('description', '')
                )
                
                indicators.append(indicator)
                
        except ET.ParseError as e:
            logger.error(f"Failed to parse XML feed: {e}")
        
        return indicators
    
    def _parse_misp(self, data: str) -> List[ThreatIndicator]:
        """Parse MISP format threat feed"""
        indicators = []
        
        try:
            misp_data = json.loads(data)
            
            for event in misp_data.get('response', []):
                event_info = event.get('Event', {})
                
                for attribute in event_info.get('Attribute', []):
                    indicator = ThreatIndicator(
                        id=f"misp_{attribute.get('id', len(indicators))}",
                        indicator_type=attribute.get('type', 'unknown'),
                        value=attribute.get('value', ''),
                        description=event_info.get('info', ''),
                        tags=set(attribute.get('Tag', [])),
                        source=ThreatSource.COMMUNITY
                    )
                    
                    indicators.append(indicator)
                    
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse MISP feed: {e}")
        
        return indicators
    
    def _extract_from_stix_pattern(self, pattern: str) -> str:
        """Extract indicator value from STIX pattern"""
        # Simple regex extraction for common patterns
        patterns = [
            r"file:hashes\.MD5\s*=\s*'([^']+)'",
            r"file:hashes\.SHA-1\s*=\s*'([^']+)'",
            r"file:hashes\.SHA-256\s*=\s*'([^']+)'",
            r"network-traffic:src_ref\.value\s*=\s*'([^']+)'",
            r"domain-name:value\s*=\s*'([^']+)'",
            r"url:value\s*=\s*'([^']+)'"
        ]
        
        for regex in patterns:
            match = re.search(regex, pattern)
            if match:
                return match.group(1)
        
        return ""
    
    def _get_indicator_type_from_pattern(self, pattern: str) -> str:
        """Determine indicator type from STIX pattern"""
        if 'file:hashes' in pattern:
            return 'hash'
        elif 'network-traffic:src_ref' in pattern:
            return 'ip'
        elif 'domain-name:value' in pattern:
            return 'domain'
        elif 'url:value' in pattern:
            return 'url'
        else:
            return 'unknown'

class ThreatEnrichment:
    """Enrich threat indicators with additional context"""
    
    def __init__(self):
        self.enrichment_cache = {}
        self.dns_cache = {}
    
    async def enrich_indicator(self, indicator: ThreatIndicator) -> ThreatIndicator:
        """Enrich threat indicator with additional context"""
        try:
            if indicator.indicator_type == 'ip':
                await self._enrich_ip(indicator)
            elif indicator.indicator_type == 'domain':
                await self._enrich_domain(indicator)
            elif indicator.indicator_type == 'hash':
                await self._enrich_hash(indicator)
            elif indicator.indicator_type == 'url':
                await self._enrich_url(indicator)
                
        except Exception as e:
            logger.error(f"Failed to enrich indicator {indicator.id}: {e}")
        
        return indicator
    
    async def _enrich_ip(self, indicator: ThreatIndicator):
        """Enrich IP address indicator"""
        ip_address = indicator.value
        
        try:
            ip = ipaddress.ip_address(ip_address)
            
            # Basic IP information
            indicator.context['is_private'] = ip.is_private
            indicator.context['is_multicast'] = ip.is_multicast
            indicator.context['is_reserved'] = ip.is_reserved
            
            # Geolocation (would integrate with GeoIP service)
            indicator.context['geolocation'] = await self._get_geolocation(ip_address)
            
            # ASN information
            indicator.context['asn'] = await self._get_asn_info(ip_address)
            
            # Reverse DNS
            indicator.context['reverse_dns'] = await self._get_reverse_dns(ip_address)
            
            # Port scan detection
            indicator.context['open_ports'] = await self._scan_ports(ip_address)
            
        except ValueError:
            logger.warning(f"Invalid IP address: {ip_address}")
    
    async def _enrich_domain(self, indicator: ThreatIndicator):
        """Enrich domain indicator"""
        domain = indicator.value
        
        try:
            # DNS resolution
            indicator.context['dns_records'] = await self._get_dns_records(domain)
            
            # WHOIS information (simplified)
            indicator.context['whois'] = await self._get_whois_info(domain)
            
            # Subdomain enumeration
            indicator.context['subdomains'] = await self._enumerate_subdomains(domain)
            
            # Certificate information
            indicator.context['ssl_cert'] = await self._get_ssl_cert_info(domain)
            
        except Exception as e:
            logger.warning(f"Failed to enrich domain {domain}: {e}")
    
    async def _enrich_hash(self, indicator: ThreatIndicator):
        """Enrich file hash indicator"""
        file_hash = indicator.value
        
        # Determine hash type
        hash_length = len(file_hash)
        if hash_length == 32:
            indicator.context['hash_type'] = 'MD5'
        elif hash_length == 40:
            indicator.context['hash_type'] = 'SHA1'
        elif hash_length == 64:
            indicator.context['hash_type'] = 'SHA256'
        else:
            indicator.context['hash_type'] = 'Unknown'
        
        # VirusTotal lookup (would integrate with VT API)
        indicator.context['virustotal'] = await self._get_virustotal_info(file_hash)
    
    async def _enrich_url(self, indicator: ThreatIndicator):
        """Enrich URL indicator"""
        url = indicator.value
        
        try:
            from urllib.parse import urlparse
            parsed_url = urlparse(url)
            
            indicator.context['scheme'] = parsed_url.scheme
            indicator.context['domain'] = parsed_url.netloc
            indicator.context['path'] = parsed_url.path
            indicator.context['query'] = parsed_url.query
            
            # Analyze domain part
            if parsed_url.netloc:
                domain_indicator = ThreatIndicator(
                    id=f"temp_domain_{int(time.time())}",
                    indicator_type='domain',
                    value=parsed_url.netloc
                )
                await self._enrich_domain(domain_indicator)
                indicator.context['domain_info'] = domain_indicator.context
            
        except Exception as e:
            logger.warning(f"Failed to enrich URL {url}: {e}")
    
    async def _get_geolocation(self, ip_address: str) -> Dict[str, str]:
        """Get geolocation for IP address"""
        # In production, integrate with GeoIP service like MaxMind
        return {
            'country': 'Unknown',
            'city': 'Unknown',
            'latitude': '0.0',
            'longitude': '0.0'
        }
    
    async def _get_asn_info(self, ip_address: str) -> Dict[str, Any]:
        """Get ASN information for IP address"""
        # In production, query ASN databases
        return {
            'asn': 0,
            'organization': 'Unknown',
            'country': 'Unknown'
        }
    
    async def _get_reverse_dns(self, ip_address: str) -> List[str]:
        """Get reverse DNS for IP address"""
        try:
            result = socket.gethostbyaddr(ip_address)
            return [result[0]] + list(result[1])
        except socket.herror:
            return []
    
    async def _scan_ports(self, ip_address: str) -> List[int]:
        """Scan common ports on IP address"""
        open_ports = []
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995]
        
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip_address, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except Exception:
                continue
        
        return open_ports
    
    async def _get_dns_records(self, domain: str) -> Dict[str, List[str]]:
        """Get DNS records for domain"""
        records = {}
        
        try:
            if not DNS_AVAILABLE:
                records['A'] = []
                records['MX'] = []
                records['TXT'] = []
                return records
                
            # A records
            try:
                answers = dns.resolver.resolve(domain, 'A')
                records['A'] = [str(answer) for answer in answers]
            except:
                records['A'] = []
            
            # MX records
            try:
                answers = dns.resolver.resolve(domain, 'MX')
                records['MX'] = [str(answer) for answer in answers]
            except:
                records['MX'] = []
            
            # TXT records
            try:
                answers = dns.resolver.resolve(domain, 'TXT')
                records['TXT'] = [str(answer) for answer in answers]
            except:
                records['TXT'] = []
                
        except Exception as e:
            logger.warning(f"DNS lookup failed for {domain}: {e}")
        
        return records
    
    async def _get_whois_info(self, domain: str) -> Dict[str, str]:
        """Get WHOIS information for domain"""
        # In production, integrate with WHOIS service
        return {
            'registrar': 'Unknown',
            'creation_date': 'Unknown',
            'expiration_date': 'Unknown',
            'registrant': 'Unknown'
        }
    
    async def _enumerate_subdomains(self, domain: str) -> List[str]:
        """Enumerate subdomains"""
        # In production, use subdomain enumeration tools
        common_subdomains = ['www', 'mail', 'ftp', 'admin', 'api', 'cdn']
        found_subdomains = []
        
        for subdomain in common_subdomains:
            full_domain = f"{subdomain}.{domain}"
            try:
                if DNS_AVAILABLE:
                    dns.resolver.resolve(full_domain, 'A')
                    found_subdomains.append(full_domain)
                else:
                    # Fallback to basic socket resolution if dns module not available
                    socket.gethostbyname(full_domain)
                    found_subdomains.append(full_domain)
            except:
                continue
        
        return found_subdomains
    
    async def _get_ssl_cert_info(self, domain: str) -> Dict[str, Any]:
        """Get SSL certificate information"""
        try:
            import ssl
            context = ssl.create_default_context()
            
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    return {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert['version'],
                        'notBefore': cert['notBefore'],
                        'notAfter': cert['notAfter'],
                        'serialNumber': cert['serialNumber']
                    }
        except Exception:
            return {}
    
    async def _get_virustotal_info(self, file_hash: str) -> Dict[str, Any]:
        """Get VirusTotal information for file hash"""
        # In production, integrate with VirusTotal API
        return {
            'positives': 0,
            'total': 0,
            'scan_date': 'Unknown',
            'permalink': ''
        }

class ThreatIntelligenceManager:
    """Main threat intelligence management system"""
    
    def __init__(self, config_dir: Optional[Path] = None):
        self.config_dir = config_dir or Path.home() / ".blrcs" / "threat_intel"
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        self.indicators: Dict[str, ThreatIndicator] = {}
        self.reports: Dict[str, ThreatReport] = {}
        self.feeds = {}
        
        self.feed_parser = ThreatFeedParser()
        self.enrichment = ThreatEnrichment()
        
        self.update_thread = None
        self.running = False
        self.lock = threading.Lock()
        
        self._load_indicators()
        self._setup_default_feeds()
    
    def _load_indicators(self):
        """Load saved threat indicators"""
        indicators_file = self.config_dir / "indicators.json"
        if indicators_file.exists():
            try:
                with open(indicators_file, 'r') as f:
                    data = json.load(f)
                
                for indicator_data in data.get('indicators', []):
                    # Convert string values back to enums
                    if 'confidence' in indicator_data and isinstance(indicator_data['confidence'], str):
                        indicator_data['confidence'] = ConfidenceLevel(indicator_data['confidence'])
                    
                    if 'source' in indicator_data and isinstance(indicator_data['source'], str):
                        indicator_data['source'] = ThreatSource(indicator_data['source'])
                    
                    if 'threat_types' in indicator_data:
                        threat_types = []
                        for tt in indicator_data['threat_types']:
                            if isinstance(tt, str):
                                threat_types.append(ThreatType(tt))
                            else:
                                threat_types.append(tt)
                        indicator_data['threat_types'] = threat_types
                    
                    # Convert datetime strings back to datetime objects
                    for date_field in ['first_seen', 'last_seen']:
                        if date_field in indicator_data and isinstance(indicator_data[date_field], str):
                            indicator_data[date_field] = datetime.fromisoformat(indicator_data[date_field])
                    
                    indicator = ThreatIndicator(**indicator_data)
                    self.indicators[indicator.id] = indicator
                
                logger.info(f"Loaded {len(self.indicators)} threat indicators")
                
            except Exception as e:
                logger.error(f"Failed to load indicators: {e}")
    
    def _save_indicators(self):
        """Save threat indicators"""
        indicators_file = self.config_dir / "indicators.json"
        try:
            data = {
                'indicators': [asdict(indicator) for indicator in self.indicators.values()],
                'updated_at': datetime.now().isoformat()
            }
            
            with open(indicators_file, 'w') as f:
                json.dump(data, f, indent=2, default=str)
                
        except Exception as e:
            logger.error(f"Failed to save indicators: {e}")
    
    def _setup_default_feeds(self):
        """Setup default threat intelligence feeds"""
        default_feeds = [
            {
                'name': 'abuse_ch_malware',
                'url': 'https://urlhaus.abuse.ch/downloads/json/',
                'format': 'json',
                'enabled': True,
                'update_interval': 3600
            },
            {
                'name': 'emergingthreats_compromised',
                'url': 'https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt',
                'format': 'csv',
                'enabled': True,
                'update_interval': 7200
            }
        ]
        
        for feed_config in default_feeds:
            self.feeds[feed_config['name']] = feed_config
    
    def start_updates(self):
        """Start automatic threat feed updates"""
        if not self.running:
            self.running = True
            
            self.update_thread = threading.Thread(
                target=self._update_loop,
                daemon=True
            )
            self.update_thread.start()
            
            logger.info("Threat intelligence updates started")
    
    def stop_updates(self):
        """Stop automatic updates"""
        self.running = False
        
        if self.update_thread:
            self.update_thread.join(timeout=5)
        
        logger.info("Threat intelligence updates stopped")
    
    def _update_loop(self):
        """Main update loop"""
        while self.running:
            try:
                for feed_name, feed_config in self.feeds.items():
                    if feed_config.get('enabled', True):
                        last_update = feed_config.get('last_update', 0)
                        interval = feed_config.get('update_interval', 3600)
                        
                        if time.time() - last_update >= interval:
                            self._update_feed(feed_name, feed_config)
                
                time.sleep(300)  # Check every 5 minutes
                
            except Exception as e:
                logger.error(f"Update loop error: {e}")
                time.sleep(60)
    
    def _update_feed(self, feed_name: str, feed_config: Dict[str, Any]):
        """Update threat feed"""
        try:
            logger.info(f"Updating threat feed: {feed_name}")
            
            url = feed_config['url']
            format_type = feed_config['format']
            
            # Download feed data
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            
            # Parse indicators
            indicators = self.feed_parser.parse_feed(response.text, format_type)
            
            # Add/update indicators
            new_indicators = 0
            updated_indicators = 0
            
            with self.lock:
                for indicator in indicators:
                    if indicator.id in self.indicators:
                        # Update existing
                        existing = self.indicators[indicator.id]
                        existing.last_seen = datetime.now()
                        existing.context.update(indicator.context)
                        updated_indicators += 1
                    else:
                        # Add new
                        indicator.source = ThreatSource.OSINT
                        self.indicators[indicator.id] = indicator
                        new_indicators += 1
            
            # Update feed config
            feed_config['last_update'] = time.time()
            feed_config['last_status'] = 'success'
            
            logger.info(f"Feed {feed_name} updated: {new_indicators} new, {updated_indicators} updated")
            
            # Save indicators periodically
            if new_indicators > 0 or updated_indicators > 0:
                self._save_indicators()
                
        except Exception as e:
            logger.error(f"Failed to update feed {feed_name}: {e}")
            feed_config['last_status'] = f'error: {str(e)}'
    
    def add_indicator(self, indicator: ThreatIndicator) -> bool:
        """Add threat indicator"""
        try:
            with self.lock:
                self.indicators[indicator.id] = indicator
            
            self._save_indicators()
            logger.info(f"Added threat indicator: {indicator.id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to add indicator: {e}")
            return False
    
    def lookup_indicator(self, value: str, indicator_type: str = None) -> List[ThreatIndicator]:
        """Lookup threat indicators by value"""
        matches = []
        
        with self.lock:
            for indicator in self.indicators.values():
                if indicator.value == value:
                    if indicator_type is None or indicator.indicator_type == indicator_type:
                        matches.append(indicator)
        
        return matches
    
    def check_threat(self, value: str, indicator_type: str = None) -> Dict[str, Any]:
        """Check if value is a known threat"""
        matches = self.lookup_indicator(value, indicator_type)
        
        if not matches:
            return {
                'is_threat': False,
                'confidence': 0,
                'threat_types': [],
                'sources': []
            }
        
        # Calculate aggregate threat score
        total_confidence = sum(match.confidence.value for match in matches)
        avg_confidence = total_confidence / len(matches)
        
        all_threat_types = set()
        all_sources = set()
        
        for match in matches:
            all_threat_types.update(match.threat_types)
            all_sources.add(match.source)
        
        return {
            'is_threat': True,
            'confidence': avg_confidence,
            'threat_types': [t.value for t in all_threat_types],
            'sources': [s.value for s in all_sources],
            'matches': len(matches),
            'indicators': [match.id for match in matches]
        }
    
    async def enrich_indicators(self, indicator_ids: List[str] = None):
        """Enrich threat indicators with additional context"""
        target_indicators = []
        
        if indicator_ids:
            target_indicators = [self.indicators[id] for id in indicator_ids if id in self.indicators]
        else:
            # Enrich all indicators without context
            target_indicators = [i for i in self.indicators.values() if not i.context]
        
        logger.info(f"Enriching {len(target_indicators)} indicators")
        
        for indicator in target_indicators:
            try:
                await self.enrichment.enrich_indicator(indicator)
            except Exception as e:
                logger.error(f"Failed to enrich indicator {indicator.id}: {e}")
        
        self._save_indicators()
    
    def cleanup_expired_indicators(self):
        """Remove expired threat indicators"""
        current_time = datetime.now()
        expired_indicators = []
        
        with self.lock:
            for indicator_id, indicator in list(self.indicators.items()):
                if indicator.ttl and current_time > indicator.ttl:
                    expired_indicators.append(indicator_id)
                    del self.indicators[indicator_id]
        
        if expired_indicators:
            logger.info(f"Cleaned up {len(expired_indicators)} expired indicators")
            self._save_indicators()
        
        return len(expired_indicators)
    
    def get_threat_statistics(self) -> Dict[str, Any]:
        """Get threat intelligence statistics"""
        with self.lock:
            total_indicators = len(self.indicators)
            
            # Count by type
            by_type = defaultdict(int)
            by_threat_type = defaultdict(int)
            by_source = defaultdict(int)
            by_confidence = defaultdict(int)
            
            active_indicators = 0
            
            for indicator in self.indicators.values():
                if indicator.active:
                    active_indicators += 1
                
                by_type[indicator.indicator_type] += 1
                by_source[indicator.source.value] += 1
                by_confidence[indicator.confidence.value] += 1
                
                for threat_type in indicator.threat_types:
                    by_threat_type[threat_type.value] += 1
        
        return {
            'total_indicators': total_indicators,
            'active_indicators': active_indicators,
            'by_type': dict(by_type),
            'by_threat_type': dict(by_threat_type),
            'by_source': dict(by_source),
            'by_confidence': dict(by_confidence),
            'feeds_configured': len(self.feeds),
            'feeds_enabled': sum(1 for f in self.feeds.values() if f.get('enabled', True))
        }
    
    def export_indicators(self, output_format: str = 'json') -> str:
        """Export threat indicators in various formats"""
        if output_format == 'json':
            return json.dumps({
                'indicators': [asdict(indicator) for indicator in self.indicators.values()],
                'exported_at': datetime.now().isoformat()
            }, indent=2, default=str)
        
        elif output_format == 'csv':
            import csv
            import io
            
            output = io.StringIO()
            writer = csv.writer(output)
            
            # Header
            writer.writerow(['id', 'type', 'value', 'threat_types', 'confidence', 'source', 'description'])
            
            # Data
            for indicator in self.indicators.values():
                writer.writerow([
                    indicator.id,
                    indicator.indicator_type,
                    indicator.value,
                    ','.join(t.value for t in indicator.threat_types),
                    indicator.confidence.value,
                    indicator.source.value,
                    indicator.description
                ])
            
            return output.getvalue()
        
        else:
            raise ValueError(f"Unsupported export format: {output_format}")

# Global threat intelligence manager instance
threat_intel_manager = ThreatIntelligenceManager()

# Convenience functions
def start_threat_intel_updates():
    """Start threat intelligence updates"""
    threat_intel_manager.start_updates()

def stop_threat_intel_updates():
    """Stop threat intelligence updates"""
    threat_intel_manager.stop_updates()

def check_threat(value: str, indicator_type: str = None) -> Dict[str, Any]:
    """Check if value is a known threat"""
    return threat_intel_manager.check_threat(value, indicator_type)

def add_threat_indicator(indicator_type: str, value: str, threat_types: List[str] = None) -> bool:
    """Add threat indicator"""
    # Convert string threat types to ThreatType enums
    converted_threat_types = []
    for t in (threat_types or []):
        try:
            # Try to find matching enum value
            threat_type = next(tt for tt in ThreatType if tt.value == t)
            converted_threat_types.append(threat_type)
        except StopIteration:
            # If not found, use MALWARE as default
            converted_threat_types.append(ThreatType.MALWARE)
    
    indicator = ThreatIndicator(
        id=f"manual_{int(time.time())}_{hashlib.md5(value.encode()).hexdigest()[:8]}",
        indicator_type=indicator_type,
        value=value,
        threat_types=converted_threat_types,
        source=ThreatSource.INTERNAL
    )
    return threat_intel_manager.add_indicator(indicator)

def get_threat_statistics() -> Dict[str, Any]:
    """Get threat intelligence statistics"""
    return threat_intel_manager.get_threat_statistics()

# Export main classes and functions
__all__ = [
    'ThreatType', 'ConfidenceLevel', 'ThreatSource',
    'ThreatIndicator', 'ThreatReport', 'ThreatFeedParser',
    'ThreatEnrichment', 'ThreatIntelligenceManager',
    'threat_intel_manager', 'start_threat_intel_updates', 'stop_threat_intel_updates',
    'check_threat', 'add_threat_indicator', 'get_threat_statistics'
]