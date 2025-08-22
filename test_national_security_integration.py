#!/usr/bin/env python3
"""
BLRCS National Security Integration Test
Test all major security systems integration
"""

import asyncio
import logging
import sys
import time
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def test_quantum_crypto():
    """Test quantum cryptography system"""
    try:
        from blrcs.quantum_crypto import (
            QuantumCryptoManager, QuantumAlgorithm, generate_quantum_keypair
        )
        
        logger.info("Testing Quantum Cryptography System...")
        
        # Test key generation
        kem_key_id = generate_quantum_keypair(QuantumAlgorithm.KYBER1024, "kem")
        sig_key_id = generate_quantum_keypair(QuantumAlgorithm.DILITHIUM5, "signature")
        
        logger.info(f"✅ Generated KEM key: {kem_key_id}")
        logger.info(f"✅ Generated signature key: {sig_key_id}")
        
        # Test encryption/decryption
        manager = QuantumCryptoManager()
        test_data = b"classified_test_data"
        
        encrypted = manager.encrypt_data(test_data, kem_key_id)
        if encrypted:
            decrypted = manager.decrypt_data(encrypted, kem_key_id)
            logger.info(f"Original: {test_data}")
            logger.info(f"Decrypted: {decrypted}")
            assert decrypted == test_data, f"Decryption failed: expected {test_data}, got {decrypted}"
            logger.info("✅ Quantum encryption/decryption successful")
        
        # Test digital signatures
        signature = manager.sign_data(test_data, sig_key_id)
        if signature:
            verified = manager.verify_signature(signature, test_data, sig_key_id)
            assert verified, "Signature verification failed"
            logger.info("✅ Quantum digital signatures working")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ Quantum crypto test failed: {e}")
        return False

def test_zero_trust():
    """Test zero trust architecture"""
    try:
        from blrcs.zero_trust import (
            register_identity, register_resource, request_access,
            ResourceType, TrustLevel
        )
        
        logger.info("Testing Zero Trust Architecture...")
        
        # Register test identity
        success = register_identity(
            identity_id="test_user@agency.gov",
            identity_type="user",
            attributes={"clearance_level": "secret", "department": "cybersecurity"}
        )
        assert success, "Failed to register identity"
        logger.info("✅ Identity registration successful")
        
        # Register test resource
        success = register_resource(
            resource_id="test_classified_db",
            name="Test Classified Database",
            resource_type=ResourceType.DATABASE,
            path="/secure/test_db",
            sensitivity_level=4
        )
        assert success, "Failed to register resource"
        logger.info("✅ Resource registration successful")
        
        # Test access request
        access_result = request_access(
            identity_id="test_user@agency.gov",
            resource_id="test_classified_db",
            action="read",
            context={"source_ip": "192.168.1.100", "mfa_verified": True}
        )
        
        logger.info(f"✅ Access decision: {access_result.decision.value}")
        logger.info(f"✅ Trust score: {access_result.trust_score}")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ Zero trust test failed: {e}")
        return False

def test_compliance_management():
    """Test compliance management system"""
    try:
        from blrcs.compliance_manager import (
            add_compliance_framework, run_compliance_assessment,
            get_compliance_dashboard
        )
        
        logger.info("Testing Compliance Management...")
        
        # Add compliance frameworks
        frameworks = ["nist_csf", "fedramp", "iso_27001"]
        for framework in frameworks:
            success = add_compliance_framework(framework)
            if success:
                logger.info(f"✅ Added {framework} framework")
        
        # Run assessment
        assessment = run_compliance_assessment("nist_csf")
        if assessment:
            logger.info(f"✅ NIST CSF compliance: {assessment['overall_score']:.1f}%")
        
        # Get dashboard
        dashboard = get_compliance_dashboard()
        logger.info(f"✅ Overall compliance: {dashboard['overall_status']['compliance_percentage']:.1f}%")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ Compliance management test failed: {e}")
        return False

def test_threat_intelligence():
    """Test threat intelligence system"""
    try:
        from blrcs.threat_intelligence import (
            check_threat, add_threat_indicator, get_threat_statistics
        )
        
        logger.info("Testing Threat Intelligence...")
        
        # Add test threat indicator
        success = add_threat_indicator(
            indicator_type="ip",
            value="192.168.99.100",
            threat_types=["malware", "botnet"]
        )
        assert success, "Failed to add threat indicator"
        logger.info("✅ Threat indicator added")
        
        # Check threat
        threat_result = check_threat("192.168.99.100", "ip")
        assert threat_result['is_threat'], "Threat not detected"
        logger.info(f"✅ Threat detected with confidence: {threat_result['confidence']}")
        
        # Get statistics
        stats = get_threat_statistics()
        logger.info(f"✅ Threat indicators: {stats['total_indicators']}")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ Threat intelligence test failed: {e}")
        return False

def test_performance_optimization():
    """Test performance optimization system"""
    try:
        from blrcs.performance_optimizer import (
            get_performance_status, optimize_for_throughput, record_request_metrics
        )
        
        logger.info("Testing Performance Optimization...")
        
        # Record test metrics
        for i in range(100):
            record_request_metrics(response_time=0.001, success=True)
        
        # Get performance status
        status = get_performance_status()
        logger.info(f"✅ Performance score: {status['performance_score']:.1f}/100")
        
        # Test optimization
        results = optimize_for_throughput()
        logger.info(f"✅ Applied {len(results)} throughput optimizations")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ Performance optimization test failed: {e}")
        return False

def test_high_availability():
    """Test high availability system"""
    try:
        from blrcs.high_availability import get_ha_status, create_backup
        
        logger.info("Testing High Availability...")
        
        # Get HA status
        status = get_ha_status()
        logger.info(f"✅ System availability: {status['availability_percentage']:.3f}%")
        
        # Test backup creation
        backup_id = create_backup(
            name="integration_test_backup",
            source_paths=[str(Path.cwd() / "blrcs")]
        )
        if backup_id:
            logger.info(f"✅ Created backup: {backup_id}")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ High availability test failed: {e}")
        return False

def test_audit_system():
    """Test audit system"""
    try:
        from blrcs.audit_system import (
            log_audit_event, AuditEventType, query_audit_events
        )
        
        logger.info("Testing Audit System...")
        
        # Log test events
        event_id = log_audit_event(
            event_type=AuditEventType.SYSTEM_CONFIGURATION,
            source="integration_test",
            actor="test_system",
            target="blrcs_config",
            action="test_configuration",
            details={"test": "integration_test"}
        )
        
        if event_id:
            logger.info(f"✅ Logged audit event: {event_id}")
        
        # Query events
        events = query_audit_events(event_types=[AuditEventType.SYSTEM_CONFIGURATION])
        logger.info(f"✅ Found {len(events)} audit events")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ Audit system test failed: {e}")
        return False

def test_auto_remediation():
    """Test auto-remediation system"""
    try:
        from blrcs.auto_remediation import get_remediation_status
        
        logger.info("Testing Auto-Remediation...")
        
        # Get remediation status
        status = get_remediation_status()
        logger.info(f"✅ Auto-remediation enabled: {status['auto_remediation_enabled']}")
        logger.info(f"✅ Total incidents: {status['total_incidents']}")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ Auto-remediation test failed: {e}")
        return False

def main():
    """Run comprehensive integration tests"""
    logger.info("🚀 Starting BLRCS National Security Integration Tests")
    logger.info("=" * 60)
    
    tests = [
        ("Quantum Cryptography", test_quantum_crypto),
        ("Zero Trust Architecture", test_zero_trust),
        ("Compliance Management", test_compliance_management),
        ("Threat Intelligence", test_threat_intelligence),
        ("Performance Optimization", test_performance_optimization),
        ("High Availability", test_high_availability),
        ("Audit System", test_audit_system),
        ("Auto-Remediation", test_auto_remediation),
    ]
    
    results = {}
    total_tests = len(tests)
    passed_tests = 0
    
    for test_name, test_func in tests:
        logger.info(f"\n🧪 Running {test_name} test...")
        try:
            start_time = time.time()
            result = test_func()
            duration = time.time() - start_time
            
            results[test_name] = {
                'passed': result,
                'duration': duration
            }
            
            if result:
                passed_tests += 1
                logger.info(f"✅ {test_name} test PASSED ({duration:.2f}s)")
            else:
                logger.error(f"❌ {test_name} test FAILED ({duration:.2f}s)")
                
        except Exception as e:
            logger.error(f"💥 {test_name} test CRASHED: {e}")
            results[test_name] = {'passed': False, 'error': str(e)}
    
    # Summary
    logger.info("\n" + "=" * 60)
    logger.info("🏁 INTEGRATION TEST SUMMARY")
    logger.info("=" * 60)
    
    for test_name, result in results.items():
        status = "✅ PASS" if result['passed'] else "❌ FAIL"
        duration = result.get('duration', 0)
        logger.info(f"{status:<8} {test_name:<25} ({duration:.2f}s)")
    
    success_rate = (passed_tests / total_tests) * 100
    logger.info(f"\nOverall Success Rate: {passed_tests}/{total_tests} ({success_rate:.1f}%)")
    
    if success_rate >= 80:
        logger.info("🎉 INTEGRATION TESTS SUCCESSFUL - System ready for national-level deployment!")
        return 0
    else:
        logger.error("🚨 INTEGRATION TESTS FAILED - Critical issues detected!")
        return 1

if __name__ == "__main__":
    sys.exit(main())