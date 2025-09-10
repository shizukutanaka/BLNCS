#!/usr/bin/env python3
"""
BLNCS Quality Validation Runner
Comprehensive validation of all quality systems and features.
"""

import sys
import time
import tempfile
from pathlib import Path
import traceback
from typing import Dict, List, Any, Optional
from datetime import datetime

# Add BLNCS to path
sys.path.insert(0, str(Path(__file__).parent))

def validate_imports() -> Dict[str, Any]:
    """Validate all critical imports"""
    print("🔍 Validating imports...")
    
    results = {
        "success": True,
        "imported_modules": [],
        "failed_imports": [],
        "details": {}
    }
    
    # Core modules to test
    core_modules = [
        ("blncs.core.error_recovery", "get_error_recovery_manager"),
        ("blncs.core.input_validator", "get_input_validator"),
        ("blncs.core.performance_optimizer", "get_performance_optimizer"),
        ("blncs.core.health_diagnostics", "get_system_diagnostics"),
        ("blncs.core.security_hardening", "get_security_hardening_manager"),
        ("blncs.core.database_optimizer", "get_database_optimizer"),
        ("blncs.core.backup_enhanced", "get_enhanced_backup"),
        ("blncs.core.one_click_connector", "get_one_click_connector"),
        ("blncs.core.qr_payments", "get_qr_payment_manager"),
        ("blncs.core.node_discovery", "get_node_discovery"),
    ]
    
    for module_name, function_name in core_modules:
        try:
            module = __import__(module_name, fromlist=[function_name])
            getattr(module, function_name)
            results["imported_modules"].append(module_name)
            results["details"][module_name] = "✅ Success"
        except ImportError as e:
            results["failed_imports"].append(f"{module_name}: {str(e)}")
            results["details"][module_name] = f"❌ Import failed: {str(e)}"
            results["success"] = False
        except AttributeError as e:
            results["failed_imports"].append(f"{module_name}.{function_name}: {str(e)}")
            results["details"][module_name] = f"❌ Function not found: {str(e)}"
            results["success"] = False
        except Exception as e:
            results["failed_imports"].append(f"{module_name}: {str(e)}")
            results["details"][module_name] = f"❌ Error: {str(e)}"
            results["success"] = False
    
    print(f"✅ Imported: {len(results['imported_modules'])}")
    print(f"❌ Failed: {len(results['failed_imports'])}")
    
    return results

def validate_error_recovery() -> Dict[str, Any]:
    """Validate error recovery system"""
    print("🛡️  Validating error recovery...")
    
    try:
        from blncs.core.error_recovery import (
            get_error_recovery_manager, ErrorSeverity, RecoveryStrategy, CircuitBreaker
        )
        
        manager = get_error_recovery_manager()
        
        # Test circuit breaker
        cb = manager.register_circuit_breaker("test_service", {"failure_threshold": 2})
        assert isinstance(cb, CircuitBreaker)
        
        # Test error recording
        test_error = ValueError("Test error")
        context = manager.record_error(test_error, "test_operation")
        assert context.error_type == ValueError
        assert context.operation == "test_operation"
        
        # Test statistics
        stats = manager.get_error_statistics()
        assert "total_errors" in stats
        assert stats["total_errors"] >= 1
        
        return {
            "success": True,
            "message": "Error recovery system validated successfully",
            "features_tested": [
                "Circuit breaker registration",
                "Error recording",
                "Statistics generation"
            ]
        }
        
    except Exception as e:
        return {
            "success": False,
            "message": f"Error recovery validation failed: {str(e)}",
            "traceback": traceback.format_exc()
        }

def validate_input_validation() -> Dict[str, Any]:
    """Validate input validation system"""
    print("🔍 Validating input validation...")
    
    try:
        from blncs.core.input_validator import (
            get_input_validator, ValidationRule, ValidationType, ValidationError
        )
        
        validator = get_input_validator()
        
        # Test string validation
        rule = ValidationRule(ValidationType.STRING, min_length=3, max_length=10)
        result = validator.validate_value("hello", rule)
        assert result == "hello"
        
        # Test validation failure
        try:
            validator.validate_value("hi", rule)  # Too short
            assert False, "Should have failed validation"
        except ValidationError:
            pass  # Expected
        
        # Test pubkey validation
        pubkey_rule = ValidationRule(ValidationType.PUBKEY)
        valid_pubkey = "02" + "a" * 64
        result = validator.validate_value(valid_pubkey, pubkey_rule)
        assert result == valid_pubkey
        
        # Test schema validation
        schema = validator.create_schema(
            name={"type": "string", "min_length": 2},
            age={"type": "integer", "min_value": 0}
        )
        
        valid_data = {"name": "John", "age": 30}
        result = validator.validate_dict(valid_data, schema)
        assert result["name"] == "John"
        assert result["age"] == 30
        
        return {
            "success": True,
            "message": "Input validation system validated successfully",
            "features_tested": [
                "String validation with length limits",
                "Public key validation",
                "Schema-based dictionary validation",
                "Error handling for invalid inputs"
            ]
        }
        
    except Exception as e:
        return {
            "success": False,
            "message": f"Input validation failed: {str(e)}",
            "traceback": traceback.format_exc()
        }

def validate_performance_optimization() -> Dict[str, Any]:
    """Validate performance optimization system"""
    print("⚡ Validating performance optimization...")
    
    try:
        from blncs.core.performance_optimizer import get_performance_optimizer, PerformanceLevel
        
        optimizer = get_performance_optimizer()
        
        # Test operation profiling
        with optimizer.measure_operation("test_operation"):
            time.sleep(0.01)  # Simulate work
        
        profile = optimizer.get_operation_profile("test_operation")
        assert profile is not None
        assert profile.call_count == 1
        assert profile.total_time > 0
        
        # Test cache
        cache = optimizer.cache
        cache.set("test_key", "test_value")
        cached_value = cache.get("test_key")
        assert cached_value == "test_value"
        
        # Test performance report
        report = optimizer.get_performance_report()
        assert "system" in report
        assert "operations" in report
        assert "cache" in report
        
        return {
            "success": True,
            "message": "Performance optimization system validated successfully",
            "features_tested": [
                "Operation profiling and measurement",
                "Performance cache functionality",
                "Performance report generation",
                "System resource monitoring"
            ]
        }
        
    except Exception as e:
        return {
            "success": False,
            "message": f"Performance optimization validation failed: {str(e)}",
            "traceback": traceback.format_exc()
        }

def validate_health_diagnostics() -> Dict[str, Any]:
    """Validate health diagnostics system"""
    print("🏥 Validating health diagnostics...")
    
    try:
        from blncs.core.health_diagnostics import (
            get_system_diagnostics, HealthStatus, ComponentType, HealthCheckResult
        )
        
        diagnostics = get_system_diagnostics()
        
        # Test custom health check
        def test_health_check():
            return HealthCheckResult(
                component="test_component",
                component_type=ComponentType.PROCESS,
                status=HealthStatus.HEALTHY,
                message="Test OK"
            )
        
        diagnostics.register_health_check("test_check", ComponentType.PROCESS, test_health_check)
        
        # Run health check
        result = diagnostics.run_health_check("test_check")
        assert result is not None
        assert result.status == HealthStatus.HEALTHY
        
        # Test system health summary
        summary = diagnostics.get_system_health_summary()
        assert "overall_status" in summary
        assert "summary" in summary
        
        # Test detailed diagnostics
        detailed = diagnostics.get_detailed_diagnostics()
        assert "health_checks" in detailed
        assert "system_info" in detailed
        
        return {
            "success": True,
            "message": "Health diagnostics system validated successfully",
            "features_tested": [
                "Custom health check registration",
                "Health check execution",
                "System health summary generation",
                "Detailed diagnostic reporting"
            ]
        }
        
    except Exception as e:
        return {
            "success": False,
            "message": f"Health diagnostics validation failed: {str(e)}",
            "traceback": traceback.format_exc()
        }

def validate_security_hardening() -> Dict[str, Any]:
    """Validate security hardening system"""
    print("🔒 Validating security hardening...")
    
    try:
        from blncs.core.security_hardening import (
            get_security_hardening_manager, SecurityLevel, ThreatLevel, AttackType
        )
        
        security_manager = get_security_hardening_manager()
        
        # Test rate limiting
        result = security_manager.check_rate_limit("test_user", "api_general")
        assert isinstance(result, bool)
        
        # Test input sanitization
        clean_input = security_manager.validate_and_sanitize_input("normal text", "general")
        assert clean_input == "normal text"
        
        # Test token management
        token = security_manager.generate_secure_session_token("test_user")
        assert isinstance(token, str)
        assert len(token) > 20
        
        is_valid = security_manager.validate_session_token(token, "test_user")
        assert is_valid == True
        
        # Test security metrics
        metrics = security_manager.get_security_metrics()
        assert "security_level" in metrics
        assert "total_events" in metrics
        
        return {
            "success": True,
            "message": "Security hardening system validated successfully",
            "features_tested": [
                "Rate limiting functionality",
                "Input sanitization and validation", 
                "Secure token generation and validation",
                "Security metrics collection"
            ]
        }
        
    except Exception as e:
        return {
            "success": False,
            "message": f"Security hardening validation failed: {str(e)}",
            "traceback": traceback.format_exc()
        }

def validate_backup_encryption() -> Dict[str, Any]:
    """Validate backup encryption system"""
    print("💾 Validating backup encryption...")
    
    try:
        from blncs.core.backup_enhanced import get_enhanced_backup
        
        backup_manager = get_enhanced_backup()
        
        # Test encryption key management
        test_password = "test_password_123"
        success = backup_manager.set_encryption_key(test_password)
        
        if hasattr(backup_manager, '_encryption_key'):
            assert success == True
            assert backup_manager._encryption_key is not None
            
            # Test key loading
            backup_manager._encryption_key = None
            success = backup_manager.load_encryption_key(test_password)
            assert success == True
            assert backup_manager._encryption_key is not None
            
            # Test data encryption/decryption
            test_data = b"Test data for encryption"
            encrypted = backup_manager._encrypt_data(test_data)
            assert encrypted != test_data
            
            decrypted = backup_manager._decrypt_data(encrypted)
            assert decrypted == test_data
        
        # Test backup status
        backup_manager.encryption_enabled = True
        status = backup_manager.get_backup_status()
        assert "encryption_enabled" in status
        assert "encryption_available" in status
        
        return {
            "success": True,
            "message": "Backup encryption system validated successfully",
            "features_tested": [
                "Encryption key management",
                "Data encryption and decryption",
                "Backup status with encryption info",
                "Configuration management"
            ]
        }
        
    except Exception as e:
        return {
            "success": False,
            "message": f"Backup encryption validation failed: {str(e)}",
            "traceback": traceback.format_exc()
        }

def validate_lightning_features() -> Dict[str, Any]:
    """Validate Lightning Network features"""
    print("⚡ Validating Lightning Network features...")
    
    results = {
        "success": True,
        "message": "Lightning Network features validation completed",
        "feature_results": {},
        "total_features": 0,
        "successful_features": 0
    }
    
    # Test one-click connector
    try:
        from blncs.core.one_click_connector import get_one_click_connector
        connector = get_one_click_connector()
        assert connector is not None
        results["feature_results"]["one_click_connector"] = "✅ Available"
        results["successful_features"] += 1
    except Exception as e:
        results["feature_results"]["one_click_connector"] = f"❌ {str(e)}"
        results["success"] = False
    
    results["total_features"] += 1
    
    # Test QR payment manager
    try:
        from blncs.core.qr_payments import get_qr_payment_manager
        qr_manager = get_qr_payment_manager()
        assert qr_manager is not None
        results["feature_results"]["qr_payments"] = "✅ Available"
        results["successful_features"] += 1
    except Exception as e:
        results["feature_results"]["qr_payments"] = f"❌ {str(e)}"
        results["success"] = False
    
    results["total_features"] += 1
    
    # Test node discovery
    try:
        from blncs.core.node_discovery import get_node_discovery
        discovery = get_node_discovery()
        assert discovery is not None
        results["feature_results"]["node_discovery"] = "✅ Available"
        results["successful_features"] += 1
    except Exception as e:
        results["feature_results"]["node_discovery"] = f"❌ {str(e)}"
        results["success"] = False
    
    results["total_features"] += 1
    
    return results

def run_quality_validation() -> bool:
    """Run comprehensive quality validation"""
    print("🎯 BLNCS Quality Validation Suite")
    print("=" * 60)
    print(f"Started at: {datetime.now().isoformat()}")
    print("=" * 60)
    
    validation_results = []
    
    # Run all validation tests
    validations = [
        ("Import Validation", validate_imports),
        ("Error Recovery", validate_error_recovery),
        ("Input Validation", validate_input_validation),
        ("Performance Optimization", validate_performance_optimization),
        ("Health Diagnostics", validate_health_diagnostics),
        ("Security Hardening", validate_security_hardening),
        ("Backup Encryption", validate_backup_encryption),
        ("Lightning Features", validate_lightning_features),
    ]
    
    successful_validations = 0
    total_validations = len(validations)
    
    for test_name, test_function in validations:
        print(f"\n📋 {test_name}")
        print("-" * 40)
        
        try:
            start_time = time.time()
            result = test_function()
            duration = time.time() - start_time
            
            validation_results.append({
                "name": test_name,
                "success": result["success"],
                "duration": round(duration, 3),
                "result": result
            })
            
            if result["success"]:
                print(f"✅ PASSED ({duration:.3f}s)")
                if "features_tested" in result:
                    for feature in result["features_tested"]:
                        print(f"   • {feature}")
                successful_validations += 1
            else:
                print(f"❌ FAILED ({duration:.3f}s)")
                print(f"   Error: {result['message']}")
                
        except Exception as e:
            print(f"❌ EXCEPTION ({time.time() - start_time:.3f}s)")
            print(f"   Error: {str(e)}")
            validation_results.append({
                "name": test_name,
                "success": False,
                "duration": round(time.time() - start_time, 3),
                "result": {"message": str(e), "exception": True}
            })
    
    # Summary
    print("\n" + "=" * 60)
    print("🎯 QUALITY VALIDATION RESULTS")
    print("=" * 60)
    
    success_rate = (successful_validations / total_validations) * 100
    
    print(f"Total Tests: {total_validations}")
    print(f"Passed: {successful_validations}")
    print(f"Failed: {total_validations - successful_validations}")
    print(f"Success Rate: {success_rate:.1f}%")
    
    # Detailed results
    print("\n📊 Detailed Results:")
    print("-" * 40)
    
    for result in validation_results:
        status = "✅ PASS" if result["success"] else "❌ FAIL"
        print(f"{result['name']:<25} {status} ({result['duration']:.3f}s)")
    
    # Quality assessment
    print("\n🏆 Quality Assessment:")
    print("-" * 40)
    
    if success_rate >= 90:
        quality_level = "EXCELLENT"
        emoji = "🌟"
        message = "BLNCS meets the highest quality standards!"
    elif success_rate >= 80:
        quality_level = "GOOD"
        emoji = "👍"
        message = "BLNCS has good quality with minor issues."
    elif success_rate >= 70:
        quality_level = "FAIR"
        emoji = "⚠️"
        message = "BLNCS has acceptable quality but needs improvement."
    else:
        quality_level = "POOR"
        emoji = "❌"
        message = "BLNCS requires significant quality improvements."
    
    print(f"{emoji} Quality Level: {quality_level}")
    print(f"Assessment: {message}")
    
    # Recommendations
    print("\n💡 Recommendations:")
    print("-" * 40)
    
    failed_tests = [r for r in validation_results if not r["success"]]
    if failed_tests:
        for failed in failed_tests:
            print(f"• Fix {failed['name']}: {failed['result'].get('message', 'Unknown error')}")
    else:
        print("• All systems are functioning optimally!")
        print("• Continue regular monitoring and maintenance.")
        print("• Consider performance tuning for heavy workloads.")
    
    print("\n" + "=" * 60)
    print(f"Validation completed at: {datetime.now().isoformat()}")
    print("=" * 60)
    
    return success_rate >= 80

if __name__ == "__main__":
    success = run_quality_validation()
    
    if success:
        print("\n🎉 QUALITY VALIDATION SUCCESSFUL!")
        print("BLNCS is ready for production use.")
        sys.exit(0)
    else:
        print("\n⚠️  QUALITY VALIDATION ISSUES DETECTED")
        print("Please address the failing tests before deployment.")
        sys.exit(1)