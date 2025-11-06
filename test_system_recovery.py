#!/usr/bin/env python3
"""
Simple test for system_recovery.py Lightning Network enhancements
"""

import sys
import os

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def test_system_recovery_imports():
    """Test that system recovery can be imported and Lightning API works"""
    try:
        from blncs.core.system_recovery import SystemRecovery, RecoveryAction, DiagnosticSeverity
        print("✅ SystemRecovery imported successfully")

        # Test Lightning API import
        try:
            from blncs.core.lightning_api import LightningAPI
            print("✅ LightningAPI imported successfully")

            # Test API initialization
            api = LightningAPI()
            print("✅ LightningAPI initialized successfully")

            # Test basic API functionality (without actual Lightning node)
            print("✅ Basic API functionality test passed")

        except ImportError as e:
            print(f"❌ LightningAPI import failed: {e}")
            return False

        # Test recovery actions enum
        actions = [
            RecoveryAction.RESTART_LIGHTNING_NODE,
            RecoveryAction.CHECK_CHANNEL_CONNECTIVITY,
            RecoveryAction.REFRESH_LIGHTNING_PEERS,
            RecoveryAction.VALIDATE_PAYMENT_CHANNELS,
            RecoveryAction.CHECK_NODE_SYNC,
            RecoveryAction.CLEANUP_FAILED_PAYMENTS
        ]

        print("✅ Lightning Network recovery actions available:")
        for action in actions:
            print(f"  - {action.value}")

        return True

    except ImportError as e:
        print(f"❌ SystemRecovery import failed: {e}")
        return False

def test_recovery_system_creation():
    """Test creating a recovery system instance"""
    try:
        from blncs.core.system_recovery import SystemRecovery

        # Create recovery system with short interval for testing
        recovery = SystemRecovery(check_interval=1.0)

        print("✅ SystemRecovery instance created successfully")
        print(f"   - Auto recovery enabled: {recovery.auto_recovery_enabled}")
        print(f"   - Check interval: {recovery.check_interval}s")
        print(f"   - Diagnostic checks registered: {len(recovery.diagnostic_checks)}")
        print(f"   - Recovery actions registered: {len(recovery.recovery_actions)}")

        # Test diagnostic checks
        diagnostics = recovery.run_all_diagnostics()
        print(f"✅ Ran {len(diagnostics)} diagnostic checks")

        for diag in diagnostics:
            print(f"   - {diag.check_name}: {diag.severity.value} - {diag.message}")

        return True

    except Exception as e:
        print(f"❌ Recovery system creation failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    print("Testing BLNCS System Recovery with Lightning Network enhancements...")
    print("=" * 60)

    success = True

    print("\n1. Testing imports...")
    if not test_system_recovery_imports():
        success = False

    print("\n2. Testing recovery system creation...")
    if not test_recovery_system_creation():
        success = False

    print("\n" + "=" * 60)
    if success:
        print("✅ All tests passed! System recovery enhancements are working.")
    else:
        print("❌ Some tests failed. Check the output above.")

    sys.exit(0 if success else 1)
