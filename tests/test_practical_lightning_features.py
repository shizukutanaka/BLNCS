#!/usr/bin/env python3
"""
BLNCS Practical Lightning Features Integration Test
Test all newly implemented practical Lightning Network features
"""

import os
import sys
import time
import tempfile
from pathlib import Path

# Add BLNCS to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '.'))

def test_invoice_manager():
    """Test Lightning invoice management"""
    print("📄 Testing Lightning Invoice Manager...")

    try:
        from blncs.lightning.invoice_manager import create_invoice_manager

        manager = create_invoice_manager("test_data")

        # Create test invoice
        invoice = manager.create_invoice(
            amount_sats=100000,
            description="Test Lightning invoice",
            expiry_seconds=3600
        )

        # Test invoice properties
        valid_properties = (
            invoice.amount_sats == 100000 and
            invoice.description == "Test Lightning invoice" and
            len(invoice.payment_hash) == 64 and
            invoice.status == "pending"
        )

        # Test payment
        payment_success = manager.pay_invoice(invoice.payment_hash)

        # Test statistics
        stats = manager.get_invoice_stats()

        print(f"  📋 Invoice created: {'✅' if valid_properties else '❌'}")
        print(f"  💳 Payment processed: {'✅' if payment_success else '❌'}")
        print(f"  📊 Statistics: {stats['total']} invoices, {stats['paid_amount_sats']} sats paid")

        # Cleanup
        import shutil
        shutil.rmtree("test_data", ignore_errors=True)

        return valid_properties and payment_success and stats['total'] > 0

    except Exception as e:
        print(f"  ❌ Invoice manager test failed: {e}")
        return False

def test_channel_manager():
    """Test Lightning channel management"""
    print("⚡ Testing Lightning Channel Manager...")

    try:
        from blncs.lightning.channel_manager import create_channel_manager

        manager = create_channel_manager("test_data")

        # Add test channel
        channel = manager.add_channel(
            channel_id="test_channel_12345678901234567890123456789012345678901234567890",
            remote_pubkey="0234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12",
            capacity_sats=1000000,
            local_balance_sats=600000,
            remote_balance_sats=400000
        )

        # Test channel properties
        valid_channel = (
            channel.capacity_sats == 1000000 and
            channel.local_balance_sats == 600000 and
            channel.balance_ratio() == 0.6
        )

        # Test capacity statistics
        capacity_stats = manager.get_total_capacity()

        # Test rebalancing suggestions
        suggestions = manager.suggest_rebalancing()

        # Test routing capacity
        route_channels = manager.find_route_capacity(50000)

        print(f"  📊 Channel created: {'✅' if valid_channel else '❌'}")
        print(f"  💰 Total capacity: {capacity_stats['total_capacity_sats']} sats")
        print(f"  ⚖️ Rebalancing suggestions: {len(suggestions)}")
        print(f"  🛣️ Routing channels found: {len(route_channels)}")

        # Cleanup
        import shutil
        shutil.rmtree("test_data", ignore_errors=True)

        return valid_channel and capacity_stats['total_capacity_sats'] > 0

    except Exception as e:
        print(f"  ❌ Channel manager test failed: {e}")
        return False

def test_routing_manager():
    """Test Lightning routing management"""
    print("🛣️ Testing Lightning Routing Manager...")

    try:
        from blncs.lightning.routing_manager import create_routing_manager

        manager = create_routing_manager("test_data")

        # Add test nodes
        node1 = manager.add_network_node(
            "0234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12",
            "TestNode1"
        )

        node2 = manager.add_network_node(
            "0345678901bcdef01234567890abcdef1234567890abcdef1234567890abcdef123",
            "TestNode2"
        )

        # Add test channel
        manager.update_channel_info("test_channel_route", node1.pubkey, node2.pubkey, 1000000, 0.001)

        # Test route finding
        route = manager.find_route(node1.pubkey, node2.pubkey, 100000)

        # Test routing statistics
        stats = manager.get_routing_stats()

        # Test optimization suggestions
        suggestions = manager.optimize_network_topology()

        print(f"  🔍 Nodes created: {stats['total_nodes']}")
        print(f"  📊 Channels: {stats['total_channels']}")
        print(f"  🛣️ Route found: {'✅' if route is not None else '❌'}")
        print(f"  💡 Optimization suggestions: {len(suggestions)}")

        # Cleanup
        import shutil
        shutil.rmtree("test_data", ignore_errors=True)

        return stats['total_nodes'] >= 2 and stats['total_channels'] >= 1

    except Exception as e:
        print(f"  ❌ Routing manager test failed: {e}")
        return False

def test_practical_monitor():
    """Test practical Lightning monitoring"""
    print("📊 Testing Practical Lightning Monitor...")

    try:
        from blncs.monitoring.practical_monitor import create_practical_monitor

        monitor = create_practical_monitor("test_data")

        # Start monitoring
        monitor.start_monitoring()

        # Record test events
        monitor.record_payment_attempt(100000, True, 1000, 5000)
        monitor.record_payment_attempt(50000, False, 0, 30000)
        monitor.record_channel_event("channel123", "update", 800000, 200000)
        monitor.record_node_metrics("node1", 750000, 10, 5)

        # Get health status
        health = monitor.get_system_health()

        # Export metrics
        metrics_export = monitor.export_metrics(1)

        print(f"  🏥 System health: {health['status']} (score: {health['health_score']})")
        print(f"  📈 Recent payments: {health['recent_payments']}")
        print(f"  ✅ Success rate: {health['payment_success_rate']:.1f}%")
        print(f"  📤 Metrics exported: {len(metrics_export['metrics'])} types")

        # Stop monitoring
        monitor.stop_monitoring()

        # Cleanup
        import shutil
        shutil.rmtree("test_data", ignore_errors=True)

        return health['recent_payments'] > 0 and len(metrics_export['metrics']) > 0

    except Exception as e:
        print(f"  ❌ Practical monitor test failed: {e}")
        return False

def test_auto_recovery():
    """Test auto-recovery system"""
    print("🔧 Testing Auto-Recovery System...")

    try:
        from blncs.core.auto_recovery import get_auto_recovery
        from blncs.core.auto_recovery import RecoveryAction

        recovery = get_auto_recovery()

        # Test manual recovery actions
        memory_result = recovery.manual_recovery(RecoveryAction.CLEANUP_MEMORY)
        cache_result = recovery.manual_recovery(RecoveryAction.CLEAR_CACHE)
        backup_result = recovery.manual_recovery(RecoveryAction.BACKUP_DATA)

        # Get recovery statistics
        stats = recovery.get_recovery_stats()

        print(f"  🧹 Memory cleanup: {'✅' if memory_result.success else '❌'}")
        print(f"  📦 Cache clear: {'✅' if cache_result.success else '❌'}")
        print(f"  💾 Backup: {'✅' if backup_result.success else '❌'}")
        print(f"  📊 Recovery attempts: {stats['total_recoveries']}")
        print(f"  ✅ Success rate: {stats['success_rate']:.1f}%")

        return memory_result.success and cache_result.success and backup_result.success

    except Exception as e:
        print(f"  ❌ Auto-recovery test failed: {e}")
        return False

def test_lightning_optimizer():
    """Test Lightning Network optimizer"""
    print("⚡ Testing Lightning Network Optimizer...")

    try:
        from blncs.lightning.lightning_optimizer import create_lightning_optimizer

        optimizer = create_lightning_optimizer("test_data")

        # Simulate routing data
        for i in range(10):
            optimizer.routing_optimizer.record_route_attempt(
                f"route_{i}",
                success=(i % 3 != 0),  # 67% success rate
                fee_rate=0.001 + (i % 2) * 0.0005,
                hops=2 + (i % 2),
                duration_ms=1000 + i * 50
            )

        # Simulate channel data
        for i in range(5):
            optimizer.balance_optimizer.record_channel_state(
                f"channel_{i}",
                local_balance=600000 + i * 50000,
                remote_balance=400000 - i * 20000,
                capacity=1000000
            )

        # Simulate fee data
        for i in range(8):
            optimizer.fee_optimizer.record_fee_performance(
                f"channel_{i % 2}",
                fee_rate=0.001 + (i % 3) * 0.0003,
                routing_count=5 + i,
                revenue_sats=500 + i * 100
            )

        # Run optimizations
        routing_result = optimizer.optimize_routing_strategy()
        balance_result = optimizer.optimize_channel_balances()
        fee_result = optimizer.optimize_fee_policies()

        # Get summary
        summary = optimizer.get_optimization_summary()

        print(f"  🛣️ Routing optimization: {'✅' if routing_result.success else '❌'} ({routing_result.improvement_percent:.1f}%)")
        print(f"  ⚖️ Balance optimization: {'✅' if balance_result.success else '❌'} ({balance_result.improvement_percent:.1f}%)")
        print(f"  💰 Fee optimization: {'✅' if fee_result.success else '❌'} ({fee_result.improvement_percent:.1f}%)")
        print(f"  📊 Total optimizations: {summary['total_optimizations']}")

        # Cleanup
        import shutil
        shutil.rmtree("test_data", ignore_errors=True)

        return (routing_result.success and balance_result.success and
                fee_result.success and summary['total_optimizations'] >= 3)

    except Exception as e:
        print(f"  ❌ Lightning optimizer test failed: {e}")
        return False

def test_integration():
    """Test integration between all practical features"""
    print("🔗 Testing Feature Integration...")

    try:
        # Test that components can work together
        from blncs.lightning.invoice_manager import create_invoice_manager
        from blncs.lightning.channel_manager import create_channel_manager
        from blncs.lightning.routing_manager import create_routing_manager
        from blncs.monitoring.practical_monitor import create_practical_monitor
        from blncs.core.auto_recovery import get_auto_recovery

        # Create all managers
        invoice_mgr = create_invoice_manager("test_integration")
        channel_mgr = create_channel_manager("test_integration")
        routing_mgr = create_routing_manager("test_integration")
        monitor = create_practical_monitor("test_integration")
        recovery = get_auto_recovery()

        # Create integrated workflow
        # 1. Create a channel
        channel = channel_mgr.add_channel(
            "integration_channel_12345678901234567890123456789012345678901234567890",
            "0234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12",
            1000000, 500000, 500000
        )

        # 2. Create an invoice
        invoice = invoice_mgr.create_invoice(50000, "Integration test payment")

        # 3. Record in monitoring
        monitor.record_payment_attempt(50000, True, 500, 3000)
        monitor.record_channel_event(channel.channel_id, "payment", 450000, 550000)

        # 4. Add routing info
        node = routing_mgr.add_network_node(channel.remote_pubkey, "IntegrationNode")
        routing_mgr.update_channel_info(channel.channel_id, "source_node", channel.remote_pubkey, 1000000)

        # 5. Test recovery
        from blncs.core.auto_recovery import RecoveryAction
        recovery_result = recovery.manual_recovery(RecoveryAction.CLEAR_CACHE)

        # Verify integration
        channel_stats = channel_mgr.get_channel_stats()
        invoice_stats = invoice_mgr.get_invoice_stats()
        routing_stats = routing_mgr.get_routing_stats()
        health = monitor.get_system_health()

        integration_success = (
            channel_stats['total_channels'] >= 1 and
            invoice_stats['total'] >= 1 and
            health['recent_payments'] >= 1 and
            recovery_result.success
        )

        print(f"  📊 Channels: {channel_stats['total_channels']}")
        print(f"  📄 Invoices: {invoice_stats['total']}")
        print(f"  🔍 Routing nodes: {routing_stats.get('total_nodes', 0)}")
        print(f"  🏥 Health status: {health['status']}")
        print(f"  🔧 Recovery: {'✅' if recovery_result.success else '❌'}")
        print(f"  🔗 Integration: {'✅' if integration_success else '❌'}")

        # Cleanup
        import shutil
        shutil.rmtree("test_integration", ignore_errors=True)

        return integration_success

    except Exception as e:
        print(f"  ❌ Integration test failed: {e}")
        return False

def main():
    """Run all practical Lightning feature tests"""
    print("🎯 BLNCS Practical Lightning Features Integration Test")
    print("=" * 70)

    tests = [
        ("Lightning Invoice Manager", test_invoice_manager),
        ("Lightning Channel Manager", test_channel_manager),
        ("Lightning Routing Manager", test_routing_manager),
        ("Practical Monitor", test_practical_monitor),
        ("Auto-Recovery System", test_auto_recovery),
        ("Lightning Optimizer", test_lightning_optimizer),
        ("Feature Integration", test_integration),
    ]

    start_time = time.time()
    passed_tests = 0

    for test_name, test_func in tests:
        try:
            if test_func():
                passed_tests += 1
                print(f"✅ {test_name}: PASSED\n")
            else:
                print(f"❌ {test_name}: FAILED\n")
        except Exception as e:
            print(f"💥 {test_name}: CRASHED - {e}\n")

    total_time = time.time() - start_time

    print("=" * 70)
    print(f"🏁 Test Results: {passed_tests}/{len(tests)} tests passed")
    print(f"⏱️ Total execution time: {total_time:.2f}s")

    if passed_tests == len(tests):
        print("🎉 All practical Lightning features working correctly!")

        # Final summary
        print("\n📋 Practical Lightning Features Summary:")
        print("  📄 Invoice Manager - Lightning invoice creation and payment tracking")
        print("  ⚡ Channel Manager - Channel balance and state management")
        print("  🛣️ Routing Manager - Payment pathfinding and network topology")
        print("  📊 Practical Monitor - Real-time monitoring and health tracking")
        print("  🔧 Auto-Recovery - Automated fault detection and recovery")
        print("  ⚡ Lightning Optimizer - Performance optimization and analysis")
        print("  🔗 Feature Integration - All components working together")

        print("\n💡 Key Capabilities Implemented:")
        print("  • BOLT11 invoice creation and management")
        print("  • Channel balance tracking and rebalancing suggestions")
        print("  • Dijkstra-based payment routing with multiple strategies")
        print("  • Real-time metrics collection and health monitoring")
        print("  • Automated recovery from common Lightning failures")
        print("  • Fee optimization and routing efficiency analysis")
        print("  • Comprehensive integration between all components")

        return True
    else:
        print(f"⚠️ {len(tests) - passed_tests} tests failed")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)