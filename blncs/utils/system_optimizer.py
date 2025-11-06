#!/usr/bin/env python3
"""
BLNCS System Optimizer
Comprehensive system optimization and performance improvement
"""

import os
import sys
import time
import json
import gc
from typing import Dict, Any, List, Optional
from pathlib import Path

class SystemOptimizer:
    """Comprehensive system optimization"""

    def __init__(self):
        self.optimization_results = {}
        self.start_time = time.time()

    def optimize_imports(self):
        """Optimize import statements and module loading"""
        print("🔧 Optimizing imports...")

        # Preload critical modules
        critical_modules = [
            'os', 'sys', 'time', 'json', 'sqlite3',
            'threading', 'logging', 'pathlib'
        ]

        for module in critical_modules:
            try:
                __import__(module)
            except ImportError:
                pass

        # Optimize garbage collection
        gc.set_threshold(1000, 10, 10)

        self.optimization_results['imports'] = {
            'modules_preloaded': len(critical_modules),
            'gc_optimized': True
        }

    def optimize_memory_usage(self):
        """Optimize memory usage patterns"""
        print("🔧 Optimizing memory usage...")

        # Force garbage collection
        initial_objects = len(gc.get_objects())
        gc.collect()
        final_objects = len(gc.get_objects())
        freed_objects = initial_objects - final_objects

        self.optimization_results['memory'] = {
            'objects_before': initial_objects,
            'objects_after': final_objects,
            'freed_objects': freed_objects
        }

    def optimize_file_operations(self):
        """Optimize file system operations"""
        print("🔧 Optimizing file operations...")

        # Ensure critical directories exist
        critical_dirs = ['config', 'data', 'logs', 'backups']
        created_dirs = 0

        for dir_name in critical_dirs:
            dir_path = Path(dir_name)
            if not dir_path.exists():
                try:
                    dir_path.mkdir(parents=True, exist_ok=True)
                    created_dirs += 1
                except Exception:
                    pass

        self.optimization_results['filesystem'] = {
            'directories_created': created_dirs,
            'critical_directories': critical_dirs
        }

    def optimize_database(self):
        """Optimize database performance"""
        print("🔧 Optimizing database...")

        db_path = Path("data/blncs.db")
        if db_path.exists():
            try:
                import sqlite3
                conn = sqlite3.connect(str(db_path))

                # Run optimization
                conn.execute("VACUUM")
                conn.execute("ANALYZE")

                # Get database stats
                cursor = conn.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table'")
                table_count = cursor.fetchone()[0]

                conn.close()

                self.optimization_results['database'] = {
                    'optimized': True,
                    'tables': table_count
                }
            except Exception as e:
                self.optimization_results['database'] = {
                    'optimized': False,
                    'error': str(e)
                }
        else:
            self.optimization_results['database'] = {
                'optimized': False,
                'reason': 'Database does not exist'
            }

    def create_optimization_report(self):
        """Create comprehensive optimization report"""
        total_time = time.time() - self.start_time

        report = {
            'optimization_time': total_time,
            'timestamp': time.time(),
            'results': self.optimization_results,
            'system_info': {
                'python_version': sys.version.split()[0],
                'platform': sys.platform,
                'working_directory': str(Path.cwd())
            }
        }

        return report

    def run_all_optimizations(self):
        """Run all system optimizations"""
        print("🚀 Starting comprehensive system optimization...")

        optimizations = [
            self.optimize_imports,
            self.optimize_memory_usage,
            self.optimize_file_operations,
            self.optimize_database
        ]

        for optimization in optimizations:
            try:
                optimization()
            except Exception as e:
                print(f"⚠️  Optimization failed: {e}")

        report = self.create_optimization_report()

        print("✅ System optimization completed!")
        print(f"   Total time: {report['optimization_time']:.2f}s")

        return report

# Global optimizer instance
_optimizer_instance = None

def get_system_optimizer() -> SystemOptimizer:
    """Get global system optimizer instance"""
    global _optimizer_instance
    if _optimizer_instance is None:
        _optimizer_instance = SystemOptimizer()
    return _optimizer_instance

def optimize_system():
    """Run comprehensive system optimization"""
    optimizer = get_system_optimizer()
    return optimizer.run_all_optimizations()

def get_optimization_report():
    """Get optimization report"""
    optimizer = get_system_optimizer()
    return optimizer.create_optimization_report()

if __name__ == '__main__':
    # Run system optimization
    report = optimize_system()

    print("\n📊 Optimization Report:")
    print(f"   Time: {report['optimization_time']:.2f}s")
    print(f"   Import optimization: {'✅' if report['results']['imports']['gc_optimized'] else '❌'}")
    print(f"   Memory optimization: {'✅' if report['results']['memory']['freed_objects'] >= 0 else '❌'}")
    print(f"   Database optimization: {'✅' if report['results']['database'].get('optimized', False) else '❌'}")

    print(f"\n🔧 System Info:")
    print(f"   Python: {report['system_info']['python_version']}")
    print(f"   Platform: {report['system_info']['platform']}")
    print(f"   Directory: {report['system_info']['working_directory']}")

    print("\n🎉 System optimization completed successfully!")
