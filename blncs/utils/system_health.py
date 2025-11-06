#!/usr/bin/env python3
"""
BLNCS System Health Monitor
Lightweight system monitoring and health checks
"""

import os
import sys
import psutil
import sqlite3
import json
from datetime import datetime
from pathlib import Path

def check_system_health():
    """Lightweight system health check"""
    health_score = 100
    issues = []

    try:
        # Check disk space
        disk_usage = psutil.disk_usage('/')
        disk_percent = (disk_usage.used / disk_usage.total) * 100

        if disk_percent > 95:
            issues.append(f"Critical disk usage: {disk_percent:.1f}%")
            health_score -= 50
        elif disk_percent > 85:
            issues.append(f"High disk usage: {disk_percent:.1f}%")
            health_score -= 20

        # Check memory
        memory = psutil.virtual_memory()
        if memory.percent > 90:
            issues.append(f"High memory usage: {memory.percent:.1f}%")
            health_score -= 15

        # Check critical files
        critical_files = [
            'blncs_main.py',
            'config/blncs.json'
        ]

        for file_path in critical_files:
            if not Path(file_path).exists():
                issues.append(f"Missing critical file: {file_path}")
                health_score -= 25

        # Check database
        db_path = 'data/blncs.db'
        if Path(db_path).exists():
            try:
                conn = sqlite3.connect(db_path)
                cursor = conn.execute("PRAGMA integrity_check")
                result = cursor.fetchone()[0]
                conn.close()

                if result != 'ok':
                    issues.append(f"Database integrity issue: {result}")
                    health_score -= 30
            except Exception as e:
                issues.append(f"Database check failed: {e}")
                health_score -= 10

    except Exception as e:
        issues.append(f"Health check error: {e}")
        health_score -= 5

    return {
        'health_score': max(0, health_score),
        'issues': issues,
        'timestamp': datetime.now().isoformat()
    }

def optimize_system():
    """Lightweight system optimization"""
    optimizations = []

    try:
        # Clean up temporary files
        temp_dirs = ['tmp', '/tmp']
        cleaned_files = 0

        for temp_dir in temp_dirs:
            if Path(temp_dir).exists():
                for file in Path(temp_dir).glob('*'):
                    if file.is_file() and (datetime.now() - datetime.fromtimestamp(file.stat().st_mtime)).days > 1:
                        try:
                            file.unlink()
                            cleaned_files += 1
                        except:
                            pass

        if cleaned_files > 0:
            optimizations.append(f"Cleaned {cleaned_files} temporary files")

        # Optimize database if exists
        db_path = 'data/blncs.db'
        if Path(db_path).exists():
            try:
                conn = sqlite3.connect(db_path)
                conn.execute('VACUUM')
                conn.execute('REINDEX')
                conn.close()
                optimizations.append("Database optimized")
            except Exception as e:
                optimizations.append(f"Database optimization failed: {e}")

    except Exception as e:
        optimizations.append(f"Optimization error: {e}")

    return optimizations

def main():
    """Main health check function"""
    if len(sys.argv) > 1 and sys.argv[1] == '--optimize':
        print("🔧 Running system optimization...")
        optimizations = optimize_system()
        for opt in optimizations:
            print(f"✅ {opt}")
        print("Optimization complete!")
    else:
        print("🏥 System Health Check")
        print("=" * 40)

        health = check_system_health()

        print(f"Health Score: {health['health_score']}/100")

        if health['health_score'] >= 90:
            print("✅ EXCELLENT - System is healthy")
        elif health['health_score'] >= 70:
            print("⚠️  GOOD - Minor issues detected")
        elif health['health_score'] >= 50:
            print("⚠️  WARNING - Several issues need attention")
        else:
            print("❌ CRITICAL - Immediate action required")

        if health['issues']:
            print(f"\n🔧 Issues found ({len(health['issues'])}):")
            for issue in health['issues']:
                print(f"  • {issue}")

        # Output JSON for automation
        if len(sys.argv) > 1 and sys.argv[1] == '--json':
            print(f"\n{json.dumps(health, indent=2)}")

if __name__ == '__main__':
    main()
