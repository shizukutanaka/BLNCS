#!/usr/bin/env python3
"""BLRCS パフォーマンスベンチマーク実行スクリプト"""

import sys
import time
import json
from pathlib import Path

# Add BLRCS to path
sys.path.insert(0, str(Path(__file__).parent))

from blrcs.benchmark import Benchmark

def run_comprehensive_benchmarks():
    """包括的ベンチマーク実行"""
    print("🚀 BLRCS パフォーマンスベンチマーク開始")
    print("=" * 60)
    
    benchmark = Benchmark()
    
    # クイックベンチマーク
    print("\n📊 クイックベンチマーク実行中...")
    quick_results = benchmark.run_quick_benchmark()
    
    print(f"\n✅ クイックベンチマーク結果:")
    print(f"  CPU スコア: {quick_results['cpu_score']:.2f}")
    print(f"  メモリスコア: {quick_results['memory_score']:.2f}")
    print(f"  I/O スコア: {quick_results['io_score']:.2f}")
    print(f"  総合スコア: {quick_results['overall_score']:.2f}")
    
    # 詳細ベンチマーク
    print("\n📈 詳細ベンチマーク実行中...")
    
    results = {
        'timestamp': time.time(),
        'quick_benchmark': quick_results,
        'detailed_benchmarks': {}
    }
    
    # CPU ベンチマーク
    print("  - CPU ベンチマーク...")
    cpu_result = benchmark.benchmark_cpu(duration=2)
    results['detailed_benchmarks']['cpu'] = cpu_result
    print(f"    完了: {cpu_result['operations_per_second']:.0f} ops/sec")
    
    # メモリベンチマーク
    print("  - メモリベンチマーク...")
    memory_result = benchmark.benchmark_memory(size_mb=10)
    results['detailed_benchmarks']['memory'] = memory_result
    print(f"    完了: {memory_result['throughput_mbps']:.2f} MB/s")
    
    # I/O ベンチマーク
    print("  - I/O ベンチマーク...")
    io_result = benchmark.benchmark_io(file_size_mb=1, iterations=10)
    results['detailed_benchmarks']['io'] = io_result
    print(f"    完了: 書込 {io_result['write_mbps']:.2f} MB/s, 読込 {io_result['read_mbps']:.2f} MB/s")
    
    # 圧縮ベンチマーク
    print("  - 圧縮ベンチマーク...")
    compression_results = benchmark.benchmark_compression(data_size_mb=1)
    results['detailed_benchmarks']['compression'] = compression_results
    
    best_compression = max(compression_results, key=lambda x: x['score'])
    print(f"    最良: {best_compression['type']} (スコア: {best_compression['score']:.2f})")
    
    # 結果保存
    results_file = Path("BLRCS_BENCHMARK_RESULTS.json")
    with open(results_file, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    print(f"\n💾 詳細結果保存: {results_file}")
    
    # パフォーマンス評価
    overall_score = quick_results['overall_score']
    if overall_score >= 90:
        grade = "🏆 EXCELLENT"
        comment = "優秀なパフォーマンス"
    elif overall_score >= 75:
        grade = "✨ VERY GOOD"
        comment = "良好なパフォーマンス"
    elif overall_score >= 60:
        grade = "✅ GOOD"
        comment = "標準的なパフォーマンス"
    elif overall_score >= 40:
        grade = "⚠️ ACCEPTABLE"
        comment = "改善の余地あり"
    else:
        grade = "❌ POOR"
        comment = "パフォーマンス改善が必要"
    
    print(f"\n📊 総合評価: {grade}")
    print(f"   {comment} (スコア: {overall_score:.2f}/100)")
    
    return results

if __name__ == "__main__":
    try:
        results = run_comprehensive_benchmarks()
        print("\n✅ ベンチマーク完了!")
    except Exception as e:
        print(f"\n❌ エラー: {e}")
        sys.exit(1)