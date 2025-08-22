#!/usr/bin/env python3
"""BLRCS 簡易パフォーマンスベンチマーク"""

import time
import hashlib
import json
import random
from pathlib import Path

def benchmark_cpu(duration=2):
    """CPU ベンチマーク"""
    start = time.time()
    operations = 0
    
    while time.time() - start < duration:
        # 数値計算
        _ = sum(i ** 2 for i in range(1000))
        # ハッシュ計算
        _ = hashlib.sha256(str(random.random()).encode()).hexdigest()
        operations += 1
    
    elapsed = time.time() - start
    return {
        'operations': operations,
        'duration': elapsed,
        'ops_per_second': operations / elapsed
    }

def benchmark_memory(iterations=1000):
    """メモリベンチマーク"""
    start = time.time()
    
    # リスト操作
    data = []
    for i in range(iterations):
        data.append([random.random() for _ in range(100)])
    
    # 辞書操作
    cache = {}
    for i in range(iterations):
        cache[f"key_{i}"] = data[i % len(data)]
    
    # ソート操作
    sorted_data = sorted(data[0])
    
    elapsed = time.time() - start
    return {
        'iterations': iterations,
        'duration': elapsed,
        'throughput': iterations / elapsed
    }

def benchmark_io(file_count=10):
    """I/O ベンチマーク"""
    temp_dir = Path("temp_benchmark")
    temp_dir.mkdir(exist_ok=True)
    
    # 書き込み
    write_start = time.time()
    for i in range(file_count):
        file_path = temp_dir / f"test_{i}.txt"
        with open(file_path, 'w') as f:
            f.write("x" * 10000)
    write_time = time.time() - write_start
    
    # 読み込み
    read_start = time.time()
    for i in range(file_count):
        file_path = temp_dir / f"test_{i}.txt"
        with open(file_path, 'r') as f:
            _ = f.read()
    read_time = time.time() - read_start
    
    # クリーンアップ
    for file_path in temp_dir.glob("*.txt"):
        file_path.unlink()
    temp_dir.rmdir()
    
    return {
        'file_count': file_count,
        'write_time': write_time,
        'read_time': read_time,
        'write_ops_per_sec': file_count / write_time,
        'read_ops_per_sec': file_count / read_time
    }

def calculate_score(cpu_result, memory_result, io_result):
    """総合スコア計算"""
    # 基準値（これらの値を100点とする）
    cpu_baseline = 1000  # ops/sec
    memory_baseline = 5000  # throughput
    io_baseline = 100  # ops/sec
    
    cpu_score = min(100, (cpu_result['ops_per_second'] / cpu_baseline) * 100)
    memory_score = min(100, (memory_result['throughput'] / memory_baseline) * 100)
    io_score = min(100, ((io_result['write_ops_per_sec'] + io_result['read_ops_per_sec']) / 2 / io_baseline) * 100)
    
    overall_score = (cpu_score * 0.4 + memory_score * 0.3 + io_score * 0.3)
    
    return {
        'cpu_score': cpu_score,
        'memory_score': memory_score,
        'io_score': io_score,
        'overall_score': overall_score
    }

def main():
    print("🚀 BLRCS 簡易パフォーマンスベンチマーク")
    print("=" * 60)
    
    print("\n📊 ベンチマーク実行中...")
    
    # 各ベンチマーク実行
    print("  1/3 CPU ベンチマーク...")
    cpu_result = benchmark_cpu(duration=2)
    
    print("  2/3 メモリベンチマーク...")
    memory_result = benchmark_memory(iterations=1000)
    
    print("  3/3 I/O ベンチマーク...")
    io_result = benchmark_io(file_count=10)
    
    # スコア計算
    scores = calculate_score(cpu_result, memory_result, io_result)
    
    # 結果表示
    print("\n✅ ベンチマーク結果:")
    print(f"  CPU パフォーマンス: {cpu_result['ops_per_second']:.0f} ops/sec (スコア: {scores['cpu_score']:.1f})")
    print(f"  メモリスループット: {memory_result['throughput']:.0f} ops/sec (スコア: {scores['memory_score']:.1f})")
    print(f"  I/O 書込速度: {io_result['write_ops_per_sec']:.1f} ops/sec")
    print(f"  I/O 読込速度: {io_result['read_ops_per_sec']:.1f} ops/sec")
    print(f"  I/O スコア: {scores['io_score']:.1f}")
    
    print(f"\n📈 総合スコア: {scores['overall_score']:.1f}/100")
    
    # 評価
    if scores['overall_score'] >= 80:
        grade = "🏆 EXCELLENT"
    elif scores['overall_score'] >= 60:
        grade = "✅ GOOD"
    elif scores['overall_score'] >= 40:
        grade = "⚠️ ACCEPTABLE"
    else:
        grade = "❌ NEEDS IMPROVEMENT"
    
    print(f"評価: {grade}")
    
    # 結果保存
    results = {
        'timestamp': time.time(),
        'cpu': cpu_result,
        'memory': memory_result,
        'io': io_result,
        'scores': scores,
        'grade': grade
    }
    
    with open('SIMPLE_BENCHMARK_RESULTS.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    print("\n💾 結果保存: SIMPLE_BENCHMARK_RESULTS.json")
    
    return results

if __name__ == "__main__":
    main()