"""
Performance Benchmarking Suite
Comprehensive benchmarking of the integrity verification system
"""

import time
import json
import tracemalloc
import statistics
from typing import Dict, List
import matplotlib.pyplot as plt
import numpy as np
from log_generator import LogCorpus
from integrity_verifier import IntegrityVerifier
from merkle_tree import OptimizedMerkleTree
from adaptive_chunking import AdaptiveChunker


class BenchmarkSuite:
    """
    Comprehensive benchmarking suite for integrity verification
    """
    
    def __init__(self):
        self.results = []
    
    def _measure_memory(self, func, *args, **kwargs):
        """Measure memory usage of a function"""
        tracemalloc.start()
        result = func(*args, **kwargs)
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        return result, peak
    
    def _repeated_ingestion_runs(self, logs: List[str], use_adaptive: bool,
                                 repeats: int = 5) -> Dict:
        """Run ingestion multiple times and return stable summary metrics."""
        rates = []
        times = []
        tree_depth = 0
        chunk_size_kb = 0.0
        
        # Lightweight warm-up run
        warmup_verifier = IntegrityVerifier(use_adaptive_chunking=use_adaptive)
        warmup_verifier.ingest_logs(logs[: min(len(logs), 500)])
        
        for _ in range(repeats):
            verifier = IntegrityVerifier(use_adaptive_chunking=use_adaptive)
            start = time.perf_counter()
            stats = verifier.ingest_logs(logs)
            elapsed = time.perf_counter() - start
            times.append(elapsed)
            rates.append(len(logs) / elapsed if elapsed > 0 else 0.0)
            tree_depth = stats['tree_depth']
            chunk_size_kb = stats['chunk_size_kb']
        
        return {
            'time_seconds_mean': statistics.mean(times),
            'time_seconds_std': statistics.stdev(times) if len(times) > 1 else 0.0,
            'logs_per_second_mean': statistics.mean(rates),
            'logs_per_second_std': statistics.stdev(rates) if len(rates) > 1 else 0.0,
            'runs': repeats,
            'tree_depth': tree_depth,
            'chunk_size_kb': chunk_size_kb
        }
    
    def benchmark_ingestion(self, log_sizes: List[int] = None, repeats: int = 5) -> Dict:
        """
        Benchmark log ingestion performance
        
        Args:
            log_sizes: List of log counts to test
            
        Returns:
            Ingestion benchmark results
        """
        if log_sizes is None:
            log_sizes = [1000, 5000, 10000, 50000, 100000]
        
        results = {
            'adaptive': [],
            'fixed': []
        }
        
        for size in log_sizes:
            # Generate logs
            logs = LogCorpus.get_medium_dataset()[:size] if size <= 10000 else LogCorpus.get_large_dataset()[:size]
            
            adaptive_summary = self._repeated_ingestion_runs(
                logs, use_adaptive=True, repeats=repeats
            )
            fixed_summary = self._repeated_ingestion_runs(
                logs, use_adaptive=False, repeats=repeats
            )

            results['adaptive'].append({
                'log_count': size,
                'time_seconds_mean': adaptive_summary['time_seconds_mean'],
                'time_seconds_std': adaptive_summary['time_seconds_std'],
                'logs_per_second': adaptive_summary['logs_per_second_mean'],
                'logs_per_second_std': adaptive_summary['logs_per_second_std'],
                'runs': adaptive_summary['runs'],
                'tree_depth': adaptive_summary['tree_depth'],
                'chunk_size_kb': adaptive_summary['chunk_size_kb']
            })
            
            results['fixed'].append({
                'log_count': size,
                'time_seconds_mean': fixed_summary['time_seconds_mean'],
                'time_seconds_std': fixed_summary['time_seconds_std'],
                'logs_per_second': fixed_summary['logs_per_second_mean'],
                'logs_per_second_std': fixed_summary['logs_per_second_std'],
                'runs': fixed_summary['runs'],
                'tree_depth': fixed_summary['tree_depth'],
                'chunk_size_kb': fixed_summary['chunk_size_kb']
            })
        
        return results

    def benchmark_controlled_stress(self,
                                    num_logs: int = 20000,
                                    window_size: int = 2000,
                                    pressure_baseline: float = 0.25,
                                    pressure_stress: float = 0.85,
                                    stress_windows: int = 3) -> Dict:
        """
        Controlled stress test for adaptive chunking.

        This experiment simulates memory-pressure phases by overriding the chunker's
        memory-pressure signal, and records how chunk size changes over ingestion windows.
        The goal is to validate the adaptation policy on a single machine in a controlled,
        reproducible manner.
        """
        logs = LogCorpus.get_medium_dataset()[:num_logs]

        chunker = AdaptiveChunker(min_chunk_size=4, max_chunk_size=64)
        tree = OptimizedMerkleTree()

        num_windows = int(np.ceil(len(logs) / window_size))
        stress_start = max(0, (num_windows // 2) - (stress_windows // 2))
        stress_end = min(num_windows, stress_start + stress_windows)

        rows = []
        t0 = time.perf_counter()
        for w in range(num_windows):
            pressure = pressure_baseline
            phase = "baseline"
            if stress_start <= w < stress_end:
                pressure = pressure_stress
                phase = "stress"

            chunker.set_memory_pressure_override(pressure)
            window_logs = logs[w * window_size: (w + 1) * window_size]

            # Force chunk-size adjustment on every window for a controlled profile.
            batches = chunker.chunk_log_entries(window_logs, performance_feedback={"avg_time": 0.0})
            for batch in batches:
                tree.add_leaves_batch(batch, rebuild=False)

            rows.append({
                "window": w,
                "phase": phase,
                "pressure": pressure,
                "window_logs": len(window_logs),
                "num_batches": len(batches),
                "chunk_size_kb": round(chunker.get_chunk_size_kb(), 3),
            })

        # One rebuild at the end to reflect the prototype's deferred rebuild strategy.
        tree.rebuild_tree()
        total_time_s = time.perf_counter() - t0

        return {
            "num_logs": num_logs,
            "window_size": window_size,
            "pressure_baseline": pressure_baseline,
            "pressure_stress": pressure_stress,
            "stress_windows": stress_windows,
            "stress_window_start": stress_start,
            "stress_window_end": stress_end,
            "total_time_seconds": total_time_s,
            "overall_throughput_logs_per_sec": (len(logs) / total_time_s) if total_time_s > 0 else 0.0,
            "rows": rows,
        }
    
    def benchmark_verification(self, num_logs: int = 10000) -> Dict:
        """
        Benchmark verification performance
        
        Args:
            num_logs: Number of logs to test
            
        Returns:
            Verification benchmark results
        """
        logs = LogCorpus.get_medium_dataset()[:num_logs]
        
        verifier = IntegrityVerifier(use_adaptive_chunking=True)
        verifier.ingest_logs(logs)
        
        # Single entry verification
        single_times = []
        for i in range(0, min(100, num_logs), 10):
            start = time.time()
            verifier.verify_entry(logs[i], i)
            single_times.append((time.time() - start) * 1000)
        
        # Batch verification
        batch_sizes = [10, 50, 100, 500, 1000]
        batch_results = []
        
        for batch_size in batch_sizes:
            if batch_size > num_logs:
                continue
            
            indices = list(range(batch_size))
            batch_logs = logs[:batch_size]
            
            start = time.time()
            result = verifier.verify_batch(batch_logs, indices)
            batch_time = (time.time() - start) * 1000
            
            batch_results.append({
                'batch_size': batch_size,
                'total_time_ms': batch_time,
                'avg_time_per_entry_ms': batch_time / batch_size
            })
        
        return {
            'single_verification': {
                'avg_time_ms': np.mean(single_times),
                'min_time_ms': np.min(single_times),
                'max_time_ms': np.max(single_times),
                'std_time_ms': np.std(single_times)
            },
            'batch_verification': batch_results
        }
    
    def benchmark_memory(self, num_logs: int = 10000) -> Dict:
        """
        Benchmark memory usage
        
        Args:
            num_logs: Number of logs to test
            
        Returns:
            Memory benchmark results
        """
        logs = LogCorpus.get_medium_dataset()[:num_logs]
        
        # Test with adaptive chunking
        verifier_adaptive = IntegrityVerifier(use_adaptive_chunking=True)
        _, peak_adaptive = self._measure_memory(verifier_adaptive.ingest_logs, logs)
        
        # Test with fixed chunking
        verifier_fixed = IntegrityVerifier(use_adaptive_chunking=False)
        _, peak_fixed = self._measure_memory(verifier_fixed.ingest_logs, logs)
        
        # Test traditional Merkle tree (without chunking)
        from merkle_tree import OptimizedMerkleTree
        tree = OptimizedMerkleTree()
        _, peak_traditional = self._measure_memory(tree.add_leaves_batch, logs)
        
        return {
            'adaptive_chunking_mb': peak_adaptive / (1024 * 1024),
            'fixed_chunking_mb': peak_fixed / (1024 * 1024),
            'traditional_merkle_mb': peak_traditional / (1024 * 1024),
            'memory_improvement_vs_traditional': (peak_traditional - peak_adaptive) / peak_traditional * 100
        }
    
    def benchmark_proof_generation(self, num_logs: int = 10000) -> Dict:
        """
        Benchmark Merkle proof generation
        
        Args:
            num_logs: Number of logs to test
            
        Returns:
            Proof generation benchmark results
        """
        logs = LogCorpus.get_medium_dataset()[:num_logs]
        
        verifier = IntegrityVerifier(use_adaptive_chunking=True)
        verifier.ingest_logs(logs)
        
        # Generate proofs for various indices
        test_indices = [0, num_logs//4, num_logs//2, 3*num_logs//4, num_logs-1]
        proof_results = []
        
        for idx in test_indices:
            start = time.time()
            proof = verifier.generate_proof(idx)
            proof_time = (time.time() - start) * 1000
            
            proof_results.append({
                'index': idx,
                'generation_time_ms': proof_time,
                'proof_size_bytes': proof['proof_size_bytes'],
                'proof_length': len(proof['proof'])
            })
        
        return {
            'proof_results': proof_results,
            'avg_generation_time_ms': np.mean([r['generation_time_ms'] for r in proof_results]),
            'avg_proof_size_bytes': np.mean([r['proof_size_bytes'] for r in proof_results])
        }
    
    def benchmark_tampering_detection(self, num_logs: int = 10000, 
                                     tamper_ratios: List[float] = None) -> Dict:
        """
        Benchmark tampering detection accuracy
        
        Args:
            num_logs: Number of logs to test
            tamper_ratios: List of tampering ratios to test
            
        Returns:
            Tampering detection results
        """
        if tamper_ratios is None:
            tamper_ratios = [0.01, 0.05, 0.1, 0.2, 0.5]
        
        from log_generator import IoTLogGenerator
        gen = IoTLogGenerator(seed=42)
        original_logs = gen.generate_logs(num_logs, attack_ratio=0.02)
        
        detection_results = []
        
        for ratio in tamper_ratios:
            tampered_logs = gen.tamper_logs(original_logs.copy(), tamper_ratio=ratio)
            
            verifier = IntegrityVerifier(use_adaptive_chunking=True)
            
            start = time.time()
            detection = verifier.detect_tampering(original_logs, tampered_logs)
            detection_time = time.time() - start
            
            detection_results.append({
                'tamper_ratio': ratio,
                'actual_tampered': detection['actual_tampered'],
                'detected_tampered': detection['num_tampered'],
                'true_positives': detection['true_positives'],
                'false_positives': detection['false_positives'],
                'false_negatives': detection['false_negatives'],
                'detection_time_seconds': detection_time,
                'detection_accuracy': detection['detection_accuracy'],
                'precision': detection['precision'],
                'recall': detection['recall'],
                'f1_score': detection['f1_score']
            })
        
        return detection_results
    
    def benchmark_hash_algorithms(self, num_logs: int = 10000) -> Dict:
        """
        Benchmark different hash algorithms
        
        Args:
            num_logs: Number of logs to test
            
        Returns:
            Hash algorithm comparison results
        """
        logs = LogCorpus.get_medium_dataset()[:num_logs]
        
        algorithms = ['sha256', 'blake2b']
        results = {}
        
        for algo in algorithms:
            verifier = IntegrityVerifier(hash_algorithm=algo, use_adaptive_chunking=True)
            
            # Ingestion
            start = time.time()
            verifier.ingest_logs(logs)
            ingestion_time = time.time() - start
            
            # Verification
            start = time.time()
            verifier.verify_entry(logs[0], 0)
            verification_time = (time.time() - start) * 1000
            
            results[algo] = {
                'ingestion_time_seconds': ingestion_time,
                'ingestion_rate_logs_per_sec': num_logs / ingestion_time,
                'verification_time_ms': verification_time,
                'root_hash': verifier.merkle_tree.get_root_hash()[:16] + '...'
            }
        
        return results
    
    def run_full_benchmark(self) -> Dict:
        """Run complete benchmark suite"""
        print("Running full benchmark suite...")
        
        results = {}
        
        print("1. Benchmarking ingestion...")
        results['ingestion'] = self.benchmark_ingestion()
        
        print("2. Benchmarking verification...")
        results['verification'] = self.benchmark_verification()
        
        print("3. Benchmarking memory...")
        results['memory'] = self.benchmark_memory()
        
        print("4. Benchmarking proof generation...")
        results['proof_generation'] = self.benchmark_proof_generation()
        
        print("5. Benchmarking tampering detection...")
        results['tampering_detection'] = self.benchmark_tampering_detection()
        
        print("6. Benchmarking hash algorithms...")
        results['hash_algorithms'] = self.benchmark_hash_algorithms()

        print("7. Controlled stress test (adaptive chunking)...")
        results['controlled_stress'] = self.benchmark_controlled_stress()
        
        print("Benchmark complete!")
        return results
    
    def save_results(self, results: Dict, filename: str = 'benchmark_results.json'):
        """Save benchmark results to file"""
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"Results saved to {filename}")
    
    def generate_plots(self, results: Dict):
        """Generate visualization plots"""
        fig, axes = plt.subplots(2, 3, figsize=(15, 10))
        fig.suptitle('Integrity Verification System Performance', fontsize=16)
        
        # 1. Ingestion performance
        ax1 = axes[0, 0]
        adaptive_data = results['ingestion']['adaptive']
        fixed_data = results['ingestion']['fixed']
        log_counts = [d['log_count'] for d in adaptive_data]
        adaptive_rates = [d['logs_per_second'] for d in adaptive_data]
        fixed_rates = [d['logs_per_second'] for d in fixed_data]
        
        ax1.plot(log_counts, adaptive_rates, 'b-o', label='Adaptive Chunking')
        ax1.plot(log_counts, fixed_rates, 'r-s', label='Fixed Chunking')
        ax1.set_xlabel('Number of Logs')
        ax1.set_ylabel('Logs/Second')
        ax1.set_title('Ingestion Performance')
        ax1.legend()
        ax1.grid(True)
        
        # 2. Verification time
        ax2 = axes[0, 1]
        batch_data = results['verification']['batch_verification']
        batch_sizes = [d['batch_size'] for d in batch_data]
        avg_times = [d['avg_time_per_entry_ms'] for d in batch_data]
        
        ax2.plot(batch_sizes, avg_times, 'g-o')
        ax2.set_xlabel('Batch Size')
        ax2.set_ylabel('Avg Time per Entry (ms)')
        ax2.set_title('Batch Verification Performance')
        ax2.grid(True)
        
        # 3. Memory usage
        ax3 = axes[0, 2]
        memory_data = results['memory']
        methods = ['Adaptive', 'Fixed', 'Traditional']
        memory_mb = [
            memory_data['adaptive_chunking_mb'],
            memory_data['fixed_chunking_mb'],
            memory_data['traditional_merkle_mb']
        ]
        
        ax3.bar(methods, memory_mb, color=['blue', 'red', 'green'])
        ax3.set_ylabel('Memory Usage (MB)')
        ax3.set_title('Memory Comparison (10K logs)')
        ax3.grid(True, axis='y')
        
        # 4. Proof size
        ax4 = axes[1, 0]
        proof_data = results['proof_generation']['proof_results']
        indices = [d['index'] for d in proof_data]
        proof_sizes = [d['proof_size_bytes'] for d in proof_data]
        
        ax4.plot(indices, proof_sizes, 'm-o')
        ax4.set_xlabel('Log Index')
        ax4.set_ylabel('Proof Size (bytes)')
        ax4.set_title('Merkle Proof Size')
        ax4.grid(True)
        
        # 5. Tampering detection
        ax5 = axes[1, 1]
        tamper_data = results['tampering_detection']
        ratios = [d['tamper_ratio'] for d in tamper_data]
        accuracies = [d['detection_accuracy'] for d in tamper_data]
        
        ax5.plot(ratios, accuracies, 'c-o')
        ax5.set_xlabel('Tampering Ratio')
        ax5.set_ylabel('Detection Accuracy')
        ax5.set_title('Tampering Detection Accuracy')
        ax5.set_ylim([0, 1.1])
        ax5.grid(True)
        
        # 6. Hash algorithm comparison
        ax6 = axes[1, 2]
        hash_data = results['hash_algorithms']
        algos = list(hash_data.keys())
        rates = [hash_data[algo]['ingestion_rate_logs_per_sec'] for algo in algos]
        
        ax6.bar(algos, rates, color=['orange', 'purple'])
        ax6.set_ylabel('Ingestion Rate (logs/sec)')
        ax6.set_title('Hash Algorithm Comparison')
        ax6.grid(True, axis='y')
        
        plt.tight_layout()
        plt.savefig('benchmark_plots.png', dpi=300, bbox_inches='tight')
        print("Plots saved to benchmark_plots.png")
        plt.close()


def main():
    """Main benchmark execution"""
    suite = BenchmarkSuite()
    results = suite.run_full_benchmark()
    suite.save_results(results)
    suite.generate_plots(results)


if __name__ == '__main__':
    main()
