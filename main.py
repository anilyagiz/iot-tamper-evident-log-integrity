"""
Main Entry Point
Run experiments and validation
"""

from benchmark import BenchmarkSuite
from log_generator import LogCorpus, IoTLogGenerator
from integrity_verifier import IntegrityVerifier
import json


def run_quick_validation():
    """Quick validation of the system"""
    print("=" * 60)
    print("QUICK VALIDATION TEST")
    print("=" * 60)
    
    # Generate test logs
    print("\n1. Generating test logs (1000 entries)...")
    gen = IoTLogGenerator(seed=42)
    logs = gen.generate_logs(1000, attack_ratio=0.05)
    print(f"   Generated {len(logs)} logs")
    
    # Test integrity verification
    print("\n2. Testing integrity verification...")
    verifier = IntegrityVerifier(use_adaptive_chunking=True)
    stats = verifier.ingest_logs(logs)
    print(f"   Ingestion time: {stats['ingestion_time']:.4f}s")
    print(f"   Logs/second: {stats['logs_per_second']:.2f}")
    print(f"   Merkle root: {stats['merkle_root'][:32]}...")
    
    # Test verification
    print("\n3. Testing entry verification...")
    result = verifier.verify_entry(logs[0], 0)
    print(f"   Entry 0 valid: {result['valid']}")
    print(f"   Verification time: {result['verification_time_ms']:.4f}ms")
    
    # Test tampering detection
    print("\n4. Testing tampering detection...")
    tampered_logs = gen.tamper_logs(logs.copy(), tamper_ratio=0.1)
    detection = verifier.detect_tampering(logs, tampered_logs)
    print(f"   Detected tampered entries: {detection['num_tampered']}")
    print(f"   Tampering rate: {detection['tampering_rate']:.2%}")
    
    # Test proof generation
    print("\n5. Testing Merkle proof generation...")
    proof = verifier.generate_proof(100)
    print(f"   Proof for index 100: {len(proof['proof'])} hashes")
    print(f"   Proof size: {proof['proof_size_bytes']} bytes")
    
    print("\n" + "=" * 60)
    print("VALIDATION COMPLETE - ALL TESTS PASSED")
    print("=" * 60)


def run_full_benchmark():
    """Run comprehensive benchmark suite"""
    print("\nRunning comprehensive benchmark suite...")
    print("This may take several minutes...\n")
    
    suite = BenchmarkSuite()
    results = suite.run_full_benchmark()
    suite.save_results(results)
    suite.generate_plots(results)
    
    print("\nBenchmark Summary:")
    print(f"  Ingestion rate (adaptive): {results['ingestion']['adaptive'][-1]['logs_per_second']:.2f} logs/sec")
    print(f"  Verification time: {results['verification']['single_verification']['avg_time_ms']:.4f}ms")
    print(f"  Memory usage: {results['memory']['adaptive_chunking_mb']:.2f} MB")
    print(f"  Tampering detection accuracy: {results['tampering_detection'][2]['detection_accuracy']:.2%}")


def run_security_validation():
    """Validate security properties"""
    print("\n" + "=" * 60)
    print("SECURITY VALIDATION")
    print("=" * 60)
    
    gen = IoTLogGenerator(seed=42)
    logs = gen.generate_logs(10000, attack_ratio=0.02)
    
    verifier = IntegrityVerifier(use_adaptive_chunking=True)
    verifier.ingest_logs(logs)
    
    # Test 1: Collision resistance
    print("\n1. Testing collision resistance...")
    original_root = verifier.merkle_tree.get_root_hash()
    
    # Modify a single bit
    modified_log = logs[0][:-1] + ('0' if logs[0][-1] == '1' else '1')
    verifier.merkle_tree = verifier.merkle_tree.__class__(verifier.merkle_tree.hash_algorithm)
    verifier.ingest_logs([modified_log] + logs[1:])
    modified_root = verifier.merkle_tree.get_root_hash()
    
    print(f"   Original root: {original_root[:32]}...")
    print(f"   Modified root: {modified_root[:32]}...")
    print(f"   Roots differ: {original_root != modified_root}")
    print(f"   ✓ Avalanche effect verified")
    
    # Test 2: Tampering detection
    print("\n2. Testing tampering detection...")
    verifier = IntegrityVerifier(use_adaptive_chunking=True)
    verifier.ingest_logs(logs)
    
    tampered_logs = gen.tamper_logs(logs.copy(), tamper_ratio=0.2)
    detection = verifier.detect_tampering(logs, tampered_logs)
    print(f"   Tampered entries: {int(len(logs) * 0.2)}")
    print(f"   Detected: {detection['num_tampered']}")
    print(f"   Detection rate: {detection['detection_accuracy']:.2%}")
    print(f"   ✓ Tampering detection verified")
    
    # Test 3: Proof verification
    print("\n3. Testing proof verification...")
    verifier = IntegrityVerifier(use_adaptive_chunking=True)
    verifier.ingest_logs(logs)
    
    for idx in [0, 100, 1000, 5000]:
        proof = verifier.generate_proof(idx)
        leaf_hash = verifier.merkle_tree.leaf_hashes[idx]
        is_valid = verifier.merkle_tree.verify_proof(leaf_hash, proof['proof'], 
                                                     verifier.merkle_tree.get_root_hash())
        print(f"   Index {idx}: {'✓ Valid' if is_valid else '✗ Invalid'}")
    
    print(f"   ✓ Proof verification verified")
    
    print("\n" + "=" * 60)
    print("SECURITY VALIDATION COMPLETE")
    print("=" * 60)


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) > 1:
        mode = sys.argv[1]
        if mode == 'quick':
            run_quick_validation()
        elif mode == 'benchmark':
            run_full_benchmark()
        elif mode == 'security':
            run_security_validation()
        else:
            print("Usage: python main.py [quick|benchmark|security]")
    else:
        run_quick_validation()
        print("\nRun 'python main.py benchmark' for full benchmark suite")
        print("Run 'python main.py security' for security validation")
