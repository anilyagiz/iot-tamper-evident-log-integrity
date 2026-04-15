"""
Integrity Verification Engine
Main system that combines Merkle tree, adaptive chunking, and verification
"""

from typing import List, Dict, Optional, Tuple
import time
import json
from merkle_tree import OptimizedMerkleTree
from adaptive_chunking import AdaptiveChunker, FixedSizeChunker


class IntegrityVerifier:
    """
    Main integrity verification system
    Combines Merkle tree with adaptive chunking for optimal performance
    """
    
    def __init__(self, hash_algorithm: str = 'sha256', 
                 use_adaptive_chunking: bool = True):
        """
        Initialize integrity verifier
        
        Args:
            hash_algorithm: 'sha256' or 'blake2b'
            use_adaptive_chunking: Whether to use adaptive chunking
        """
        self.merkle_tree = OptimizedMerkleTree(hash_algorithm)
        self.use_adaptive_chunking = use_adaptive_chunking
        
        if use_adaptive_chunking:
            self.chunker = AdaptiveChunker(min_chunk_size=4, max_chunk_size=64)
        else:
            self.chunker = FixedSizeChunker(chunk_size_kb=16)
        
        self.verification_stats = {
            'total_verifications': 0,
            'successful_verifications': 0,
            'failed_verifications': 0,
            'total_time': 0.0
        }
    
    def ingest_logs(self, logs: List[str]) -> Dict:
        """
        Ingest logs into the integrity system
        
        Args:
            logs: List of log entries (JSON strings)
            
        Returns:
            Statistics about ingestion
        """
        start_time = time.time()
        
        # Chunk logs for efficient processing
        batches = self.chunker.chunk_log_entries(logs)
        
        # Add all leaves in batch mode and rebuild once for better scalability
        for batch in batches:
            self.merkle_tree.add_leaves_batch(batch, rebuild=False)
        self.merkle_tree.rebuild_tree()
        
        ingestion_time = time.time() - start_time
        
        stats = {
            'num_logs': len(logs),
            'num_batches': len(batches),
            'ingestion_time': ingestion_time,
            'logs_per_second': len(logs) / ingestion_time if ingestion_time > 0 else 0,
            'chunk_size_kb': self.chunker.get_chunk_size_kb(),
            'merkle_root': self.merkle_tree.get_root_hash(),
            'tree_depth': self.merkle_tree.get_tree_stats()['tree_depth']
        }
        
        return stats
    
    def verify_entry(self, log_entry: str, index: int) -> Dict:
        """
        Verify integrity of a single log entry
        
        Args:
            log_entry: The log entry to verify
            index: Index of the entry in the tree
            
        Returns:
            Verification result with metadata
        """
        start_time = time.time()
        
        is_valid = self.merkle_tree.verify_integrity(log_entry, index)
        
        verification_time = time.time() - start_time
        
        # Update stats
        self.verification_stats['total_verifications'] += 1
        if is_valid:
            self.verification_stats['successful_verifications'] += 1
        else:
            self.verification_stats['failed_verifications'] += 1
        self.verification_stats['total_time'] += verification_time
        
        return {
            'valid': is_valid,
            'index': index,
            'verification_time_ms': verification_time * 1000,
            'merkle_root': self.merkle_tree.get_root_hash()
        }
    
    def verify_batch(self, log_entries: List[str], indices: List[int]) -> Dict:
        """
        Verify integrity of multiple log entries
        
        Args:
            log_entries: List of log entries to verify
            indices: Corresponding indices
            
        Returns:
            Batch verification result
        """
        start_time = time.time()
        
        results = []
        for entry, idx in zip(log_entries, indices):
            result = self.verify_entry(entry, idx)
            results.append(result)
        
        batch_time = time.time() - start_time
        
        valid_count = sum(1 for r in results if r['valid'])
        
        return {
            'total_entries': len(log_entries),
            'valid_entries': valid_count,
            'invalid_entries': len(log_entries) - valid_count,
            'batch_time_ms': batch_time * 1000,
            'avg_time_per_entry_ms': (batch_time * 1000) / len(log_entries),
            'results': results
        }
    
    def generate_proof(self, index: int) -> Dict:
        """
        Generate Merkle proof for an entry
        
        Args:
            index: Index of the entry
            
        Returns:
            Proof with metadata
        """
        start_time = time.time()
        
        proof = self.merkle_tree.generate_proof(index)
        
        generation_time = time.time() - start_time
        
        return {
            'index': index,
            'proof': proof,
            'proof_size_bytes': len(json.dumps(proof).encode('utf-8')),
            'generation_time_ms': generation_time * 1000,
            'root_hash': self.merkle_tree.get_root_hash()
        }
    
    def detect_tampering(self, original_logs: List[str], 
                       suspected_logs: List[str]) -> Dict:
        """
        Detect tampering by comparing original vs suspected logs
        
        Args:
            original_logs: Original untampered logs
            suspected_logs: Suspected tampered logs
            
        Returns:
            Tampering detection results
        """
        # Build tree from original logs
        self.merkle_tree = OptimizedMerkleTree(self.merkle_tree.hash_algorithm)
        self.ingest_logs(original_logs)
        original_root = self.merkle_tree.get_root_hash()
        
        # Compare original and suspected streams index-by-index.
        # For efficiency, we only verify entries that differ (or are missing),
        # since identical JSON strings imply identical leaf hashes in this model.
        max_len = max(len(original_logs), len(suspected_logs))
        actual_tampered_set = set()
        detected_tampered_set = set()
        
        for i in range(max_len):
            orig = original_logs[i] if i < len(original_logs) else None
            sus = suspected_logs[i] if i < len(suspected_logs) else None
            
            if orig != sus:
                actual_tampered_set.add(i)
            
            # Missing entries (stream length mismatch) are directly flagged as tampered.
            if sus is None or i >= len(original_logs):
                detected_tampered_set.add(i)
                continue

            # If strings are identical, there is no need to verify the proof here.
            if orig == sus:
                continue

            result = self.verify_entry(sus, i)
            if not result['valid']:
                detected_tampered_set.add(i)
        
        true_positives = len(detected_tampered_set & actual_tampered_set)
        false_positives = len(detected_tampered_set - actual_tampered_set)
        false_negatives = len(actual_tampered_set - detected_tampered_set)
        
        detection_accuracy = (
            true_positives / len(actual_tampered_set) if actual_tampered_set else 1.0
        )
        precision = (
            true_positives / len(detected_tampered_set) if detected_tampered_set else 1.0
        )
        recall = detection_accuracy
        f1_score = (
            (2 * precision * recall) / (precision + recall)
            if (precision + recall) > 0 else 0.0
        )
        
        return {
            'original_root': original_root,
            'num_tampered': len(detected_tampered_set),
            'tampered_indices': sorted(detected_tampered_set),
            'actual_tampered': len(actual_tampered_set),
            'true_positives': true_positives,
            'false_positives': false_positives,
            'false_negatives': false_negatives,
            'tampering_rate': len(actual_tampered_set) / max_len if max_len else 0,
            'detection_accuracy': detection_accuracy,
            'precision': precision,
            'recall': recall,
            'f1_score': f1_score
        }
    
    def get_system_stats(self) -> Dict:
        """Get overall system statistics"""
        merkle_stats = self.merkle_tree.get_tree_stats()
        
        if self.use_adaptive_chunking:
            chunker_stats = self.chunker.get_stats()
        else:
            chunker_stats = {
                'chunk_size_kb': self.chunker.get_chunk_size_kb(),
                'adaptive': False
            }
        
        avg_verification_time = 0
        if self.verification_stats['total_verifications'] > 0:
            avg_verification_time = (self.verification_stats['total_time'] / 
                                   self.verification_stats['total_verifications']) * 1000
        
        return {
            'merkle_tree': merkle_stats,
            'chunker': chunker_stats,
            'verification': {
                **self.verification_stats,
                'avg_verification_time_ms': avg_verification_time
            }
        }
    
    def reset_stats(self):
        """Reset verification statistics"""
        self.verification_stats = {
            'total_verifications': 0,
            'successful_verifications': 0,
            'failed_verifications': 0,
            'total_time': 0.0
        }
