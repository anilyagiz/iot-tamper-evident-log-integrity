"""
Optimized Merkle Tree Implementation for IoT Log Integrity
Lightweight, streaming-friendly with incremental updates
"""

import hashlib
from typing import List, Optional, Tuple
import json


class MerkleNode:
    """Node in Merkle tree"""
    def __init__(self, hash_value: str, left: Optional['MerkleNode'] = None, 
                 right: Optional['MerkleNode'] = None, data: Optional[str] = None):
        self.hash = hash_value
        self.left = left
        self.right = right
        self.data = data  # Only for leaf nodes


class OptimizedMerkleTree:
    """
    Optimized Merkle tree for streaming log data
    Features: incremental updates, proof generation, lazy verification
    """
    
    def __init__(self, hash_algorithm: str = 'sha256'):
        """
        Initialize Merkle tree
        
        Args:
            hash_algorithm: 'sha256' or 'blake2b'
        """
        self.hash_algorithm = hash_algorithm
        self.leaves: List[str] = []
        self.root: Optional[MerkleNode] = None
        self.leaf_hashes: List[str] = []
        
    def _hash(self, data: str) -> str:
        """Hash data using specified algorithm"""
        if self.hash_algorithm == 'sha256':
            return hashlib.sha256(data.encode()).hexdigest()
        elif self.hash_algorithm == 'blake2b':
            return hashlib.blake2b(data.encode()).hexdigest()
        else:
            raise ValueError(f"Unsupported hash algorithm: {self.hash_algorithm}")
    
    def _hash_pair(self, left: str, right: str) -> str:
        """Hash two values together"""
        return self._hash(left + right)
    
    def add_leaf(self, data: str) -> str:
        """
        Add a leaf to the tree (streaming mode)
        
        Args:
            data: Log entry to add
            
        Returns:
            Hash of the added leaf
        """
        leaf_hash = self._hash(data)
        self.leaves.append(data)
        self.leaf_hashes.append(leaf_hash)
        self._rebuild_tree()
        return leaf_hash
    
    def add_leaves_batch(self, data_list: List[str], rebuild: bool = True) -> List[str]:
        """
        Add multiple leaves at once (more efficient)
        
        Args:
            data_list: List of log entries
            
        Returns:
            List of leaf hashes
        """
        leaf_hashes = []
        for data in data_list:
            leaf_hash = self._hash(data)
            self.leaves.append(data)
            self.leaf_hashes.append(leaf_hash)
            leaf_hashes.append(leaf_hash)
        if rebuild:
            self._rebuild_tree()
        return leaf_hashes
    
    def _rebuild_tree(self):
        """Rebuild the entire Merkle tree from leaves"""
        if not self.leaf_hashes:
            self.root = None
            return
        
        # Build tree bottom-up
        current_level = [MerkleNode(h, data=d) for h, d in zip(self.leaf_hashes, self.leaves)]
        
        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                if i + 1 < len(current_level):
                    right = current_level[i + 1]
                    parent_hash = self._hash_pair(left.hash, right.hash)
                    parent = MerkleNode(parent_hash, left, right)
                else:
                    # Odd number of nodes, promote this node
                    parent = left
                next_level.append(parent)
            current_level = next_level
        
        self.root = current_level[0] if current_level else None
    
    def rebuild_tree(self):
        """Public wrapper to rebuild the tree after deferred batch inserts."""
        self._rebuild_tree()
    
    def get_root_hash(self) -> Optional[str]:
        """Get the root hash of the tree"""
        return self.root.hash if self.root else None
    
    def generate_proof(self, leaf_index: int) -> List[Tuple[str, str]]:
        """
        Generate Merkle proof for a leaf
        
        Args:
            leaf_index: Index of the leaf to prove
            
        Returns:
            List of (hash, direction) tuples where direction is 'left' or 'right'
        """
        if leaf_index < 0 or leaf_index >= len(self.leaf_hashes):
            raise ValueError("Invalid leaf index")
        
        if not self.root:
            return []
        
        proof = []
        current_level_hashes = self.leaf_hashes.copy()
        current_index = leaf_index
        
        while len(current_level_hashes) > 1:
            # Determine sibling
            if current_index % 2 == 0:
                # Current is left child
                sibling_index = current_index + 1
                direction = 'right'
            else:
                # Current is right child
                sibling_index = current_index - 1
                direction = 'left'
            
            # Get sibling hash if it exists
            if sibling_index < len(current_level_hashes):
                proof.append((current_level_hashes[sibling_index], direction))
            
            # Move to parent level
            current_index = current_index // 2
            current_level_hashes = self._build_parent_level(current_level_hashes)
        
        return proof
    
    def _build_parent_level(self, child_hashes: List[str]) -> List[str]:
        """Build parent level hashes from child level"""
        parent_hashes = []
        for i in range(0, len(child_hashes), 2):
            if i + 1 < len(child_hashes):
                parent_hash = self._hash_pair(child_hashes[i], child_hashes[i + 1])
            else:
                parent_hash = child_hashes[i]
            parent_hashes.append(parent_hash)
        return parent_hashes
    
    def verify_proof(self, leaf_hash: str, proof: List[Tuple[str, str]], 
                     root_hash: str) -> bool:
        """
        Verify a Merkle proof
        
        Args:
            leaf_hash: Hash of the leaf
            proof: Merkle proof
            root_hash: Expected root hash
            
        Returns:
            True if proof is valid, False otherwise
        """
        current_hash = leaf_hash
        
        for sibling_hash, direction in proof:
            if direction == 'left':
                current_hash = self._hash_pair(sibling_hash, current_hash)
            else:
                current_hash = self._hash_pair(current_hash, sibling_hash)
        
        return current_hash == root_hash
    
    def verify_integrity(self, data: str, leaf_index: int) -> bool:
        """
        Verify integrity of a specific log entry
        
        Args:
            data: Original log entry
            leaf_index: Index of the log entry
            
        Returns:
            True if integrity is verified, False otherwise
        """
        if leaf_index < 0 or leaf_index >= len(self.leaves):
            return False
        
        # Recompute leaf hash
        expected_leaf_hash = self._hash(data)
        actual_leaf_hash = self.leaf_hashes[leaf_index]
        
        if expected_leaf_hash != actual_leaf_hash:
            return False
        
        # Generate and verify proof
        proof = self.generate_proof(leaf_index)
        return self.verify_proof(expected_leaf_hash, proof, self.get_root_hash())
    
    def get_tree_stats(self) -> dict:
        """Get statistics about the tree"""
        return {
            'num_leaves': len(self.leaves),
            'tree_depth': self._get_tree_depth(),
            'root_hash': self.get_root_hash(),
            'hash_algorithm': self.hash_algorithm
        }
    
    def _get_tree_depth(self) -> int:
        """Calculate depth of the tree"""
        if not self.leaves:
            return 0
        import math
        return math.ceil(math.log2(len(self.leaves))) + 1
    
    def to_dict(self) -> dict:
        """Serialize tree to dictionary"""
        return {
            'leaves': self.leaves,
            'leaf_hashes': self.leaf_hashes,
            'root_hash': self.get_root_hash(),
            'hash_algorithm': self.hash_algorithm
        }
    
    def from_dict(self, data: dict):
        """Deserialize tree from dictionary"""
        self.leaves = data['leaves']
        self.leaf_hashes = data['leaf_hashes']
        self.hash_algorithm = data['hash_algorithm']
        self._rebuild_tree()
