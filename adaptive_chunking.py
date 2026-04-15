"""
Adaptive Chunking Mechanism for IoT Log Integrity
Dynamically adjusts chunk size based on memory constraints and log patterns
"""

import hashlib
from typing import List, Tuple
import psutil
import os


class AdaptiveChunker:
    """
    Adaptive chunking that balances memory vs computation
    Adjusts chunk size based on:
    - Available memory
    - Log entry size variance
    - Performance requirements
    """
    
    def __init__(self, min_chunk_size: int = 4, max_chunk_size: int = 64,
                 target_memory_usage: float = 0.3):
        """
        Initialize adaptive chunker
        
        Args:
            min_chunk_size: Minimum chunk size in KB
            max_chunk_size: Maximum chunk size in KB
            target_memory_usage: Target memory usage ratio (0-1)
        """
        self.min_chunk_size = min_chunk_size * 1024  # Convert to bytes
        self.max_chunk_size = max_chunk_size * 1024  # Convert to bytes
        self.target_memory_usage = target_memory_usage
        self.current_chunk_size = self._calculate_initial_chunk_size()
        self.chunk_history: List[int] = []
        self._memory_pressure_override: float | None = None
        
    def _calculate_initial_chunk_size(self) -> int:
        """Calculate initial chunk size based on available memory"""
        available_memory = psutil.virtual_memory().available
        target_memory = available_memory * self.target_memory_usage
        
        # Start with a conservative estimate
        initial_size = min(self.max_chunk_size, 
                          max(self.min_chunk_size, int(target_memory / 1000)))
        
        return initial_size
    
    def _get_memory_pressure(self) -> float:
        """Get current memory pressure (0-1, higher = more pressure)"""
        if self._memory_pressure_override is not None:
            return float(self._memory_pressure_override)
        mem = psutil.virtual_memory()
        return mem.percent / 100.0

    def set_memory_pressure_override(self, value: float | None):
        """
        Override memory pressure for controlled experiments.

        Args:
            value: None to disable override, or a float in [0, 1].
        """
        if value is None:
            self._memory_pressure_override = None
            return
        if not (0.0 <= value <= 1.0):
            raise ValueError("memory pressure override must be within [0, 1]")
        self._memory_pressure_override = float(value)
    
    def _adjust_chunk_size(self, performance_feedback: dict = None) -> int:
        """
        Adjust chunk size based on system conditions and performance feedback
        
        Args:
            performance_feedback: Dict with 'avg_time', 'memory_used' metrics
            
        Returns:
            New chunk size
        """
        memory_pressure = self._get_memory_pressure()
        
        # Base adjustment on memory pressure
        if memory_pressure > 0.8:
            # High memory pressure, reduce chunk size
            adjustment_factor = 0.8
        elif memory_pressure > 0.6:
            adjustment_factor = 0.9
        elif memory_pressure < 0.3:
            # Low memory pressure, can increase chunk size
            adjustment_factor = 1.1
        else:
            adjustment_factor = 1.0
        
        # Adjust based on performance feedback if available
        if performance_feedback:
            avg_time = performance_feedback.get('avg_time', 0)
            if avg_time > 0.1:  # If operations are slow (>100ms)
                adjustment_factor *= 0.9  # Reduce chunk size for faster operations
        
        # Calculate new chunk size
        new_size = int(self.current_chunk_size * adjustment_factor)
        
        # Clamp to bounds
        new_size = max(self.min_chunk_size, min(self.max_chunk_size, new_size))
        
        # Update history
        self.chunk_history.append(new_size)
        if len(self.chunk_history) > 100:
            self.chunk_history.pop(0)
        
        self.current_chunk_size = new_size
        return new_size
    
    def chunk_data(self, data: str, performance_feedback: dict = None) -> List[str]:
        """
        Chunk data into adaptive-sized blocks
        
        Args:
            data: String data to chunk
            performance_feedback: Optional performance metrics
            
        Returns:
            List of data chunks
        """
        # Adjust chunk size if needed
        if performance_feedback or len(self.chunk_history) % 10 == 0:
            self._adjust_chunk_size(performance_feedback)
        
        chunk_size = self.current_chunk_size
        chunks = []
        
        for i in range(0, len(data), chunk_size):
            chunk = data[i:i + chunk_size]
            chunks.append(chunk)
        
        return chunks
    
    def chunk_log_entries(self, log_entries: List[str], 
                          performance_feedback: dict = None) -> List[List[str]]:
        """
        Chunk log entries into batches
        
        Args:
            log_entries: List of log entry strings
            performance_feedback: Optional performance metrics
            
        Returns:
            List of batches (each batch is a list of log entries)
        """
        # Adjust chunk size if needed
        if performance_feedback or len(self.chunk_history) % 10 == 0:
            self._adjust_chunk_size(performance_feedback)
        
        chunk_size_bytes = self.current_chunk_size
        batches = []
        current_batch = []
        current_batch_size = 0
        
        for entry in log_entries:
            entry_size = len(entry.encode('utf-8'))
            
            if current_batch_size + entry_size > chunk_size_bytes and current_batch:
                batches.append(current_batch)
                current_batch = []
                current_batch_size = 0
            
            current_batch.append(entry)
            current_batch_size += entry_size
        
        if current_batch:
            batches.append(current_batch)
        
        return batches
    
    def get_optimal_chunk_size(self) -> int:
        """Get current optimal chunk size in bytes"""
        return self.current_chunk_size
    
    def get_chunk_size_kb(self) -> float:
        """Get current chunk size in KB"""
        return self.current_chunk_size / 1024
    
    def get_stats(self) -> dict:
        """Get chunking statistics"""
        return {
            'current_chunk_size_bytes': self.current_chunk_size,
            'current_chunk_size_kb': self.get_chunk_size_kb(),
            'min_chunk_size_kb': self.min_chunk_size / 1024,
            'max_chunk_size_kb': self.max_chunk_size / 1024,
            'memory_pressure': self._get_memory_pressure(),
            'adjustment_count': len(self.chunk_history),
            'avg_chunk_size': sum(self.chunk_history) / len(self.chunk_history) if self.chunk_history else 0
        }


class FixedSizeChunker:
    """
    Fixed-size chunker for comparison
    """
    
    def __init__(self, chunk_size_kb: int = 16):
        self.chunk_size = chunk_size_kb * 1024
    
    def chunk_log_entries(self, log_entries: List[str]) -> List[List[str]]:
        """Chunk log entries into fixed-size batches"""
        batches = []
        current_batch = []
        current_batch_size = 0
        
        for entry in log_entries:
            entry_size = len(entry.encode('utf-8'))
            
            if current_batch_size + entry_size > self.chunk_size and current_batch:
                batches.append(current_batch)
                current_batch = []
                current_batch_size = 0
            
            current_batch.append(entry)
            current_batch_size += entry_size
        
        if current_batch:
            batches.append(current_batch)
        
        return batches
    
    def get_chunk_size_kb(self) -> float:
        return self.chunk_size / 1024
