"""
Synthetic Log Generator for IoT Security Testing
Generates realistic IoT device logs with various patterns and attack scenarios
"""

import random
import json
from datetime import datetime, timedelta
from typing import List, Dict
import string


class IoTLogGenerator:
    """
    Generate synthetic IoT device logs for testing integrity verification
    Simulates realistic patterns: periodic events, alerts, attacks
    """
    
    def __init__(self, seed: int = None):
        """
        Initialize log generator
        
        Args:
            seed: Random seed for reproducibility
        """
        if seed is not None:
            random.seed(seed)
        
        self.device_types = ['sensor', 'actuator', 'gateway', 'controller', 'camera']
        self.event_types = ['temperature', 'humidity', 'motion', 'access', 'error', 'warning']
        self.severity_levels = ['INFO', 'WARNING', 'ERROR', 'CRITICAL']
        
    def _generate_timestamp(self, start_time: datetime, offset_seconds: int) -> str:
        """Generate ISO timestamp"""
        return (start_time + timedelta(seconds=offset_seconds)).isoformat()
    
    def _generate_device_id(self) -> str:
        """Generate random device ID"""
        return f"dev-{random.choice(string.ascii_lowercase)}{random.randint(1000, 9999)}"
    
    def _generate_normal_log(self, timestamp: str) -> Dict:
        """Generate a normal log entry"""
        return {
            'timestamp': timestamp,
            'device_id': self._generate_device_id(),
            'device_type': random.choice(self.device_types),
            'event_type': random.choice(self.event_types),
            'severity': random.choices(self.severity_levels, weights=[0.7, 0.2, 0.08, 0.02])[0],
            'value': round(random.uniform(0, 100), 2),
            'message': f"Normal operation - {random.choice(['reading', 'update', 'heartbeat'])}"
        }
    
    def _generate_attack_log(self, timestamp: str, attack_type: str) -> Dict:
        """Generate an attack-related log entry"""
        attack_messages = {
            'injection': "SQL injection attempt detected",
            'bruteforce': "Multiple failed authentication attempts",
            'dos': "Denial of service pattern detected",
            'unauthorized': "Unauthorized access attempt",
            'tampering': "Data tampering detected"
        }
        
        return {
            'timestamp': timestamp,
            'device_id': self._generate_device_id(),
            'device_type': random.choice(self.device_types),
            'event_type': 'security',
            'severity': 'CRITICAL',
            'value': -1,
            'message': attack_messages.get(attack_type, "Unknown attack"),
            'attack_type': attack_type
        }
    
    def generate_logs(self, num_logs: int, attack_ratio: float = 0.05) -> List[str]:
        """
        Generate synthetic logs
        
        Args:
            num_logs: Number of log entries to generate
            attack_ratio: Ratio of attack logs (0-1)
            
        Returns:
            List of JSON-formatted log strings
        """
        logs = []
        start_time = datetime.now() - timedelta(hours=24)
        
        num_attacks = int(num_logs * attack_ratio)
        attack_indices = random.sample(range(num_logs), num_attacks)
        attack_types = ['injection', 'bruteforce', 'dos', 'unauthorized', 'tampering']
        
        for i in range(num_logs):
            timestamp = self._generate_timestamp(start_time, i)
            
            if i in attack_indices:
                log = self._generate_attack_log(timestamp, random.choice(attack_types))
            else:
                log = self._generate_normal_log(timestamp)
            
            logs.append(json.dumps(log))
        
        return logs
    
    def generate_logs_with_pattern(self, num_logs: int, pattern: str = 'random') -> List[str]:
        """
        Generate logs with specific patterns
        
        Args:
            num_logs: Number of logs
            pattern: 'random', 'periodic', 'burst', 'anomaly'
            
        Returns:
            List of JSON-formatted log strings
        """
        logs = []
        start_time = datetime.now() - timedelta(hours=24)
        
        if pattern == 'random':
            return self.generate_logs(num_logs, attack_ratio=0.05)
        
        elif pattern == 'periodic':
            # Periodic heartbeat-like pattern
            for i in range(num_logs):
                timestamp = self._generate_timestamp(start_time, i * 10)  # Every 10 seconds
                log = self._generate_normal_log(timestamp)
                log['message'] = f"Periodic heartbeat - cycle {i % 100}"
                logs.append(json.dumps(log))
        
        elif pattern == 'burst':
            # Burst pattern with quiet periods
            burst_size = 50
            quiet_period = 100
            for i in range(num_logs):
                cycle = i // (burst_size + quiet_period)
                in_burst = i % (burst_size + quiet_period) < burst_size
                timestamp = self._generate_timestamp(start_time, i)
                
                if in_burst:
                    log = self._generate_normal_log(timestamp)
                    log['severity'] = random.choice(['INFO', 'WARNING'])
                else:
                    log = self._generate_normal_log(timestamp)
                    log['message'] = "Quiet period - low activity"
                
                logs.append(json.dumps(log))
        
        elif pattern == 'anomaly':
            # Normal logs with sudden anomaly spikes
            anomaly_points = [num_logs // 4, num_logs // 2, 3 * num_logs // 4]
            for i in range(num_logs):
                timestamp = self._generate_timestamp(start_time, i)
                
                if i in anomaly_points or any(abs(i - ap) < 10 for ap in anomaly_points):
                    log = self._generate_attack_log(timestamp, 'anomaly')
                else:
                    log = self._generate_normal_log(timestamp)
                
                logs.append(json.dumps(log))
        
        return logs
    
    def tamper_logs(self, logs: List[str], tamper_ratio: float = 0.1) -> List[str]:
        """
        Tamper with logs to test integrity verification
        
        Args:
            logs: Original logs
            tamper_ratio: Ratio of logs to tamper
            
        Returns:
            Tampered logs
        """
        tampered_logs = logs.copy()
        num_tamper = int(len(logs) * tamper_ratio)
        tamper_indices = random.sample(range(len(logs)), num_tamper)
        
        for idx in tamper_indices:
            # Different tampering strategies
            strategy = random.choice(['modify', 'delete', 'inject'])
            
            if strategy == 'modify':
                # Modify log content
                log_dict = json.loads(tampered_logs[idx])
                log_dict['value'] = 999.99  # Impossible value
                log_dict['message'] = "TAMPERED ENTRY"
                tampered_logs[idx] = json.dumps(log_dict)
            
            elif strategy == 'delete':
                # Replace with empty
                tampered_logs[idx] = json.dumps({'deleted': True})
            
            elif strategy == 'inject':
                # Inject fake field
                log_dict = json.loads(tampered_logs[idx])
                log_dict['fake_field'] = "malicious_injection"
                tampered_logs[idx] = json.dumps(log_dict)
        
        return tampered_logs
    
    def get_log_statistics(self, logs: List[str]) -> Dict:
        """Get statistics about generated logs"""
        if not logs:
            return {}
        
        sizes = [len(log.encode('utf-8')) for log in logs]
        
        return {
            'total_logs': len(logs),
            'total_size_bytes': sum(sizes),
            'avg_size_bytes': sum(sizes) / len(sizes),
            'min_size_bytes': min(sizes),
            'max_size_bytes': max(sizes),
            'unique_devices': len(set(json.loads(log)['device_id'] for log in logs))
        }


class LogCorpus:
    """
    Pre-defined log datasets for testing
    """
    
    @staticmethod
    def get_small_dataset() -> List[str]:
        """Small dataset: 1K logs"""
        gen = IoTLogGenerator(seed=42)
        return gen.generate_logs(1000, attack_ratio=0.05)
    
    @staticmethod
    def get_medium_dataset() -> List[str]:
        """Medium dataset: 10K logs"""
        gen = IoTLogGenerator(seed=42)
        return gen.generate_logs(10000, attack_ratio=0.03)
    
    @staticmethod
    def get_large_dataset() -> List[str]:
        """Large dataset: 100K logs"""
        gen = IoTLogGenerator(seed=42)
        return gen.generate_logs(100000, attack_ratio=0.02)
    
    @staticmethod
    def get_burst_pattern_dataset() -> List[str]:
        """Dataset with burst pattern"""
        gen = IoTLogGenerator(seed=42)
        return gen.generate_logs_with_pattern(5000, pattern='burst')
    
    @staticmethod
    def get_anomaly_pattern_dataset() -> List[str]:
        """Dataset with anomaly pattern"""
        gen = IoTLogGenerator(seed=42)
        return gen.generate_logs_with_pattern(5000, pattern='anomaly')
