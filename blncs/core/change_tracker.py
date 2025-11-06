"""
BLNCS Configuration Change Tracker
Lightweight configuration change tracking and audit system
"""

import time
import threading
import hashlib
from typing import Dict, Any, List, Optional, Set
from collections import deque
from datetime import datetime


class ConfigChangeTracker:
    """Lightweight configuration change tracking system"""

    def __init__(self, max_history: int = 100):
        self.max_history = max_history
        self.change_history: deque = deque(maxlen=max_history)
        self.current_config_hash: Optional[str] = None
        self.baseline_config: Optional[Dict[str, Any]] = None
        self._lock = threading.Lock()

    def set_baseline(self, config: Dict[str, Any]):
        """Set baseline configuration"""
        with self._lock:
            self.baseline_config = self._deep_copy_config(config)
            self.current_config_hash = self._calculate_config_hash(config)

    def record_config_change(self, new_config: Dict[str, Any],
                           change_source: str = "unknown",
                           metadata: Optional[Dict[str, Any]] = None):
        """Record a configuration change"""
        with self._lock:
            if self.baseline_config is None:
                self.set_baseline(new_config)
                return

            new_hash = self._calculate_config_hash(new_config)
            old_hash = self.current_config_hash

            if new_hash == old_hash:
                return  # No change

            # Record the change
            change_record = {
                'timestamp': time.time(),
                'datetime': datetime.now().isoformat(),
                'old_hash': old_hash,
                'new_hash': new_hash,
                'change_source': change_source,
                'metadata': metadata or {},
                'changed_keys': self._get_changed_keys(self.baseline_config, new_config),
                'added_keys': self._get_added_keys(self.baseline_config, new_config),
                'removed_keys': self._get_removed_keys(self.baseline_config, new_config)
            }

            self.change_history.append(change_record)
            self.current_config_hash = new_hash

    def _calculate_config_hash(self, config: Dict[str, Any]) -> str:
        """Calculate configuration hash"""
        config_str = self._config_to_sorted_string(config)
        return hashlib.sha256(config_str.encode()).hexdigest()[:16]

    def _config_to_sorted_string(self, config: Dict[str, Any]) -> str:
        """Convert config to sorted string for hashing"""
        def sort_dict(d):
            if not isinstance(d, dict):
                return str(d)
            return {k: sort_dict(v) for k, v in sorted(d.items())}

        import json
        return json.dumps(sort_dict(config), sort_keys=True)

    def _deep_copy_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Deep copy configuration"""
        import copy
        return copy.deepcopy(config)

    def _get_changed_keys(self, old_config: Dict[str, Any], new_config: Dict[str, Any]) -> List[str]:
        """Get keys that have changed values"""
        changed = []

        def compare_configs(old_cfg, new_cfg, path=""):
            if not isinstance(old_cfg, dict) or not isinstance(new_cfg, dict):
                if old_cfg != new_cfg:
                    changed.append(path)
                return

            for key in set(old_cfg.keys()) | set(new_cfg.keys()):
                current_path = f"{path}.{key}" if path else key
                if key in old_cfg and key in new_cfg:
                    compare_configs(old_cfg[key], new_cfg[key], current_path)
                elif key in old_cfg:
                    changed.append(current_path)
                elif key in new_cfg:
                    changed.append(current_path)

        compare_configs(old_config, new_config)
        return changed

    def _get_added_keys(self, old_config: Dict[str, Any], new_config: Dict[str, Any]) -> List[str]:
        """Get keys that were added"""
        added = []

        def find_added(old_cfg, new_cfg, path=""):
            if not isinstance(new_cfg, dict):
                return

            for key, value in new_cfg.items():
                current_path = f"{path}.{key}" if path else key
                if key not in old_cfg:
                    added.append(current_path)
                else:
                    find_added(old_cfg.get(key, {}), value, current_path)

        find_added(old_config, new_config)
        return added

    def _get_removed_keys(self, old_config: Dict[str, Any], new_config: Dict[str, Any]) -> List[str]:
        """Get keys that were removed"""
        removed = []

        def find_removed(old_cfg, new_cfg, path=""):
            if not isinstance(old_cfg, dict):
                return

            for key in old_cfg.keys():
                current_path = f"{path}.{key}" if path else key
                if key not in new_cfg:
                    removed.append(current_path)
                elif isinstance(old_cfg[key], dict) and isinstance(new_cfg.get(key), dict):
                    find_removed(old_cfg[key], new_cfg[key], current_path)

        find_removed(old_config, new_config)
        return removed

    def get_change_history(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Get change history"""
        with self._lock:
            history = list(self.change_history)
            if limit:
                return history[-limit:]
            return history

    def get_recent_changes(self, minutes: int = 60) -> List[Dict[str, Any]]:
        """Get changes from the last N minutes"""
        with self._lock:
            cutoff_time = time.time() - (minutes * 60)
            return [change for change in self.change_history if change['timestamp'] >= cutoff_time]

    def get_change_summary(self) -> Dict[str, Any]:
        """Get change summary"""
        with self._lock:
            if not self.change_history:
                return {'total_changes': 0, 'recent_changes': 0}

            total_changes = len(self.change_history)
            recent_changes = len(self.get_recent_changes(60))

            # Get change sources
            sources = {}
            for change in self.change_history:
                source = change['change_source']
                sources[source] = sources.get(source, 0) + 1

            return {
                'total_changes': total_changes,
                'recent_changes': recent_changes,
                'change_sources': sources,
                'baseline_hash': self.current_config_hash,
                'oldest_change': self.change_history[0]['timestamp'] if self.change_history else None,
                'newest_change': self.change_history[-1]['timestamp'] if self.change_history else None
            }

    def rollback_to_change(self, change_index: int) -> Optional[Dict[str, Any]]:
        """Rollback configuration to a specific change"""
        with self._lock:
            if 0 <= change_index < len(self.change_history):
                # This would require storing full config at each change
                # For now, return None as this is a complex operation
                return None
            return None

    def clear_history(self):
        """Clear change history"""
        with self._lock:
            self.change_history.clear()


class SystemEventTracker:
    """Track system events and changes"""

    def __init__(self, max_events: int = 500):
        self.max_events = max_events
        self.events: deque = deque(maxlen=max_events)
        self._lock = threading.Lock()

    def record_event(self, event_type: str, description: str,
                    metadata: Optional[Dict[str, Any]] = None):
        """Record a system event"""
        with self._lock:
            event = {
                'timestamp': time.time(),
                'datetime': datetime.now().isoformat(),
                'event_type': event_type,
                'description': description,
                'metadata': metadata or {}
            }

            self.events.append(event)

    def get_events(self, event_type: Optional[str] = None,
                  limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Get events with optional filtering"""
        with self._lock:
            events = list(self.events)

            if event_type:
                events = [e for e in events if e['event_type'] == event_type]

            if limit:
                events = events[-limit:]

            return events

    def get_event_summary(self) -> Dict[str, Any]:
        """Get event summary"""
        with self._lock:
            if not self.events:
                return {'total_events': 0, 'event_types': {}}

            event_types = {}
            for event in self.events:
                event_type = event['event_type']
                event_types[event_type] = event_types.get(event_type, 0) + 1

            return {
                'total_events': len(self.events),
                'event_types': event_types,
                'oldest_event': self.events[0]['timestamp'] if self.events else None,
                'newest_event': self.events[-1]['timestamp'] if self.events else None
            }

    def clear_events(self):
        """Clear all events"""
        with self._lock:
            self.events.clear()


# Global instances
_config_tracker = None
_event_tracker = None
_tracker_lock = threading.Lock()


def get_config_change_tracker() -> ConfigChangeTracker:
    """Get global configuration change tracker"""
    global _config_tracker
    if _config_tracker is None:
        with _tracker_lock:
            if _config_tracker is None:
                _config_tracker = ConfigChangeTracker()
    return _config_tracker


def get_system_event_tracker() -> SystemEventTracker:
    """Get global system event tracker"""
    global _event_tracker
    if _event_tracker is None:
        with _tracker_lock:
            if _event_tracker is None:
                _event_tracker = SystemEventTracker()
    return _event_tracker


def record_config_change(config: Dict[str, Any], source: str = "system",
                        metadata: Optional[Dict[str, Any]] = None):
    """Record configuration change (convenience function)"""
    tracker = get_config_change_tracker()
    tracker.record_config_change(config, source, metadata)


def record_system_event(event_type: str, description: str,
                       metadata: Optional[Dict[str, Any]] = None):
    """Record system event (convenience function)"""
    tracker = get_system_event_tracker()
    tracker.record_event(event_type, description, metadata)


def get_change_summary():
    """Get change summary (convenience function)"""
    config_tracker = get_config_change_tracker()
    event_tracker = get_system_event_tracker()

    return {
        'config_changes': config_tracker.get_change_summary(),
        'system_events': event_tracker.get_event_summary(),
        'recent_events': event_tracker.get_events(limit=10)
    }


__all__ = [
    'ConfigChangeTracker', 'SystemEventTracker',
    'get_config_change_tracker', 'get_system_event_tracker',
    'record_config_change', 'record_system_event', 'get_change_summary'
]
