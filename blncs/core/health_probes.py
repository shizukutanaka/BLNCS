#!/usr/bin/env python3
"""
Advanced Health Checks and Probes Module
Implements Kubernetes liveness, readiness, and startup probes (2025 best practices)
Based on Kubernetes Pod Health Check standards and cloud-native patterns
"""

import asyncio
import logging
import time
from typing import Dict, List, Optional, Callable, Any, Awaitable
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
from contextlib import asynccontextmanager

logger = logging.getLogger(__name__)


class ProbeType(Enum):
    """Health probe types following Kubernetes standards"""
    LIVENESS = "liveness"      # Is the container running?
    READINESS = "readiness"    # Is the container ready to receive traffic?
    STARTUP = "startup"        # Has the container started?


class ProbeStatus(Enum):
    """Health probe status outcomes"""
    SUCCESS = "success"
    FAILURE = "failure"
    UNKNOWN = "unknown"


@dataclass
class ProbeConfig:
    """Configuration for a health probe"""
    name: str
    probe_type: ProbeType
    check_func: Callable[[], Awaitable[bool]]
    initial_delay_seconds: int = 0  # Delay before first check
    timeout_seconds: int = 1        # Timeout for the probe
    period_seconds: int = 10        # How often to perform the probe
    success_threshold: int = 1      # Consecutive successes required
    failure_threshold: int = 3      # Consecutive failures before marking unhealthy
    critical: bool = False          # If failure should block readiness


@dataclass
class ProbeResult:
    """Result of a health probe execution"""
    name: str
    probe_type: ProbeType
    status: ProbeStatus
    timestamp: datetime = field(default_factory=datetime.utcnow)
    error_message: Optional[str] = None
    execution_time_ms: float = 0.0
    consecutive_successes: int = 0
    consecutive_failures: int = 0


class HealthProbeManager:
    """
    Manages Kubernetes-style health probes (liveness, readiness, startup)
    Implements cloud-native health checking best practices
    """

    def __init__(self):
        self.probes: Dict[str, ProbeConfig] = {}
        self.results: Dict[str, ProbeResult] = {}
        self.probe_history: Dict[str, List[ProbeResult]] = {}
        self.last_check_time: Dict[str, datetime] = {}
        self.max_history: int = 100  # Keep last N results

    def register_probe(
        self,
        config: ProbeConfig
    ) -> None:
        """Register a new health probe"""
        self.probes[config.name] = config
        self.results[config.name] = ProbeResult(
            name=config.name,
            probe_type=config.probe_type,
            status=ProbeStatus.UNKNOWN
        )
        self.probe_history[config.name] = []
        logger.info(f"Registered {config.probe_type.value} probe: {config.name}")

    async def run_probe(self, probe_name: str) -> ProbeResult:
        """
        Execute a single health probe

        Args:
            probe_name: Name of the probe to execute

        Returns:
            ProbeResult with status and details
        """
        if probe_name not in self.probes:
            raise ValueError(f"Unknown probe: {probe_name}")

        config = self.probes[probe_name]
        start_time = time.time()

        try:
            # Wait for initial delay before first check
            if probe_name not in self.last_check_time:
                if config.initial_delay_seconds > 0:
                    await asyncio.sleep(config.initial_delay_seconds)

            # Execute probe with timeout
            health_check = await asyncio.wait_for(
                config.check_func(),
                timeout=config.timeout_seconds
            )

            execution_time = (time.time() - start_time) * 1000

            if health_check:
                # Success
                current_result = self.results[probe_name]
                current_result.consecutive_successes += 1
                current_result.consecutive_failures = 0

                if current_result.consecutive_successes >= config.success_threshold:
                    current_result.status = ProbeStatus.SUCCESS
                    current_result.error_message = None

                logger.debug(
                    f"Probe {probe_name} succeeded "
                    f"(consecutive: {current_result.consecutive_successes})"
                )
            else:
                # Failure
                current_result = self.results[probe_name]
                current_result.consecutive_failures += 1
                current_result.consecutive_successes = 0

                if current_result.consecutive_failures >= config.failure_threshold:
                    current_result.status = ProbeStatus.FAILURE
                    current_result.error_message = "Health check returned false"

                logger.warning(
                    f"Probe {probe_name} failed "
                    f"(consecutive: {current_result.consecutive_failures})"
                )

            current_result.execution_time_ms = execution_time
            current_result.timestamp = datetime.utcnow()

        except asyncio.TimeoutError:
            logger.error(f"Probe {probe_name} timed out after {config.timeout_seconds}s")
            current_result = self.results[probe_name]
            current_result.status = ProbeStatus.FAILURE
            current_result.error_message = f"Timeout after {config.timeout_seconds}s"
            current_result.consecutive_failures += 1
            current_result.consecutive_successes = 0
            current_result.execution_time_ms = (time.time() - start_time) * 1000

        except Exception as e:
            logger.error(f"Probe {probe_name} raised exception: {e}")
            current_result = self.results[probe_name]
            current_result.status = ProbeStatus.FAILURE
            current_result.error_message = str(e)
            current_result.consecutive_failures += 1
            current_result.consecutive_successes = 0
            current_result.execution_time_ms = (time.time() - start_time) * 1000

        # Keep history
        self._record_history(probe_name, current_result)
        self.last_check_time[probe_name] = datetime.utcnow()

        return current_result

    def _record_history(self, probe_name: str, result: ProbeResult) -> None:
        """Keep a rolling history of probe results"""
        if probe_name not in self.probe_history:
            self.probe_history[probe_name] = []

        self.probe_history[probe_name].append(result)

        # Keep only recent history
        if len(self.probe_history[probe_name]) > self.max_history:
            self.probe_history[probe_name] = self.probe_history[probe_name][-self.max_history:]

    async def run_all_probes_of_type(self, probe_type: ProbeType) -> Dict[str, ProbeResult]:
        """
        Run all probes of a specific type concurrently

        Args:
            probe_type: Type of probes to run

        Returns:
            Dict of probe results
        """
        probes_to_run = [
            name for name, config in self.probes.items()
            if config.probe_type == probe_type
        ]

        if not probes_to_run:
            return {}

        # Run probes concurrently
        tasks = [self.run_probe(name) for name in probes_to_run]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        result_dict = {}
        for probe_name, result in zip(probes_to_run, results):
            if isinstance(result, Exception):
                result_dict[probe_name] = ProbeResult(
                    name=probe_name,
                    probe_type=ProbeType(probe_name),
                    status=ProbeStatus.FAILURE,
                    error_message=str(result)
                )
            else:
                result_dict[probe_name] = result

        return result_dict

    def get_liveness_status(self) -> bool:
        """
        Get overall liveness status
        Container should be restarted if liveness is false
        """
        liveness_probes = {
            name: config for name, config in self.probes.items()
            if config.probe_type == ProbeType.LIVENESS
        }

        if not liveness_probes:
            return True  # No liveness probes means alive

        for name in liveness_probes.keys():
            result = self.results.get(name)
            if result and result.status == ProbeStatus.FAILURE:
                return False

        return True

    def get_readiness_status(self) -> bool:
        """
        Get overall readiness status
        Container should not receive traffic if readiness is false
        """
        readiness_probes = {
            name: config for name, config in self.probes.items()
            if config.probe_type == ProbeType.READINESS
        }

        if not readiness_probes:
            return True  # No readiness probes means ready

        # All readiness probes must pass
        for name, config in readiness_probes.items():
            result = self.results.get(name)
            if result and result.status == ProbeStatus.FAILURE:
                if config.critical:
                    return False

        return True

    def get_startup_status(self) -> bool:
        """
        Get overall startup status
        Liveness and readiness probes don't start until startup succeeds
        """
        startup_probes = {
            name: config for name, config in self.probes.items()
            if config.probe_type == ProbeType.STARTUP
        }

        if not startup_probes:
            return True  # No startup probes means started

        # All startup probes must pass
        for name in startup_probes.keys():
            result = self.results.get(name)
            if result and result.status != ProbeStatus.SUCCESS:
                return False

        return True

    def get_health_summary(self) -> Dict[str, Any]:
        """
        Get comprehensive health summary
        Suitable for metrics/monitoring endpoints
        """
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "liveness": {
                "status": "healthy" if self.get_liveness_status() else "unhealthy",
                "probes": {
                    name: {
                        "status": result.status.value,
                        "last_check": result.timestamp.isoformat(),
                        "consecutive_failures": result.consecutive_failures,
                        "error": result.error_message
                    }
                    for name, result in self.results.items()
                    if self.probes[name].probe_type == ProbeType.LIVENESS
                }
            },
            "readiness": {
                "status": "ready" if self.get_readiness_status() else "not_ready",
                "probes": {
                    name: {
                        "status": result.status.value,
                        "last_check": result.timestamp.isoformat(),
                        "consecutive_failures": result.consecutive_failures,
                        "error": result.error_message
                    }
                    for name, result in self.results.items()
                    if self.probes[name].probe_type == ProbeType.READINESS
                }
            },
            "startup": {
                "status": "started" if self.get_startup_status() else "starting",
                "probes": {
                    name: {
                        "status": result.status.value,
                        "last_check": result.timestamp.isoformat(),
                        "error": result.error_message
                    }
                    for name, result in self.results.items()
                    if self.probes[name].probe_type == ProbeType.STARTUP
                }
            }
        }

    def reset_probe_counters(self, probe_name: str) -> None:
        """Reset consecutive success/failure counters for a probe"""
        if probe_name in self.results:
            self.results[probe_name].consecutive_successes = 0
            self.results[probe_name].consecutive_failures = 0


# Global probe manager instance
_global_probe_manager: Optional[HealthProbeManager] = None


def get_probe_manager() -> HealthProbeManager:
    """Get or create global probe manager"""
    global _global_probe_manager
    if _global_probe_manager is None:
        _global_probe_manager = HealthProbeManager()
    return _global_probe_manager


@asynccontextmanager
async def health_probe_context(
    manager: Optional[HealthProbeManager] = None
):
    """Context manager for probe management"""
    mgr = manager or get_probe_manager()
    try:
        yield mgr
    finally:
        pass


__all__ = [
    'ProbeType',
    'ProbeStatus',
    'ProbeConfig',
    'ProbeResult',
    'HealthProbeManager',
    'get_probe_manager',
    'health_probe_context',
]
