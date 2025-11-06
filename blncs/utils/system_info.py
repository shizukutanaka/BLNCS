def _sample_cpu_percent() -> Optional[float]:
    """Return a single CPU usage sample without blocking."""

    global _CPU_PERCENT_WARMED

    if psutil is None:
        return None

    try:
        if not _CPU_PERCENT_WARMED:
            psutil.cpu_percent(interval=None)
            _CPU_PERCENT_WARMED = True

        value = psutil.cpu_percent(interval=0.0)
        return round(float(value), 1)
    except Exception:
        return None
#!/usr/bin/env python3
"""System Information Utility.

Provides lightweight system resource monitoring and diagnostics while
preferentially using :mod:`psutil` for cross-platform support. Falls back to
standard-library only behaviour when psutil is unavailable.
"""

import argparse
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Optional, Tuple, Union

try:
    import psutil  # type: ignore
except Exception:  # pragma: no cover - psutil is optional at runtime
    psutil = None  # type: ignore

try:
    from tabulate import tabulate
except Exception:  # pragma: no cover - optional dependency
    tabulate = None


_ORIGINAL_TIME = time
_CPU_PERCENT_WARMED = False


def _sample_cpu_percent() -> Optional[float]:
    """Return a single CPU usage sample without blocking."""

    global _CPU_PERCENT_WARMED

    if psutil is None:
        return None

    try:
        if not _CPU_PERCENT_WARMED:
            psutil.cpu_percent(interval=None)
            _CPU_PERCENT_WARMED = True

        value = psutil.cpu_percent(interval=0.0)
        return round(float(value), 1)
    except Exception:
        return None


def _bytes_to_gb(value: float) -> float:
    """Convert raw bytes to gigabytes with two decimal precision."""

    return round(value / (1024 ** 3), 2)


def _format_duration(total_seconds: int) -> str:
    """Convert a duration in seconds to a human-readable string."""

    if total_seconds <= 0:
        return "0s"

    units = (
        ("d", 86400),
        ("h", 3600),
        ("m", 60),
        ("s", 1),
    )

    parts: list[str] = []
    remainder = total_seconds

    for suffix, length in units:
        if remainder < length and not parts:
            continue

        value, remainder = divmod(remainder, length)
        if value or suffix == "s":
            parts.append(f"{value}{suffix}")

    return " ".join(parts)


def _clone_data(value: Any) -> Any:
    """Clone JSON-style values so filtered reports do not share references."""

    if isinstance(value, dict):
        return {key: _clone_data(sub_value) for key, sub_value in value.items()}
    if isinstance(value, list):
        return [_clone_data(item) for item in value]
    return value


def _parse_field_paths(raw_fields: Optional[str]) -> list[tuple[str, ...]]:
    if raw_fields is None:
        return []

    entries = [entry.strip() for entry in raw_fields.split(",")]
    field_paths: list[tuple[str, ...]] = []

    for entry in entries:
        if not entry:
            raise ValueError("Field list contains an empty entry.")

        components = [component.strip() for component in entry.split(".")]
        components = [component for component in components if component]
        if not components:
            raise ValueError(f"Field path '{entry}' is invalid.")

        field_paths.append(tuple(components))

    unique_paths: dict[tuple[str, ...], None] = {path: None for path in field_paths}
    return list(unique_paths.keys())


def _filter_report_fields(report: Dict[str, Any], field_paths: Iterable[tuple[str, ...]]) -> Dict[str, Any]:
    if not field_paths:
        return _clone_data(report)

    filtered: Dict[str, Any] = {}

    for path in field_paths:
        source_cursor: Any = report
        filtered_cursor: Dict[str, Any] = filtered

        for index, key in enumerate(path):
            if not isinstance(source_cursor, dict) or key not in source_cursor:
                joined = ".".join(path)
                raise ValueError(f"Field path '{joined}' not found in report.")

            value = source_cursor[key]
            is_last = index == (len(path) - 1)

            if is_last:
                filtered_cursor[key] = _clone_data(value)
                continue

            next_filtered = filtered_cursor.get(key)
            if not isinstance(next_filtered, dict):
                next_filtered = {}
                filtered_cursor[key] = next_filtered

            filtered_cursor = next_filtered
            source_cursor = value

    return filtered


REPORT_SECTIONS: tuple[str, ...] = ("system", "memory", "cpu", "disk", "network", "processes")
PROC_UPTIME_PATH = Path("/proc/uptime")
_LAST_UPTIME_STRATEGY: Optional[str] = None
_UPTIME_SOURCE_LABELS: dict[str, str] = {
    "psutil": "psutil.boot_time",
    "clock": "time.clock_gettime",
    "windows": "GetTickCount64",
    "proc": "/proc/uptime",
    "darwin": "sysctl kern.boottime",
}


def _uptime_from_psutil() -> Optional[int]:
    """Attempt to derive uptime using psutil when available."""

    if psutil is None:
        return None

    try:
        boot_time = float(psutil.boot_time())
    except Exception:
        return None

    try:
        current_time = time.time()
    except Exception:
        current_time = datetime.now().timestamp()

    uptime = current_time - boot_time
    if uptime < 0:
        return None

    return int(uptime)


def _uptime_from_clock() -> Optional[int]:
    """Attempt to derive uptime using available clock_gettime clocks."""

    clock_gettime = getattr(time, "clock_gettime", None)
    if clock_gettime is None:
        return None

    clock_ids = [
        getattr(time, name, None)
        for name in ("CLOCK_BOOTTIME", "CLOCK_UPTIME", "CLOCK_UPTIME_RAW")
    ]

    for clock_id in clock_ids:
        if clock_id is None:
            continue
        try:
            value = clock_gettime(clock_id)
        except (OSError, ValueError):
            continue
        if value is None:
            continue
        seconds = int(value)
        if seconds >= 0:
            return seconds

    return None


def _uptime_from_windows() -> Optional[int]:
    """Use Windows-specific GetTickCount64 fallback if available."""

    if platform.system() != "Windows":
        return None

    try:
        import ctypes  # local import for Windows-only usage

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        tick_count = kernel32.GetTickCount64()
    except Exception:
        return None

    return int(tick_count // 1000)


def _uptime_from_proc() -> Optional[int]:
    """Parse /proc/uptime when available (primarily Linux)."""

    if platform.system() != "Linux":
        return None

    try:
        if not PROC_UPTIME_PATH.exists():
            return None
        raw = PROC_UPTIME_PATH.read_text(encoding="utf-8").split()[0]
        seconds = int(float(raw))
    except (OSError, ValueError, IndexError):
        return None

    if seconds < 0:
        return None

    return seconds


def _uptime_from_darwin_sysctl() -> Optional[int]:
    """Fallback for macOS using sysctl kern.boottime when psutil is absent."""

    if platform.system() != "Darwin":
        return None

    try:
        output = subprocess.check_output(
            ["sysctl", "-n", "kern.boottime"],
            encoding="utf-8",
            stderr=subprocess.DEVNULL,
        ).strip()
    except (subprocess.SubprocessError, FileNotFoundError, OSError):
        return None

    match = re.search(r"sec\s*=\s*(\d+)", output)
    if match is None:
        try:
            boot_time = float(output)
        except ValueError:
            return None
    else:
        boot_time = float(match.group(1))

    uptime = time.time() - boot_time
    if uptime < 0:
        return None

    return int(uptime)


def _get_uptime_seconds() -> Tuple[Optional[int], Optional[str], bool, list[str], list[float], list[bool]]:
    """Resolve system uptime using a series of lightweight strategies."""

    global _LAST_UPTIME_STRATEGY

    strategies = [
        ("psutil", _uptime_from_psutil),
        ("clock", _uptime_from_clock),
        ("windows", _uptime_from_windows),
        ("proc", _uptime_from_proc),
        ("darwin", _uptime_from_darwin_sysctl),
    ]

    attempts: list[str] = []
    attempt_durations: list[float] = []
    attempt_successes: list[bool] = []

    perf_counter_func = getattr(time, "perf_counter", None)
    if perf_counter_func is None:
        perf_counter_func = time.time

    if _LAST_UPTIME_STRATEGY is not None:
        cached = next(
            (entry for entry in strategies if entry[0] == _LAST_UPTIME_STRATEGY),
            None,
        )
        if cached is not None:
            name, func = cached
            attempts.append(name)
            start_time = perf_counter_func()
            uptime = func()
            duration = max(perf_counter_func() - start_time, 0.0)
            attempt_durations.append(duration)
            succeeded = uptime is not None
            attempt_successes.append(succeeded)
            if succeeded:
                _LAST_UPTIME_STRATEGY = name
                return uptime, name, True, attempts, attempt_durations, attempt_successes

    for name, func in strategies:
        if name == _LAST_UPTIME_STRATEGY:
            continue
        attempts.append(name)
        start_time = perf_counter_func()
        uptime = func()
        duration = max(perf_counter_func() - start_time, 0.0)
        attempt_durations.append(duration)
        succeeded = uptime is not None
        attempt_successes.append(succeeded)
        if succeeded:
            _LAST_UPTIME_STRATEGY = name
            return uptime, name, True, attempts, attempt_durations, attempt_successes

    _LAST_UPTIME_STRATEGY = None
    return None, None, False, attempts, attempt_durations, attempt_successes


def get_basic_system_info() -> Dict[str, Any]:
    """Get basic system information."""
    try:
        info: Dict[str, Any] = {
            "platform": platform.system(),
            "platform_version": platform.version(),
            "architecture": platform.architecture()[0],
            "processor": platform.processor() or "Unknown",
            "hostname": platform.node(),
            "python_version": platform.python_version(),
            "timestamp": datetime.now().isoformat()
        }

        uptime_seconds, uptime_source, uptime_success, uptime_attempts, uptime_durations, uptime_successes = _get_uptime_seconds()

        label = _UPTIME_SOURCE_LABELS.get(uptime_source or "", uptime_source)

        if uptime_seconds is not None:
            info["uptime_seconds"] = uptime_seconds
            info["uptime_human"] = _format_duration(uptime_seconds)
            if uptime_source is not None:
                info["uptime_source"] = uptime_source
                if label:
                    info["uptime_source_label"] = label
            info["uptime_success"] = uptime_success
        else:
            info["uptime_success"] = uptime_success
            info["uptime_message"] = "Uptime unavailable"

        if uptime_attempts:
            info["uptime_attempts"] = uptime_attempts
            info["uptime_attempt_labels"] = [
                _UPTIME_SOURCE_LABELS.get(name, name) for name in uptime_attempts
            ]
            info["uptime_attempt_count"] = len(uptime_attempts)
        if uptime_durations:
            info["uptime_attempt_durations"] = uptime_durations
            info["uptime_attempt_total_duration"] = sum(uptime_durations)
        if uptime_successes:
            info["uptime_attempt_successes"] = uptime_successes

        return info
    except Exception as e:
        return {"error": f"Failed to get system info: {e}"}


def get_memory_info() -> Dict[str, Any]:
    """Get memory usage information."""

    try:
        if psutil is not None:
            vm = psutil.virtual_memory()
            info: Dict[str, Any] = {
                "total_gb": _bytes_to_gb(vm.total),
                "available_gb": _bytes_to_gb(vm.available),
                "used_gb": _bytes_to_gb(vm.used),
                "used_percent": round(vm.percent, 1)
            }

            try:
                swap = psutil.swap_memory()
                if getattr(swap, "total", 0):
                    info.update(
                        {
                            "swap_total_gb": _bytes_to_gb(swap.total),
                            "swap_used_gb": _bytes_to_gb(swap.used),
                            "swap_percent": round(swap.percent, 1)
                        }
                    )
            except Exception:
                pass

            return info

        if platform.system() == "Linux":
            with open('/proc/meminfo', 'r', encoding='utf-8') as file_handle:
                meminfo = file_handle.read()

            mem_total = 0
            mem_available = 0

            for line in meminfo.split('\n'):
                if 'MemTotal:' in line:
                    mem_total = int(line.split()[1]) * 1024
                elif 'MemAvailable:' in line:
                    mem_available = int(line.split()[1]) * 1024

            if mem_total > 0:
                used = mem_total - mem_available
                return {
                    "total_gb": _bytes_to_gb(mem_total),
                    "available_gb": _bytes_to_gb(mem_available),
                    "used_gb": _bytes_to_gb(used),
                    "used_percent": round((used / mem_total) * 100, 1)
                }

        return {"status": "Memory info not available on this platform"}
    except Exception as e:
        return {"error": f"Failed to get memory info: {e}"}


def get_cpu_info() -> Dict[str, Any]:
    """Get CPU usage information."""
    try:
        if psutil is not None:
            logical = psutil.cpu_count(logical=True) or os.cpu_count() or 1
            physical = psutil.cpu_count(logical=False)
            usage_percent = _sample_cpu_percent()
            info: Dict[str, Any] = {
                "logical_cores": logical,
                "physical_cores": physical,
            }

            if usage_percent is not None:
                info["usage_percent"] = usage_percent

            try:
                freq = psutil.cpu_freq()
                if freq is not None and getattr(freq, "current", 0):
                    info["frequency_mhz"] = round(freq.current, 1)
            except Exception:
                pass

            if hasattr(os, 'getloadavg'):
                try:
                    load1, load5, load15 = os.getloadavg()
                    info.update(
                        {
                            "load_1min": round(load1, 2),
                            "load_5min": round(load5, 2),
                            "load_15min": round(load15, 2)
                        }
                    )
                except Exception:
                    pass

            return info

        # Standard library fallback
        cpu_count = os.cpu_count() or 1

        load_info: Dict[str, Any] = {}
        if hasattr(os, 'getloadavg'):
            try:
                load1, load5, load15 = os.getloadavg()
                load_info = {
                    "load_1min": round(load1, 2),
                    "load_5min": round(load5, 2),
                    "load_15min": round(load15, 2)
                }
            except Exception:
                load_info = {}

        result = {"logical_cores": cpu_count}
        result.update(load_info)
        return result
    except Exception as e:
        return {"error": f"Failed to get CPU info: {e}"}


def get_disk_info(path: Optional[Union[Path, str]] = None) -> Dict[str, Any]:
    """Get disk usage information."""

    target_path = Path(path).expanduser() if path is not None else Path.cwd()
    target = str(target_path)

    try:
        if psutil is not None:
            usage = psutil.disk_usage(target)
            info: Dict[str, Any] = {
                "total_gb": _bytes_to_gb(usage.total),
                "used_gb": _bytes_to_gb(usage.used),
                "free_gb": _bytes_to_gb(usage.free),
                "used_percent": round(usage.percent, 1)
            }

            try:
                io_counters = psutil.disk_io_counters()
                if io_counters is not None:
                    info.update(
                        {
                            "read_gb": _bytes_to_gb(io_counters.read_bytes),
                            "write_gb": _bytes_to_gb(io_counters.write_bytes)
                        }
                    )
            except Exception:
                pass

            return info

        total, used, free = shutil.disk_usage(target)

        return {
            "total_gb": _bytes_to_gb(total),
            "used_gb": _bytes_to_gb(used),
            "free_gb": _bytes_to_gb(free),
            "used_percent": round((used / total) * 100, 1)
        }
    except FileNotFoundError:
        return {"error": f"Disk path not found: {target}"}
    except OSError as error:
        return {"error": f"Failed to access disk path {target}: {error}"}
    except Exception as error:  # pragma: no cover - unexpected failure
        return {"error": f"Failed to get disk info: {error}"}


def get_network_connections() -> Dict[str, Any]:
    """Get basic network information."""
    try:
        if psutil is not None:
            interface_stats = psutil.net_if_stats()
            interface_names = list(interface_stats.keys())
            active_interfaces = [name for name, stats in interface_stats.items() if getattr(stats, "isup", False)]
            non_loopback = [name for name in active_interfaces if name.lower() not in {"lo", "loopback"}]

            info: Dict[str, Any] = {
                "network_interfaces": len(interface_names),
                "active_interfaces": len(active_interfaces),
                "interface_names": (non_loopback or active_interfaces)[:3]
            }

            try:
                counters = psutil.net_io_counters(pernic=True)
                if counters:
                    total_sent = sum(getattr(counters.get(name), "bytes_sent", 0) for name in active_interfaces)
                    total_recv = sum(getattr(counters.get(name), "bytes_recv", 0) for name in active_interfaces)
                    info.update(
                        {
                            "bytes_sent_mb": round(total_sent / (1024 ** 2), 2),
                            "bytes_recv_mb": round(total_recv / (1024 ** 2), 2)
                        }
                    )
            except Exception:
                pass

            return info

        if platform.system() == "Linux":
            with open('/proc/net/dev', 'r', encoding='utf-8') as file_handle:
                lines = file_handle.readlines()[2:]
                interfaces = [line.split(':')[0].strip() for line in lines]
                interfaces = [iface for iface in interfaces if iface != 'lo']

                return {
                    "network_interfaces": len(interfaces),
                    "interface_names": interfaces[:3]
                }

        return {"status": "Network info not available on this platform"}
    except Exception as e:
        return {"error": f"Failed to get network info: {e}"}


def get_process_count() -> Dict[str, Any]:
    """Get basic process information."""
    try:
        info: Dict[str, Any] = {
            "current_pid": os.getpid(),
            "parent_pid": os.getppid() if hasattr(os, 'getppid') else None,
            "python_executable": sys.executable
        }

        if psutil is not None:
            try:
                info["process_count"] = len(psutil.pids())
            except Exception:
                pass

            try:
                current = psutil.Process()
                memory = current.memory_info()
                info["current_memory_mb"] = round(memory.rss / (1024 ** 2), 2)
            except Exception:
                pass

        return info
    except Exception as e:
        return {"error": f"Failed to get process info: {e}"}


def get_comprehensive_system_report(
    sections: Optional[Iterable[str]] = None,
    *,
    disk_path: Optional[Union[Path, str]] = None,
) -> Dict[str, Any]:
    """Get comprehensive system report."""

    requested = list(dict.fromkeys(sections or REPORT_SECTIONS))
    requested_set = set(requested)

    report: Dict[str, Any] = {}
    if "system" in requested_set:
        report["system"] = get_basic_system_info()
    if "memory" in requested_set:
        report["memory"] = get_memory_info()
    if "cpu" in requested_set:
        report["cpu"] = get_cpu_info()
    if "disk" in requested_set:
        report["disk"] = get_disk_info(disk_path)
    if "network" in requested_set:
        report["network"] = get_network_connections()
    if "processes" in requested_set:
        report["processes"] = get_process_count()

    return {section: report[section] for section in requested if section in report}


def format_system_report(report: Dict[str, Any], include_sections: Optional[Iterable[str]] = None) -> str:
    """Format system report for display."""

    include = list(dict.fromkeys(include_sections or REPORT_SECTIONS))
    include_set = set(include)

    output: list[str] = []
    output.append("System Information Report")
    output.append("=" * 40)
    # System Info
    if "system" in include_set and "system" in report:
        system = report["system"] or {}
        if "error" not in system:
            output.append("System:")
            output.append(f"  Platform: {system.get('platform', 'Unknown')} ({system.get('architecture', 'Unknown')})")
            output.append(f"  Hostname: {system.get('hostname', 'Unknown')}")
            output.append(f"  Python: {system.get('python_version', 'Unknown')}")
            uptime_success = system.get('uptime_success')
            label = system.get('uptime_source_label') or system.get('uptime_source')
            if system.get('uptime_human') is not None:
                uptime_seconds = system.get('uptime_seconds')
                uptime_line = f"  Uptime: {system['uptime_human']}"
                if uptime_seconds is not None:
                    uptime_line = f"{uptime_line} ({uptime_seconds}s)"
                if label:
                    uptime_line = f"{uptime_line} via {label}"
                output.append(uptime_line)
            elif system.get('uptime_seconds') is not None:
                uptime_line = f"  Uptime: {system['uptime_seconds']} seconds"
                if label:
                    uptime_line = f"{uptime_line} via {label}"
                output.append(uptime_line)
            elif uptime_success is False:
                message = system.get('uptime_message', 'Uptime unavailable')
                output.append(f"  Uptime: {message}")
            if system.get('uptime_attempt_labels'):
                attempts = ", ".join(system['uptime_attempt_labels'])
                output.append(f"  Uptime attempts: {attempts}")
                durations = system.get('uptime_attempt_durations') or []
                if durations:
                    formatted = ", ".join(f"{duration:.4f}s" for duration in durations)
                    output.append(f"  Uptime attempt durations: {formatted}")
                count = system.get('uptime_attempt_count')
                total = system.get('uptime_attempt_total_duration')
                successes = system.get('uptime_attempt_successes') or []
                if count is not None:
                    output.append(f"  Uptime attempt count: {count}")
                if total is not None:
                    output.append(f"  Uptime attempt total duration: {total:.4f}s")
                if successes:
                    formatted_successes = ", ".join("ok" if flag else "fail" for flag in successes)
                    output.append(f"  Uptime attempt successes: {formatted_successes}")
            output.append("")

    # CPU Info
    if "cpu" in include_set and "cpu" in report:
        cpu = report["cpu"] or {}
        if "error" not in cpu:
            output.append("CPU:")
            output.append(f"  Logical cores: {cpu.get('logical_cores', 0)}")
            if cpu.get('physical_cores') is not None:
                output.append(f"  Physical cores: {cpu['physical_cores']}")
            if cpu.get('usage_percent') is not None:
                output.append(f"  Usage: {cpu['usage_percent']:.1f}%")
            if cpu.get('frequency_mhz') is not None:
                output.append(f"  Frequency: {cpu['frequency_mhz']:.1f} MHz")
            if cpu.get('load_1min') is not None:
                output.append(f"  Load Average: {cpu['load_1min']} (1min), {cpu.get('load_5min', 'n/a')} (5min)")
            output.append("")

    # Memory Info
    if "memory" in include_set and "memory" in report:
        memory = report["memory"] or {}
        if "error" not in memory:
            output.append("Memory:")
            if memory.get('total_gb') is not None:
                output.append(
                    "  Usage: {used:.1f}% ({used_gb:.1f}GB / {total_gb:.1f}GB)".format(
                        used=memory.get('used_percent', 0),
                        used_gb=memory.get('used_gb', 0),
                        total_gb=memory.get('total_gb', 0)
                    )
                )
            if memory.get('available_gb') is not None:
                output.append(f"  Available: {memory.get('available_gb', 0):.1f}GB")
            if memory.get('swap_total_gb'):
                output.append(
                    "  Swap: {swap_percent:.1f}% ({swap_used:.1f}GB / {swap_total:.1f}GB)".format(
                        swap_percent=memory.get('swap_percent', 0),
                        swap_used=memory.get('swap_used_gb', 0),
                        swap_total=memory.get('swap_total_gb', 0)
                    )
                )
            output.append("")

    # Disk Info
    if "disk" in include_set and "disk" in report:
        disk = report["disk"] or {}
        if "error" not in disk:
            output.append("Disk:")
            if disk.get('used_percent') is not None:
                output.append(
                    "  Usage: {used:.1f}% ({used_gb:.1f}GB / {total_gb:.1f}GB)".format(
                        used=disk.get('used_percent', 0),
                        used_gb=disk.get('used_gb', 0),
                        total_gb=disk.get('total_gb', 0)
                    )
                )
            if disk.get('free_gb') is not None:
                output.append(f"  Free Space: {disk.get('free_gb', 0):.1f}GB")
            if disk.get('read_gb') is not None or disk.get('write_gb') is not None:
                output.append(
                    "  IO: {read:.2f}GB read / {write:.2f}GB written".format(
                        read=disk.get('read_gb', 0.0),
                        write=disk.get('write_gb', 0.0)
                    )
                )
            output.append("")

    # Process Info
    if "processes" in include_set and "processes" in report:
        processes = report["processes"] or {}
        if "error" not in processes:
            output.append("Process Info:")
            output.append(f"  Current PID: {processes.get('current_pid', 'Unknown')}")
            if processes.get('parent_pid'):
                output.append(f"  Parent PID: {processes['parent_pid']}")
            output.append(f"  Python: {processes.get('python_executable', 'Unknown')}")
            if processes.get('process_count') is not None:
                output.append(f"  Process Count: {processes['process_count']}")
            if processes.get('current_memory_mb') is not None:
                output.append(f"  Current Process Memory: {processes['current_memory_mb']:.2f}MB")
            output.append("")

    # Network Info (summary only)
    if "network" in include_set and "network" in report:
        network = report["network"] or {}
        if "error" not in network and not network.get("status"):
            output.append("Network:")
            output.append(f"  Interfaces: {network.get('network_interfaces', 0)}")
            if network.get('active_interfaces') is not None:
                output.append(f"  Active: {network['active_interfaces']}")
            if network.get('interface_names'):
                output.append(f"  Names: {', '.join(network['interface_names'])}")
            if network.get('bytes_sent_mb') is not None or network.get('bytes_recv_mb') is not None:
                output.append(
                    "  Traffic: {sent:.2f}MB sent / {recv:.2f}MB received".format(
                        sent=network.get('bytes_sent_mb', 0.0),
                        recv=network.get('bytes_recv_mb', 0.0)
                    )
                )
            output.append("")

    return "\n".join(output)


def build_table_rows(report: Dict[str, Any], include_sections: Iterable[str]) -> list[list[str]]:
    """Convert the report into rows suitable for tabular display."""

    rows: list[list[str]] = []

    for section in include_sections:
        data = report.get(section)
        if not isinstance(data, dict) or data.get("error"):
            continue

        rows.append([section.upper(), "", ""])

        for key, value in data.items():
            if isinstance(value, (dict, list)):
                continue
            if key == "uptime_source_label":
                continue
            rows.append(["", key, str(value)])

        if data.get("uptime_source_label"):
            rows.append(["", "uptime_source_display", str(data["uptime_source_label"])])
        if data.get("uptime_attempt_labels"):
            rows.append(["", "uptime_attempts_display", ", ".join(map(str, data["uptime_attempt_labels"]))])
        if data.get("uptime_attempt_durations"):
            formatted = ", ".join(f"{value:.4f}s" for value in data["uptime_attempt_durations"])
            rows.append(["", "uptime_attempt_durations", formatted])
        if data.get("uptime_attempt_count") is not None:
            rows.append(["", "uptime_attempt_count", str(data["uptime_attempt_count"])])
        if data.get("uptime_attempt_total_duration") is not None:
            rows.append(["", "uptime_attempt_total_duration", f"{data['uptime_attempt_total_duration']:.4f}s"])
        if data.get("uptime_attempt_successes"):
            formatted_successes = ", ".join("ok" if flag else "fail" for flag in data["uptime_attempt_successes"])
            rows.append(["", "uptime_attempt_successes", formatted_successes])

    return rows


def _build_argument_parser() -> argparse.ArgumentParser:
    """Create the argument parser for the CLI entry point."""

    parser = argparse.ArgumentParser(description="Display BLNCS system diagnostics.")
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit the system report as JSON for automation pipelines."
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Write the rendered report to the provided file path."
    )
    parser.add_argument(
        "--sections",
        metavar="NAMES",
        help=(
            "Comma-separated list of sections to include. "
            "Available sections: system,memory,cpu,disk,network,processes."
        )
    )
    parser.add_argument(
        "--table",
        action="store_true",
        help="Render output as a table (requires tabulate)."
    )
    parser.add_argument(
        "--list-sections",
        action="store_true",
        help="Print available sections and exit."
    )
    parser.add_argument(
        "--watch",
        type=float,
        help="Refresh interval in seconds for continuous monitoring."
    )
    parser.add_argument(
        "--iterations",
        type=int,
        help="Limit the number of refresh cycles when using --watch. Defaults to infinite."
    )
    parser.add_argument(
        "--clear-screen",
        action="store_true",
        help="Clear the terminal between watch iterations."
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress stdout output (useful when writing reports to a file)."
    )
    parser.add_argument(
        "--duration",
        type=float,
        help="Maximum watch duration in seconds (default unlimited)."
    )
    parser.add_argument(
        "--fields",
        metavar="PATHS",
        help=(
            "Comma-separated list of dotted field paths (e.g. system.platform,memory.used_percent). "
            "Filters the output to only the requested values."
        ),
    )
    parser.add_argument(
        "--disk-path",
        type=Path,
        help="Override the filesystem path used when gathering disk statistics."
    )

    return parser


def _normalize_sections(raw_sections: Optional[str]) -> list[str]:
    """Parse and validate a comma-separated sections string."""

    if raw_sections is None:
        return list(REPORT_SECTIONS)

    parts = [part.strip().lower() for part in raw_sections.split(",")]
    sections = [name for name in dict.fromkeys(parts) if name]

    if not sections:
        raise ValueError(
            "No sections provided. Specify comma-separated names such as 'system,memory'."
        )

    invalid = [name for name in sections if name not in REPORT_SECTIONS]
    if invalid:
        allowed = ", ".join(REPORT_SECTIONS)
        raise ValueError(
            f"Invalid sections: {', '.join(invalid)}. Allowed sections: {allowed}."
        )

    return sections


def _clear_terminal() -> None:
    """Clear the terminal in a cross-platform way when possible."""

    stdout = getattr(sys, "stdout", None)
    if stdout is None or not hasattr(stdout, "isatty") or not stdout.isatty():
        return

    try:
        if os.name == "nt":
            os.system("cls")
        else:
            print("\033[2J\033[H", end="", flush=True)
    except Exception:
        # Clearing the screen is a non-critical enhancement; ignore failures.
        pass


def _resolve_monotonic_clock(time_module: Any) -> Optional[Callable[[], float]]:
    """Resolve an available monotonic clock from the provided module."""

    for candidate in ("monotonic", "perf_counter", "time"):
        func = getattr(time_module, candidate, None)
        if callable(func):
            return func
    return None


def _render_once(
    sections: list[str],
    args: argparse.Namespace,
    iteration: Optional[int] = None,
    *,
    field_paths: Optional[list[tuple[str, ...]]] = None,
) -> int:
    """Render the report according to CLI flags and handle output."""

    report = get_comprehensive_system_report(sections, disk_path=args.disk_path)

    if field_paths:
        try:
            report = _filter_report_fields(report, field_paths)
        except ValueError as error:
            print(str(error), file=sys.stderr)
            return 1

    if args.watch is not None and iteration is not None:
        timestamp = datetime.now().isoformat(timespec="seconds")
        if args.clear_screen:
            _clear_terminal()
        if not args.quiet:
            if not args.clear_screen and iteration > 1:
                print()
            print(f"--- Watch refresh #{iteration} @ {timestamp} ---")

    if args.json:
        rendered = json.dumps(report, indent=2)
    elif args.table:
        if tabulate is None:
            print("Tabular output requested but tabulate is not installed.", file=sys.stderr)
            return 1
        rows = build_table_rows(report, sections)
        rendered = tabulate(rows, headers=["Section", "Metric", "Value"], tablefmt="github")
    else:
        rendered = format_system_report(report, include_sections=sections)

    if not args.quiet:
        print(rendered)

    if args.output is not None:
        try:
            output_path = args.output
            parent = output_path.parent
            if parent and not parent.exists():
                parent.mkdir(parents=True, exist_ok=True)

            content = rendered
            if not args.json and not content.endswith("\n"):
                content = f"{content}\n"

            output_path.write_text(content, encoding="utf-8")
        except OSError as error:
            print(f"Failed to write system report to {output_path}: {error}", file=sys.stderr)
            return 1

    return 0


def main(argv: Optional[list[str]] = None) -> int:
    """CLI entry point for rendering the system report."""

    parser = _build_argument_parser()
    args = parser.parse_args(argv)

    if args.list_sections:
        print(",".join(REPORT_SECTIONS))
        return 0

    try:
        sections = _normalize_sections(args.sections)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    watch_interval = args.watch
    max_iterations = args.iterations
    duration_limit = args.duration

    try:
        field_paths = _parse_field_paths(args.fields)
    except ValueError as error:
        print(str(error), file=sys.stderr)
        return 1

    if watch_interval is not None and watch_interval <= 0:
        print("Watch interval must be a positive number of seconds.", file=sys.stderr)
        return 1

    if max_iterations is not None and max_iterations <= 0:
        print("Iterations must be a positive integer when provided.", file=sys.stderr)
        return 1

    if duration_limit is not None and duration_limit <= 0:
        print("Duration must be a positive number of seconds when provided.", file=sys.stderr)
        return 1

    if watch_interval is None:
        if max_iterations is not None:
            print("--iterations requires --watch to be specified.", file=sys.stderr)
            return 1
        if duration_limit is not None:
            print("--duration requires --watch to be specified.", file=sys.stderr)
            return 1
        if args.clear_screen:
            print("--clear-screen requires --watch to be specified.", file=sys.stderr)
            return 1

    iterations = 0
    monotonic_clock: Optional[Callable[[], float]] = None
    if watch_interval is not None:
        monotonic_clock = _resolve_monotonic_clock(time)
        if monotonic_clock is None:
            monotonic_clock = _resolve_monotonic_clock(_ORIGINAL_TIME)
        if duration_limit is not None and monotonic_clock is None:
            print("--duration requires a monotonic clock on this platform.", file=sys.stderr)
            return 1

    sleep_func: Callable[[float], None]
    if hasattr(time, "sleep") and callable(getattr(time, "sleep")):
        sleep_func = getattr(time, "sleep")  # type: ignore[assignment]
    else:
        sleep_func = _ORIGINAL_TIME.sleep

    start_time = monotonic_clock() if monotonic_clock is not None else None

    try:
        while True:
            iteration_index = iterations + 1
            exit_code = _render_once(
                sections,
                args,
                iteration=iteration_index,
                field_paths=field_paths,
            )
            if exit_code != 0:
                return exit_code

            iterations += 1

            if watch_interval is None:
                break

            if max_iterations is not None and iterations >= max_iterations:
                break

            if duration_limit is not None and start_time is not None and monotonic_clock is not None:
                elapsed = monotonic_clock() - start_time
                if elapsed >= duration_limit:
                    break

            sleep_func(watch_interval)
    except KeyboardInterrupt:
        return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())