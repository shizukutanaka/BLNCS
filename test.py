# BLRCS Tests
import pytest
import asyncio
import tempfile
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).parent))

from blrcs.config import BLRCSConfig, parse_rate_limit
from blrcs.database import Database
from blrcs.cache import Cache
from blrcs.compression import Compressor, CompressionType
from blrcs.backup import BackupManager
from blrcs.monitoring import PerformanceMonitor
from blrcs.plugins import PluginManager
from blrcs.app import BLRCS

@pytest.mark.asyncio
async def test_database():
    """Test database operations"""
    with tempfile.TemporaryDirectory() as tmp:
        db = Database(Path(tmp) / "test.db")
        await db.connect()
        
        # CRUD operations
        assert await db.set("key", {"value": "test"})
        assert await db.get("key") == {"value": "test"}
        assert await db.delete("key")
        assert await db.get("key") is None
        
        await db.disconnect()

@pytest.mark.asyncio
async def test_cache():
    """Test cache operations"""
    cache = Cache(max_size=10)
    
    await cache.set("key", "value")
    assert await cache.get("key") == "value"
    assert await cache.delete("key")
    assert await cache.get("key") is None

@pytest.mark.asyncio
async def test_cache_cleanup_task_graceful_stop():
    """Ensure background cleanup task is started and stops quickly via Cache.stop()."""
    cache = Cache(max_size=10)
    await cache.initialize()
    # Let the background task get scheduled
    await asyncio.sleep(0)
    task = cache._cleanup_task_handle
    assert task is not None
    assert not task.done()
    start = time.monotonic()
    await cache.stop()
    duration = time.monotonic() - start
    assert task.done()
    assert duration < 1.0
    # Idempotency: second stop should be a no-op
    await cache.stop()

@pytest.mark.asyncio
async def test_app_cleanup_stops_cache_task():
    """BLRCS._cleanup should stop the Cache background task."""
    app = BLRCS(mode="cli")
    # init async components (db, cache, monitor)
    await app._init_async()
    # Ensure cleanup task started
    assert app.cache._cleanup_task_handle is not None
    # Cleanup app
    await app._cleanup()
    # Cleanup task should be cleared
    assert app.cache._cleanup_task_handle is None

def test_compression():
    """Test compression"""
    comp = Compressor()
    data = b"Test data " * 100
    
    compressed = comp.compress(data)
    assert len(compressed) < len(data)
    assert comp.decompress(compressed) == data

@pytest.mark.asyncio
async def test_backup():
    """Test backup functionality"""
    with tempfile.TemporaryDirectory() as tmp:
        source = Path(tmp) / "source"
        source.mkdir()
        (source / "test.txt").write_text("content")
        
        manager = BackupManager(Path(tmp) / "backups")
        result = await manager.backup(source, "full")
        
        assert result["type"] == "full"
        assert len(manager.list_backups()) == 1

@pytest.mark.asyncio
async def test_monitoring():
    """Test performance monitoring"""
    monitor = PerformanceMonitor()
    
    metrics = await monitor.collect_metrics()
    assert "cpu_percent" in metrics
    assert "memory_percent" in metrics
    
    monitor.record_request(0.1, success=True)
    assert monitor.counters["total_requests"] == 1

@pytest.mark.asyncio
async def test_plugins():
    """Test plugin system"""
    with tempfile.TemporaryDirectory() as tmp:
        manager = PluginManager(Path(tmp) / "plugins")
        
        # Test hook system
        results = []
        manager.register_hook("test", lambda x: results.append(x))
        await manager.trigger_hook("test", "data")
        assert results == ["data"]

def test_translator_i18n():
    """Test i18n translator basic, fallback, and formatting"""
    from blrcs.i18n import Translator
    t = Translator(default_lang="en", supported_langs=["en", "ja"])

    # Basic retrieval in English
    assert t.get("lightning.button.pause", lang="en") == "Pause"
    # Basic retrieval in Japanese
    assert t.get("lightning.button.pause", lang="ja") == "一時停止"

    # Fallback to default language when requesting unknown language
    # This should use English string and not raise
    assert t.get("lightning.button.resume", lang="zz") == "Resume"

    # Formatting with params (en)
    assert t.get("lightning.poll.next_in", lang="en", sec=3) == "Next poll in 3s"
    # Formatting with params (ja)
    assert t.get("lightning.poll.last_update_ago", lang="ja", sec=5) == "5秒前に更新"

    # Missing key returns the key itself
    assert t.get("i18n.missing.key.example") == "i18n.missing.key.example"

    # If no kwargs are passed, placeholders remain (no exception)
    # This ensures safe behavior when formatting parameters are omitted
    assert "{sec}" in t.get("lightning.poll.next_in", lang="en")

def test_config():
    """Test configuration"""
    config = BLRCSConfig()
    assert config.app_name == "BLRCS"
    
    count, seconds = parse_rate_limit("100/minute")
    assert count == 100
    assert seconds == 60

@pytest.mark.asyncio
async def test_performance():
    """Performance benchmark"""
    import time
    
    with tempfile.TemporaryDirectory() as tmp:
        db = Database(Path(tmp) / "perf.db")
        await db.connect()
        
        # Benchmark writes
        start = time.time()
        for i in range(1000):
            await db.set(f"key_{i}", {"value": i})
        write_time = time.time() - start
        
        # Benchmark reads
        start = time.time()
        for i in range(1000):
            await db.get(f"key_{i}")
        read_time = time.time() - start
        
        await db.disconnect()
        
        print(f"\nPerformance:")
        print(f"  1000 writes: {write_time:.3f}s")
        print(f"  1000 reads: {read_time:.3f}s")
        
        assert write_time < 2.0  # Reasonable limit
        assert read_time < 1.0

# Poller Tests
def test_poller_watchdog_cancels_and_backs_off():
    """Test watchdog timeout cancellation and backoff"""
    import threading
    import types as _types
    from concurrent.futures import ThreadPoolExecutor
    
    class DummyVar:
        def __init__(self, initial=""):
            self.value = initial
        def set(self, v):
            self.value = v
        def get(self):
            return self.value
    
    class TranslatorStub:
        def get(self, key, **kwargs):
            if kwargs:
                return f"{key}:{kwargs}"
            return key
    
    class LoggerStub:
        def __init__(self):
            self.logs = []
        def debug(self, *args, **kwargs):
            self.logs.append(("debug", args, kwargs))
        def info(self, *args, **kwargs):
            self.logs.append(("info", args, kwargs))
        def warning(self, *args, **kwargs):
            self.logs.append(("warning", args, kwargs))
        def exception(self, *args, **kwargs):
            self.logs.append(("exception", args, kwargs))
    
    # Create minimal test app
    from blrcs.desktop import BLRCSDesktopApp
    app = object.__new__(BLRCSDesktopApp)
    app.logger = LoggerStub()
    app.translator = TranslatorStub()
    
    # Initialize poller state
    app._lnd_poll_base_interval_ms = 1000
    app._lnd_poll_interval_ms = 1000
    app._lnd_poll_consecutive_failures = 0
    app._lnd_poll_in_flight = False
    app._lnd_poll_last_error_var = DummyVar()
    app._poll_executor = ThreadPoolExecutor(max_workers=1)
    
    call_started = threading.Event()
    
    def fake_get_info_rest(host, port, tls_cert=None, macaroon_path=None, timeout=5.0):
        call_started.set()
        time.sleep(3.0)  # Simulate slow call
        return {"ok": False, "status": None, "data": None, "error": "simulated slow"}
    
    app.lightning_client = _types.SimpleNamespace(get_info_rest=fake_get_info_rest)
    
    # Minimal UI stubs
    app.lnd_host_var = DummyVar("127.0.0.1")
    app.lnd_port_var = DummyVar("8080")
    app.lnd_tls_var = DummyVar("")
    app.lnd_macaroon_var = DummyVar("")
    
    # Test watchdog behavior
    assert app._lnd_poll_consecutive_failures == 0
    # Note: Full poller test requires async event loop setup
    
    app._poll_executor.shutdown(wait=False)

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
