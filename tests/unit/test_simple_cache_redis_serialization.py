"""Regression tests for the Redis backend serialization of SimpleCache.

The Redis backend previously used pickle for values, which meant anyone
able to write to Redis could execute code in this process. Values are
now stored as JSON (with explicit type tags for a few extra Python
types). These tests pin that behavior with an in-memory fake Redis.
"""

import json
from datetime import date, datetime
from decimal import Decimal

import pytest

from blncs.core import simple_cache
from blncs.core.simple_cache import LightningCache, SimpleCache


class FakeRedis:
    """Minimal in-memory stand-in for a redis-py client."""

    def __init__(self):
        self.store = {}

    def ping(self):
        return True

    def get(self, key):
        return self.store.get(key)

    def set(self, key, value):
        self.store[key] = value
        return True

    def setex(self, key, ttl, value):
        self.store[key] = value
        return True

    def delete(self, *keys):
        removed = 0
        for key in keys:
            if key in self.store:
                del self.store[key]
                removed += 1
        return removed

    def keys(self, pattern):
        prefix = pattern.rstrip("*")
        return [k for k in self.store if k.startswith(prefix)]


@pytest.fixture
def redis_cache(monkeypatch):
    if not simple_cache.HAS_REDIS:
        pytest.skip("redis-py is not installed")
    fake = FakeRedis()
    monkeypatch.setattr(simple_cache.redis, "from_url", lambda url: fake)
    cache = SimpleCache(backend="redis", redis_url="redis://localhost:6379")
    assert cache.backend == "redis"
    return cache, fake


def test_redis_round_trip_json_native_values(redis_cache):
    cache, _ = redis_cache
    samples = {
        "text": "hello",
        "int": 42,
        "float": 1.25,
        "bool": True,
        "list": [1, "two", 3.5, None],
        "dict": {"name": "node", "nested": {"channels": [1, 2, 3]}},
    }
    for key, value in samples.items():
        assert cache.set(key, value) is True
        assert cache.get(key) == value

    sentinel = object()
    assert cache.set("nothing", None) is True
    assert cache.get("nothing", sentinel) is None
    assert cache.get("missing", sentinel) is sentinel


def test_redis_round_trip_tagged_types(redis_cache):
    cache, _ = redis_cache
    samples = {
        "tuple": (1, "two", 3.5),
        "set": {1, 2, 3},
        "datetime": datetime(2026, 11, 17, 12, 30, 15),
        "date": date(2026, 11, 17),
        "decimal": Decimal("1234.5678"),
        "bytes": b"\x00\x01binary\xff",
    }
    for key, value in samples.items():
        assert cache.set(key, value) is True
        result = cache.get(key)
        assert result == value
        assert type(result) is type(value)


def test_redis_dict_with_reserved_tag_key_round_trips(redis_cache):
    cache, _ = redis_cache
    value = {"__blncs_type__": "tuple", "items": "user data, not a tag"}
    assert cache.set("tricky", value) is True
    assert cache.get("tricky") == value


def test_redis_stored_payload_is_plain_json(redis_cache):
    cache, fake = redis_cache
    assert cache.set("k", {"a": [1, 2]}) is True
    raw = fake.store["blncs:k"]
    assert isinstance(raw, bytes)
    assert not raw.startswith(b"\x80")  # pickle protocol magic
    assert json.loads(raw.decode("utf-8")) == {"a": [1, 2]}


def test_redis_pickle_payload_is_never_executed(redis_cache, tmp_path):
    cache, fake = redis_cache
    marker = tmp_path / "pickle_executed"
    # Hand-written protocol-0 pickle that would run os.system if any
    # code path unpickled it. Stored raw, as an attacker with Redis
    # write access could plant it.
    payload = (
        "cos\nsystem\np0\n(S'touch " + str(marker) + "'\np1\ntp2\nRp3\n."
    ).encode()
    fake.store["blncs:evil"] = payload

    sentinel = object()
    assert cache.get("evil", sentinel) is sentinel
    assert not marker.exists()


def test_redis_legacy_or_corrupt_payload_is_a_miss(redis_cache):
    cache, fake = redis_cache
    fake.store["blncs:legacy"] = b"\x80\x04\x95\x05\x00\x00\x00\x00\x00\x00\x00."
    sentinel = object()
    assert cache.get("legacy", sentinel) is sentinel


def test_redis_unserializable_value_is_not_cached(redis_cache):
    cache, fake = redis_cache
    assert cache.set("obj", object()) is False
    assert "blncs:obj" not in fake.store


def test_lightning_cache_round_trip_over_redis(redis_cache):
    cache, _ = redis_cache
    lightning = LightningCache(cache=cache)
    info = {"channel_id": "123x456", "capacity": 1_000_000, "active": True}
    assert lightning.cache_channel_info("123x456", info) is True
    assert lightning.get_channel_info("123x456") == info

    route = [{"pubkey": "abc", "fee_msat": 1000}, {"pubkey": "def", "fee_msat": 2000}]
    assert lightning.cache_route("hash123", route) is True
    assert lightning.get_route("hash123") == route
