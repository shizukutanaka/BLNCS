import time

from blncs.core.simple_cache import SimpleCache


def test_simple_cache_set_get_round_trip():
    cache = SimpleCache(max_size=4, default_ttl=10)
    cache.set('alpha', {'value': 1})

    retrieved = cache.get('alpha')

    assert retrieved == {'value': 1}
    stats = cache.stats()
    assert stats['size'] == 1
    assert stats['hits'] == 1


def test_simple_cache_ttl_expiration():
    cache = SimpleCache(max_size=4, default_ttl=1)
    cache.set('token', 'secret', ttl=0.1)

    time.sleep(0.2)

    assert cache.get('token') is None
    stats = cache.stats()
    assert stats['size'] == 0
    assert stats['misses'] >= 1


def test_simple_cache_eviction_order():
    cache = SimpleCache(max_size=2, default_ttl=10)
    cache.set('k1', 'v1')
    cache.set('k2', 'v2')
    cache.get('k1')  # promote k1
    cache.set('k3', 'v3')  # should evict k2 (least recently used)

    assert cache.get('k1') == 'v1'
    assert cache.get('k2') is None
    assert cache.get('k3') == 'v3'


def test_simple_cache_configure_adjusts_limits():
    cache = SimpleCache(max_size=3, default_ttl=5)
    cache.configure(max_size=1, default_ttl=1)
    cache.set('k1', 'v1')
    cache.set('k2', 'v2')

    assert cache.get('k1') is None  # evicted when resizing
    assert cache.get('k2') == 'v2'
    stats = cache.stats()
    assert stats['max_size'] == 1
    assert stats['ttl'] == 1
