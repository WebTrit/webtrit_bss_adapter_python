"""Admission control on the shared httpx client, and the pool state it protects (WT-1922).

Once a checkout has to queue behind a full pool, a request cancelled while
queued leaves the connection the pool already assigned to it in a state that is
neither usable nor reclaimable — no socket, never reaped — and the pod loses
that slot for good. Keeping fewer requests in flight than the pool can hold
means a checkout never queues, so there is nothing to strand.
"""
import asyncio
import os
import sys

import pytest

_app_path = os.path.join(os.path.dirname(__file__), '..', 'app')
sys.path.insert(0, _app_path)

import metrics  # noqa: E402
from bss.async_http_api import (DEFAULT_MAX_CONNECTIONS,  # noqa: E402
                                AsyncHTTPAPIConnector,
                                close_shared_async_clients, inflight_limit)


# --- how many requests are admitted ----------------------------------------

@pytest.mark.parametrize("max_connections, expected", [
    (100, 90),   # 10% headroom
    (50, 45),
    (20, 18),    # the 10% would be 2, which is also the floor
    (10, 8),     # floor applies: 10% is 1, minimum headroom is 2
    (3, 1),
    (1, 1),      # never zero, or nothing could ever be sent
])
def test_admission_limit_stays_below_the_pool(max_connections, expected):
    assert inflight_limit(max_connections) == expected
    assert inflight_limit(max_connections) < max_connections or max_connections == 1


def test_admission_limit_falls_back_to_the_httpx_default():
    """A connector that sets no limit gets httpx's own pool size (100)."""
    for unset in (None, 0, -5, "nonsense"):
        assert inflight_limit(unset) == inflight_limit(DEFAULT_MAX_CONNECTIONS)


# --- the semaphore actually bounds concurrency ------------------------------

class RecordingConnector(AsyncHTTPAPIConnector):
    """Counts how many requests are inside the HTTP exchange at once."""

    def __init__(self, max_connections):
        super().__init__("http://pbx.example.com")
        self._verify_https = False
        self._max_connections = max_connections
        self._max_keepalive_connections = 2
        self.inflight = 0
        self.peak = 0

    async def _send_rest_request(self, *args, **kwargs):
        self.inflight += 1
        self.peak = max(self.peak, self.inflight)
        try:
            await asyncio.sleep(0.01)
            return {"ok": True}
        finally:
            self.inflight -= 1


@pytest.mark.asyncio
async def test_concurrent_requests_never_exceed_the_admission_limit():
    await close_shared_async_clients()
    connector = RecordingConnector(max_connections=10)
    try:
        await asyncio.gather(
            *(connector.send_rest_request("GET", "/rest/Account/get_account_list")
              for _ in range(60))
        )
        assert connector.peak == inflight_limit(10)
        assert connector.peak < 10, "a checkout must never be able to queue"
    finally:
        await close_shared_async_clients()


@pytest.mark.asyncio
async def test_the_permit_is_released_when_a_request_fails():
    """A failing request must not consume a permit permanently, or the adapter
    would strangle itself after enough errors."""
    await close_shared_async_clients()

    class Failing(RecordingConnector):
        async def _send_rest_request(self, *args, **kwargs):
            raise RuntimeError("boom")

    connector = Failing(max_connections=4)
    try:
        for _ in range(20):
            with pytest.raises(RuntimeError):
                await connector.send_rest_request("GET", "/rest/Generic/get_version")
        # still able to send: the permits came back
        connector.__class__ = RecordingConnector
        await connector.send_rest_request("GET", "/rest/Generic/get_version")
    finally:
        await close_shared_async_clients()


# --- the pool state that made WT-1922 invisible -----------------------------

class Conn:
    """Stands in for httpcore's AsyncHTTPConnection.

    `is_idle` mirrors httpcore 1.0.9 exactly — `self._connect_failed if
    self._connection is None else self._connection.is_idle()` — because the
    classification under review depends on that coupling: a connection that
    failed to connect reports itself idle, which is how the pool comes to reap
    it. A stub with an independent `idle` flag would let the test assert a
    combination the real object cannot produce.
    """

    def __init__(self, inner_idle=False, connection=object(), connect_failed=False):
        self._connection = _Inner(inner_idle) if connection is not None else None
        self._connect_failed = connect_failed

    def is_idle(self):
        if self._connection is None:
            return self._connect_failed
        return self._connection.is_idle()


class _Inner:
    def __init__(self, idle):
        self._idle = idle

    def is_idle(self):
        return self._idle


def test_pool_state_separates_a_stranded_connection_from_a_busy_one():
    # assigned to a request that never ran: no protocol object, no connect failure
    assert metrics._connection_state(Conn(connection=None)) == "connecting"
    # genuinely serving a request
    assert metrics._connection_state(Conn()) == "active"
    # keep-alive, waiting to be reused
    assert metrics._connection_state(Conn(inner_idle=True)) == "idle"
    # a checkout that failed to connect reports itself idle, which is how the
    # pool comes to reap it — so it must not be counted as stranded
    assert metrics._connection_state(Conn(connection=None, connect_failed=True)) == "idle"


def test_pool_state_of_an_unknown_object_stays_active():
    """httpcore keeps these attributes private, so a rename upstream must cost
    the new state, not turn every connection into a false alarm."""

    class Opaque:
        def is_idle(self):
            return False

    assert metrics._connection_state(Opaque()) == "active"
