"""Admission control on the shared httpx client (WT-1922).

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
