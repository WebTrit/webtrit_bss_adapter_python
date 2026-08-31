"""Unit tests for the Prometheus metrics (WT-1718).

No server and no network: the connection pool is faked, because what is worth
testing is the reading of it — every attribute httpcore keeps private is read
defensively, and a rename upstream must cost the metric rather than the scrape.
"""

import os
import sys

import pytest
from httpcore._async.connection_pool import AsyncPoolRequest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

import metrics  # noqa: E402


def pool_request(queued: bool) -> AsyncPoolRequest:
    """Build a real httpcore request so that `is_queued()` is httpcore's own.

    A request counts as waiting only until a connection is assigned to it, so a
    stand-in of our own would test our assumption rather than httpcore's
    behaviour. The connection is set directly instead of through
    `assign_to_connection`, which also fires an anyio event and would need a
    running loop; `is_queued` reads the attribute and nothing else.
    """
    request = AsyncPoolRequest(object())
    if not queued:
        request.connection = object()
    return request


class FakeConnection:
    """Duck-types what the collector reads off an httpcore connection."""

    def __init__(self, host: str, idle: bool):
        self._origin = type("Origin", (), {"host": host.encode()})()
        self._idle = idle

    def is_idle(self) -> bool:
        return self._idle


class FakePool:
    def __init__(self, connections, queued=0, active=0, max_connections=100):
        self.connections = connections
        # `_requests` mixes both, exactly as httpcore keeps it.
        self._requests = [pool_request(queued=True) for _ in range(queued)] + [
            pool_request(queued=False) for _ in range(active)
        ]
        self._max_connections = max_connections


class FakeClient:
    def __init__(self, pool):
        self._transport = type("Transport", (), {"_pool": pool})()


@pytest.fixture
def collected(monkeypatch):
    """Return a function that collects the pool metrics off the given pools."""

    def _collect(pools: dict):
        clients = {verify: FakeClient(pool) for verify, pool in pools.items()}
        monkeypatch.setattr("bss.async_http_api._shared_clients", clients, raising=False)

        samples = {}
        for family in metrics.HttpxPoolCollector().collect():
            for sample in family.samples:
                samples[(sample.name, tuple(sorted(sample.labels.items())))] = sample.value
        return samples

    return _collect


def test_reports_the_limit_the_queue_and_the_connections(collected) -> None:
    pool = FakePool(
        connections=[
            FakeConnection("ps.example.com", idle=False),
            FakeConnection("ps.example.com", idle=False),
            FakeConnection("ps.example.com", idle=True),
        ],
        queued=7,
        max_connections=3,
    )

    samples = collected({False: pool})

    assert samples[("httpx_pool_max_connections", (("verify", "false"),))] == 3
    assert samples[("httpx_pool_queued_requests", (("verify", "false"),))] == 7
    assert samples[
        ("httpx_pool_connections", (("host", "ps.example.com"), ("state", "active"), ("verify", "false")))
    ] == 2
    assert samples[
        ("httpx_pool_connections", (("host", "ps.example.com"), ("state", "idle"), ("verify", "false")))
    ] == 1


def test_does_not_count_requests_that_already_hold_a_connection(collected) -> None:
    """Only the waiting requests are queued, though `_requests` carries both.

    Counting the whole list would report a queue whenever anything is in flight
    at all — most of the time under load — and the saturation signal, which is
    the pool at its limit *and* a queue behind it, would then never go quiet.
    """
    pool = FakePool(connections=[], queued=2, active=9, max_connections=100)

    samples = collected({False: pool})

    assert samples[("httpx_pool_queued_requests", (("verify", "false"),))] == 2


def test_reports_each_shared_client_separately(collected) -> None:
    samples = collected(
        {
            True: FakePool(connections=[], queued=1, max_connections=100),
            False: FakePool(connections=[], queued=2, max_connections=50),
        }
    )

    assert samples[("httpx_pool_queued_requests", (("verify", "true"),))] == 1
    assert samples[("httpx_pool_queued_requests", (("verify", "false"),))] == 2


def test_skips_what_a_future_httpcore_may_have_renamed(collected) -> None:
    """A pool without the private attributes yields fewer samples, not an error."""

    class Renamed:
        connections = []

    samples = collected({False: Renamed()})

    assert ("httpx_pool_max_connections", (("verify", "false"),)) not in samples
    assert ("httpx_pool_queued_requests", (("verify", "false"),)) not in samples


def test_survives_a_connection_that_answers_nothing(collected) -> None:
    class Odd:
        pass

    samples = collected({False: FakePool(connections=[Odd()], queued=0)})

    # Unknown host, and a connection that cannot say it is idle counts as active.
    assert samples[
        ("httpx_pool_connections", (("host", "unknown"), ("state", "active"), ("verify", "false")))
    ] == 1


@pytest.mark.parametrize(
    "server, expected",
    [
        ("https://ps.example.com/rest", "ps.example.com"),
        ("http://127.0.0.1:8080", "127.0.0.1"),
        ("not a url", "unknown"),
        ("", "unknown"),
    ],
)
def test_host_label_is_reduced_to_the_hostname(server: str, expected: str) -> None:
    assert metrics._host_of(server) == expected


def test_counters_record_what_was_given_up_on() -> None:
    before_deadline = metrics.REQUEST_DEADLINE_EXPIRED.labels(method="retrieve_contacts")._value.get()
    before_pool = metrics.HTTPX_POOL_TIMEOUTS.labels(host="ps.example.com")._value.get()

    metrics.record_deadline_expired("retrieve_contacts")
    metrics.record_pool_timeout("https://ps.example.com/rest")

    assert metrics.REQUEST_DEADLINE_EXPIRED.labels(method="retrieve_contacts")._value.get() == before_deadline + 1
    assert metrics.HTTPX_POOL_TIMEOUTS.labels(host="ps.example.com")._value.get() == before_pool + 1


def test_a_call_with_no_name_is_still_counted() -> None:
    before = metrics.REQUEST_DEADLINE_EXPIRED.labels(method="unknown")._value.get()

    metrics.record_deadline_expired("")

    assert metrics.REQUEST_DEADLINE_EXPIRED.labels(method="unknown")._value.get() == before + 1
