"""Prometheus metrics for the adapter (WT-1718).

WT-1717 took an instance down while every alert stayed green: the thread pool
was exhausted, requests piled up — "902 requests in / 0 out" — and nothing
reported it, because the container was alive and `/api/health-check` returns a
constant. These metrics make that state visible.

Metrics are served on their own port rather than on the application's, so that
`/metrics` is never reachable through the public ingress. The port is read from
`METRICS_PORT` and defaults to 9568, matching what the Helm chart passes.

The server runs in a daemon thread of this process, which is correct for the
single uvicorn worker the image starts. Adding `--workers` would give each
worker its own registry, and a scrape would then report just one of them; that
would need the multiprocess mode of `prometheus_client`.
"""

import logging
from typing import Any

from fastapi import FastAPI
from prometheus_client import REGISTRY, Counter, start_http_server
from prometheus_client.core import GaugeMetricFamily
from prometheus_fastapi_instrumentator import Instrumentator

DEFAULT_METRICS_PORT = 9568

#: Both counters are deliberately threshold-free: any increment already means a
#: request was given up on, so an alert on `> 0` needs no baseline to tune. The
#: latency histogram shows the same slowness, but not that it was *this* that
#: ended the request.
REQUEST_DEADLINE_EXPIRED = Counter(
    "request_deadline_expired_total",
    "Adapter calls aborted because the whole call chain exceeded REQUEST_DEADLINE.",
    ["method"],
)

HTTPX_POOL_TIMEOUTS = Counter(
    "httpx_pool_timeouts_total",
    "Requests that gave up waiting for a free connection in the shared httpx pool.",
    ["host"],
)


def record_deadline_expired(method: str) -> None:
    """Count an adapter call killed by the per-request deadline (WT-1720)."""
    try:
        REQUEST_DEADLINE_EXPIRED.labels(method=method or "unknown").inc()
    except Exception as e:
        logging.debug(f"Could not record a deadline expiry: {e}")


def record_pool_timeout(server: str) -> None:
    """Count a checkout that gave up on the connection pool.

    The Elixir components get this from Finch as a telemetry event; in httpx it
    surfaces as an exception, so it has to be counted where it is caught.
    """
    try:
        HTTPX_POOL_TIMEOUTS.labels(host=_host_of(server)).inc()
    except Exception as e:
        logging.debug(f"Could not record a pool timeout: {e}")


def _host_of(server: str) -> str:
    """Reduce a base URL to its host, so the label matches the pool metrics."""
    try:
        from urllib.parse import urlparse

        return urlparse(server).hostname or "unknown"
    except Exception:
        return "unknown"


def instrument_app(app: FastAPI) -> None:
    """Attach the ASGI middleware that records request rate, latency and status.

    Middleware rather than the `RouteWithLogging` route class: the latter only
    wraps routes registered on the routers, so `/api/health-check` — declared
    straight on the app — would be missing.

    `requests_inprogress` is the metric WT-1717 lacked, so it is enabled here
    even though the library leaves it off by default. Its labels stay bounded:
    the handler is the route template (`/user/voicemails/{message_id}`), never
    the resolved path, and status codes are grouped into 2xx/3xx/4xx/5xx.
    """
    Instrumentator(
        should_group_status_codes=True,
        should_instrument_requests_inprogress=True,
        inprogress_labels=True,
    ).instrument(app)


def start_metrics_server(config: Any) -> None:
    """Serve /metrics on its own port.

    A failure here is logged and swallowed: metrics are not worth refusing to
    serve traffic over, and a port already in use must not turn into an outage.
    """
    register_httpx_pool_collector()

    port = _metrics_port(config)

    try:
        start_http_server(port)
        logging.info(f"Prometheus metrics available on port {port}")
    except Exception as e:
        logging.error(f"Could not start the metrics server on port {port}: {e}")


def register_httpx_pool_collector() -> None:
    """Register the pool collector once, tolerating a repeated call."""
    global _pool_collector_registered

    if _pool_collector_registered:
        return

    try:
        REGISTRY.register(HttpxPoolCollector())
        _pool_collector_registered = True
    except Exception as e:
        logging.error(f"Could not register the httpx pool collector: {e}")


_pool_collector_registered = False


class HttpxPoolCollector:
    """Reports how close the shared httpx clients are to their connection limit.

    This is the resource that failed in WT-1717: the pool is bounded
    (`PORTASWITCH_MAX_CONNECTIONS`, 100 by default) and once every connection is
    in use, further calls queue instead of failing, so the instance stops
    answering while still looking healthy. `queued_requests` above zero means
    that is happening right now.

    Values are read when Prometheus scrapes rather than on a timer, so they are
    never stale. `connections` hands out a copy of the list and `len()` on a
    list cannot tear, so reading from the scrape thread is safe; the numbers may
    be a moment behind the event loop, which does not matter for a gauge.

    httpcore keeps the queue and the limit private, so every attribute is read
    defensively: a future version that renames them costs the metric, not the
    scrape.
    """

    def collect(self):
        limit = GaugeMetricFamily(
            "httpx_pool_max_connections",
            "Connection limit of the shared httpx client.",
            labels=["verify"],
        )
        queued = GaugeMetricFamily(
            "httpx_pool_queued_requests",
            "Requests waiting for a free connection; above zero the pool is exhausted.",
            labels=["verify"],
        )
        connections = GaugeMetricFamily(
            "httpx_pool_connections",
            "Connections currently held, by destination and state.",
            labels=["verify", "host", "state"],
        )

        for verify, pool in _shared_pools():
            _collect_pool(pool, str(verify).lower(), limit, queued, connections)

        yield limit
        yield queued
        yield connections


def _collect_pool(
    pool: Any,
    verify: str,
    limit: GaugeMetricFamily,
    queued: GaugeMetricFamily,
    connections: GaugeMetricFamily,
) -> None:
    max_connections = getattr(pool, "_max_connections", None)
    if isinstance(max_connections, int):
        limit.add_metric([verify], max_connections)

    waiting = getattr(pool, "_requests", None)
    if waiting is not None:
        queued.add_metric([verify], len(waiting))

    counted: dict = {}
    for connection in getattr(pool, "connections", []):
        host = _connection_host(connection)
        state = "idle" if _is_idle(connection) else "active"
        counted[(host, state)] = counted.get((host, state), 0) + 1

    for (host, state), count in counted.items():
        connections.add_metric([verify, host, state], count)


def _shared_pools():
    """Yield (verify, pool) for every shared client that has a pool.

    Imported here rather than at module scope so that metrics never take part in
    the import order of the adapters.
    """
    try:
        from bss.async_http_api import _shared_clients
    except Exception as e:
        logging.debug(f"httpx pool metrics unavailable: {e}")
        return

    for verify, client in list(_shared_clients.items()):
        pool = getattr(getattr(client, "_transport", None), "_pool", None)
        if pool is not None:
            yield verify, pool


def _connection_host(connection: Any) -> str:
    origin = getattr(connection, "_origin", None)
    host = getattr(origin, "host", None)
    if isinstance(host, bytes):
        return host.decode("ascii", "replace")
    return str(host) if host else "unknown"


def _is_idle(connection: Any) -> bool:
    is_idle = getattr(connection, "is_idle", None)
    try:
        return bool(is_idle())
    except Exception:
        return False


def _metrics_port(config: Any) -> int:
    try:
        return int(config.get_conf_val("Metrics", "Port", default=DEFAULT_METRICS_PORT))
    except (TypeError, ValueError):
        logging.warning(f"METRICS_PORT is not a number, falling back to {DEFAULT_METRICS_PORT}")
        return DEFAULT_METRICS_PORT
