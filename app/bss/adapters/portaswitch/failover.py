"""Disaster-recovery (geographically dispersed PortaSwitch) failover support.

When the main PortaSwitch site goes down, the installation switches to standalone
(delta) mode: only the secondary site is operational and its API is read-only.

Detection is reactive and fault-code based (there is no mode-reporting endpoint
to poll for the *forward* switch — see BA-47610):

* "main site unavailable" is observed as an httpx timeout / connection error
  against the main site → switch API traffic to the secondary site;
* the secondary site identifies its mode through fault codes returned on calls
  not allowed in the current mode (used for graceful write degradation).

Switching *back* to the main site uses the authoritative `operating_mode` field
of `generic.get_session_data` (BA-47641): while running on standby, the main site
is probed out-of-band and we return to it only once it reports `normal`.

This module holds the shared active-site state, the PortaBilling fault codes, and
the operating_mode values used to drive the failover.
"""
import asyncio
import enum
import logging
from datetime import datetime, timedelta
from typing import Awaitable, Callable, Optional

# Fault codes raised by a PortaBilling secondary site to signal its current mode.
STANDALONE_MODE_FAULT = "standalone_mode"
SECONDARY_SITE_FAULT = "secondary_site"
READ_ONLY_MODE_FAULT = "read_only_mode"
DELTA_CONNECTION_FAILED_FAULT = "pb_delta.connection_failed"

# Faults that mean the request reached a site that cannot service writes/updates
# right now (delta / read-only). They are the signal to degrade gracefully.
#
# DELTA_CONNECTION_FAILED_FAULT is intentionally NOT included: it signals that
# the delta DB itself is unreachable (an infrastructure failure), not that the
# method was rejected for being a write in read-only mode.
READ_ONLY_FAULTS = frozenset(
    {
        STANDALONE_MODE_FAULT,
        SECONDARY_SITE_FAULT,
        READ_ONLY_MODE_FAULT,
    }
)

# operating_mode values reported by generic.get_session_data (BA-47641).
OPERATING_MODE_NORMAL = "normal"
OPERATING_MODE_SECONDARY = "secondary"
OPERATING_MODE_STANDALONE = "standalone"
OPERATING_MODE_READ_ONLY = "read_only"


class Site(enum.Enum):
    MAIN = "main"
    STANDBY = "standby"


class SiteState:
    """Active-site tracker shared by the Admin and Account API connectors of a
    single PortaSwitch adapter (both sites fail and recover together).

    Runs on the single asyncio event loop, so its flags are plain attributes with
    no locking (same rationale as the token storage in ``AsyncHTTPAPIConnector``).

    Forward switch (MAIN -> STANDBY): reactive, the request layer calls
    ``report_unreachable()`` when a main-site request fails with a timeout /
    connection error.

    Backward switch (STANDBY -> MAIN): while on standby, user requests are routed
    straight to the standby (never to the dead main), and the main site is probed
    **out-of-band** via a fire-and-forget task (``probe``); we return to the main
    site only once it reports ``operating_mode == normal`` for
    ``switch_back_threshold`` consecutive probes (hysteresis to avoid flapping and
    to avoid returning while the site is still recovering / read-only).
    """

    def __init__(self, recheck_interval: int = 60, switch_back_threshold: int = 2):
        """
        Parameters:
            recheck_interval (int): Seconds between out-of-band main-site probes
                while running on standby.
            switch_back_threshold (int): Consecutive ``normal`` probe results
                required before switching back to the main site.
        """
        self._active = Site.MAIN
        self._recheck_interval = timedelta(seconds=recheck_interval)
        self._switch_back_threshold = max(1, switch_back_threshold)
        self._last_probe: Optional[datetime] = None
        self._normal_streak = 0
        self._probe_in_flight = False
        self._probe_task: Optional[asyncio.Task] = None
        #: async callable returning the main site's operating_mode (or None if
        #: unreachable / not reported). Injected by the adapter after the Admin
        #: connector exists.
        self._probe: Optional[Callable[[], Awaitable[Optional[str]]]] = None

    @property
    def active(self) -> Site:
        return self._active

    def set_probe(self, probe: Callable[[], Awaitable[Optional[str]]]) -> None:
        self._probe = probe

    def next_targets(self, main_server: str, standby_server: str) -> list:
        """Ordered base server URLs to try for the next request.

        On the main site: try main, fall back to standby. On standby: go straight
        to the standby (the main site is known-down; probing it is done
        out-of-band) and schedule a switch-back probe when due.
        """
        if self._active is Site.MAIN:
            return [main_server, standby_server]

        self._maybe_schedule_probe()
        return [standby_server]

    def report_unreachable(self) -> None:
        """Record that the main site failed to respond (timeout/connection error)."""
        if self._active is not Site.STANDBY:
            logging.warning("PortaSwitch DR: main site unreachable, switching to standby site")
        self._active = Site.STANDBY
        self._normal_streak = 0

    def _maybe_schedule_probe(self) -> None:
        """Kick off a single out-of-band main-site probe if one is due and none is
        already running. Never blocks the caller (fire-and-forget task)."""
        if self._probe is None or self._probe_in_flight:
            return
        now = datetime.now()
        if self._last_probe is not None and (now - self._last_probe) < self._recheck_interval:
            return
        self._last_probe = now
        self._probe_in_flight = True
        try:
            # Keep a reference so the task is not garbage-collected mid-flight.
            self._probe_task = asyncio.get_running_loop().create_task(self._run_probe())
        except RuntimeError:
            # No running loop (e.g. called outside the event loop in a test).
            self._probe_in_flight = False

    async def _run_probe(self) -> None:
        try:
            mode = await self._probe()
            if mode == OPERATING_MODE_NORMAL:
                self._normal_streak += 1
                logging.info(
                    "PortaSwitch DR: main site probe reported normal "
                    f"({self._normal_streak}/{self._switch_back_threshold})"
                )
                if self._normal_streak >= self._switch_back_threshold:
                    logging.warning("PortaSwitch DR: main site back to normal mode, switching back")
                    self._active = Site.MAIN
                    self._normal_streak = 0
            else:
                # Unreachable (None) or not yet normal (standalone/read_only/…):
                # stay on standby and reset the hysteresis streak.
                self._normal_streak = 0
        except Exception as e:  # never let a background probe crash the loop
            logging.warning(f"PortaSwitch DR: main site probe failed: {e}")
            self._normal_streak = 0
        finally:
            self._probe_in_flight = False
