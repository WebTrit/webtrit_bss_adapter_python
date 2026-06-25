"""Disaster-recovery (geographically dispersed PortaSwitch) failover support.

When the main PortaSwitch site goes down, the installation switches to standalone
(delta) mode: only the secondary site is operational and its API is read-only.
There is no API endpoint that reports the operating mode (see BA-47610), so
detection is reactive and fault-code based:

* "main site unavailable" is observed as a request timeout / connection error
  against the main site;
* the secondary site identifies its mode through fault codes returned on calls
  that are not allowed in the current mode.

This module holds the shared active-site state and the PortaBilling fault codes
used to drive the failover and graceful write degradation.
"""
import enum
import logging
import threading
from datetime import datetime, timedelta

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
# method was rejected for being a write in read-only mode. It should surface as
# a generic backend error rather than the "service is read-only" degradation.
READ_ONLY_FAULTS = frozenset(
    {
        STANDALONE_MODE_FAULT,
        SECONDARY_SITE_FAULT,
        READ_ONLY_MODE_FAULT,
    }
)


class Site(enum.Enum):
    MAIN = "main"
    STANDBY = "standby"


class SiteState:
    """Thread-safe active-site tracker shared by the Admin and Account API
    connectors of a single PortaSwitch adapter.

    Both sites fail and recover together, so the active-site decision is shared
    between the two connectors. Detection is reactive: the request layer reports
    main-site reachability (``report_unreachable`` on a timeout/connection error,
    ``report_reachable`` on a successful main-site response) and this object
    decides which site the next request should target.
    """

    def __init__(self, recheck_interval: int = 60, switch_back_threshold: int = 2):
        """
        Parameters:
            recheck_interval (int): Seconds to wait before re-probing the main
                site while running on standby (switch-back probe cadence).
            switch_back_threshold (int): Number of consecutive successful
                main-site responses required before switching back to the main
                site (hysteresis to avoid flapping).
        """
        self._lock = threading.Lock()
        self._active = Site.MAIN
        self._recheck_interval = timedelta(seconds=recheck_interval)
        self._switch_back_threshold = max(1, switch_back_threshold)
        self._last_main_probe = None
        self._main_success_streak = 0

    @property
    def active(self) -> Site:
        with self._lock:
            return self._active

    def next_targets(self, main_server: str, standby_server: str) -> list:
        """Return the ordered list of base server URLs to try for the next request.

        While on the main site (or when it is time to re-probe the main site for
        switch-back) the main server is tried first with the standby as fallback.
        While on standby between probes the request goes straight to the standby
        so we do not pay a connect-timeout against the dead main site every time.
        """
        with self._lock:
            if self._active is Site.MAIN:
                return [main_server, standby_server]

            now = datetime.now()
            if self._last_main_probe is None or (now - self._last_main_probe) >= self._recheck_interval:
                # Time to re-probe the main site for switch-back.
                self._last_main_probe = now
                return [main_server, standby_server]

            return [standby_server]

    def report_unreachable(self) -> None:
        """Record that the main site failed to respond (timeout/connection error)."""
        with self._lock:
            if self._active is not Site.STANDBY:
                logging.warning("PortaSwitch DR: main site unreachable, switching to standby site")
            self._active = Site.STANDBY
            self._main_success_streak = 0
            self._last_main_probe = datetime.now()

    def report_reachable(self) -> None:
        """Record a successful main-site response (drives switch-back)."""
        with self._lock:
            if self._active is Site.MAIN:
                return
            self._main_success_streak += 1
            if self._main_success_streak >= self._switch_back_threshold:
                logging.warning("PortaSwitch DR: main site healthy again, switching back from standby")
                self._active = Site.MAIN
                self._main_success_streak = 0
