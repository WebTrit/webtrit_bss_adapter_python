"""Async HTTP API connectors for the PortaSwitch adapter (WT-1720).

This is the asyncio/httpx twin of :mod:`bss.http_api`. It exists as a separate
module so the shared synchronous stack (and every other vendor adapter) keeps
running unchanged: only the PortaSwitch adapter inherits these classes.

Why async: with the synchronous ``requests`` stack every in-flight request pins
a Starlette thread-pool worker (~40 tokens). A slow/hung PortaSwitch exhausts
the pool and the whole instance stops serving (WT-1717). On the event loop an
I/O-bound request is a coroutine (~KB), unrelated traffic keeps flowing, and a
hard per-request deadline becomes possible.

Design notes:
* One shared :class:`httpx.AsyncClient` per process (keyed by the TLS-verify
  flag), created lazily inside the running loop and closed on app shutdown.
  httpx pools connections per client, unlike the module-level ``requests`` call.
* TLS verification is a *client-construction* option in httpx (not a per-request
  kwarg like ``requests``), so subclasses must NOT inject ``verify`` into the
  per-request params — the shared client is built with it instead.
* The full :class:`httpx.Timeout` is specified (connect/read/write/pool) so a
  stalled send or a pool wait is bounded too, not just connect+read.
* Errors are caught as :class:`httpx.HTTPError` — its subclass
  ``HTTPStatusError`` (raised by ``raise_for_status``) is NOT a ``RequestError``,
  so catching only ``RequestError`` would silently drop every non-2xx fault. The
  error body is read (``await response.aread()``) before ``.json()`` so streamed
  error responses still populate ``bss_response_trace`` for fault mapping.
"""
import asyncio
import logging
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import Final, Optional

import httpx

from report_error import raise_webtrit_error
from request_trace import (get_request_id, truncate_log_message,
                           sanitize_data, sanitize_text, mask_token)

# Re-exported so the PortaSwitch API classes can keep importing the auth models
# from a single place; the models themselves live in the sync module (unchanged).
from bss.http_api import APIUser, AuthSessionData, OAuthSessionData  # noqa: F401

DEFAULT_CHUNK_SIZE: Final[int] = 8192


def build_httpx_timeout(value) -> httpx.Timeout:
    """Translate the legacy ``(connect, read)`` tuple or a single float/int
    timeout into a fully specified :class:`httpx.Timeout`.

    ``requests`` only used connect+read; leaving write/pool unset in httpx means
    "no limit", which would let a stalled send or a pool wait hang forever —
    exactly what WT-1717 was about. So write is bounded by the read timeout and
    pool by the connect timeout.
    """
    if value is None:
        connect, read = 5.0, 25.0
    elif isinstance(value, (int, float)):
        connect = read = float(value)
    elif isinstance(value, (tuple, list)) and len(value) == 2:
        connect, read = float(value[0]), float(value[1])
    else:
        connect = read = 25.0
    return httpx.Timeout(connect=connect, read=read, write=read, pool=connect)


# --- shared per-process client registry -----------------------------------
#
# These (and each connector's asyncio.Lock) are created at import/construction
# time and bind lazily to the first event loop that uses them. This is correct
# for the single long-lived uvicorn loop we run under in production. It is NOT
# safe to reuse the same process across multiple/replaced event loops (e.g.
# repeated asyncio.run()); that is why the async unit tests use per-test loops
# with fresh connectors instead of the module-level client.

_shared_clients: dict[bool, httpx.AsyncClient] = {}
_shared_clients_lock = asyncio.Lock()


async def get_shared_async_client(verify: bool, limits: Optional[httpx.Limits] = None) -> httpx.AsyncClient:
    """Return the process-wide :class:`httpx.AsyncClient` for the given TLS
    verify setting, creating it lazily inside the running event loop.

    ``limits`` (connection-pool sizing) is applied only when the client is first
    created for a given verify key; a later caller with different limits reuses
    the existing client. In practice all connectors in one deployment pass the
    same limits, so this is not a concern.
    """
    client = _shared_clients.get(verify)
    if client is not None and not client.is_closed:
        return client
    async with _shared_clients_lock:
        client = _shared_clients.get(verify)
        if client is None or client.is_closed:
            kwargs = {"verify": verify}
            if limits is not None:
                kwargs["limits"] = limits
            client = httpx.AsyncClient(**kwargs)
            _shared_clients[verify] = client
        return client


async def close_shared_async_clients() -> None:
    """Close all shared clients — call from a FastAPI shutdown handler so
    pooled connections are released and no "Unclosed AsyncClient" leaks occur."""
    async with _shared_clients_lock:
        for client in _shared_clients.values():
            if not client.is_closed:
                await client.aclose()
        _shared_clients.clear()


def _record_pool_timeout(server: str) -> None:
    """Count a pool timeout (WT-1718).

    Imported here rather than at module scope so that this connector keeps
    working — and stays importable on its own — when the metrics stack is
    unavailable. Pool timeouts are rare, so the import cost does not matter.
    """
    try:
        from metrics import record_pool_timeout

        record_pool_timeout(server)
    except Exception as e:
        logging.debug(f"Could not record a pool timeout: {e}")


class AsyncHTTPAPIConnector(ABC):
    """Extract data from a remote server via REST/HTTP using httpx (async)."""

    #: (connect, read) timeout in seconds. Mirrors the sync base default; a
    #: subclass may override it with a single float (see PortaSwitch API_TIMEOUT).
    DEFAULT_REQUEST_TIMEOUT = (5, 25)

    def __init__(self, api_server: str, site_state=None, standby_server: str = None):
        self.api_server = api_server
        # DR failover (opt-in): when a duck-typed ``site_state`` and a
        # ``standby_server`` are set, requests are routed to the active site and
        # retried once against the standby on a main-site outage. Both None ->
        # behavior unchanged.
        self.site_state = site_state
        self._standby_server = standby_server

    def _verify(self) -> bool:
        # Subclasses set self._verify_https after super().__init__(); the client
        # is fetched lazily per request, so the final value is always used.
        return getattr(self, "_verify_https", True)

    def _request_timeout(self) -> httpx.Timeout:
        return build_httpx_timeout(self.DEFAULT_REQUEST_TIMEOUT)

    def _limits(self) -> Optional[httpx.Limits]:
        # Subclasses set _max_connections / _max_keepalive_connections after
        # super().__init__(); returns None to keep httpx's own defaults.
        mc = getattr(self, "_max_connections", None)
        mk = getattr(self, "_max_keepalive_connections", None)
        if mc is None and mk is None:
            return None
        return httpx.Limits(max_connections=mc, max_keepalive_connections=mk)

    async def _client(self) -> httpx.AsyncClient:
        return await get_shared_async_client(self._verify(), self._limits())

    def add_auth_info(self, url: str, request_params: dict,
                      auth_session: AuthSessionData) -> dict:
        """Inject authentication info (Bearer token) into the request params."""
        if auth_session and getattr(auth_session, "access_token", None):
            if "headers" in request_params and request_params["headers"] is not None:
                headers = request_params["headers"]
            else:
                request_params["headers"] = headers = {}
            headers["Authorization"] = "Bearer " + auth_session.access_token
        return request_params

    def add_trace_info(self, request_params: dict) -> dict:
        """Inject B3 tracing headers into the request params."""
        if "headers" not in request_params or request_params["headers"] is None:
            request_params["headers"] = {}
        request_params["headers"]["X-B3-TraceId"] = get_request_id()
        request_params["headers"]["X-B3-SpanId"] = uuid.uuid4().hex[:16]
        return request_params

    async def send_rest_request(self,
                                method: str,
                                path: str,
                                server=None,
                                data=None,
                                json=None,
                                query_params=None,
                                stream=None,
                                headers={'Content-Type': 'application/json'},
                                auth_session: AuthSessionData = None) -> dict:
        """Send an HTTP request and return the decoded response.

        When DR failover is configured (``site_state`` + ``standby_server``) and
        no explicit ``server`` is given, the request is routed to the active site
        and, on a main-site timeout / connection error, retried once against the
        standby. An explicit ``server`` is honored as-is and disables failover.
        """
        # Note: no 'verify' and no 'stream' key here — verify is client-level in
        # httpx, and streaming is handled via client.send(stream=True) below.
        client = await self._client()
        timeout = self._request_timeout()

        targets = self._request_targets(server)
        last = len(targets) - 1
        for index, base_server in enumerate(targets):
            url = base_server + path
            params = {
                'headers': headers.copy() if headers else None,
                'data': data if data else None,
                'params': query_params if query_params else None,
                'json': json if json else None,
            }
            params_with_auth = self.add_auth_info(url, params, auth_session)
            params_final = self.add_trace_info(params_with_auth)

            try:
                logging.debug(f"Sending {method} request to {url} with parameters {sanitize_data(params_final)}")
                if stream:
                    # Build + send with stream=True so the body is not pulled into
                    # memory: it is consumed lazily by decode_response/caller.
                    request = client.build_request(method, url, timeout=timeout, **params_final)
                    response = await client.send(request, stream=True)
                    response.raise_for_status()
                    logging.debug(f"Received {response.status_code} (streamed, body not logged)")
                    return await self.decode_response(response)

                response = await client.request(method, url, timeout=timeout, **params_final)
                clean_text = truncate_log_message(sanitize_text(response.text.replace("\n", " ")))
                logging.debug(f"Received {response.status_code} {clean_text}")
                response.raise_for_status()
                return await self.decode_response(response)

            except httpx.HTTPError as e:
                # A timeout / connection error means the site is unreachable; an
                # HTTP status error (raise_for_status) means the site answered and
                # is NOT a failover trigger. PoolTimeout is excluded: it is a local
                # connection-pool exhaustion event, not a main-site outage, so it
                # must not flip the active site (it still yields the 408 trace below).
                connectivity = (
                    isinstance(e, (httpx.TimeoutException, httpx.ConnectError))
                    and not isinstance(e, httpx.PoolTimeout)
                )
                if isinstance(e, httpx.PoolTimeout):
                    _record_pool_timeout(base_server)

                if connectivity:
                    self._note_site_unreachable(base_server)
                    if index < last:
                        logging.warning(
                            f"{base_server} unreachable ({e}); failing over to {targets[index + 1]}"
                        )
                        continue

                if isinstance(e, httpx.TimeoutException):
                    logging.debug(f"Connection to {url} timed out")
                    raise_webtrit_error(500,
                                        error_message="Request execution error on the other side",
                                        bss_request_trace={
                                            'method': method,
                                            'url': url,
                                            **params
                                        },
                                        bss_response_trace={
                                            'status_code': 408,
                                            'text': 'Timed out',
                                            'response_content': {}
                                        }
                                        )

                logging.debug(f"Request error: {e}")

                response_content = {}
                response = getattr(e, "response", None)
                if response is not None:
                    try:
                        # Streamed error responses are not read yet; read before json().
                        await response.aread()
                    except Exception:
                        pass
                    try:
                        response_content = response.json()
                    except ValueError:
                        pass

                raise_webtrit_error(500,
                                    error_message="Request execution error on the BSS/VoIP system side",
                                    bss_request_trace={
                                                          'method': method,
                                                          'url': url,
                                                      } | params,
                                    bss_response_trace={
                                        'status_code': 500,
                                        'text': f"{e}",
                                        'response_content': response_content
                                    }
                                    )

    def _request_targets(self, server: str) -> list:
        """Ordered base server URLs for a request. An explicit ``server`` disables
        failover; otherwise the active-site tracker decides (or just api_server)."""
        if server:
            return [server]
        if self.site_state is not None and self._standby_server:
            return self.site_state.next_targets(self.api_server, self._standby_server)
        return [self.api_server]

    def _note_site_unreachable(self, base_server: str) -> None:
        if self.site_state is not None and base_server == self.api_server:
            self.site_state.report_unreachable()

    async def decode_response(self, response) -> dict:
        """Decode the JSON response. Override for custom parsing."""
        return response.json()


class AsyncHTTPAPIConnectorWithLogin(AsyncHTTPAPIConnector):
    """Async HTTP API that must log in as admin first to obtain an access token.

    Login is serialized per connector by an :class:`asyncio.Lock` (single-flight):
    when the token is missing/expired, concurrent coroutines wait for a single
    login instead of each firing their own. Token storage is plain dict access —
    safe on the single-threaded event loop, no threading.Lock needed.
    """
    REFRESH_TOKEN_IN_ADVANCE = 15  # minutes
    SHARED_TOKENS = None

    #: str: The login of the API user.
    api_user = None
    #: str: The password of the API user.
    api_password = None

    def __init__(self,
                 api_server: str,
                 api_user: str = None,
                 api_password: str = None,
                 api_token: str = None,
                 api_token_expires_at: datetime = None,
                 site_state=None,
                 standby_server: str = None):
        super().__init__(api_server, site_state=site_state, standby_server=standby_server)

        self.api_user = api_user
        self.api_password = api_password
        # Serializes concurrent logins (asyncio single-flight). Constructed here,
        # before any loop exists; asyncio.Lock binds to a loop lazily on acquire.
        self._login_lock = asyncio.Lock()

        self.init_token_storage()
        if api_token:
            self.store_auth_session(OAuthSessionData(
                access_token=api_token,
                access_token_expires_at=api_token_expires_at))

    def user_id(self, user: APIUser) -> str:
        return str(user) if user else None

    def init_token_storage(self):
        """Initialize the in-memory storage for API sessions."""
        if self.SHARED_TOKENS is None:
            self.SHARED_TOKENS = {}
        return self.SHARED_TOKENS

    def get_auth_session(self, user: APIUser = None) -> OAuthSessionData:
        return self.SHARED_TOKENS.get(self.user_id(user))

    def store_auth_session(self, session: OAuthSessionData, user: APIUser = None) -> OAuthSessionData:
        self.SHARED_TOKENS[self.user_id(user)] = session
        return session

    def delete_auth_session(self, user: APIUser = None) -> Optional[OAuthSessionData]:
        return self.SHARED_TOKENS.pop(self.user_id(user), None)

    def _valid_session(self, auth_session: OAuthSessionData) -> bool:
        """Pure, no-network check: does a usable (unexpired, not-due-for-proactive
        -refresh) session already exist? Used for the lock-free fast path."""
        if auth_session is None or not auth_session.access_token:
            return False
        exp = auth_session.access_token_expires_at
        if exp is None:
            return True
        now = datetime.now()
        if now > exp:
            return False
        if auth_session.refresh_token and (exp - now) < timedelta(minutes=self.REFRESH_TOKEN_IN_ADVANCE):
            # within the proactive-refresh window (disabled when the threshold is 0)
            return False
        return True

    async def send_rest_request(self,
                                method: str,
                                path: str,
                                server=None,
                                data=None,
                                json=None,
                                query_params=None,
                                headers={'Content-Type': 'application/json'},
                                turn_off_login=False,
                                user: APIUser = None) -> dict:
        auth_session = self.get_auth_session(user)
        if not turn_off_login:
            if not self._valid_session(auth_session):
                # Single-flight: only one coroutine logs in; peers await and reuse.
                async with self._login_lock:
                    auth_session = self.get_auth_session(user)
                    if not self._valid_session(auth_session):
                        current_session = await self.session_in_progress(user, auth_session)
                        if not current_session:
                            if hasattr(user, 'password') and user.password is None:
                                raise_webtrit_error(401,
                                                    error_message="Authentication session is closed, need to re-login",
                                                    extra_error_code="access_token_expired")
                            auth_session = await self.login(user)
                            self.store_auth_session(auth_session, user)
                            if auth_session is None or auth_session.access_token is None:
                                raise ValueError("Cannot log in to the server")
                        else:
                            auth_session = current_session

            if hasattr(user, 'api_key') and user.api_key:
                auth_session = OAuthSessionData(access_token=user.api_key)

        return await super().send_rest_request(method, path, server,
                                               data, json, query_params,
                                               headers=headers,
                                               auth_session=auth_session)

    async def session_in_progress(self, user: APIUser, auth_session: OAuthSessionData) -> OAuthSessionData:
        """Return None if a fresh login is required, otherwise the session to use.
        May trigger a refresh or re-login for expired/expiring tokens."""
        if auth_session is None:
            return None
        if auth_session.access_token and auth_session.access_token_expires_at:
            if datetime.now() > auth_session.access_token_expires_at:
                auth_session.access_token = None
                if auth_session.refresh_token:
                    logging.debug("The access token expired, attempting to re-fresh it")
                    auth_session = await self.refresh(user, auth_session)
                else:
                    logging.debug("The access token expired, logging in again")
                    auth_session = await self.login(user)
            elif auth_session.access_token_expires_at - datetime.now() < \
                    timedelta(minutes=self.REFRESH_TOKEN_IN_ADVANCE) \
                    and auth_session.refresh_token:
                logging.debug("The access token will expire soon " +
                              f"{auth_session.access_token_expires_at.isoformat()}, refreshing it")
                auth_session = await self.refresh(user, auth_session)

        return auth_session if auth_session.access_token else None

    def extract_access_token(self, response: dict) -> OAuthSessionData:
        """Extract the OAuth2 access token and metadata from a login response."""
        expires_in = response.get("expires_in", None)
        if expires_in:
            access_token_expires_at = datetime.now() + timedelta(seconds=expires_in)
        else:
            access_token_expires_at = None
        session = OAuthSessionData(access_token=response.get("access_token", None),
                                   access_token_expires_at=access_token_expires_at,
                                   refresh_token=response.get("refresh_token", None))
        logging.debug(f"Got access token {mask_token(session.access_token)} expires at " +
                      f"{session.access_token_expires_at} refresh token {mask_token(session.refresh_token)}")
        return session

    @abstractmethod
    async def login(self, user: APIUser = None) -> OAuthSessionData:
        """Obtain a session access token from the remote server."""
        pass

    @abstractmethod
    async def refresh(self, user: APIUser, auth_session: OAuthSessionData) -> OAuthSessionData:
        """Exchange a refresh token for a new session access token."""
        pass
