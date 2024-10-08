import logging
from abc import ABC, abstractmethod
from typing import Optional

from pydantic import BaseModel, Field
from datetime import datetime, timedelta

import requests

from report_error import raise_webtrit_error
import threading


# from bss.types import SignupExtAPIErrorCode as ExtAPIErrorCode


class APIUser(BaseModel):
    """User, accessing the API"""
    user_id: str = None

    def __str__(self):
        return self.user_id


class AuthSessionData(BaseModel):
    """Abstract info about authenticated session"""
    pass


class OAuthSessionData(AuthSessionData):
    access_token: str
    access_token_expires_at: datetime = Field(default=None)
    refresh_token: str = Field(default=None)


class HTTPAPIConnector(ABC):
    """Extract data from a remote server via REST/GRAPHQL or other HTTP-based API"""

    def __init__(self, api_server: str):
        """Create a new API connector object.

        Args:
            api_server (str): The hostname/port portion of the URL where
                requests will be sent, e.g. http://1.2.3.4:8080

        """

        self.api_server = api_server

    def add_auth_info(self, url: str, request_params: dict,
                      auth_session: AuthSessionData) -> dict:
        """Change the parameters of requests.request call to add
        there required authentication information (into headers,
        basic auth, etc.). The
        requests.request(method, url, **params_returned)

        Args:
            url (str): The URL the request is being sent to (in case if auth
                info differs for various paths)
            request_params (dict): The current set of parameters for the
                requests.request call. Most likely you will need include
                "headers" key, as well as others like "json" or "data"
            auth_session (AuthSessionData): The session data object that contains
                auth tokens, etc.

        Returns:
            dict: the modified set of parameters for requests.request. You can
                add new keys (or remove the ones which are already there.
        """
        if auth_session and hasattr(auth_session, "access_token"):
            if "headers" in request_params:
                headers = request_params["headers"]
            else:
                request_params["headers"] = headers = {}
            # override the auth header
            headers["Authorization"] = "Bearer " + auth_session.access_token

        return request_params

    def send_rest_request(self,
                          method: str,
                          path: str,
                          server=None,
                          data=None,
                          json=None,
                          query_params=None,
                          stream=None,
                          headers={'Content-Type': 'application/json'},
                          auth_session: AuthSessionData = None) -> dict:
        """Send a HTTP request to the server and return the JSON response as a dict"""
        url = (server if server else self.api_server) + path
        params = {
            'headers': headers.copy() if headers else None,
            'data': data if data else None,
            'params': query_params if query_params else None,
            'json': json if json else None,
            'stream': stream,
        }
        params_final = self.add_auth_info(url, params, auth_session)

        try:
            logging.debug(f"Sending {method} request to {url} with parameters {params_final}")
            response = requests.request(method, url, **params_final)
            logging.debug(f"Received {response.status_code} {response.text}")
            response.raise_for_status()
            return self.decode_response(response)

        except requests.exceptions.Timeout:
            logging.debug(f"Connection to {self.api_server} timed out")
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
        except requests.exceptions.RequestException as e:
            logging.debug(f"Request error: {e}")

            response_content = {}
            try:
                if e.response is not None:
                    response_content = e.response.json()
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

    def decode_response(self, response) -> dict:
        """Decode the JSON response from the server into a dict.
        This is a default implementation that simply returns the
        result of response.json() - but you can override this method
        to do your own custom parsing of the response."""
        return response.json()


class HTTPAPIConnectorWithLogin(HTTPAPIConnector):
    """Use HTTP-based API that requires to login as admin first
    to obtain an access token for this session, to be used when
    retrieving data for ANY user."""
    REFRESH_TOKEN_IN_ADVANCE = 15  # minutes
    SHARED_TOKENS = {}

    #: str: The login of the API user.
    api_user = None
    #: str: The password of the API user.
    api_password = None

    def __init__(self,
                 api_server: str,
                 api_user: str = None,  # when using a single admin API account
                 api_password: str = None,
                 api_token: str = None,
                 api_token_expires_at: datetime = None):
        super().__init__(api_server)

        self.lock = threading.Lock()
        # only used when we have a single admin account
        self.api_user = api_user
        self.api_password = api_password

        # we have the token already, no need to do login
        if api_token:
            # store for default user
            self.store_auth_session(OAuthSessionData(
                access_token=api_token,
                access_token_expires_at=api_token_expires_at))

    def user_id(self, user: APIUser) -> str:
        return str(user) if user else None

    def get_auth_session(self, user: APIUser = None) -> OAuthSessionData:
        """Return the session data for the given user or a global one
        if there are no logis per user"""
        # one global session by default
        return self.SHARED_TOKENS.get(self.user_id(user))

    def store_auth_session(self, session: OAuthSessionData, user: APIUser = None) -> OAuthSessionData:
        """Store the session for this user"""
        # one global session by default
        with self.lock:
            self.SHARED_TOKENS[self.user_id(user)] = session
        return session

    def delete_auth_session(self, user: APIUser = None) -> Optional[OAuthSessionData]:
        """Remove the session for this user"""

        with self.lock:
            return self.SHARED_TOKENS.pop(self.user_id(user), None)

    def send_rest_request(self,
                          method: str,
                          path: str,
                          server=None,
                          data=None,
                          json=None,
                          query_params=None,
                          headers={'Content-Type': 'application/json'},
                          turn_off_login=False,
                          user: APIUser = None) -> dict:
        """Send a HTTP request to the server and return the JSON response as a dict"""
        auth_session = self.get_auth_session(user)
        if not turn_off_login and self.have_to_login(user,
                                                     self.get_auth_session(user)):
            # we do not have an access token, need to log in first
            auth_session = self.login(user)
            self.store_auth_session(auth_session, user)
            if auth_session is None or auth_session.access_token is None:
                # cannot proceed
                raise ValueError("Cannot log in to the server")

        return super().send_rest_request(method, path, server,
                                         data, json, query_params,
                                         headers=headers,
                                         auth_session=auth_session)

    def have_to_login(self, user: APIUser, auth_session: OAuthSessionData) -> bool:
        """Return True if we need to log in to the server
        before running actual API requests."""
        if auth_session is None:
            return True
        if auth_session.access_token and auth_session.access_token_expires_at:
            # token has an expiration date
            if datetime.now() > auth_session.access_token_expires_at:
                # the token has expired
                auth_session.access_token = None
                if auth_session.refresh_token:
                    # try to refresh the token
                    logging.debug("The access token expired, attempting to re-fresh it")
                    auth_session = self.refresh(auth_session.refresh_token)
                else:
                    logging.debug("The access token expired, logging in again")
                    auth_session = self.login(user)
            elif auth_session.access_token_expires_at - datetime.now() < \
                    timedelta(minutes=self.REFRESH_TOKEN_IN_ADVANCE) \
                    and auth_session.refresh_token:
                # proactively refresh the token a bit before the expiration time
                logging.debug("The access token will expire soon " +
                              f"{auth_session.access_token_expires_at.isoformat()}, refreshing it")
                auth_session = self.refresh(auth_session)

        return False if auth_session.access_token else True

    # redefine these in your sub-class if you something else that OAuth2
    def extract_access_token(self, response: dict) -> OAuthSessionData:
        """Extract the Oauth2 access token and other data (expiration time,
        refresh token, etc.) from the response and store in the object.

        Returns:
        OAuthSessionData"""

        expires_in = response.get("expires_in", None)
        if expires_in:
            access_token_expires_at = datetime.now() + timedelta(seconds=expires_in)
        else:
            access_token_expires_at = None
        session = OAuthSessionData(access_token=response.get("access_token", None),
                                   access_token_expires_at=access_token_expires_at,
                                   refresh_token=response.get("refresh_token", None))
        logging.debug(f"Got access token {session.access_token} expires at " + \
                      f"{session.access_token_expires_at} refresh token {session.refresh_token}")
        return session

    @abstractmethod
    def login(self, user: APIUser = None) -> OAuthSessionData:
        """Override this method in your sub-class to provide the ability
        to get a session access token from the remote server.

        Returns: OAuthSessionData (session info) """
        pass

    @abstractmethod
    def refresh(self, refresh_token: str) -> bool:
        """Override this method in your sub-class to provide the ability
        to exchange a refresh token for a new session access token.

        Returns: OAuthSessionData (session info)"""
        pass
