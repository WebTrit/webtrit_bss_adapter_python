import logging
import requests
from datetime import datetime, timedelta
from abc import ABC, abstractmethod
from report_error import WebTritErrorException
from bss.types import SignupExtAPIErrorCode as ExtAPIErrorCode

class HTTPAPIConnector(ABC):
    """Extract data from a remote server via REST/GRAPHQL or other HTTP-based API"""

    def __init__(self, api_server: str,
                 api_user: str,
                 api_password: str):
        """Create a new API connector object.
        
        Args:
            api_server (str): The hostname/port portion of the URL where
                requests will be sent, e.g. http://1.2.3.4:8080
            api_user (str):  Username (client ID) of the API user
            api_password (str): Password (client secret) of the API user
        """

        self.api_server = api_server
        self.api_user = api_user
        self.api_password = api_password

    def have_to_login(self) -> bool:
        """Override it in your class, return True if we need to log in
        to the server before running actual API requests. This will trigger
        calling a login() methid (which you also need to write) before
        issuing a first request.
        """
        return False

    def add_auth_info(self, url: str, request_params: dict) -> dict:
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

        Returns:
            dict: the modified set of parameters for requests.request. You can
                add new keys (or remove the ones which are already there.
        """
        pass

    def send_rest_request(self,
                          method: str,
                          path: str,
                          server = None,
                          data = None,
                          json = None,
                          headers = { 'Content-Type': 'application/json'},
                          turn_off_login = False) -> dict:
        """Send a HTTP request to the server and return the JSON response as a dict"""
        if not turn_off_login and self.have_to_login():
            # we do not have an access token, need to log in first
            if not self.login():
                # cannot proceed
                raise ValueError("Cannot log in to the server")

        url = (server if server else self.api_server) + path        
        params = {
                'headers': headers.copy() if headers else None,
                'data': data.copy() if data else None,
                'json': json.copy() if json else None
        }
        params_final = self.add_auth_info(url, params)

        try:
            logging.debug(f"Sending {method} request to {url} " + \
                          f"with parameters {params_final}")
            response = requests.request(method, url, **params_final)
            logging.debug(f"Received {response.status_code} {response.text}")
            response.raise_for_status()
            return self.decode_response(response)

        except requests.exceptions.Timeout:
            logging.debug(f"Connection to {self.api_server} timed out")
            raise WebTritErrorException(
                    status_code=500,
                    code=ExtAPIErrorCode.external_api_issue,
                    error_message="Request execution error on the other side",
                    bss_request_trace = {
                        'method': method,
                        'url': url,
                        **params
                        },
                    bss_response_trace = {
                        'status_code': 408,
                        'text': 'Timed out'
                    }
                )
            return None
        except requests.exceptions.RequestException as e:
            logging.debug(f"Request error: {e}")

            raise WebTritErrorException(
                    status_code=500,
                    code=ExtAPIErrorCode.external_api_issue,
                    error_message="Request execution error on the BSS/VoIP system side",
                    bss_request_trace = {
                        'method': method,
                        'url': url,
                        } | params,
                    bss_response_trace = {
                        'status_code': 500,
                        'text': f"{e}"
                    }
                )

            return None

    def decode_response(self, response) -> dict:
        """Decode the JSON response from the server into a dict.
        This is a default implementation that simply returns the
        result of response.json() - but you can override this method
        to do your own custom parsing of the response."""
        return response.json()

    def login(self) -> bool:
        """Here we assume no login is required, so it always succeeds.
        Override this method in your sub-class to provide the ability
        to do a proper login and get a session access token from
        the remote server."""
        return True


class HTTPAPIConnectorWithLogin(HTTPAPIConnector):
    """Use HTTP-based API that requires to login first
    to obtain an access token for this session"""
    REFRESH_TOKEN_IN_ADVANCE = 10 # minutes
    def __init__(self, api_server: str, api_user: str,
                api_password: str, api_token: str = None,
                api_token_expires_at: datetime = None):
        super().__init__(api_server, api_user, api_password)
        # we have the token already, no need to login
        self.access_token = api_token
        self.access_token_expires_at = api_token_expires_at
        self.refresh_token = None

    def have_to_login(self) -> bool:
        """Return True if we need to log in to the server
        before running actual API requests."""
        if self.access_token and self.access_token_expires_at:
            # token has an expiration date
            if datetime.now() > self.access_token_expires_at:
                # the token has expired
                self.access_token = None
                if self.refresh_token:
                    # try to refresh the token
                    logging.debug("The access token expired, attempting to re-fresh it")
                    self.refresh()
                else:
                    logging.debug("The access token expired, logging in again")
                    self.login()
            elif self.access_token_expires_at - datetime.now() < \
                timedelta(minutes=self.REFRESH_TOKEN_IN_ADVANCE) \
                    and self.refresh_token:
                # proactiveluy refresh the token a bit before the expiration time
                logging.debug("The access token will expire soon " + 
                    f"{self.access_token_expires_at.isoformat()}, refreshing it")
                self.refresh()               

        return False if self.access_token else True
  
    # redefine these in your sub-class
    @abstractmethod
    def extract_access_token(self, response: dict) -> bool:
        """Extract the access token and other data (expiration time,
        refresh token, etc.) from the response and store in the object.
        
        Returns:
        True if success"""
        pass

    @abstractmethod
    def access_token_path(self) -> str:
        """The path to the endpoint where the access token is requested"""
        pass

    @abstractmethod        
    def login(self) -> bool:
        """Override this method in your sub-class to provide the ability
        to get a session access token from the remote server."""
        pass

    @abstractmethod        
    def refresh(self) -> bool:
        """Override this method in your sub-class to provide the ability
        to exchange a refresh token for a new session access token."""
        pass


