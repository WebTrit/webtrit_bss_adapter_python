import logging
import requests
from abc import ABC, abstractmethod    

class HTTPAPIConnector(ABC):
    """Extract data from a remote server via REST/GRAPHQL or other HTTP-based API"""

    # cached access token
    access_token = None

    def __init__(self, api_server: str, api_user: str,
                 api_password: str, api_token: str = None):
        self.api_server = api_server
        self.api_user = api_user
        self.api_password = api_password
        if api_token:
            HTTPAPIConnector.access_token = api_token

    # redefine these in your sub-class
    @abstractmethod
    def extract_access_token(self, response: dict) -> str:
        """Extract the access token from the response"""
        pass
    @abstractmethod
    def access_token_path(self) -> str:
        """The path to the endpoint where the access token is requested"""
        pass

    def get_access_token(self):
        return HTTPAPIConnector.access_token
    
    def send_rest_request(self, method, path,
                          data = None, json = None,
                          headers = { 'Content-Type': 'application/json'},
                          graphql = False,
                          token = None,
                          auto_login = True) -> dict:
        """Send a REST request to the server and return the JSON response as a dict"""
        if auto_login and HTTPAPIConnector.access_token is None and token is None:
            # we do not have a token, need to log in first
            self.login()
        
        if not token:
            token = HTTPAPIConnector.access_token
        
        headers_final = headers.copy()
        if token:
            headers_final['Authorization'] = 'Bearer ' + token 

        try:
            logging.debug(f"Sending {method} request to {self.api_server + path} with headers {headers_final} and data {data}")
            response = requests.request(
                method, self.api_server + path,
                headers=headers_final,
                data=data,
                json={'query': json } if graphql else json)
            logging.debug(f"Received {response.status_code} {response.text}")
            response.raise_for_status()
            return response.json()

        except requests.exceptions.Timeout:
            logging.debug(f"Connection to {self.api_server} timed out")
            return None
        except requests.exceptions.RequestException as e:
            logging.debug(f"Request error: {e}")
            return None

    @abstractmethod        
    def login(self):
        """Override this method in your sub-class"""
        pass



