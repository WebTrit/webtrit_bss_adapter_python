import logging
from datetime import datetime, timedelta

from app_config import AppConfig
from bss.http_api import HTTPAPIConnectorWithLogin


class AdminAPI(HTTPAPIConnectorWithLogin):
    """Provides an access to Admin realm of the PortaSwitch API."""
    #: bool: Shows whether this interface shall verify HTTPS certificates while accessing
    #: the server.
    __shall_verify_https: bool = True
    #: str: The channel to deliver the OTP tokens to end-users. Possible values: sms, mail.
    __otp_delivery_channel: str = 'mail'

    def __init__(self, config: AppConfig) -> None:
        """The class constructor.

        Parameters:
            :config (app_config.AppConfig): The instance with all the service config options.

        """
        api_server: str = config.get_conf_val('PortaSwitch', 'Admin', 'API', 'Server')
        api_user: str = config.get_conf_val('PortaSwitch', 'Admin', 'API', 'User')
        api_password: str = config.get_conf_val('PortaSwitch', 'Admin', 'API', 'Password')
        self.api_token: str = config.get_conf_val('PortaSwitch', 'Admin', 'API', 'Token')
        self.use_api_token = self.api_token is not None

        self.__otp_delivery_channel: str = config.get_conf_val('PortaSwitch', 'OTP', 'delivery', 'channel', default='mail')
        assert self.__otp_delivery_channel in ('sms', 'mail')

        self.__shall_verify_https: bool = config.get_conf_val('PortaSwitch', 'Verify', 'HTTPS', default='True') == 'True'

        super().__init__(api_server, api_user, 'use-token' if self.use_api_token else api_password)

    def extract_access_token(self, response: dict) -> bool:
        """Extract the access token and other data (expiration time,
        refresh token, etc.) from the response and store in the object.

        Returns:
            :(bool): Shows whether the self.access_token is extracted.

        """
        self.access_token = response.get('access_token', None)
        self.refresh_token = response.get("refresh_token", None)

        expires_in = response.get('expires_in', None)
        if expires_in:
            self.access_token_expires_at = datetime.now() + timedelta(seconds=expires_in)
        else:
            self.access_token_expires_at = None

        logging.debug(f"Got access token {self.access_token} expires at " + \
                      f"{self.access_token_expires_at} refresh token {self.refresh_token}")

        return True if self.access_token else False

    def __send_request(self, module: str, method: str, params: dict, turn_off_login: bool = False):
        """Sends the Porta-Billing API method by means of HTTP POST request.

        Parameters:
            :module (str): The module of the Porta-Billing API methods from which the method to be
                called.
            :method (str): The name of the Porta-Billing API method to be called.
            :params (dict): The object with parameters the API method to be called with.
            :turn_off_login (bool): Shows whether the login is not automatically performed for this
                method call.

        Returns:
            :response (object): The API method execution result.

        """
        logging.debug(f"Sending Admin.API request: {module}/{method}/{params}")

        result = self.send_rest_request(
            method="POST",
            path=f"/rest/{module}/{method}",
            json={
                "params": params
            },
            turn_off_login=turn_off_login,
        )

        logging.debug(f"Processing the Admin.API result: {module}/{method}/{params}: \n {result}")
        return result

    def login(self, params: dict = None):
        """Performs a PortaBilling API user login.

        Parameters:
            :params (dict|None): Contains parameters for the PortaBilling Session.login method
                if this method is used to refresh the self.access_token. Otherwise it is None, and
                the login shall be performed using self.api_user + self.api_password pair.

        Returns:
            :(bool): True is the login succeeded.

        """
        if params is None:
            params: dict = {
                "login": self.api_user,

            }
        if self.use_api_token:
            params["token"] = self.api_token
        else:
            params["password"] = self.api_password

        response = self.__send_request(module='Session',
                                       method='login',
                                       params=params,
                                       turn_off_login=True)

        if response and self.extract_access_token(response):
            # access token was extracted and stored
            return True

        logging.debug(f"Could not find an access token in the response {response}")
        raise ValueError("Could not find an access token in the response")

    def refresh(self):
        """Rerfreshes access token."""
        return self.login({
            "login": self.api_user,
            "refresh_token": self.refresh_token,
        })

    def add_auth_info(self, url: str, request_params: dict) -> dict:
        """Change the parameters of requests.request call to add
        there required authentication information (into headers,
        basic auth, etc.). The
        requests.request(method, url, **params_returned)

        Parameters:
            :url (str): The URL the request is being sent to (in case if auth info differs for
                various paths).
            :request_params (dict): The current set of parameters for the requests.request call.

        Returns:
            :(dict): The modified set of parameters for requests.request.

        """
        if self.access_token:
            if "headers" in request_params:
                headers = request_params["headers"]
            else:
                request_params["headers"] = headers = {}
            # override the auth header
            headers["Authorization"] = "Bearer " + self.access_token

        request_params["verify"] = self.__shall_verify_https

        return request_params

    def get_account_list(self, i_customer: int):
        """Returns information about accounts related to the input i_customer.

        Parameters:
            :i_customer (int): The identifier of a customer which accounts to be returned.

        Returns:
            :(dict): The API method execution result that contains info about accounts.

        """
        return self.__send_request(
            module='Account',
            method='get_account_list',
            params={
                'i_customer': i_customer,
                'with_aliases': 1,
            })

    def get_extensions_list(self, i_customer: int) -> dict:
        """Returns information about extensions related to the input i_customer.
            Parameters:
                i_customer: int: The identifier of a customer which accounts to be returned.
            Returns:
                extensions_list: dict: The API method execution result that contains info about accounts.
        """
        return self.__send_request(
            module='Customer',
            method='get_extensions_list',
            params={
                'i_customer': i_customer,
                'detailed_info': 1,
            })

    def create_otp(self, user_ref: str) -> dict:
        """Requests PortaSwitch to generate an OTP token.

        Parameters:
            :user_ref (str): The identifier of the account (i_account) for which to generate
                the OTP.

        Returns:
            :(dict): The API method execution result.

        """
        return self.__send_request(
            module='AccessControl',
            method='create_otp',
            params={
                'send_to': 'account',
                'id': user_ref,
                'notification_type': self.__otp_delivery_channel,
                'operation': 'General',
            }, )

    def verify_otp(self, otp_token: str) -> dict:
        """Requests PortaSwitch to verify the OTP token.

        Parameters:
            :otp_token (str): The OTP token to be vefiried.

        Returns:
            dict: The API method execution result.
        """
        return self.__send_request(
            module='AccessControl',
            method='verify_otp',
            params={
                'one_time_password': otp_token,
                'operation': 'General',
            }, )

    def get_account_info(self, **params) -> dict:
        """Returns the account_info by i_account.

        Parameters:
            **params: Additional keyword arguments for account info search.

        Returns:
            dict: The API method execution result that contains an account info.
        """
        return self.__send_request(
            module='Account',
            method='get_account_info',
            params={
                'without_service_features': 1,
                **params
            })

    def get_env_info(self) -> dict:
        """Returns PortaSwitch environment info.
        Returns:
            dict: The API method execution result that contains an env info.
        """
        response = self.__send_request(module='Env', method='get_env_info', params={})

        return response.get('env_info', dict())
