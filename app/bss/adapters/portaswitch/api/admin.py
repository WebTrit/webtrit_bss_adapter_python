import logging

from app_config import AppConfig
from bss.adapters.portaswitch.types import PortaSwitchAdminUser
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
        api_token: str = config.get_conf_val('PortaSwitch', 'Admin', 'API', 'Token')
        self._api_user = PortaSwitchAdminUser(user_id=api_user, token=api_token)

        self.__otp_delivery_channel: str = config.get_conf_val('PortaSwitch', 'OTP', 'delivery', 'channel',
                                                               default='mail')
        assert self.__otp_delivery_channel in ('sms', 'mail')

        self.__shall_verify_https: bool = config.get_conf_val('PortaSwitch', 'Verify', 'HTTPS',
                                                              default='True') == 'True'

        super().__init__(api_server)

    def login(self, user: PortaSwitchAdminUser = None):
        """Performs a PortaBilling API user login.

        Parameters:
            :params (dict|None): Contains parameters for the PortaBilling Session.login method
                if this method is used to refresh the self.access_token. Otherwise it is None, and
                the login shall be performed using self.api_user + self.api_password pair.

        Returns:
            :(bool): True is the login succeeded.

        """
        user = user or self._api_user

        response = self._send_request(module='Session',
                                      method='login',
                                      params=dict(login=user.user_id, token=user.token),
                                      turn_off_login=True)

        if response and (session := self.extract_access_token(response)):
            return session

        logging.debug(f"Could not find an access token in the response {response}")
        raise ValueError("Could not find an access token in the response")

    def refresh(self):
        """Rerfreshes access token."""
        return self.login(self._api_user)

    def get_account_list(self, i_customer: int):
        """Returns information about accounts related to the input i_customer.

        Parameters:
            :i_customer (int): The identifier of a customer which accounts to be returned.

        Returns:
            :(dict): The API method execution result that contains info about accounts.

        """
        return self._send_request(
            module='Account',
            method='get_account_list',
            params={
                'i_customer': i_customer,
                'with_aliases': 1,
                'limit_alias_did_number_list': 100,
            })

    def get_extensions_list(self, i_customer: int) -> dict:
        """Returns information about extensions related to the input i_customer.
            Parameters:
                i_customer: int: The identifier of a customer which accounts to be returned.
            Returns:
                extensions_list: dict: The API method execution result that contains info about accounts.
        """
        return self._send_request(
            module='Customer',
            method='get_extensions_list',
            params={
                'i_customer': i_customer,
                'detailed_info': 1,
                'limit_alias_did_number_list': 100,
            })

    def create_otp(self, user_ref: str) -> dict:
        """Requests PortaSwitch to generate an OTP token.

        Parameters:
            :user_ref (str): The identifier of the account (i_account) for which to generate
                the OTP.

        Returns:
            :(dict): The API method execution result.

        """
        return self._send_request(
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
        return self._send_request(
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
        return self._send_request(
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
        response = self._send_request(module='Env', method='get_env_info', params={})

        return response.get('env_info', dict())

    def _send_request(self, module: str, method: str, params: dict, turn_off_login: bool = False):
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
            user=self._api_user
        )

        logging.debug(f"Processing the Admin.API result: {module}/{method}/{params}: \n {result}")
        return result
