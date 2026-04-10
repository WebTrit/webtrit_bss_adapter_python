import logging
from typing import Optional

from bss.adapters.portaswitch.config import PortaSwitchSettings
from bss.adapters.portaswitch.types import PortaSwitchAdminUser
from bss.adapters.portaswitch.utils import extract_fault_code
from bss.http_api import HTTPAPIConnectorWithLogin
from bss.models import DeliveryChannel
from report_error import WebTritErrorException


class AdminAPI(HTTPAPIConnectorWithLogin):
    """Provides an access to Admin realm of the PortaSwitch API."""

    def __init__(self, portaswitch_settings: PortaSwitchSettings) -> None:
        """The class constructor.

        Parameters:
            :config (app_config.AppConfig): The instance with all the service config options.
        """
        super().__init__(portaswitch_settings.ADMIN_API_URL)

        self._api_user = PortaSwitchAdminUser(
            user_id=portaswitch_settings.ADMIN_API_LOGIN, token=portaswitch_settings.ADMIN_API_TOKEN
        )

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

        response = self._send_request(
            module="Session", method="login", params=dict(login=user.user_id, token=user.token), turn_off_login=True
        )

        if response and (session := self.extract_access_token(response)) and session.access_token is not None:
            return session

        logging.debug(f"Could not find an access token in the response {response}")
        raise ValueError("Could not find an access token in the response")

    def refresh(self, user=None, auth_session=None):
        """Refreshes access token."""
        session = self.login(self._api_user)
        self.store_auth_session(session, self._api_user)
        return session

    def get_account_list(self, i_customer: int, **search_params):
        """Returns information about accounts related to the input i_customer.

        Parameters:
            :i_customer (int): The identifier of a customer which accounts to be returned.
            :limit (int): Maximum number of accounts to return.
            :offset (int): Number of accounts to skip.
            :**search_params: Additional search parameters (e.g., firstname, lastname, extension_name, email).

        Returns:
            :(dict): The API method execution result that contains info about accounts.

        """
        params = {
            "i_customer": i_customer,
            "with_aliases": 1,
            "get_not_closed_accounts": 1,
            "get_only_real_accounts": 1,
            "get_statuses": 1,
            "get_total": 1,
            "limit_alias_did_number_list": 100
        }
        params.update(search_params)

        return self._send_request(
            module="Account",
            method="get_account_list",
            params=params,
        )

    def get_customer_info(self, i_customer: int) -> dict:
        """Returns information about the customer, including office type and hierarchy.

        Parameters:
            i_customer (int): The identifier of the customer.

        Returns:
            dict: The API method execution result containing customer_info with i_office_type
                  (1=none, 2=branch_office, 3=main_office) and i_main_office for branch offices.
        """
        return self._send_request(
            module="Customer",
            method="get_customer_info",
            params={"i_customer": i_customer},
        )

    def get_customer_list(self, i_main_office: int) -> dict:
        """Returns the list of branch customers under a main office customer.

        Parameters:
            i_main_office (int): The i_customer of the main office whose branch offices to retrieve.

        Returns:
            dict: The API method execution result containing customer_list with branch office records.
        """
        return self._send_request(
            module="Customer",
            method="get_customer_list",
            params={"i_main_office": i_main_office},
        )

    def get_extensions_list(self, i_customer: int, get_main_office_extensions: bool = False) -> dict:
        """Returns information about extensions related to the input i_customer.
        Parameters:
            i_customer: int: The identifier of a customer which accounts to be returned.
            get_main_office_extensions: bool: When True, includes extensions from all branch offices
                (used when i_customer is the main office) or returns main office extensions
                (used when i_customer is a branch office via its main office ID).
        Returns:
            extensions_list: dict: The API method execution result that contains info about accounts.
        """
        params = {
            "i_customer": i_customer,
            "detailed_info": 1,
            "limit_alias_did_number_list": 100,
        }
        if get_main_office_extensions:
            params["get_main_office_extensions"] = 1
        return self._send_request(
            module="Customer",
            method="get_extensions_list",
            params=params,
        )

    def create_otp(self, user_ref: str, delivery_channel: DeliveryChannel) -> dict:
        """Requests PortaSwitch to generate an OTP token.

        Parameters:
            :user_ref (str): The identifier of the account (i_account) for which to generate
                the OTP.

        Returns:
            :(dict): The API method execution result.

        """
        return self._send_request(
            module="AccessControl",
            method="create_otp",
            params={
                "send_to": "account",
                "id": user_ref,
                "notification_type": "mail" if delivery_channel == DeliveryChannel.email else delivery_channel,
                "operation": "General",
            },
        )

    def verify_otp(self, otp_token: str) -> dict:
        """Requests PortaSwitch to verify the OTP token.

        Parameters:
            :otp_token (str): The OTP token to be vefiried.

        Returns:
            dict: The API method execution result.
        """
        return self._send_request(
            module="AccessControl",
            method="verify_otp",
            params={
                "one_time_password": otp_token,
                "operation": "General",
            },
        )

    def get_account_info(self, **params) -> dict:
        """Returns the account_info by i_account.

        Parameters:
            **params: Additional keyword arguments for account info search.

        Returns:
            dict: The API method execution result that contains an account info.
        """
        return self._send_request(
            module="Account",
            method="get_account_info",
            params={
                "without_service_features": 1,
                "detailed_info": 1,
                "get_auth_info": 1,
                **params
            }
        )

    def update_account(self, i_account: int, **account_info_fields) -> dict:
        """Updates account fields for the given i_account.

        Parameters:
            i_account (int): The internal PortaSwitch account identifier.
            **account_info_fields: Fields to update inside account_info (e.g. api_token="...").

        Returns:
            dict: The API method execution result.
        """
        return self._send_request(
            module="Account",
            method="update_account",
            params={
                "account_info": {
                    "i_account": i_account,
                    **account_info_fields,
                },
            },
        )

    def get_env_info(self) -> dict:
        """Returns PortaSwitch environment info.
        Returns:
            dict: The API method execution result that contains an env info.
        """
        response = self._send_request(module="Env", method="get_env_info", params={})

        return response.get("env_info", dict())

    def get_version(self) -> Optional[str]:
        """Returns PortaSwitch version.
        Returns:
            str: The API method execution result that contains a PortaSwitch version.
        """
        response = self._send_request(module="Generic", method="get_version", params={})

        return response.get("version")

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
        try:
            result = self.send_rest_request(
                method="POST",
                path=f"/rest/{module}/{method}",
                json={"params": params},
                turn_off_login=turn_off_login,
                user=self._api_user,
            )
        except WebTritErrorException as error:
            fault_code = extract_fault_code(error)
            if fault_code in (
                    'Server.Session.check_auth.auth_failed',
                    'Client.Session.check_auth.failed_to_process_access_token',
            ):
                logging.warning(f"Unexpected session error from PBX: {error}. Trying to refresh access token...")
                self.refresh()

                result = self.send_rest_request(
                    method="POST",
                    path=f"/rest/{module}/{method}",
                    json={"params": params},
                    turn_off_login=turn_off_login,
                    user=self._api_user,
                )
            else:
                raise error

        return result
