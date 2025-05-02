import logging
from datetime import datetime
from typing import Final, List, Union, Iterator

import requests

from bss.adapters.portaswitch.types import PortaSwitchMailboxMessageFlag, PortaSwitchMailboxMessageFlagAction
from bss.http_api import HTTPAPIConnector, AuthSessionData
from bss.adapters.portaswitch.config import PortaSwitchSettings

DEFAULT_CHUNK_SIZE: Final[int] = 8192


class AccountAPI(HTTPAPIConnector):
    """Provides access to Admin realm of the PortaSwitch API."""

    def __init__(self, portaswitch_settings: PortaSwitchSettings):
        """The class constructor.

        Parameters:
            :config (app_config.AppConfig): The instance with all the service config options.

        """
        super().__init__(portaswitch_settings.ACCOUNT_API_URL)

        self._verify_https = portaswitch_settings.VERIFY_HTTPS

    def __send_request(
        self, module: str, method: str, params: dict, stream: bool | None = None, access_token: str | None = None
    ) -> Union[dict, tuple[str, Union[bytes, Iterator]]]:
        """Sends the PortaBilling API method by means of HTTP POST request.

        Parameters:
            :module (str): The module of the Porta-Billing API methods from which the method to be
                called.
            :method (str): The name of the Porta-Billing API method to be called.
            :params (dict): The object with parameters the API method to be called with.

        Returns:
            :response (dict): The API method execution result.

        """
        logging.debug(f"Sending Account.API request: {module}/{method}/{params}")

        headers = None
        if access_token:
            headers = {"Authorization": f"Bearer {access_token}"}

        result = self.send_rest_request(
            method="POST",
            path=f"/rest/{module}/{method}",
            json={"params": params},
            headers=headers,
            stream=stream,
        )

        logging.debug(f"Processing the Account.API result: {module}/{method}/{params}: \n {result}")
        return result

    def add_auth_info(self, url: str, request_params: dict, auth_session: AuthSessionData) -> dict:
        """Change the parameters of requests.request call to add
        there required authentication information (into headers,
        basic auth, etc.). The
        requests.request(method, url, **params_returned)

        Parameters:
            :url (str): The URL the request is being sent to (in case if auth info differs for
                various paths).
            :request_params (dict): The current set of parameters for the requests.request call.
            :auth_session (AuthSessionData): Current user's access token - not currently used.

        Returns:
            :(dict): The modified set of parameters for requests.request.

        """
        request_params["verify"] = self._verify_https

        return request_params

    def decode_response(self, response: requests.models.Response) -> Union[dict, tuple[str, Union[bytes, Iterator]]]:
        """Decode the response.

        Parameters:
            :response (requests.models.Response): The response to be decoded.

        Returns:
            Response :dict|bytes: Returns dict with parsed JSON in case the response contains JSON content type.
                Returns bytes if the response is an attachment.
                Returns Iterator if the response marked as `chunked`
        """

        headers = response.headers
        content_type = headers.get("Content-Type", "")
        if "application/json" in content_type:
            return response.json()

        if "attachment" in headers.get("Content-Disposition", ""):
            if "chunked" in headers.get("Transfer-Encoding", ""):
                return content_type, response.iter_content(DEFAULT_CHUNK_SIZE)
            else:
                return content_type, response.content

        raise ValueError("Not expected response")

    def login(self, login: str, password: str) -> dict:
        """Performs an account login by its login and password.

        Parameters:
            :login (str): The login of the account.
            :password (str): The password of the account.

        Returns:
            :(dict): The API method execution result.

        """
        return self.__send_request(
            module="Session", method="login", params={"login": login, "password": password, "token": password}
        )

    def logout(self, access_token: str) -> dict:
        """Performs an account logout.

        Parameters:
            :access_token (str): The identifier of the session to be logged.

        Returns:
            :(dict): The API method execution result.

        """
        return self.__send_request(
            module="Session",
            method="logout",
            params={
                "access_token": access_token,
            },
        )

    def refresh(self, refresh_token: str) -> dict:
        """Performs an account login by its login and password.

        Parameters:
            :refresh_token (str): The login of the account.

        Returns:
            :(dict): The API method execution result.

        """
        return self.__send_request(
            module="Session",
            method="refresh_access_token",
            params={
                "refresh_token": refresh_token,
            },
        )

    def ping(self, access_token: str) -> dict:
        """Checks whether the access_token is valid.

        Parameters:
            :access_token (str): The access_token to be checked.

        Returns:
            :(dict): The API method execution result.

        """
        return self.__send_request(
            module="Session",
            method="ping",
            params={
                "access_token": access_token,
            },
        )

    def get_account_info(self, access_token: str) -> dict:
        """Returns the account_info of the account, which created a session related to
        the access_token.

        Parameters:
            :access_token (str): The token that enables the API user to be authenticated
                in the PortaBilling API using the account realm.

        Returns:
            :(dict): The API method execution result that contains an account info.

        """
        return self.__send_request(
            module="Account",
            method="get_account_info",
            params={
                "detailed_info": 1,  # to acquire the extension_id
                "without_service_features": 1,
                "limit_alias_did_number_list": 100,
            },
            access_token=access_token,
        )

    def get_alias_list(self, access_token: str) -> dict:
        """Returns the alias list of the account, which created a session related to
        the access_token.

        Parameters:
            :i_account (int): The identifier of the account which aliases to fetch.
            :access_token (str): The token that enables the API user to be authenticated
                in the PortaBilling API using the account realm.

        Returns:
            :(dict): The API method execution result that contains an account info.

        """
        return self.__send_request(module="Account", method="get_alias_list", params={}, access_token=access_token)

    def get_xdr_list(
        self, access_token: str, page: int, items_per_page: int, time_from: datetime, time_to: datetime
    ) -> dict:
        """Returns the account_info of the account, which created a session related to
        the access_token.

        Parameters:
            :access_token (str): The token that enables the API user to be authenticated
                in the PortaBilling API using the account realm.
            :page (int): Shows what page of the CDR history to return.
            :items_per_page (int): Shows the number of items to return.
            :time_from (datetime): Filters the time frame of the CDR history.
            :time_to (datetime): Filters the time frame of the CDR history.

        Returns:
            :(dict): The API method execution result that contains an account info.

        """
        return self.__send_request(
            module="Account",
            method="get_xdr_list",
            params={
                "get_total": 1,
                "show_unsuccessful": 1,
                "limit": items_per_page,
                "offset": items_per_page * (page - 1),
                "from_date": time_from.strftime("%Y-%m-%d %H:%M:%S"),
                "to_date": time_to.strftime("%Y-%m-%d %H:%M:%S"),
            },
            access_token=access_token,
        )

    def get_phonebook_list(self, access_token: str, page: int, items_per_page: int) -> dict:
        """Return the phonebook list of the account.

        Args:
            access_token (str): Token that authenticates the API user in the PortaBilling API using the account realm.
            page (int): Shows what page of the phonebook to return.
            items_per_page (int): Shows the number of items to return.

        Returns:
            dict: API method execution result containing phonebook items.
        """
        return self.__send_request(
            module="Account",
            method="get_phonebook_list",
            params={
                "get_total": 1,
                "limit": items_per_page,
                "offset": items_per_page * (page - 1),
            },
            access_token=access_token)

    def get_call_recording(self, recording_id: int, access_token: str) -> bytes:
        """Returns the bytes of the call recording file.

        Parameters:
            :recording_id (int): The identifier of the call recording.
            :access_token (str): The token that enables the API user to be authenticated
                in the PortaBilling API using the account realm.

        Returns:
            :(dict): The API method execution result that contains an account info.

        """
        return self.__send_request(
            module="CDR",
            method="get_call_recording",
            params={
                "i_xdr": recording_id,
            },
            access_token=access_token,
        )

    def get_mailbox_messages(self, access_token: str) -> List[dict]:
        """
        Returns the mailbox of the account, which created a session related to the access_token.
            Parameters:
                access_token :str: The token that enables the API user to be authenticated in the PortaBilling API using the account realm.

            Returns:
                Response :dict: The API method execution result that contains a list of mailbox messages.
        """

        return self.__send_request(
            module="Account",
            method="get_mailbox_message_list",
            params={},
            access_token=access_token,
        )["messages"]

    def get_mailbox_message_details(self, access_token: str, message_id: str) -> dict:
        """
        Returns the mailbox message details of the account, which created a session related to the access_token.
            Parameters:
                access_token :str: The token that enables the API user to be authenticated in the PortaBilling API using the account realm.
                message_id :str: The unique ID of the message.

            Returns:
                Response :dict: The API method execution result that contains a details of mailbox message.
        """

        return self.__send_request(
            module="Account",
            method="get_mailbox_message_details",
            params={
                "message_uid": message_id,
            },
            access_token=access_token,
        )

    def get_mailbox_message_attachment(self, access_token: str, message_id: str, file_format: str) -> tuple[str, Iterator]:
        """
        Returns the mailbox message attachment of the account, which created a session related to the access_token.
            Parameters:
                access_token :str: The token that enables the API user to be authenticated in the PortaBilling API using the account realm.
                message_id :str: The unique ID of the message.
                file_format :str: Provided file format.

            Returns:
                Response :bytes: The API method execution result that contains a raw bytes of a mailbox message attachment.
        """

        return self.__send_request(
            module="Account",
            method="get_mailbox_message_attachment",
            params={"message_uid": message_id, "format": file_format},
            stream=True,
            access_token=access_token,
        )

    def set_mailbox_message_flag(
        self,
        access_token: str,
        message_id: str,
        flag: PortaSwitchMailboxMessageFlag,
        action: PortaSwitchMailboxMessageFlagAction,
    ) -> dict:
        """
        Returns the mailbox message details of the account, which created a session related to the access_token.
            Parameters:
                access_token :str: The token that enables the API user to be authenticated in the PortaBilling API using the account realm.
                message_id :str: The unique ID of the message.
                flag: :PortaSwitchMailboxMessageFlag: The flag to set.
                action: :PortaSwitchMailboxMessageFlagAction: Set the flag if it has value `set_flag`, remove the flag otherwise.

            Returns:
                Response :dict: The API method execution result.
        """

        return self.__send_request(
            module="Account",
            method="set_mailbox_messages_flag",
            params={"action": action.value, "flag": flag.value, "message_uids": [message_id]},
            access_token=access_token,
        )

    def delete_mailbox_message(self, access_token: str, message_id: str) -> None:
        """
        Deletes the mailbox message of the account, which created a session related to the access_token.
            Parameters:
                access_token :str: The token that enables the API user to be authenticated in the PortaBilling API using the account realm.
                message_id :str: The unique ID of the message.
        """

        return self.__send_request(
            module="Account",
            method="delete_mailbox_messages",
            params={"message_uids": [message_id]},
            access_token=access_token,
        )
