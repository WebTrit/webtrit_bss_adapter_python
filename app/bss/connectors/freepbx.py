from bss.connector import (
    BSSConnector,
    SessionStorage,
    SessionInfo,
    EndUser,
    Contacts,
    Calls,
    ContactInfo,
    Capabilities,
)
from bss.models import (
    NumbersSchema,
    OtpCreateResponseSchema,
    OtpVerifyRequestSchema,
    OtpSentType,
    SipInfoSchema,
    SipStatusSchema,
    ServerSchema,
)

from bss.models import SipStatusSchema as SIPStatus
from bss.models import CDRInfoSchema as CDRInfo
from bss.models import CallInfoSchema as CallInfo
from report_error import WebTritErrorException
from bss.http_api import HTTPAPIConnectorWithLogin

from bss.sessions import FileSessionStorage
from app_config import AppConfig


import datetime
import logging

import re

VERSION = "0.0.1"


class FreePBXAPI(HTTPAPIConnectorWithLogin):
    def __init__(self, api_server: str, api_user: str, api_password: str, **kwargs):
        super().__init__(api_server, api_user, api_password)
        if "graphql_path" in kwargs:
            self.graphql_path = kwargs["graphql_path"]
        else:
            self.graphql_path = "/admin/api/api/gql"

    def extract_access_token(self, response: dict) -> str:
        return response.get("access_token", None)

    def access_token_path(self) -> str:
        return "/admin/api/api/token"

    query_ext = """{ 
            fetchExtension(extensionId: <extid>) {
                status message id extensionId
                user {
                    password extPassword name sipname
                }
            }
        }"""
    query_voicemail = """{
            fetchVoiceMail (extensionId: <extid>) {
                status message name password email
            }
        }"""

    def get_extension(self, user_id: str):
        """Get the extension info"""

        query = self.query_ext.replace("<extid>", user_id)
        user = self.send_rest_request("POST", self.graphql_path, json={"query": query})
        if user:
            # found such extension, but the extension data does not
            # contain the email or the password :-( so we have to
            # retrieve it from the voicemail data
            query = self.query_voicemail.replace("<extid>", user_id)
            vm = self.send_rest_request(
                "POST", self.graphql_path, json={"query": query}
            )
            if vm:
                user_data = user.get("data", {}).get("fetchExtension", {})
                user_data["vm"] = vm.get("data", {}).get("fetchVoiceMail", {})
                # merge the data
                return user_data

        return None

    query_all_extensions = """{
            fetchAllExtensions {
                status
                message
                totalCount
                extension {
                    id
                    extensionId
                    user {
                    name password outboundCid ringtimer sipname password extPassword
                    }
                    coreDevice {
                    deviceId dial devicetype description emergencyCid
                    }
                }
            }
        }"""

    def get_all_extensions(self):
        """Get the extension info"""
        users = self.send_rest_request(
            "POST", self.graphql_path, json={"query": self.query_all_extensions}
        )
        if users:
            return (
                users.get("data", {}).get("fetchAllExtensions", {}).get("extension", [])
            )

        return None

    def login(self):
        res = self.send_rest_request(
            "POST",
            self.access_token_path(),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={
                "client_id": self.api_user,
                "client_secret": self.api_password,
                "scope": "",
                "grant_type": "client_credentials",
            },
            turn_off_login=True,
        )
        if res and self.extract_access_token(res):
            # store it globally
            self.access_token = self.extract_access_token(res)
            return True

        logging.debug(f"Could not find an access token in the response {res}")
        raise ValueError("Could not find an access token in the response")

    def add_auth_info(self, url: str, request_params: dict) -> dict:
        """Change the parameters of requests.request call to add
        there required authentication information (into headers,
        basic auth, etc.)"""
        if self.access_token:
            headers = request_params.get("headers", {}).copy()
            # override the auth header
            new_headers = {
                **headers,
                **{"Authorization": "Bearer " + self.access_token},
            }
            return {**request_params, **{"headers": new_headers}}

        return request_params


class FreePBXConnector(BSSConnector):
    """Supply to WebTrit core the required information about
    VoIP users using a built-in list of users. Suitable
    for development / testing"""

    def __init__(self, config: AppConfig):
        super().__init__(config)
        api_server = config.get_conf_val(
            "FreePBX", "API_Server", default="http://127.0.0.1"
        )
        api_user = config.get_conf_val("FreePBX", "API_User")
        api_password = config.get_conf_val("FreePBX", "API_Secret")
        self.sip_server = config.get_conf_val(
            "FreePBX", "SIP_Server", default="167.172.185.158"
        )
        # store sessions in a global variable
        self.api_client = FreePBXAPI(
            api_server=api_server, api_user=api_user, api_password=api_password
        )
        self.storage = FileSessionStorage(config)

    @classmethod
    def name(cls) -> str:
        return "FreePBX connector"

    @classmethod
    def version(cls) -> str:
        global VERSION
        return VERSION

    def get_capabilities(self) -> list:
        """Capabilities of your hosted PBX / BSS / your API adapter"""
        return [
            # log in user with username / password
            Capabilities.passwordSignin,
            # log in user using one-time-password generated on the BSS side
            # Capabilities.otpSignin,
            # obtain user's call history
            # Capabilities.callHistory,
            # obtain the list of other extensions in the PBX
            Capabilities.extensions,
            # download call recordings - currently not supported
            # SupportedEnum.recordings
        ]

    def authenticate(self, user_id: str, password: str = None) -> SessionInfo:
        """Authenticate user with username and password and obtain an API token for
        further requests."""

        user = self.api_client.get_extension(user_id)
        if user:
            if user.get("vm", {}).get("password", None) == password:
                # everything is in order, create a session
                session = self.storage.create_session(user_id)
                self.storage.store_session(session)
                return session

            raise WebTritErrorException(
                status_code=401,
                code=42,
                error_message="Invalid password",
            )

        # something is wrong. your code should return a more descriptive
        # error message to simplify the process of fixing the problem
        raise WebTritErrorException(
            status_code=401,
            code=42,
            error_message="User authentication error",
        )

    def generate_otp(self, user_id: str) -> OtpCreateResponseSchema:
        pass

    def validate_otp(self, otp: OtpVerifyRequestSchema) -> SessionInfo:
        pass

    def freepbx_ext_to_webtrit_user(self, ext: dict, produce_user_info=True):
        """Convert the data returned by FreePBX API into an object:
        * EndUser (info about the user who is logging in)
        * ContactInfo (info about other extensions in the PBX)
        """
        ext_info = ext.get("user", {})
        parts = ext_info.get("name", "").split()
        firstname = parts[0]
        lastname = " ".join(parts[1:])
        outbound_id = ext_info.get("outboundCid", f"<{ext.get('extensionId', '')}>")
        match = re.search(r"<(\d+)>", outbound_id)
        if match:
            main_number = match.group(1)
        else:
            main_number = ext.get("extensionId", "")
        data = {
            "firstname": firstname,
            "lastname": lastname,
            "email": ext_info.get("email", None),
        }
        if produce_user_info:
            data["sip"] = SipInfoSchema(
                login=ext.get("extensionId", ""),
                password=ext_info.get("extPassword", ""),
                sip_server=ServerSchema(host=self.sip_server, port=5060),
            )
            return EndUser(**data)
        else:
            data["sip"] = SipStatusSchema(
                # TODO: fix it
                display_name=ext.get("extensionId", ""),
                status="registered",
            )
            data["numbers"] = NumbersSchema(
                ext=ext.get("extensionId", ""), main=main_number
            )
            return ContactInfo(**data)

    def retrieve_user(self, session: SessionInfo, user_id: str) -> EndUser:
        """Obtain user's information - most importantly, his/her SIP credentials."""

        user = self.api_client.get_extension(user_id)
        if user:
            return self.freepbx_ext_to_webtrit_user(user)

        # no such session
        raise WebTritErrorException(
            status_code=404, code=42, error_message="User not found"
        )

    def retrieve_contacts(self, session: SessionInfo, user_id: str) -> Contacts:
        """List of other extensions in the PBX"""

        ext_list = self.api_client.get_all_extensions()

        contacts = [
            self.freepbx_ext_to_webtrit_user(x, produce_user_info=False)
            for x in ext_list
            if x.get("extensionId", "") != user_id
        ]

        return Contacts(__root__=contacts)

    def retrieve_calls(self, session: SessionInfo, user_id: str, **kwargs) -> Calls:
        pass

    # call recording is not supported in this example
    def retrieve_call_recording(
        self, session: SessionInfo, call_recording: str
    ) -> bytes:
        """Get the media file for a previously recorded call."""
        # not yet implemented
        pass
