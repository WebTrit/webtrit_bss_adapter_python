from bss.adapters import BSSAdapter
from bss.types import (Capabilities, UserInfo, EndUser, Contacts, ContactInfo,
                       Calls, CDRInfo, ConnectStatus, SessionInfo, SIPRegistrationStatus,
                       Balance, BalanceType, Numbers, SIPServer, SIPInfo,
                       OTPCreateResponse, OTPVerifyRequest,
                       CreateSessionUnauthorizedErrorResponse,  )

from bss.dbs import TiedKeyValue
from bss.sessions import configure_session_storage
from report_error import WebTritErrorException
from app_config import AppConfig
from bss.http_api import HTTPAPIConnectorWithLogin, OAuthSessionData, APIUser
from typing import Union, List, Dict, Tuple
from datetime import datetime, timedelta
from pydantic import BaseModel, Field
import logging

import re

VERSION = "0.0.1"

# Interface to Netsapiens cloud PBX https://docs.ns-api.com/reference/

class NetsapiensUser(APIUser):
    user_id: str
    password: str = Field(default=None)
    client_id: str = Field(default=None)
    client_secret: str = Field(default=None)

class NetsapiensAPI(HTTPAPIConnectorWithLogin):
    def __init__(self, api_server: str, **kwargs):
        # api user/password are not used, since they are individual for each user
        super().__init__(api_server, **kwargs)


    def access_token_path(self) -> str:
        return "/ns-api/v2/tokens"

    def login(self, user: NetsapiensUser) -> OAuthSessionData:
        # populate the data properly
        req_data = {
                "client_id": user.client_id,
                "client_secret": user.client_secret,
                "username": user.user_id,
                "password": user.password,
                # "scope": "",
                "grant_type": "password",
            }

        res = self.send_rest_request(
            "POST",
            self.access_token_path(),
            headers={"Content-Type": "application/json"},
            json=req_data,
            turn_off_login=True,
            user = user
        )
        if res and (session := self.extract_access_token(res)):
            # access token was extracted and stored - remember the session
            # for this user
            self.store_auth_session(session, user)
            return session

        logging.debug(f"Could not find an access token in the response {res}")
        raise ValueError("Could not find an access token in the response")

    def refresh(self):
        """Rerfresh access token"""
        return self.login(data={
                "client_id": self.api_user,
                "client_secret": self.api_password,
                "scope": "",
                "refresh_token": self.refresh_token,
                "grant_type": "refresh_token",
            })
    
    def split_uid(self, uid: str) -> Tuple[str, str]:
        """Split the user ID into domain and user ID"""
        parts = uid.split('@')
        if len(parts) == 2:
            return parts
        return (None, None)

    DEVICE_PATH = "/ns-api/v2/domains/<domain>/users/<user_id>/devices"
    def get_extension(self, user_id: str) -> Dict:
        """Get the extension info"""

        uid, domain = self.split_uid(user_id)
        path = self.DEVICE_PATH.replace("<domain>", domain).replace("<user_id>", uid)

        user_info = self.send_rest_request("GET", path, json={},
                                           user=NetsapiensUser(user_id=user_id))
        if user_info:
            if isinstance(user_info, list):
                # need to figure out which one is the right one
                return user_info[0]
            return user_info

        return None
    

    def get_all_extensions(self) -> List[Dict]:
        """Get all extensions defined in the PBX"""
        reply = self.send_rest_request(
            "POST", self.graphql_path, json={"query": self.query_all_extensions}
        )
        if reply:
            return reply.get("data", {}). \
                                get("fetchAllExtensions", {}). \
                                    get("extension", [])

        return []
    


# class FreePBXAdapter(BSSAdapter, SampleOTPHandler):
class NetsapiensAdapter(BSSAdapter):
    """Connect WebTrit and Netsapiens. Authenticate a user using the API, 
    retrieve user's SIP credentials to be used by
    WebTrit and return a list of other configured extenstions (to
    be provided as 'Cloud PBX' contacts).
    Currently does not support OTP login."""
    
    def __init__(self, config: AppConfig):
        super().__init__(config)
        api_server = config.get_conf_val(
            "Netsapiens", "API_Server", default="http://127.0.0.1"
        )

        self.api_client = NetsapiensAPI(
            api_server=api_server
        )
        self.sessions = configure_session_storage(config)
        # for debugging only
        self.otp_db = TiedKeyValue()

    @classmethod
    def name(cls) -> str:
        return f"Netsapiens adapter"

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

    def generate_otp(self, user: UserInfo) -> OTPCreateResponse:
        """Not supported"""
        pass

    def validate_otp(self, otp: OTPVerifyRequest) -> SessionInfo:
        """Not supported"""
        pass


    def extract_user_id(self, user_data: object) -> str:
        """Extract user_id (unique and unmutable identifier of the user)
        from the data in the DB. Please override it in your sub-class"""
        # for production systems it is more appropriate to use 'id'
        # which is a permanent identifier of the user; but for testing
        # extension number is more convenient
        return user_data.get("uid", None)

    def parse_semicolon_list(self, semicolon_list: str) -> Dict[str, str]:
        """Parse parameters in the form of key1=value1;key2=value2;..."""
        pairs = semicolon_list.split(';')

        # Initialize an empty dictionary to store keys and values
        key_value_dict = {}

        # Loop through each pair and split by '=' only at the first occurrence
        for pair in pairs:
            if '=' in pair:
                key, value = pair.split('=', 1)  # Split by '=' only at the first occurrence
                key_value_dict[key] = value
        return key_value_dict
    
    def authenticate(self, user: UserInfo, password: str = None) -> SessionInfo:
        """Authenticate user with username and password and obtain an API token for
        further requests."""

        extra_data = self.parse_semicolon_list(user.login)
        if not extra_data.get("user_id") or not extra_data.get("client_id") or not extra_data.get("client_secret"):
            raise WebTritErrorException(
                status_code=422,
                error_message="Not enough data to authenticate the user",
            )
        token_data = self.api_client.login(NetsapiensUser(
            user_id=extra_data.get("user_id"),
            password=password,
            client_id=extra_data.get("client_id"),
            client_secret=extra_data.get("client_secret")
        ))
        if token_data:
            # everything is in order, create a session

            # proper user ID - override the one that has client_id and client_secret
            user.user_id = extra_data.get("user_id")
            session = self.sessions.create_session(user)
            self.sessions.store_session(session)
            return session

        # something is wrong. your code should return a more descriptive
        # error message to simplify the process of fixing the problem
        raise WebTritErrorException(
            status_code=401,
            error_message="User authentication error",
        )

    def retrieve_user(self, session: SessionInfo, user: UserInfo) -> EndUser:
        """Obtain user's information - most importantly, his/her SIP credentials."""

        user = self.api_client.get_extension(user.user_id)
        if user:
            return self.netsapiens_to_webtrit_obj(user, produce_user_info=True)

        # no such session
        raise WebTritErrorException(
            status_code=404, 
            error_message="User not found"
        )

    def retrieve_contacts(self, session: SessionInfo, user: UserInfo) -> List[ContactInfo]:
        """List of other extensions in the PBX"""

        ext_list = self.api_client.get_all_extensions()

        contacts = [
            self.freepbx_to_webtrit_obj(x, produce_user_info=False)
            for x in ext_list
            if x.get("extensionId", "") != user.user_id
        ]

        return contacts

    def retrieve_calls(self, session: SessionInfo, user: UserInfo, **kwargs) -> List[CDRInfo]:
        pass

    # call recording is not supported in this example
    def retrieve_call_recording(
        self, session: SessionInfo, call_recording: str
    ) -> bytes:
        """Get the media file for a previously recorded call."""
        # not yet implemented
        pass

    def netsapiens_to_webtrit_obj(self, ext: dict, produce_user_info=True) -> dict:
        """Convert the JSON data returned by FreePBX API into an dictionary
        that can be used to crate a WebTrit object (either EndUser or ContactInfo)):

            Args:
                * ext (dict): A dictionary (representing JSON structure,
                    returned by the FreePBX API), which contains the
                    extension's information.
                * produce_user_info (bool, optional): A flag to indicate
                    whether to generate data for EndUser (info about a
                    specific extension, includes SIP credentials, etc.) 
                    or ContactInfo (basic info about other extensions in PBX)

            Returns:
                dict: data to be passed to object's constructor
        """

        firstname =  ext.get("name-full-name", "Unknown")
        lastname = ""

        # TODO: numbers
        data = {
            "company_name": "Netsapiens", # TODO?
            "first_name": firstname,
            "last_name": lastname,
            "email": "Unknown@unknown.com",
            "numbers": Numbers(
                ext=ext.get("user", ""),
                main=ext.get("user", ""),
                additional=[]
            ),
            "balance": Balance( balance_type=BalanceType.inapplicable, )
        }
        display_name = ext.get("name-full-name", "???")

        if produce_user_info:
            data["sip"] = SIPInfo(
                username=ext.get("login-username", ""),
                display_name=display_name,
                password=ext.get("device-sip-registration-password", ""),
                sip_server=SIPServer(host=ext.get("core-server", ""), port=5060),
            )
            return EndUser(**data)
        else:
            # TODO: find out whether we can get the real
            # registration status via API - for now all extensions
            # are assumed to be registered
            data["sip_status"] = SIPRegistrationStatus.registered

            return ContactInfo(**data)

    def create_new_user(self, user_data, tenant_id: str = None):
        """Create a new user as a part of the sign-up process - not supported yet"""
        pass
