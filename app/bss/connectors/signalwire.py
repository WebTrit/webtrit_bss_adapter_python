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
    ServerSchema    
)

from bss.models import SipStatusSchema as SIPStatus
from bss.models import CDRInfoSchema as CDRInfo
from bss.models import CallInfoSchema as CallInfo
from report_error import WebTritErrorException
from bss.http_api import HTTPAPIConnector
from bss.sessions import FileSessionStorage
from app_config import AppConfig

import uuid
import datetime
import logging
import random

import re

VERSION = "0.0.1"

class SignalWireAPI(HTTPAPIConnector):
    def have_to_login(self) -> bool:
        """No need to login, project_id:token are sent in every request"""
        return False

    def login(self) -> bool:
        pass

    def add_auth_info(self, url: str, request_params: dict) -> dict:
        """Add project_id:token as basic auth"""
        new_params = request_params.copy()
        new_params['auth'] = (self.api_user, self.api_password)
        
        return new_params
    


class SingalWireConnector(BSSConnector):
    """Supply to WebTrit core the required information about
    VoIP users using a built-in list of users. Suitable
    for development / testing"""
    PATH_COMMON = ''
    PATH_SIP_ENDPOINTS = '/endpoints/sip'
    def path(self, path: str, id = None) -> str:
        if id:
            # TODO: do a replace in case if ID is in the middle of the path
            return self.PATH_COMMON + path + '/' + id
        return self.PATH_COMMON + path

    def __init__(self, config: AppConfig):
        super().__init__(config)
        api_server = config.get_conf_val('SIGNALWIRE', 'API_URL',
                            default = 'http://127.0.0.1')
        api_user = config.get_conf_val('SIGNALWIRE', 'PROJECT_ID')
        api_password = config.get_conf_val('SIGNALWIRE', 'API_TOKEN')
        # TODO: where to get this?
        self.sip_server = config.get_conf_val('FreePBX', 'SIP_Server',
                                         default = '167.172.185.158')
        # store sessions in a global variable
        self.api_client = SignalWireAPI(api_server = api_server,
                                     api_user = api_user,
                                     api_password = api_password)
        self.storage = FileSessionStorage(config)

    @classmethod
    def name(cls) -> str:
        return "SignalWire connector"

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
            #Capabilities.otpSignin,
            # obtain user's call history
            #Capabilities.callHistory,
            # obtain the list of other extensions in the PBX
            Capabilities.extensions,
            # download call recordings - currently not supported
            # SupportedEnum.recordings
        ]

    def authenticate(self, user_id: str, password: str = None) -> SessionInfo:
        """Authenticate user with username and password and obtain an API token for
        further requests."""

        user = self.api_client.send_rest_request('GET',
                                      self.path(self.PATH_SIP_ENDPOINTS, user_id)
                                      )

        if user:
            # no passwrd check for now
            #if user.get("user", {}).get("extPassword", None) == password:
            # everything is in order, create a session
            session = self.storage.create_session(user_id)
            self.storage.store_session(session)
            return session

            # raise WebTritErrorException(
            #     status_code=401,
            #     code=42,
            #     error_message="Invalid password",
            # )

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

    def rest_to_contact(self, ep: dict) -> ContactInfo:
        data = {
            # not perfect, but we need to store it somewhere
            'first_name': ep.get('id', None),
        }
        data['numbers'] = NumbersSchema(
            # there is no extension numbers as such in SignalWire
            ext = str(random.randint(1000, 9999)),
            main = '123'
        )
        return ContactInfo(**data)

    def retrieve_user(self, session: SessionInfo, user_id: str) -> EndUser:
        """Obtain user's information - most importantly, his/her SIP credentials."""

        user = self.api_client.send_rest_request('GET',
                                      self.path(self.PATH_SIP_ENDPOINTS, user_id)
                                      )
        if user:
            return self.freepbx_ext_to_webtrit_user(user)

        # no such session
        raise WebTritErrorException(
            status_code=404, code=42, error_message="User not found"
        )


    def retrieve_contacts(self, session: SessionInfo, user_id: str) -> Contacts:
        """List of other extensions in the PBX"""

        ext_list = self.api_client.send_rest_request('GET',
                                      self.path(self.PATH_SIP_ENDPOINTS)
                                      )

        if 'data' in ext_list and ext_list['data']:
            contacts = [
#            self.freepbx_ext_to_webtrit_user(x, produce_user_info = False)
                ContactInfo(**x)
                for x in ext_list
    #            if x.get('extensionId', '') != user_id
        ]

        return Contacts( __root__ = contacts)

    def retrieve_calls(self, session: SessionInfo, user_id: str, **kwargs) -> Calls:
        pass

    # call recording is not supported in this example
    def retrieve_call_recording(
        self, session: SessionInfo, call_recording: str
    ) -> bytes:
        """Get the media file for a previously recorded call."""
        # not yet implemented
        pass
