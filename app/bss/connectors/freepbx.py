from bss.connector import (
    BSSConnector,
    Calls,
    SessionInfo,
    EndUser,
    Contacts,
    ContactInfo,
    Capabilities,
)
from bss.models import (
    NumbersSchema,
    SipInfoSchema,
    SipStatusSchema,
    ServerSchema,
    OtpCreateResponseSchema,
    OtpVerifyRequestSchema,
)
import uuid
from report_error import WebTritErrorException
from bss.http_api import HTTPAPIConnector
from bss.sessions import FileSessionStorage
from app_config import AppConfig

import datetime
import logging

import re

VERSION = "0.0.1"



class FreePBXAPI(HTTPAPIConnector):
    def __init__(self, api_server: str, api_user: str,
                 api_password: str, api_token: str = None,
                 **kwargs):
        super().__init__(api_server, api_user, api_password, api_token)
        if 'graphql_path' in kwargs:
            self.graphql_path = kwargs['graphql_path']
        else:
            self.graphql_path = '/admin/api/api/gql'

    def extract_access_token(self, response: dict) -> str:
        return response.get('access_token', None)
    def access_token_path(self) -> str:
        return "/admin/api/api/token"
    
    def get_extension(self, user_id: str) -> str:
        """Get the extension info"""
        query = """query { 
            fetchExtension(extensionId: <extid>) {
                status
                message
                id
                extensionId
            
                user {
                    password
                    extPassword
                    name
                    sipname
                }
            }
        }
        """
        query = query.replace('<extid>', user_id)
        user = self.send_rest_request('POST', self.graphql_path,
                                    json = query, graphql = True)
        if user:
            return user.get('data', {}).get('fetchExtension', None)
        return None

    def get_all_extensions(self) -> str:
        """Get the extension info"""
        query = """{
    fetchAllExtensions {
        status
        message
        totalCount
        extension {
            id
            extensionId
            user {
              name
              password
              outboundCid
              ringtimer
              noanswer
              sipname
              password
              extPassword
            }
              coreDevice {
              deviceId
              dial
              devicetype
              description
              emergencyCid
            }
        }
    }
}
        """
        users = self.send_rest_request('POST', self.graphql_path,
                                    json = query, graphql = True)
        if users:
            return users.get('data', {}).get('fetchAllExtensions', {}).get('extension', [])
  
        return None

class FreePBXConnector(BSSConnector):
    """Supply to WebTrit core the required information about
    VoIP users in FreePBX system"""

    def __init__(self, config: AppConfig):
        super().__init__(config)
        api_server = config.get_conf_val('FreePBX', 'API_Server',
                            default = 'http://127.0.0.1')
        api_user = config.get_conf_val('FreePBX', 'API_User')
        api_password = config.get_conf_val('FreePBX', 'API_Secret')
        self.sip_server = config.get_conf_val('FreePBX', 'SIP_Server',
                                         default = '167.172.185.158')
        # store sessions in a global variable
        self.api_client = FreePBXAPI(api_server = api_server,
                                     api_user = api_user,
                                     api_password = api_password)
        self.storage = FileSessionStorage(config)


    def create_session(self, user_id: str) -> SessionInfo:
        session = SessionInfo(
            user_id=user_id,
            session_id=str(uuid.uuid1()),
            access_token=str(uuid.uuid1()),
            refresh_token=str(uuid.uuid1()),
            expires_at=datetime.datetime.now() + datetime.timedelta(days=1),
        )

        return session

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

        user = self.api_client.get_extension(user_id)
        if user:
            if user.get("user", {}).get("extPassword", None) == password:
                # everything is in order, create a session
                session = self.create_session(user_id)
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

    def freepbx_ext_to_webtrit_user(self, ext: dict,
                                    produce_user_info = True):
        ext_info = ext.get('user', {})
        parts = ext_info.get('name', '').split()
        firstname = parts[0]
        lastname = ' '.join(parts[1:])
        outbound_id = ext_info.get('outboundCid',
                                   f"<{ext.get('extensionId', '')}>")
        match = re.search(r'<(\d+)>', outbound_id)
        if match:
            main_number = match.group(1)
        else:
            main_number = ext.get('extensionId', '')
        data = {
            'firstname': firstname,
            'lastname': lastname,
            'email': ext_info.get('email', None),

            }
        if produce_user_info:
            data['sip'] = SipInfoSchema(
                            login = ext.get('extensionId', ''),
                            password = ext_info.get('extPassword', ''),
                            sip_server = ServerSchema(
                                host = self.sip_server,
                                port = 5060
                            )
                        )
            return EndUser(**data)
        else:
            data['sip'] = SipStatusSchema(
                # TODO: fix it
                display_name = ext.get('extensionId', ''),
                status = "registered"
            )
            data['numbers'] = NumbersSchema(
                            ext = ext.get('extensionId', ''),
                            main = main_number
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
            self.freepbx_ext_to_webtrit_user(x, produce_user_info = False)
            for x in ext_list
            if x.get('extensionId', '') != user_id
        ]

        return Contacts( __root__ = contacts)

    def generate_otp(self, user_id: str) -> OtpCreateResponseSchema:
        pass

    def validate_otp(self, otp: OtpVerifyRequestSchema) -> SessionInfo:
        pass
    
    def retrieve_calls(
        self,
        session: SessionInfo,
        user_id: str,
        page: None,
        items_per_page: None,
        date_from: None,
        date_to: None,
    ) -> Calls:
        pass


    def retrieve_call_recording(
        self, session: SessionInfo, call_recording: str
    ) -> bytes:
        pass
