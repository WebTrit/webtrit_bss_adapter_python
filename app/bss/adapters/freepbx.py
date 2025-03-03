from bss.adapters import BSSAdapter
from bss.types import (Capabilities, UserInfo, EndUser, Contacts, ContactInfo,
                       Calls, CDRInfo, ConnectStatus, SessionInfo, SIPRegistrationStatus,
                       Balance, BalanceType, Numbers, SIPServer, SIPInfo,
                       OTPCreateResponse, OTPVerifyRequest,
                       FailedAuthCode,UserNotFoundCode, )

from bss.dbs import TiedKeyValue
from bss.sessions import configure_session_storage
from report_error import WebTritErrorException
from app_config import AppConfig
from bss.http_api import HTTPAPIConnectorWithLogin, OAuthSessionData
from typing import Union, List, Dict
from datetime import datetime, timedelta
import logging

import re

VERSION = "0.0.2"

class FreePBXAPI(HTTPAPIConnectorWithLogin):
    def __init__(self, api_server: str, api_user: str, api_password: str, **kwargs):
        super().__init__(api_server, api_user, api_password)
        if "graphql_path" in kwargs:
            self.graphql_path = kwargs["graphql_path"]
        else:
            self.graphql_path = "/admin/api/api/gql"


    def access_token_path(self) -> str:
        return "/admin/api/api/token"
    
    def extract_access_token(self, response: dict) -> bool:
        """Extract the access token and other data (expiration time,
        refresh token, etc.) from the response and store in the object.
        
        Returns:
        True if success"""
        self.access_token = response.get("access_token", None)
        expires_in = response.get("expires_in", None)
        if expires_in:
            self.access_token_expires_at = datetime.now() + timedelta(seconds=expires_in)
        else:
            self.access_token_expires_at = None
        self.refresh_token = response.get("refresh_token", None)
        logging.debug(f"Got access token {self.access_token} expires at " + \
                      f"{self.access_token_expires_at} refresh token {self.refresh_token}")
        return True if self.access_token else False

    def login(self, data: dict = None):
        if data is None:
            # populate the data properly
            data = {
                "client_id": self.api_user,
                "client_secret": self.api_password,
                "scope": "",
                "grant_type": "client_credentials",
            }

        res = self.send_rest_request(
            "POST",
            self.access_token_path(),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=data,
            turn_off_login=True,
        )
        if res and self.extract_access_token(res):
            # access token was extracted and stored

            return True

        logging.debug(f"Could not find an access token in the response {res}")
        raise ValueError("Could not find an access token in the response")

    def refresh(self, user: str, auth_session: OAuthSessionData):
        """Rerfresh access token"""
        return self.login(data={
                "client_id": self.api_user,
                "client_secret": self.api_password,
                "scope": "",
                "refresh_token": self.refresh_token,
                "grant_type": "refresh_token",
            })
    
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
        if self.access_token:
            if "headers" in request_params:
                headers = request_params["headers"]
            else:
                request_params["headers"] = headers = {}
            # override the auth header
            headers["Authorization"] = "Bearer " + self.access_token

        return request_params

    # GraphQL query to get a specific extension
    query_ext = """{ 
            fetchExtension(extensionId: <extid>) {
                status message id extensionId
                user {
                    password extPassword name sipname
                }
            }
        }"""
    # GraphQL query to get a specific extension's voicemail data
    query_voicemail = """{
            fetchVoiceMail (extensionId: <extid>) {
                status message name password email
            }
        }"""

    def get_extension(self, user_id: str) -> Dict:
        """Get the extension info"""

        if not user_id.isdigit():
            # ext ID has to be numeric
            return None
        
        query = self.query_ext.replace("<extid>", user_id)
        user = self.send_rest_request("POST", self.graphql_path, json={"query": query})
        if user:
            # found such extension, but the extension data does not
            # contain the email or the password :-( so we have to
            # retrieve it from the voicemail data
            user_data = user.get("data", {}).get("fetchExtension", {})
            query = self.query_voicemail.replace("<extid>", user_id)
            vm = self.send_rest_request(
                "POST", self.graphql_path, json={"query": query}
            )
            if vm:
                # append the data from the voicemail part
                user_data["vm"] = vm.get("data", {}).get("fetchVoiceMail", {})

            return user_data

        return None
    
    # GraphQL query to get all extensions
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
class FreePBXAdapter(BSSAdapter):
    """Connect WebTrit and FreePBX. Authenticate a user using his/her
    data in FreePBX, retrieve user's SIP credentials to be used by
    WebTrit and return a list of other configured extenstions (to
    be provided as 'Cloud PBX' contacts).
    Currently does not support OTP login, CDRs and call recording retrieval."""
    
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

        self.api_client = FreePBXAPI(
            api_server=api_server, api_user=api_user, api_password=api_password
        )
        self.sessions = configure_session_storage(config)
        # for debugging only
        self.otp_db = TiedKeyValue()

    @classmethod
    def name(cls) -> str:
        return "FreePBX adapter"

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
        return user_data.get("extensionId", None)

    def authenticate(self, user: UserInfo, password: str = None) -> SessionInfo:
        """Authenticate user with username and password and obtain an API token for
        further requests."""

        user_data = self.api_client.get_extension(user.login)
        if user_data:
            if user_data.get("vm", {}).get("password", None) == password:
                # everything is in order, create a session
                user.user_id = self.extract_user_id(user_data)
                session = self.sessions.create_session(user)
                self.sessions.store_session(session)
                return session

            raise WebTritErrorException(
                status_code=401,
                code=FailedAuthCode.invalid_credentials,
                error_message="Invalid password",
            )

        # something is wrong. your code should return a more descriptive
        # error message to simplify the process of fixing the problem
        raise WebTritErrorException(
            status_code=401,
            code=FailedAuthCode.invalid_credentials,
            error_message="User authentication error",
        )

    def retrieve_user(self, session: SessionInfo, user: UserInfo) -> EndUser:
        """Obtain user's information - most importantly, his/her SIP credentials."""

        user = self.api_client.get_extension(user.user_id)
        if user:
            return self.freepbx_to_webtrit_obj(user, produce_user_info=True)

        # no such session
        raise WebTritErrorException(
            status_code=404, code=UserNotFoundCode.user_not_found,
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

    def freepbx_to_webtrit_obj(self, ext: dict, produce_user_info=True) -> dict:
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
        ext_info = ext.get("user", {})
        parts = ext_info.get("name", "").split()
        firstname = parts[0]
        lastname = " ".join(parts[1:])
        lastname = "" if not lastname else lastname

        outbound_id = ext_info.get("outboundCid", f"<{ext.get('extensionId', '')}>")
        match = re.search(r"<(\d+)>", outbound_id)
        if match:
            main_number = match.group(1)
        else:
            main_number = ext.get("extensionId", "")
        data = {
            "company_name": "FreePBX",
            "first_name": firstname,
            "last_name": lastname,
            "email": ext.get("vm", {}).get("email", 'test@webtrit.com'),
            "numbers": Numbers(
                ext=ext.get("extensionId", ""),
                main=main_number,
                additional=[]
            ),
            "balance": Balance( balance_type=BalanceType.inapplicable, )
        }
        if firstname or lastname:
            display_name = lastname if lastname else ""
            if display_name:
                display_name = display_name + ", "
            display_name = display_name + firstname 
        else:
            display_name = "Ext " + ext.get("extensionId", "???")

        if produce_user_info:
            data["sip"] = SIPInfo(
                username=ext.get("extensionId", ""),
                display_name=display_name,
                password=ext_info.get("extPassword", ""),
                sip_server=SIPServer(host=self.sip_server, port=5060),
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
