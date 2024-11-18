from bss.adapters import BSSAdapter
from bss.types import (Capabilities, UserInfo, EndUser, Contacts, ContactInfo,
                       Calls, CDRInfo, ConnectStatus, SessionInfo, SIPRegistrationStatus,
                       Balance, BalanceType, Numbers, SIPServer, SIPInfo,
                       OTPCreateResponse, OTPVerifyRequest,
                       )

from bss.dbs import TiedKeyValue
from json import JSONDecodeError, loads as load_json
from bss.sessions import configure_session_storage
from report_error import WebTritErrorException
from app_config import AppConfig
from bss.http_api import HTTPAPIConnectorWithLogin, OAuthSessionData, APIUser
from typing import Union, List, Dict, Tuple
#from datetime import datetime, timedelta
from pydantic import BaseModel, Field
import logging


VERSION = "0.1.2"

# Interface to Netsapiens cloud PBX https://docs.ns-api.com/reference/

# class NetsapiensSession(OAuthSessionData):
#     api_server: str = Field(default=None,
#                             description="URL of API, on which the session resides")

class NetsapiensDeviceFilter:
    """Logic of finding the device entry for WebTrit in the list of devices"""

    def __init__(self, pattern: str = "WebTrit"):
        # Marker of the correct device entry in the list of devices
        self.pattern = pattern

    def find_device_entry(self, devices: List[Dict]) -> Dict:
        """Find the device entry that matches the pattern"""
        for dev in devices:
            if self.pattern in dev.get("name-full-name", ""):
                return dev
        return None
    
class NetsapiensClient(BaseModel):
    client_id: str = Field(default=None,
                           description="Client ID to be sent to API request for login")
    client_secret: str = Field(default=None,
                               description="Client secret to be sent to API request for login")
    api_server: str = Field(default=None,
                            description="API server URL")
    domain: str = Field(default=None,
                               description="SIP domain (returned after the login)")
    device_filter: str = Field(default="WebTrit",
                        description="Pattern to search for the correct device entry")


class NetsapiensUser(APIUser):
    user_id: str
    password: str = Field(default=None)
    ns_client: NetsapiensClient = Field(default=None,
                                        description="Info about NS tenant")

class NetsapiensAPI(HTTPAPIConnectorWithLogin):
    def __init__(self, api_server: str, **kwargs):
        # api server is not used, since it is individual for each client (tenant)
        self.clients = {}
        if "netsapiens_clients" in kwargs:
            self.clients = kwargs.pop("netsapiens_clients")

        super().__init__(api_server, **kwargs)

    def split_uid(self, uid: str) -> Tuple[str, str]:
        """Split the user ID like abc@xyz.com into domain xyz.com and user name abc"""
        parts = uid.split('@')
        if len(parts) >= 2:
            return (parts[0], parts[1])
        return (None, None)

    def get_client(self, user_id: str) -> NetsapiensClient:
        """Obtain the NS client object for the given user"""
        uid, domain = self.split_uid(user_id)
        if domain:
            return self.clients.get(domain)
     
        raise KeyError(f"Could not find a client entry for {user_id}")
    
    def get_api_server(self, user_id: str, default: str = None) -> str:
        """Obtain server API URL for the given user"""
        client = self.get_client(user_id)
        return client.api_server
        
    def access_token_path(self) -> str:
        return "/ns-api/v2/tokens"

    def send_rest_request(self,
                          method: str,
                          path: str,
                          server=None,
                          data=None,
                          json=None,
                          query_params=None,
                          headers={'Content-Type': 'application/json'},
                          turn_off_login=False,
                          user: NetsapiensUser = None) -> dict:
        """Override the parent method to place there the correct API_URL"""
        if user:
            # set the API server for this user
            if user.ns_client and user.ns_client.api_server:
                self.api_server = user.ns_client.api_server
            else:
                self.api_server = self.get_api_server(user_id=user.user_id)

        return super().send_rest_request(
            method, path, server, data, json, query_params, headers, turn_off_login, user
        )
    
    def login(self, user: NetsapiensUser) -> OAuthSessionData:
        # populate the data properly
        req_data = dict(
                client_id = user.ns_client.client_id,
                client_secret =  user.ns_client.client_secret,
                username = user.user_id,
                password =  user.password,
                # "scope": "",
                grant_type =  "password",
        )
        self.api_server = self.get_api_server( user_id = user.user_id,
                                              default=user.ns_client.api_server)
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
                "client_id": self.api_user, # TODO: fill correct values
                "client_secret": self.api_password,
                "scope": "",
                "refresh_token": self.refresh_token,
                "grant_type": "refresh_token",
            })
    


    DEVICE_PATH = "/ns-api/v2/domains/<domain>/users/<user_id>/devices"
    def get_extension(self, user_id: str) -> Dict:
        """Get the extension info"""

        uid, domain = self.split_uid(user_id)
        path = self.DEVICE_PATH.replace("<domain>", domain).replace("<user_id>", uid)

        device_list = self.send_rest_request("GET", path, json={},
                                           user=NetsapiensUser(user_id=user_id))
        if device_list:
            ns_filter = NetsapiensDeviceFilter(pattern = self.get_client(user_id).device_filter)
            if isinstance(device_list, list):
                # need to figure out which one is the right one
                correct_device = ns_filter.find_device_entry(device_list)

                if correct_device is None:
                    # TODO: ensure it is visible in the app
                    raise WebTritErrorException(
                        status_code=422,
                        error_message=f"Cannot find a proper device entry on Netsapiens side",
                    )
                return correct_device

            return device_list

        return None
    
    CONTACTS_PATH = "/ns-api/v2/domains/engagep2p/users/100/contacts"
    def get_all_extensions(self, user_id: str) -> List[Dict]:
        """Get all extensions defined in the PBX"""

        uid, domain = self.split_uid(user_id)
        path = self.CONTACTS_PATH.replace("<domain>", domain).replace("<user_id>", uid)

        reply = self.send_rest_request(
            "GET", path, json={},
            query_params = { "includeDomain": "yes"},
            user = NetsapiensUser(user_id=user_id)
        )
        if reply:
            return reply

        return []
    


class NetsapiensAdapter(BSSAdapter):
    """Connect WebTrit and Netsapiens. Authenticate a user using the API, 
    retrieve user's SIP credentials to be used by
    WebTrit and return a list of other configured extenstions (to
    be provided as 'Cloud PBX' contacts).
    Currently does not support OTP login.
    
    
    Config variables:
    
    NETSAPIENS_CLIENTS = JSON string with a list of dicts, each containing:
        - client_id
            For API access
        - client_secret
            For API access
        - api_server
        - domain
            Domain visible to the end-user; users are expected to login as
            username@domain
        - device_filter  
            used to find the correct entry in the list of devices (searches for
            the given string in the name-full-name field). Default: "WebTrit"
           """
    
    def __init__(self, config: AppConfig):
        super().__init__(config)

        self.clients = {}
        if client_list := config.get_conf_val(
            "Netsapiens", "Clients", default=""
        ):
            try:
                self.clients = {
                    c.get("domain"): NetsapiensClient(**c)
                    for c in load_json(client_list)
                }
            except JSONDecodeError as e:
                logging.error(f"Could not parse the client list {client_list}: {e}")

        self.api_client = NetsapiensAPI(
            api_server= "http://localhost", # does not really matter
            netsapiens_clients=self.clients
        )

        self.sessions = configure_session_storage(config)

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

    # def parse_semicolon_list(self, semicolon_list: str) -> Dict[str, str]:
    #     """Parse parameters in the form of key1=value1;key2=value2;..."""
    #     pairs = semicolon_list.split(';')

    #     # Initialize an empty dictionary to store keys and values
    #     key_value_dict = {}

    #     # Loop through each pair and split by '=' only at the first occurrence
    #     for pair in pairs:
    #         if '=' in pair:
    #             key, value = pair.split('=', 1)  # Split by '=' only at the first occurrence
    #             key_value_dict[key] = value
    #     return key_value_dict
    
    def authenticate(self, user: UserInfo, password: str = None) -> SessionInfo:
        """Authenticate user with username and password and obtain an API token for
        further requests."""

        def split_uid(uid: str) -> Tuple[str, str]:
            """Split the user ID like abc@xyz.com into domain xyz.com and user name abc"""
            parts = uid.split('@')
            if len(parts) >= 2:
                return (parts[0], parts[1])
            return (None, None)
        
        username, domain = split_uid(user.login)

        if not username or not domain:
            raise WebTritErrorException(
                status_code=422,
                error_message=f"Invalid login {user.login}, it should contain both username and client id, e.g. 100@abc",
            )
        client = self.clients.get(domain)
        if client is None:
            raise WebTritErrorException(
                status_code=422,
                error_message=f"Unknown Netsapiense domain {domain}",
            )
        token_data = self.api_client.login(NetsapiensUser(
            user_id=user.login,
            password=password,
            ns_client=client
        ))
        if token_data:
            # everything is in order, create a session
            user.user_id = user.login
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

        device = self.api_client.get_extension(user.user_id)
        if device:
            # need to append the info like email address from contacts
            ext_list = self.api_client.get_all_extensions(user.user_id)
            if ext_list:
                # we need to find the correct "device" entry in the list
                for ext in ext_list:
                    if ext.get("uid") == user.user_id:
                        device.update(ext)
                        break
            return self.netsapiens_to_webtrit_obj(device, produce_user_info=True)

        # no such session
        raise WebTritErrorException(
            status_code=404, 
            error_message=f"User  with ID {user.user_id} not found"
        )

    def retrieve_contacts(self, session: SessionInfo, user: UserInfo) -> List[ContactInfo]:
        """List of other extensions in the PBX"""

        ext_list = self.api_client.get_all_extensions(user.user_id)

        contacts = [
            self.netsapiens_to_webtrit_obj(x, produce_user_info=False)
            for x in ext_list
            if x.get("uid") != user.user_id
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

        firstname =  ext.get("name-first-name", ext.get("name-full-name", "Unknown"))
        lastname = ext.get("name-last-name", "")

        # TODO: numbers
        data = {
            "company_name": "Netsapiens", # TODO?
            "first_name": firstname,
            "last_name": lastname,
            "email": ext.get("email", "Unknown@unknown.com"),
            "numbers": Numbers(
                ext=ext.get("user", ""),
                main=ext.get("user", ""),
                additional=[]
            ),
            "balance": Balance( balance_type=BalanceType.inapplicable, )
        }
        display_name = ext.get("name-full-name", f"{lastname}, {firstname}")

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

    def signup(self, user_data, tenant_id: str = None):
        """Create a new user as a part of the sign-up process - not supported yet"""
        pass
