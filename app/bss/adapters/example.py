from bss.adapters import BSSAdapterExternalDB
from bss.dbs import TiedKeyValue, FileStoredKeyValue
from bss.types import (Capabilities, UserInfo, EndUser, Contacts, ContactInfo,
                       Calls, CDRInfo, ConnectStatus, SIPRegistrationStatus,
                       Direction,
                       SessionInfo, Numbers,
                       CustomRequest, CustomResponse)
 
from report_error import raise_webtrit_error
from typing import List, Dict, Optional
from bss.sessions import configure_session_storage
from app_config import AppConfig

import uuid
import datetime
import random
import logging
import faker

import re

VERSION = "0.0.2"

# otherwise it produces annoying messages about locale
# when the app log level is set to DEBUG
logging.getLogger("faker.factory").setLevel(logging.ERROR)

class MadeUpThings(faker.Faker):
    """Auto-generate names, phone numbers, etc. for demo purposes"""

    def random_phone_number(self) -> str:
        return re.sub(r"\D", "", self.phone_number())

    def random_name(self) -> str:
        return self.name().partition(" ")[0]

    def random_lastname(self) -> str:
        return self.name().partition(" ")[2]

    def random_list_member(self, x: list):
        return x[random.randint(0, len(x) - 1)]


class ExampleBSSAdapter(BSSAdapterExternalDB):
    """Supply to WebTrit core the required information about
    VoIP users using a built-in list of users. Suitable
    for development / testing"""

    def __init__(self, config: AppConfig, *args, **kwargs):
        super().__init__(config, *args, **kwargs)
        self.config = config
        # for generation of fake names, etc.
        self.fake = MadeUpThings()

        self.sessions = configure_session_storage(config)

        # retrieve user data from the in-memory variable
        self.user_db = TiedKeyValue()
        # Change the data below to suite your needs during the development.
        # DO NOT USE THIS IN PRODUCTION!
        self.user_db["john"] = {
            "user_id": "john",
            "password": "qwerty",
            "firstname": "John",
            "lastname": "Doe",
            "email": "contact@webtrit.com",
            "status": "active",
            "company_name": "WebTrit, Inc",
            "sip": {
                "username": "12065551234",
                "auth_username": "abc",
                "password": "SlavaUkraini!",
                "display_name": "Heroyam Slava!",
                "sip_server": {"host": "127.0.0.1", "port": 5060},
            },
            "balance": {"amount": 50.00, "balance_type": "prepaid", "currency": "USD"},
            "numbers": {
                "ext": "2719",
                "main": "12065551234",
                "additional": ["380441234567", "34001235678"],
            },
            "time_zone": "Europe/Kyiv",
        }
        
        self.otp_db = TiedKeyValue()

        self.config_token_db = TiedKeyValue()
        # again, just for demo - user's config token is generated as his/her email
        # with characters in reverse order
        for id, user in self.user_db.values():
            self.config_token_db[user.get("email", "")[::-1]] = id
        

    @classmethod
    def name(cls) -> str:
        return "Example BSS adapter"

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
            Capabilities.otpSignin,
            # obtain user's call history
            Capabilities.callHistory,
            # obtain the list of other extensions in the PBX
            Capabilities.extensions,
            # download call recordings - currently not supported
            # Capabilities.recordings
            # create a new user
            Capabilities.signup,
            Capabilities.customMethods,
            Capabilities.autoProvision
        ]


    def retrieve_contacts(self, session: SessionInfo, user: UserInfo) -> List[ContactInfo]:
        """List of other extensions in the PBX"""

        min_contacts = 4
        max_contacts = 10
        statuses = [ SIPRegistrationStatus.registered, SIPRegistrationStatus.notregistered ]
        contacts = [
            ContactInfo(
                firstname=self.fake.random_name(),
                lastname=self.fake.random_lastname(),
                email=self.fake.email(),
                company_name=self.fake.company(),
                numbers=Numbers(
                    main=self.fake.random_phone_number(),
                    ext=str(random.randrange(1000, 2000)),
                    additional=[
                        self.fake.random_phone_number()
                        for i in range(random.randint(0, 3))
                    ],
                ),
                sip_status=self.fake.random_list_member(statuses),
            )
            for n in range(random.randint(min_contacts, max_contacts))
        ]

        return contacts

    def retrieve_calls(self, session: SessionInfo,
                       user: UserInfo,
                       page: int, items_per_page: int,
                       time_from: datetime = None,
                       time_to: datetime = None) -> tuple[list[CDRInfo], int]:
        """Obtain CDRs (call history) of the user"""
        if time_from and time_from < datetime.datetime(2020, 1, 1):
            # return fixed number of calls to test pagination
            calls = 250
        else:
            min_calls = 20
            max_calls = 200
            calls = random.randint(min_calls, max_calls)
        directions = [x.value for x in Direction]
        statuses = [x.value for x in ConnectStatus]
        cdrs = [
                CDRInfo(
                    call_id=str(uuid.uuid1()),
                    recording_id=str(uuid.uuid1()),
                    connect_time=datetime.datetime.now()
                        + datetime.timedelta(
                            minutes=n * 5 + random.randint(1, 5),
                            seconds=random.randint(1, 20),
                        ),
                    callee=self.fake.random_phone_number(),
                    caller=self.fake.random_phone_number(),
                    duration=0 if random.randint(1, 2) == 1 else random.randint(1, 300),
                    direction=self.fake.random_list_member(directions),
                    status=self.fake.random_list_member(statuses),
                    disconnect_reason="Unknown"
                )
                for n in range(calls)
            ]
        return cdrs, len(cdrs)

    # call recording is not supported in this example
    def retrieve_call_recording(
        self, session: SessionInfo, call_recording: str
    ) -> bytes:
        """Get the media file for a previously recorded call."""
        # not yet implemented
        pass

    def signup(self, user_data: dict, tenant_id: str = None):
        """Create a new user as a part of the sign-up process"""
        if isinstance(user_data, dict) \
                and 'user_id' in user_data \
                and 'password' in user_data:
            # add this record to the internal DB
            self.user_db[user_data['user_id']] = user_data
            # and log the user in
            return self.authenticate(user = UserInfo(login=user_data['user_id'],
                                            user_id=user_data['user_id']),
                                    password = user_data['password'])

        raise_webtrit_error(422, error_message = "Wrong data structure")

    
    def delete_user(self, user: UserInfo):
        """Delete an existing user - this functionality is required if the
        app allows sign up"""
        try:
            del self.user_db[user.user_id]
            return {}
        except KeyError:
            raise_webtrit_error(404, error_message = "User not found")

        except Exception as e:
            raise_webtrit_error(500, error_message = f"Application error: {e}")


    def custom_method_public(self,
                        method_name: str,
                        data: CustomRequest,
                        headers: Optional[Dict] = {},
                        extra_path_params: Optional[str] = None,
                        tenant_id: str = None) -> CustomResponse:
        """Custom function"""
        return dict(message = f"You called {method_name} with {data}!")
    
    def custom_method_private(self,
                    session: SessionInfo,
                    user_id: str,
                    method_name: str,
                    data: CustomRequest,
                    headers: Optional[Dict] = {},
                    extra_path_params: Optional[str] = None,
                    tenant_id: str = None) -> CustomResponse:
        """Custom function"""
        return dict(message =
                              f"On behalf of user {user_id} you called {method_name} with {data}!")

    def autoprovision_session(self, config_token: str, tenant_id: str = None) -> SessionInfo:
        """Create a new session based on the config token"""
        # this is of course just for demo purposes - your code should really
        # check the external DB, where the provisioning tokens are stored
        if user_id := self.config_token_db.get(config_token):
            if user := self.user_db.get(user_id):
                # and now we just produce the same result as with "normal" login
                return self.authenticate(user = UserInfo(login=user_id,
                                                user_id=user_id),
                                            password = user.get('password')
                            )

            
        raise_webtrit_error(401, error_message = "Invalid config token")
