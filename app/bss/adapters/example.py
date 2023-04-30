from bss.adapters import BSSAdapterExternalDB
from bss.dbs import TiedKeyValue, FileStoredKeyValue
from bss.types import (Capabilities, UserInfo, EndUser, Contacts, ContactInfo,
                       Calls, CDRInfo, ConnectStatus, SIPStatus, SessionInfo,
                       Numbers)
from typing import List
from bss.sessions import configure_session_storage
from app_config import AppConfig

import uuid
import datetime
import random
import logging
import faker

import re


VERSION = "0.0.1"

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
            "company_name": "WebTrit, Inc",
            "sip": {
                "login": "12065551234",
                "password": "SlavaUkraini!",
                "display_name": "Geroyam Slava!",
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
            # SupportedEnum.recordings
        ]



    def retrieve_contacts(self, session: SessionInfo, user: UserInfo) -> List[ContactInfo]:
        """List of other extensions in the PBX"""

        min_contacts = 4
        max_contacts = 10
        statuses = ["unknown", "registered", "notregistered"]
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
                sip=SIPStatus(
                    display_name=self.fake.name(),
                    status=self.fake.random_list_member(statuses),
                ),
            )
            for n in range(random.randint(min_contacts, max_contacts))
        ]

        return contacts

    def retrieve_calls(self, session: SessionInfo, user: UserInfo, **kwargs) -> Calls:
        """Obtain CDRs (call history) of the user"""
        min_calls = 5
        max_calls = 20
        calls = random.randint(min_calls, max_calls)
        directions = ["incoming", "outgoing"]
        statuses = ["accepted", "declined", "missed", "error"]
        cdrs = {
            "items": [
                CDRInfo(
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
                    disconnected_reason="Unknown"
                )
                for n in range(calls)
            ],
            "pagination": {
                "items_per_page": calls,
                "items_total": calls * random.randint(3, 10),
                "page": random.randint(1, 3),
            },
        }
        return cdrs

    # call recording is not supported in this example
    def retrieve_call_recording(
        self, session: SessionInfo, call_recording: str
    ) -> bytes:
        """Get the media file for a previously recorded call."""
        # not yet implemented
        pass
