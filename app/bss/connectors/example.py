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
)

from bss.models import SipStatusSchema as SIPStatus
from bss.models import CDRInfoSchema as CDRInfo
from bss.models import CallInfoSchema as CallInfo
from report_error import WebTritErrorException
import threading
import uuid
import datetime
import random
import logging
import faker

import re
import os
from dataclasses import dataclass

VERSION = "0.0.1"

# otherwise it produces annoying messages about locale
# when the app log level is set to DEBUG
logging.getLogger("faker.factory").setLevel(logging.ERROR)


@dataclass
class OTP:
    """One-time password for user authentication"""
    otp_expected_code: str
    user_id: str
    expires_at: datetime


class InMemorySessionStorage(SessionStorage):
    """Store sessions in a class variable. Suitable only
    for demo / development. Implement a real persistent
    session storage for your application using something like
    memcached."""

    fake_session_db: dict = {}

    def __init__(self, config):
        """Initialize the object and set storage to be in-memory"""
        super().__init__(config)
        self.sessions = InMemorySessionStorage.fake_session_db


class MadeUpThings(faker.Faker):
    """Auto-generate names, phone numbers, etc. for demo purposes"""

    # def __init__(self):
    #     pass

    def random_phone_number(self) -> str:
        return re.sub(r"\D", "", self.phone_number())

    def random_name(self) -> str:
        return self.name().partition(" ")[0]

    def random_lastname(self) -> str:
        return self.name().partition(" ")[2]

    def random_list_member(self, x: list):
        return x[random.randint(0, len(x) - 1)]


class ExampleBSSConnector(BSSConnector):
    """Supply to WebTrit core the required information about
    VoIP users using a built-in list of users. Suitable
    for development / testing"""

    # Change the data below to suite your needs during the development.
    # DO NOT USE THIS IN PRODUCTION!

    fake_user_db: dict = {
        "john": {
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
    }
    otp_db_lock = threading.Lock()
    fake_otp_db: dict = {}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # for generation of fake names, etc.
        self.fake = MadeUpThings()
        # store sessions in a global variable
        self.storage = InMemorySessionStorage(config = self.config)

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
        return "Example BSS connector"

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

    def authenticate(self, user_id: str, password: str = None) -> SessionInfo:
        """Authenticate user with username and password and obtain an API token for
        further requests."""

        user = ExampleBSSConnector.fake_user_db.get(user_id, None)
        if user:
            if user["password"] == password:
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

    def generate_otp(self, user_id: str) -> OtpCreateResponseSchema:
        """Request that the remote hosted PBX system / BSS generates a new
        one-time-password (OTP) and sends it to the user via the
        configured communication channel (e.g. SMS)"""

        # the code that the user should provide to prove that
        # he/she is who he/she claims to be
        code = random.randrange(100000, 999999)
        code_for_tests = os.environ.get("PERMANENT_OTP_CODE", None)
        if code_for_tests:
            # while running automated tests, we have to produce the
            # same OTP as configured in the test suite. make sure
            # this env var is NOT set in production!
            code = int(code_for_tests)
        # so we can see it and use during debug
        logging.info(f"OTP code {code}")

        otp_id = str(uuid.uuid1())

        otp = OTP(
            user_id=user_id,
            otp_expected_code="{:06d}".format(code),
            expires_at=datetime.datetime.now() + datetime.timedelta(minutes=10),
        )
        # memorize it
        with ExampleBSSConnector.otp_db_lock:
            ExampleBSSConnector.fake_otp_db[otp_id] = otp

        return OtpCreateResponseSchema(
            # OTP sender's address so the user can find it easier
            otp_sent_from="sample@webtrit.com",
            otp_id=otp_id,
            otp_sent_type=OtpSentType.email,
        )

    def validate_otp(self, otp: OtpVerifyRequestSchema) -> SessionInfo:
        """Verify that the OTP code, provided by the user, is correct."""

        otp_id = otp.otp_id.__root__
        original = ExampleBSSConnector.fake_otp_db.get(otp_id, None)
        if not original:
            raise WebTritErrorException(
                status_code=401,
                code=42,
                error_message="Invalid OTP ID",
            )

        if original.expires_at < datetime.datetime.now():
            raise WebTritErrorException(
                status_code=419,
                code=42,
                error_message="OTP has expired",
            )

        if original.otp_expected_code != otp.code:
            raise WebTritErrorException(
                status_code=401,
                code=42,
                error_message="Invalid OTP",
            )

        # everything is in order, create a session
        session = self.create_session(original.user_id)
        self.storage.store_session(session)
        return session

    def validate_session(self, access_token: str) -> SessionInfo:
        """Validate that the supplied API token is still valid."""

        session = self.storage.get_session(access_token=access_token)

        if session:
            if not session.still_active():
                # remove it from the DB
                self.storage.delete_session(
                    access_token=access_token, refresh_token=session.refresh_token
                )
                # raise an error
                raise WebTritErrorException(
                    status_code=401,
                    code=42,
                    error_message="Access token expired",
                )

            return session

        raise WebTritErrorException(
            status_code=401,
            code=42,
            error_message="Invalid access token",
        )

    def refresh_session(self, user_id: str, refresh_token: str) -> SessionInfo:
        """Extend the API session be exchanging the refresh token for
        a new API access token."""
        session = self.storage.get_session(refresh_token=refresh_token)
        if not session:
            raise WebTritErrorException(
                status_code=401,
                code=42,
                error_message="Invalid refresh token",
            )
        # everything is in order, create a new session
        session = self.create_session(user_id)
        self.storage.store_session(session)
        return session

    def close_session(self, access_token: str) -> bool:
        """Close the API session and logout the user."""
        session = self.storage.get_session(access_token)
        if session:
            return self.storage.delete_session(access_token)

        raise WebTritErrorException(
            status_code=401,
            code=42,
            error_message="Error closing the session",
        )

    def retrieve_user(self, session: SessionInfo, user_id: str) -> EndUser:
        """Obtain user's information - most importantly, his/her SIP credentials."""

        user = ExampleBSSConnector.fake_user_db.get(user_id, None)
        if user:
            return EndUser(**user)

        # no such session
        raise WebTritErrorException(
            status_code=404, code=42, error_message="User not found"
        )

    def retrieve_contacts(self, session: SessionInfo, user_id: str) -> Contacts:
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
                numbers=NumbersSchema(
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

    def retrieve_calls(self, session: SessionInfo, user_id: str, **kwargs) -> Calls:
        """Obtain CDRs (call history) of the user"""
        min_calls = 5
        max_calls = 20
        calls = random.randint(min_calls, max_calls)
        directions = ["incoming", "outgoing"]
        statuses = ["accepted", "declined", "missed", "error"]
        cdrs = {
            "items": [
                CDRInfo(
                    call_recording_id=str(uuid.uuid1()),
                    call_start_time=datetime.datetime.now()
                    + datetime.timedelta(
                        minutes=n * 5 + random.randint(1, 5),
                        seconds=random.randint(1, 20),
                    ),
                    callee=self.fake.random_phone_number(),
                    caller=self.fake.random_phone_number(),
                    duration=0 if random.randint(1, 2) == 1 else random.randint(1, 300),
                    call=CallInfo(
                        direction=self.fake.random_list_member(directions),
                        status=self.fake.random_list_member(statuses),
                    ),
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
