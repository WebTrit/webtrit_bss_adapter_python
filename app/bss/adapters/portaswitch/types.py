from enum import Enum
from typing import Optional

from bss.http_api import APIUser


class PortaSwitchAdminUser(APIUser):
    token: Optional[str] = None


class PortaSwitchSignInCredentialsType(Enum):
    SELF_CARE = "self-care"
    SIP = "sip"

    @classmethod
    def _missing_(cls, value):
        return cls.SELF_CARE


class PortaSwitchContactsSelectingMode(Enum):
    ACCOUNTS = "accounts"
    EXTENSIONS = "extensions"
    PHONEBOOK = "phonebook"
    PHONE_DIRECTORY = "phone_directory"

    @classmethod
    def _missing_(cls, value):
        return cls.ACCOUNTS


class PortaSwitchExtensionType(Enum):
    UNASSIGNED = "Unassigned"
    ACCOUNT = "Account"
    GROUP = "Group"

    @classmethod
    def _missing_(cls, value):
        return cls.UNASSIGNED


class PortaSwitchDualVersionSystem(Enum):
    UNSPECIFIED = None
    SOURCE = "source"
    TARGET = "target"

    @classmethod
    def _missing_(cls, value):
        return cls.UNSPECIFIED


class PortaSwitchMailboxMessageFlag(Enum):
    SEEN = "Seen"
    ANSWERED = "Answered"
    FLAGGED = "Flagged"


class PortaSwitchMailboxMessageFlagAction(Enum):
    SET = "set_flag"
    UNSET = "remove_flag"


class PortaSwitchMailboxMessageAttachmentFormat(Enum):
    WAV = "wav"
    MP3 = "mp3"
    AU = "au"

    @classmethod
    def has_value(cls, value):
        return value in cls._value2member_map_
