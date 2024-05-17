from enum import Enum


class PortaSwitchSignInCredentialsType(str, Enum):
    SELF_CARE = 'self-care'
    SIP = 'sip'

    @classmethod
    def _missing_(cls, value):
        return cls.SELF_CARE


class PortaSwitchContactsSelectingMode(str, Enum):
    ACCOUNTS = 'accounts'
    EXTENSIONS = 'extensions'

    @classmethod
    def _missing_(cls, value):
        return cls.ACCOUNTS


class PortaSwitchExtensionType(str, Enum):
    UNASSIGNED = 'Unassigned'
    ACCOUNT = 'Account'
    GROUP = 'Group'

    @classmethod
    def _missing_(cls, value):
        return cls.UNASSIGNED
