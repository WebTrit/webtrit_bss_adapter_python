from enum import Enum


class PortaSwitchSignInCredentialsType(str, Enum):
    SELF_CARE = 'self-care'
    SIP = 'sip'

    @classmethod
    def _missing_(cls, value):
        return cls.SELF_CARE
