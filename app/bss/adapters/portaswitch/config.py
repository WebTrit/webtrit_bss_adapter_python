import json
from typing import Optional, List, Union

from pydantic import BaseSettings, validator

from .types import (
    PortaSwitchContactsSelectingMode,
    PortaSwitchExtensionType,
    PortaSwitchSignInCredentialsType,
)


class PortaSwitchSettings(BaseSettings):
    ADMIN_API_URL: str
    ADMIN_API_LOGIN: str
    ADMIN_API_TOKEN: str
    ACCOUNT_API_URL: str
    SIP_SERVER_HOST: str = "127.0.0.1"
    SIP_SERVER_PORT: int = 5060
    VERIFY_HTTPS: Optional[bool] = True
    SIGNIN_CREDENTIALS: PortaSwitchSignInCredentialsType = PortaSwitchSignInCredentialsType.SELF_CARE
    CONTACTS_SELECTING: PortaSwitchContactsSelectingMode = PortaSwitchContactsSelectingMode.ACCOUNTS
    CONTACTS_SELECTING_EXTENSION_TYPES: Union[List[PortaSwitchExtensionType], str] = list(PortaSwitchExtensionType)
    CONTACTS_SELECTING_CUSTOMER_IDS: Union[List[str], str] = []
    CONTACTS_SKIP_WITHOUT_EXTENSION: bool = False
    CONTACTS_CUSTOM: Union[List[dict], str] = []
    HIDE_BALANCE_IN_USER_INFO: Optional[bool] = False
    SELF_CONFIG_PORTAL_URL: Optional[str] = None
    ALLOWED_ADDONS: Union[List[str], str] = []

    @validator("CONTACTS_SELECTING_EXTENSION_TYPES", pre=True)
    def decode_contacts_selecting_extension_types(cls, v: Union[List, str]) -> List[PortaSwitchExtensionType]:
        return [PortaSwitchExtensionType(x) for x in v.split(';')] if isinstance(v, str) else v

    @validator("CONTACTS_SELECTING_CUSTOMER_IDS", pre=True)
    def decode_contacts_selecting_customer_ids(cls, v: Union[List, str]) -> List[str]:
        if isinstance(v, int):
            v = str(v)

        return [x.strip() for x in v.split(';')] if isinstance(v, str) else v

    @validator("CONTACTS_CUSTOM", pre=True)
    def decode_contacts_custom(cls, v: Union[List, str]) -> List[dict]:
        return [json.loads(x) for x in v.split(';')] if isinstance(v, str) and v else v

    @validator("ALLOWED_ADDONS", pre=True)
    def decode_allowed_addons(cls, v: Union[List, str]) -> List[str]:
        if isinstance(v, int):
            v = str(v)

        return [x.strip() for x in v.split(';')] if isinstance(v, str) else v

    class Config:
        env_prefix = "PORTASWITCH_"
        env_file_encoding = "utf-8"
        case_sensitive = False


class OTPSettings(BaseSettings):
    IGNORE_ACCOUNTS: Union[List[str], str] = []

    @validator("IGNORE_ACCOUNTS", pre=True)
    def decode_ignore_accounts(cls, v: Union[List, str]) -> List[str]:
        if isinstance(v, int):
            v = str(v)

        return [x.strip() for x in v.split(';')] if isinstance(v, str) else v

    class Config:
        env_prefix = "OTP_"
        env_file_encoding = "utf-8"
        case_sensitive = False


class Settings(BaseSettings):
    JANUS_SIP_FORCE_TCP: bool = False

    PORTASWITCH_SETTINGS: PortaSwitchSettings = PortaSwitchSettings()
    OTP_SETTINGS: OTPSettings = OTPSettings()

    class Config:
        env_file_encoding = "utf-8"
        case_sensitive = False
