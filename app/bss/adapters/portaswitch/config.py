import json
from typing import Optional, List, Union

from pydantic import field_validator
from pydantic_settings import BaseSettings

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
    CONTACTS_SELECTING_PHONEBOOK_CUSTOMER_IDS: Union[List[str], str] = []
    CONTACTS_SKIP_WITHOUT_EXTENSION: bool = False
    CONTACTS_CUSTOM: Union[List[dict], str] = []
    HIDE_BALANCE_IN_USER_INFO: Optional[bool] = False
    SELF_CONFIG_PORTAL_URL: Optional[str] = None
    ALLOWED_ADDONS: Union[List[str], str] = []

    @field_validator("CONTACTS_SELECTING_EXTENSION_TYPES", mode='before')
    @classmethod
    def decode_contacts_selecting_extension_types(cls, v: Union[List, str]) -> List[PortaSwitchExtensionType]:
        return [PortaSwitchExtensionType(x) for x in v.split(';')] if isinstance(v, str) else v

    @field_validator("CONTACTS_SELECTING_PHONEBOOK_CUSTOMER_IDS", mode='before')
    @classmethod
    def decode_contacts_selecting_phonebook_customer_ids(cls, v: Union[List, str]) -> List[str]:
        return [x.strip() for x in v.split(';')] if isinstance(v, str) else v

    @field_validator("CONTACTS_CUSTOM", mode='before')
    @classmethod
    def decode_contacts_custom(cls, v: Union[List, str]) -> List[dict]:
        return [json.loads(x) for x in v.split(';')] if isinstance(v, str) and v else v

    @field_validator("ALLOWED_ADDONS", mode='before')
    def decode_allowed_addons(cls, v: Union[List, str]) -> List[str]:
        return [x.strip() for x in v.split(';')] if isinstance(v, str) and v else v

    model_config = {
        "env_prefix": "PORTASWITCH_",
        "env_file_encoding": "utf-8",
        "case_sensitive": False
    }


class OTPSettings(BaseSettings):
    IGNORE_ACCOUNTS: Union[List[str], str] = []

    @field_validator("IGNORE_ACCOUNTS", mode='before')
    @classmethod
    def decode_ignore_accounts(cls, v: str) -> List[str]:
        return [str(x) for x in v.split(';')] if isinstance(v, str) else v

    model_config = {
        "env_prefix": "OTP_",
        "env_file_encoding": "utf-8",
        "case_sensitive": False
    }


class Settings(BaseSettings):
    JANUS_SIP_FORCE_TCP: bool = False

    PORTASWITCH_SETTINGS: PortaSwitchSettings = PortaSwitchSettings()
    OTP_SETTINGS: OTPSettings = OTPSettings()

    model_config = {
        "env_file_encoding": "utf-8",
        "case_sensitive": False
    }
