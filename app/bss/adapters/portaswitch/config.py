from typing import Optional

from pydantic import BaseSettings

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
    CONTACTS_SELECTING_EXTENSION_TYPES: list[PortaSwitchExtensionType] = list(PortaSwitchExtensionType)
    CONTACTS_SKIP_WITHOUT_EXTENSION: bool = False
    HIDE_BALANCE_IN_USER_INFO: Optional[bool] = False
    SELF_CONFIG_PORTAL_URL: Optional[str] = None

    class Config:
        env_prefix = "PORTASWITCH_"
        env_file_encoding = "utf-8"
        case_sensitive = False


class OTPSettings(BaseSettings):
    IGNORE_ACCOUNTS: list[str] = []

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
