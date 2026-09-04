import json
from typing import Optional, List, Union

from pydantic import field_validator
from pydantic_settings import BaseSettings

from .types import (
    PortaSwitchContactsSelectingMode,
    PortaSwitchExtensionType,
    PortaSwitchSignInCredentialsType,
)


def parse_string_list(value: Union[List, str, int, None]) -> List[str]:
    if not value:
        return []
    if isinstance(value, int):
        return [str(value)]
    if isinstance(value, str):
        return [x.strip() for x in value.split(';') if x.strip()]
    if isinstance(value, list):
        return [str(x).strip() for x in value if str(x).strip()]


class PortaSwitchSettings(BaseSettings):
    ADMIN_API_URL: str
    ADMIN_API_LOGIN: str
    ADMIN_API_TOKEN: str
    ACCOUNT_API_URL: str
    SIP_SERVER_HOST: str = "127.0.0.1"
    SIP_SERVER_PORT: int = 5060
    VERIFY_HTTPS: Optional[bool] = True
    # Per-request timeout (seconds) for outbound PortaSwitch/PortaBilling API calls.
    # Overrides HTTPAPIConnector.DEFAULT_REQUEST_TIMEOUT for PortaSwitch only, so a
    # slow/unresponsive switch can't pin worker threads indefinitely (WT-1717).
    # Configurable via PORTASWITCH_API_TIMEOUT; set empty to keep the base default.
    API_TIMEOUT: Optional[float] = 25
    # httpx connection-pool limits for the async client (WT-1720). This pool — not
    # the old ~40 Starlette thread-pool tokens — is now the real per-pod ceiling on
    # concurrent requests toward the switch. Defaults match httpx's own (100/20):
    # an order of magnitude above the former thread cap, while staying polite to the
    # switch. Raise MAX_CONNECTIONS for a large switch / high Cloud Run concurrency;
    # lower it to protect a small or shared one. Keep MAX_KEEPALIVE_CONNECTIONS
    # <= MAX_CONNECTIONS. Configurable via PORTASWITCH_MAX_CONNECTIONS /
    # PORTASWITCH_MAX_KEEPALIVE_CONNECTIONS.
    MAX_CONNECTIONS: int = 100
    MAX_KEEPALIVE_CONNECTIONS: int = 20
    # Disaster-recovery failover for a geographically dispersed installation
    # (WT-1654). When a standby URL is unset, failover is disabled and behavior
    # is unchanged. On a main-site outage, API traffic fails over to the standby;
    # switch-back uses the operating_mode signal (BA-47641).
    ADMIN_API_URL_STANDBY: Optional[str] = None
    ACCOUNT_API_URL_STANDBY: Optional[str] = None
    # Seconds between out-of-band main-site probes while running on standby.
    SITE_RECHECK_INTERVAL: int = 60
    # Consecutive main-site 'normal' probes required to switch back (hysteresis).
    SITE_SWITCH_BACK_THRESHOLD: int = 2
    SIGNIN_CREDENTIALS: PortaSwitchSignInCredentialsType = PortaSwitchSignInCredentialsType.SELF_CARE
    CONTACTS_SELECTING: PortaSwitchContactsSelectingMode = PortaSwitchContactsSelectingMode.ACCOUNTS
    CONTACTS_SELECTING_EXTENSION_TYPES: Union[List[PortaSwitchExtensionType], str] = list(PortaSwitchExtensionType)
    CONTACTS_SELECTING_CUSTOMER_IDS: Union[List[str], str] = []
    CONTACTS_SKIP_WITHOUT_EXTENSION: bool = False
    CONTACTS_CUSTOM: Union[List[dict], str] = []
    HIDE_BALANCE_IN_USER_INFO: Optional[bool] = False
    SELF_CONFIG_PORTAL_URL: Optional[str] = None
    ALLOWED_ADDONS: Union[List[str], str] = []

    @field_validator("API_TIMEOUT", mode='before')
    @classmethod
    def decode_api_timeout(cls, v: Union[str, float, int, None]) -> Optional[float]:
        # Treat an empty/blank or non-positive value as "unset" so operators can
        # fall back to the base HTTPAPIConnector.DEFAULT_REQUEST_TIMEOUT (e.g.
        # PORTASWITCH_API_TIMEOUT="") and can't accidentally set a 0/negative
        # timeout, which requests treats as fail-immediately rather than "no limit".
        if v is None or (isinstance(v, str) and not v.strip()):
            return None
        try:
            v = float(v)
        except (TypeError, ValueError):
            return None
        return v if v > 0 else None

    @staticmethod
    def _positive_int_or(v: Union[str, int, None], default: int) -> int:
        # Treat blank/invalid/non-positive as "unset" so a stray empty env var
        # (e.g. PORTASWITCH_MAX_CONNECTIONS="") falls back to the safe default.
        if v is None or (isinstance(v, str) and not v.strip()):
            return default
        try:
            iv = int(v)
        except (TypeError, ValueError):
            return default
        return iv if iv > 0 else default

    @field_validator("MAX_CONNECTIONS", mode='before')
    @classmethod
    def decode_max_connections(cls, v: Union[str, int, None]) -> int:
        return cls._positive_int_or(v, 100)

    @field_validator("MAX_KEEPALIVE_CONNECTIONS", mode='before')
    @classmethod
    def decode_max_keepalive_connections(cls, v: Union[str, int, None]) -> int:
        return cls._positive_int_or(v, 20)

    @field_validator("CONTACTS_SELECTING_EXTENSION_TYPES", mode='before')
    @classmethod
    def decode_contacts_selecting_extension_types(cls, v: Union[List, str]) -> List[PortaSwitchExtensionType]:
        if v is None or (isinstance(v, list) and len(v) == 0):
            return list(PortaSwitchExtensionType)

        if isinstance(v, list) and all(isinstance(item, PortaSwitchExtensionType) for item in v):
            return v

        v = str(v)

        if not v or not v.strip():
            return list(PortaSwitchExtensionType)

        parts = [x.strip() for x in v.split(';') if x.strip()]
        if not parts:
            return list(PortaSwitchExtensionType)

        return [PortaSwitchExtensionType(x) for x in parts]

    @field_validator("CONTACTS_SELECTING_CUSTOMER_IDS", mode='before')
    @classmethod
    def decode_contacts_selecting_customer_ids(cls, v: Union[List, str, int, None]) -> List[str]:
        return parse_string_list(v)

    @field_validator("CONTACTS_CUSTOM", mode='before')
    @classmethod
    def decode_contacts_custom(cls, v: Union[List, str]) -> List[dict]:
        if v is None or (isinstance(v, list) and len(v) == 0):
            return []

        # If it's already a list of dicts, return it as-is
        if isinstance(v, list) and all(isinstance(item, dict) for item in v):
            return v

        # If it's a single dict, wrap it in a list
        if isinstance(v, dict):
            return [v]

        v = str(v)

        if not v or not v.strip():
            return []

        parts = [x.strip() for x in v.split(';') if x.strip()]
        if not parts:
            return []

        return [json.loads(x) for x in parts]

    @field_validator("ALLOWED_ADDONS", mode='before')
    @classmethod
    def decode_allowed_addons(cls, v: Union[List, str, int, None]) -> List[str]:
        return parse_string_list(v)

    model_config = {
        "env_prefix": "PORTASWITCH_",
        "env_file_encoding": "utf-8",
        "case_sensitive": False
    }


class OTPSettings(BaseSettings):
    IGNORE_ACCOUNTS: Union[List[str], str] = []
    STORAGE_COLLECTION: Optional[str] = None
    STORAGE_TTL_MINUTES: int = 30

    @field_validator("IGNORE_ACCOUNTS", mode='before')
    @classmethod
    def decode_ignore_accounts(cls, v: Union[List, str, int, None]) -> List[str]:
        return parse_string_list(v)

    model_config = {
        "env_prefix": "OTP_",
        "env_file_encoding": "utf-8",
        "case_sensitive": False
    }


class Settings(BaseSettings):
    JANUS_SIP_FORCE_TCP: bool = False
    ENABLE_ON_DEMAND_SESSION_MIGRATION: bool = False

    PORTASWITCH_SETTINGS: PortaSwitchSettings = PortaSwitchSettings()
    OTP_SETTINGS: OTPSettings = OTPSettings()

    model_config = {
        "env_file_encoding": "utf-8",
        "case_sensitive": False
    }
