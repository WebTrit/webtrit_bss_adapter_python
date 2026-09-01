import asyncio
import logging
import re
import uuid
from inspect import isawaitable
from datetime import datetime, timedelta, UTC
from typing import AsyncIterator, Awaitable, Callable, Final, Optional, Dict, List

import urllib3
from jose.exceptions import ExpiredSignatureError, JWTError

from app_config import AppConfig
from bss.adapters import BSSAdapter
from bss.models import (
    DeliveryChannel,
    SipServer,
    CustomRequest,
    CustomResponse,
    CustomPage,
    UserId,
    OtpId,
    AccessToken, SessionResponse,
)
from bss.types import (
    CallRecordingId,
    Capabilities,
    CDRInfo,
    ContactInfo,
    EndUser,
    OTPCreateResponse,
    OTPVerifyRequest,
    SessionInfo,
    UserInfo,
    safely_extract_scalar_value,
    UserVoicemailsResponse,
    UserVoicemailMessagePatch,
    VoicemailMessageDetails,
    UserEventGroup,
    UserEventType,
)
from localization import get_translation_func
from report_error import WebTritErrorException
from .api import AccountAPI, AdminAPI
from .config import Settings
from .failover import SiteState
from .exceptions import (
    method_not_found_error,
    external_api_issue_error,
    not_found_user_error,
    not_found_otp_code_error,
    not_found_contact_error,
    not_found_recording_error,
    incorrect_credentials_error,
    user_authentication_error,
    delivery_channel_unspecified_error,
    password_change_required_error,
    access_token_expired_error,
    access_token_invalid_error,
    unsupported_file_format_error,
    missing_tokens_error,
    session_close_error,
    refresh_token_invalid_error,
    addon_required_error,
    session_upgrade_needed_error,
    voicemail_not_configured,
)
from .serializer import Serializer
from .types import (
    PortaSwitchSignInCredentialsType,
    PortaSwitchContactsSelectingMode,
    PortaSwitchDualVersionSystem,
    PortaSwitchMailboxMessageFlag,
    PortaSwitchMailboxMessageFlagAction,
    PortaSwitchMailboxMessageAttachmentFormat,
)
from .otp_storage import configure_otp_storage
from .utils import generate_otp_id, extract_fault_code, generate_hash_dictionary, encrypt_secret, decrypt_secret

PORTASWITCH_VERSION_WITH_TOKEN: Final[str] = "MR128"

#: Default fan-out concurrency for parallel PortaSwitch API calls (replaces the
#: former ThreadPoolExecutor(max_workers=10) pools). WT-1720.
FANOUT_LIMIT: Final[int] = 10


async def _gather_limited(coros: List[Awaitable], limit: int = FANOUT_LIMIT,
                          return_exceptions: bool = False) -> list:
    """Run the given coroutines concurrently, capped at `limit` in flight.

    Async replacement for ThreadPoolExecutor(max_workers=limit) + executor.map.
    A FRESH semaphore is created per call, so nested fan-outs (e.g.
    _get_all_accounts_by_customer invoked inside another fan-out) each get their
    own budget and cannot dead-lock each other on a shared global semaphore.
    Result order matches input order (like executor.map / asyncio.gather).
    """
    if not coros:
        return []
    sem = asyncio.Semaphore(limit)

    async def _guard(coro: Awaitable):
        async with sem:
            return await coro

    return await asyncio.gather(*(_guard(c) for c in coros), return_exceptions=return_exceptions)


class PortaSwitchAdapter(BSSAdapter):
    """Bridges WebTrit Core with PortaSwitch APIs.

    Provides authentication (password, OTP, auto-provision), session lifecycle management,
    SIP credential retrieval, contacts, call history, voicemail, notifications, and other
    capabilities required by WebTrit clients.
    """

    VERSION: Final[str] = "1.1.1"
    OTP_DELIVERY_CHANNEL: Final[DeliveryChannel] = DeliveryChannel.email
    OTP_LOGIN_IDENTIFIERS = ('phone_number',)
    CAPABILITIES: Final[Capabilities] = [
        Capabilities.signup,
        Capabilities.otpSignin,
        Capabilities.passwordSignin,
        Capabilities.recordings,
        Capabilities.callHistory,
        Capabilities.extensions,
        Capabilities.voicemail,
        Capabilities.customMethods,
        Capabilities.internal_messaging,
        Capabilities.sms_messaging,
        Capabilities.notifications,
        Capabilities.notifications_push,
        Capabilities.sip_presence,
        Capabilities.sip_dialogs
    ]

    def __init__(self, config: AppConfig):
        super().__init__(config)

        self._settings = Settings()
        self._portaswitch_settings = self._settings.PORTASWITCH_SETTINGS
        self._otp_settings = self._settings.OTP_SETTINGS

        if not self._portaswitch_settings.VERIFY_HTTPS:
            # HTTPS verification is intentionally disabled (e.g. self-signed PortaBilling
            # cert); silence urllib3's per-request InsecureRequestWarning to avoid log spam.
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        # Disaster-recovery failover (WT-1654): a single active-site tracker shared
        # by both connectors (both sites fail and recover together). Enabled only
        # when BOTH standby URLs are set — a partial config would flip the shared
        # state to standby while the un-configured realm kept hitting the dead
        # main, reintroducing the very timeouts this feature removes.
        admin_standby = self._portaswitch_settings.ADMIN_API_URL_STANDBY
        account_standby = self._portaswitch_settings.ACCOUNT_API_URL_STANDBY
        site_state = None
        if admin_standby and account_standby:
            site_state = SiteState(
                recheck_interval=self._portaswitch_settings.SITE_RECHECK_INTERVAL,
                switch_back_threshold=self._portaswitch_settings.SITE_SWITCH_BACK_THRESHOLD,
            )
        elif admin_standby or account_standby:
            logging.warning(
                "PortaSwitch DR: only one of ADMIN_API_URL_STANDBY / ACCOUNT_API_URL_STANDBY "
                "is set; DR failover is disabled. Set both (same secondary site) to enable it."
            )

        self._admin_api = AdminAPI(self._portaswitch_settings, site_state=site_state)
        self._account_api = AccountAPI(self._portaswitch_settings, site_state=site_state)

        if site_state is not None:
            # Out-of-band switch-back probe: read the main site's operating_mode
            # (BA-47641) via the admin connector, without touching live traffic.
            site_state.set_probe(
                lambda: self._admin_api.get_operating_mode(self._portaswitch_settings.ADMIN_API_URL)
            )
        self._sip_server = SipServer(
            host=self._portaswitch_settings.SIP_SERVER_HOST, port=self._portaswitch_settings.SIP_SERVER_PORT
        )

        self._otp_storage = configure_otp_storage(self._otp_settings)
        self._cached_capabilities = self.calculate_capabilities()
        self._hash_dictionary = generate_hash_dictionary() if self._settings.ENABLE_ON_DEMAND_SESSION_MIGRATION else {}

    @classmethod
    def name(cls) -> str:
        """Returns the name of the adapter."""
        return cls.__name__

    @classmethod
    def version(cls) -> str:
        """Returns the version of the adapter."""
        return cls.VERSION

    def get_capabilities(self) -> list[Capabilities]:
        """Returns the capabilities of this API adapter."""
        return self._cached_capabilities

    async def authenticate(self, user: UserInfo, password: str = None) -> SessionInfo:
        """Authenticate a PortaSwitch account with login and password.

        Parameters:
            user (UserInfo): The information about the account to be logged in.
            password (str): The password of the account to be verified.

        Returns:
            SessionInfo: The object with the obtained session tokens and expiration information.

        Raises:
            WebTritErrorException: If authentication fails or the account is not authorized.
        """
        try:
            is_sip_credentials = self._portaswitch_settings.SIGNIN_CREDENTIALS == PortaSwitchSignInCredentialsType.SIP
            login_attr = "id" if is_sip_credentials else "login"
            password_attr = "h323_password" if is_sip_credentials else "password"

            account_info = (await self._admin_api.get_account_info(**{login_attr: user.login})).get("account_info")

            # If the provided identifier refers to an alias, resolve to the master account
            if account_info and (master_id := account_info.get("i_master_account")):
                account_info = (await self._admin_api.get_account_info(i_account=master_id)).get("account_info")

            if not account_info or account_info[password_attr] != password:
                raise incorrect_credentials_error()

            if self._portaswitch_settings.ALLOWED_ADDONS:
                self._check_allowed_addons(account_info)

            if await self._is_portaswitch_version_with_token():
                token = await self._get_or_create_api_token(account_info)
                if token:
                    session_data = await self._account_api.login(account_info["login"], token=token)
                else:
                    session_data = await self._account_api.login(account_info["login"], account_info["password"])
            else:
                session_data = await self._account_api.login(account_info["login"], account_info["password"], token=account_info["password"])

            return SessionInfo(
                user_id=UserId(str(account_info["i_account"])),
                access_token=AccessToken(session_data["access_token"]),
                refresh_token=session_data["refresh_token"],
                expires_at=datetime.now() + timedelta(seconds=session_data["expires_in"]),
            )

        except WebTritErrorException as error:
            fault_code = extract_fault_code(error)
            if fault_code in (
                    "Server.Session.auth_failed",
                    "Server.Session.cannot_login_brute_force_activity",
                    "Client.Session.check_auth.failed_to_process_access_token",
            ):
                raise user_authentication_error()

            raise error

    async def generate_otp(self, user: UserInfo) -> OTPCreateResponse:
        """Requests PortaSwitch to generate and send an OTP code to the user.

        Parameters:
            user (UserInfo): The object containing the user identifier.

        Returns:
            OTPCreateResponse: Information about the created OTP, including the OTP ID,
                delivery channel, and sender address.

        Raises:
            WebTritErrorException: If the account is not found, a delivery channel is unspecified,
                or OTP generation fails.
        """
        try:
            account_info = (await self._admin_api.get_account_info(id=user.user_id)).get("account_info")
            if not account_info:
                raise not_found_user_error(user.user_id)

            if self._portaswitch_settings.ALLOWED_ADDONS:
                self._check_allowed_addons(account_info)

            i_account = account_info.get("i_master_account", account_info["i_account"])
            success: int = (await self._admin_api.create_otp(i_account, self.OTP_DELIVERY_CHANNEL))["success"]
            if not success:
                raise external_api_issue_error()

            otp_id: str = generate_otp_id()
            # WT-1686: remember the admin session that created this OTP so that
            # verification can run under the same PortaSwitch session even when a
            # different adapter replica handles otp-verify. The session token is
            # encrypted at rest (key derived from ADMIN_API_TOKEN).
            bss_token = self._admin_api.current_access_token()
            stored_token = encrypt_secret(bss_token, self._portaswitch_settings.ADMIN_API_TOKEN) if bss_token else None
            # OTP storage may be Firestore-backed (blocking I/O) — keep it off the loop.
            await asyncio.to_thread(self._otp_storage.store, otp_id, i_account, user.user_id, stored_token)

            env_info = await self._admin_api.get_env_info()

            return OTPCreateResponse(
                otp_id=OtpId(otp_id), delivery_channel=self.OTP_DELIVERY_CHANNEL, delivery_from=env_info.get("email")
            )

        except WebTritErrorException as error:
            fault_code = extract_fault_code(error)
            if fault_code in ("Server.AccessControl.empty_rec_and_bcc",):
                raise delivery_channel_unspecified_error()

            raise error

    async def validate_otp(self, otp: OTPVerifyRequest) -> SessionInfo:
        """Validates the OTP code provided by the user and creates a session.

        Parameters:
            otp (OTPVerifyRequest): The object containing the OTP token to be verified.

        Returns:
            SessionInfo: Session information including access token, refresh token, and user ID.

        Raises:
            WebTritErrorException: If the OTP code is invalid or expired, or if authentication fails.
        """
        try:
            # PortaSwitch API does not operate with otp_id.
            # We need the otp_id only for storing the i_account.
            otp_id = safely_extract_scalar_value(otp.otp_id)

            i_account, user_ref, stored_token = await asyncio.to_thread(self._otp_storage.retrieve, otp_id)
            if not i_account:
                raise not_found_otp_code_error(otp.code)

            # WT-1686: verify under the same PortaSwitch admin session that
            # created the OTP (decrypted from storage), so verification succeeds
            # regardless of which replica handles this request.
            bss_token = decrypt_secret(stored_token, self._portaswitch_settings.ADMIN_API_TOKEN) if stored_token else None
            data: dict = await self._admin_api.verify_otp(otp_token=otp.code, bss_token=bss_token)
            if user_ref not in self._otp_settings.IGNORE_ACCOUNTS and not data["success"]:
                raise not_found_otp_code_error(otp.code)

            await asyncio.to_thread(self._otp_storage.delete, otp_id)

            i_account = str(i_account)
            session_data = await self._emulate_account_login(i_account)

            return SessionInfo(
                user_id=UserId(i_account),
                access_token=session_data["access_token"],
                refresh_token=session_data["refresh_token"],
                expires_at=datetime.now() + timedelta(seconds=session_data["expires_in"]),
            )

        except WebTritErrorException as error:
            fault_code = extract_fault_code(error)
            if fault_code in ("Server.Session.alert_You_must_change_password",):
                raise password_change_required_error()

            raise error

    async def validate_session(self, access_token: str) -> SessionInfo:
        """Validates whether the provided access token is still valid.

        Parameters:
            access_token (str): The token used to access PortaSwitch API.

        Returns:
            SessionInfo: The object containing the validated session information.

        Raises:
            WebTritErrorException: If the token is invalid, expired, or cannot be verified.
        """
        try:
            data = self._account_api.decode_and_verify_access_token_expiration(access_token)
        except ExpiredSignatureError:
            raise access_token_expired_error()
        except JWTError:
            if self._settings.ENABLE_ON_DEMAND_SESSION_MIGRATION:
                raise session_upgrade_needed_error()
            raise access_token_invalid_error()

        user_id = data.get("i_account")
        if user_id is None:
            # Tokens minted via Session/login_to_realm (e.g. an embedded page
            # logging the account in through the admin realm) carry no i_account
            # claim, so the JWT alone cannot identify the session owner. Resolve
            # it server-side via Session/ping, as pre-1.x versions did (WT-1900).
            try:
                session_data = await self._account_api.ping(access_token=access_token)
            except WebTritErrorException as error:
                if extract_fault_code(error) == "Client.Session.ping.failed_to_process_access_token":
                    raise access_token_invalid_error()

                raise error

            user_id = session_data.get("user_id")
            if not user_id:
                raise access_token_invalid_error()

        return SessionInfo(user_id=UserId(str(user_id)), access_token=AccessToken(access_token))

    async def refresh_session(self, refresh_token: str) -> SessionInfo:
        """Refreshes the PortaSwitch account session.

        Parameters:
            refresh_token (str): The token used to refresh the session or hashed i_account in case of on-demand session migration

        Returns:
            (SessionInfo): The object with the obtained session tokens.

        """
        try:

            if self._settings.ENABLE_ON_DEMAND_SESSION_MIGRATION and refresh_token.isdigit():
                # On-demand session migration is enabled. We need to emulate account login to get a new access token
                i_account = self._hash_dictionary.get(refresh_token, refresh_token)
                logging.info(f"On-demand session migration is enabled. Trying to emulate {i_account} account login")
                session_data = await self._emulate_account_login(str(i_account))
            else:
                session_data = await self._account_api.refresh(refresh_token)

            access_token: str = session_data["access_token"]
            account_info: dict = (await self._account_api.get_account_info(access_token=access_token))["account_info"]

            return SessionInfo(
                user_id=UserId(str(account_info["i_account"])),
                access_token=session_data["access_token"],
                refresh_token=session_data["refresh_token"],
                expires_at=datetime.now() + timedelta(seconds=session_data["expires_in"]),
            )

        except WebTritErrorException as error:
            fault_code = extract_fault_code(error)
            if fault_code in (
                    "Server.Session.refresh_access_token.refresh_failed",
                    "Client.Session.check_auth.failed_to_process_access_token",
            ):
                raise refresh_token_invalid_error()

            raise error

    async def close_session(self, access_token: str) -> bool:
        """Closes the PortaSwitch account session.

        Parameters:
            access_token (str): The token used to close the session.

        Returns:
            bool: True if the session was successfully closed, False otherwise.

        Raises:
            WebTritErrorException: If the session is not found or cannot be closed.
        """
        try:
            return (await self._account_api.logout(access_token=access_token))["success"] == 1

        except WebTritErrorException as error:
            fault_code = extract_fault_code(error)
            if fault_code in ("Client.Session.logout.failed_to_process_access_token",):
                raise session_close_error()

            raise error

    async def retrieve_user(self, session: SessionInfo, user: UserInfo) -> EndUser:
        """Returns information about the PortaSwitch account in WebTrit representation.

        Parameters:
            session (SessionInfo): The session of the PortaSwitch account.
            user (UserInfo): The information about the PortaSwitch account.

        Returns:
            EndUser: Fetched information about the PortaSwitch account including SIP credentials,
                aliases, and balance information.

        Raises:
            WebTritErrorException: If the user is not found or the session is invalid.
        """
        try:
            access_token = safely_extract_scalar_value(session.access_token)
            # Two independent read calls — fetch them concurrently on the loop.
            account_info_resp, alias_resp = await asyncio.gather(
                self._account_api.get_account_info(access_token=access_token),
                self._account_api.get_alias_list(access_token=access_token),
            )
            account_info: dict = account_info_resp["account_info"]
            aliases: list = alias_resp["alias_list"]

            return Serializer.get_end_user(
                account_info,
                aliases,
                self._sip_server,
                self._portaswitch_settings.HIDE_BALANCE_IN_USER_INFO,
                self._settings.JANUS_SIP_FORCE_TCP,
            )

        except WebTritErrorException as error:
            fault_code = extract_fault_code(error)
            if fault_code in ("Client.Session.check_auth.failed_to_process_access_token",):
                raise access_token_expired_error()

            raise error

    async def retrieve_contacts(self, session: SessionInfo, user: UserInfo) -> list[ContactInfo]:
        """Returns information about contacts based on the configured selection mode.

        Supports multiple selection modes: EXTENSIONS, ACCOUNTS, PHONEBOOK, or PHONE_DIRECTORY.

        Parameters:
            session (SessionInfo): The session of the PortaSwitch account.
            user (UserInfo): The information about the PortaSwitch account.

        Returns:
            list[ContactInfo]: List of contacts in WebTrit representation, including custom entries
                if configured.

        Raises:
            WebTritErrorException: If the user is not found or the session is invalid.
        """
        try:
            access_token = safely_extract_scalar_value(session.access_token)
            account_info = (await self._account_api.get_account_info(access_token))["account_info"]
            i_customer = int(account_info["i_customer"])
            i_account = int(account_info["i_account"])
            main_i_customer, all_i_customers = await self._get_office_customer_ids(i_customer)
            is_hierarchy = len(all_i_customers) > 1

            contacts = []
            match self._portaswitch_settings.CONTACTS_SELECTING:
                case PortaSwitchContactsSelectingMode.EXTENSIONS:
                    allowed_ext_types = {
                        type.value for type in
                        self._portaswitch_settings.CONTACTS_SELECTING_EXTENSION_TYPES
                    }
                    accounts_per_customer = await _gather_limited(
                        [self._get_all_accounts_by_customer(c) for c in all_i_customers]
                    )
                    accounts = [acc for accs in accounts_per_customer for acc in accs]
                    account_to_aliases = {account["i_account"]: account.get("alias_list", []) for account in accounts}
                    extensions = (await self._admin_api.get_extensions_list(
                        main_i_customer, get_main_office_extensions=is_hierarchy
                    ))["extensions_list"]

                    for ext in extensions:
                        if ext["type"] in allowed_ext_types and ext.get("i_account") != i_account:
                            aliases = account_to_aliases.get(ext.get("i_account"), [])
                            contacts.append(Serializer.get_contact_info_by_extension(ext, aliases, i_account))
                case PortaSwitchContactsSelectingMode.ACCOUNTS:
                    # Fetch accounts from all offices in the hierarchy
                    accounts_per_customer = await _gather_limited(
                        [self._get_all_accounts_by_customer(c) for c in all_i_customers]
                    )
                    accounts = [acc for accs in accounts_per_customer for acc in accs]

                    # When filtering by extension and in a hierarchy, use the unified extensions list
                    # (get_main_office_extensions returns extensions across all offices) as the filter
                    extension_i_accounts: set[int] = set()
                    if self._portaswitch_settings.CONTACTS_SKIP_WITHOUT_EXTENSION and is_hierarchy:
                        ext_list = (await self._admin_api.get_extensions_list(
                            main_i_customer, get_main_office_extensions=True
                        ))["extensions_list"]
                        extension_i_accounts = {ext["i_account"] for ext in ext_list if ext.get("i_account")}

                    for account in accounts:
                        if (status := account.get("status")) and status == "blocked":
                            continue
                        dual_version_system = PortaSwitchDualVersionSystem(account.get("dual_version_system"))
                        if dual_version_system != PortaSwitchDualVersionSystem.SOURCE:
                            has_extension = account.get("extension_id") or (
                                is_hierarchy and account["i_account"] in extension_i_accounts
                            )
                            if (not self._portaswitch_settings.CONTACTS_SKIP_WITHOUT_EXTENSION or has_extension) \
                                    and account["i_account"] != i_account:
                                contacts.append(Serializer.get_contact_info_by_account(account, i_account))
                case PortaSwitchContactsSelectingMode.PHONEBOOK:
                    phonebook = []
                    pb_page = 1
                    PHONEBOOK_BATCH = 1000
                    while True:
                        batch = (await self._account_api.get_phonebook_list(
                            access_token, pb_page, PHONEBOOK_BATCH
                        )).get('phonebook_rec_list', [])
                        phonebook.extend(batch)
                        if len(batch) < PHONEBOOK_BATCH:
                            break
                        pb_page += 1

                    # Extract phone numbers from phonebook records
                    phonebook_numbers = set()
                    for record in phonebook:
                        phone_number = record.get("phone_number", "").replace("+", "")
                        if phone_number:
                            phonebook_numbers.add(phone_number)

                    # Get account mapping only for phonebook numbers (on-demand)
                    number_to_accounts = await self._get_number_to_customer_accounts_map_for_numbers(phonebook_numbers)

                    for record in phonebook:
                        # Normalize phone number by removing the '+' prefix
                        phonebook_record_number = record.get("phone_number").replace("+", "")
                        phonebook_contact_info = Serializer.get_contact_info_by_phonebook_record(record)

                        if account := number_to_accounts.get(phonebook_record_number):
                            # If we found a matching account, use its contact info but update with phonebook data
                            contact = Serializer.get_contact_info_by_account(account, i_account)
                            contact.alias_name = phonebook_contact_info.alias_name
                            contact.numbers.main = phonebook_record_number
                        else:
                            # No matching account found, use phonebook contact info as is
                            contact = phonebook_contact_info
                            if contact.numbers.main:
                                contact.numbers.main = contact.numbers.main.replace("+", "")

                        if contact.is_current_user is not True:
                            contacts.append(contact)

                case PortaSwitchContactsSelectingMode.PHONE_DIRECTORY:
                    phone_directories = (await self._account_api.get_phone_directory_list(access_token, 1, 100))[
                        'phone_directory_list']

                    # Fetch each directory once, collect phone numbers and cache results
                    phone_directory_numbers = set()
                    fetched_directory_infos = {}
                    for directory in phone_directories:
                        directory_info = (await self._account_api.get_phone_directory_info(
                            access_token,
                            directory['i_ua_config_directory'],
                            1,
                            10_000
                        ))['phone_directory_info']
                        fetched_directory_infos[directory['i_ua_config_directory']] = directory_info
                        for record in directory_info['directory_records']:
                            office_number = record.get("office_number", "").replace("+", "")
                            if office_number:
                                phone_directory_numbers.add(office_number)

                    # Get account mapping only for phone directory numbers (on-demand)
                    number_to_accounts = await self._get_number_to_customer_accounts_map_for_numbers(phone_directory_numbers)

                    for directory in phone_directories:
                        directory_info = fetched_directory_infos[directory['i_ua_config_directory']]
                        for record in directory_info['directory_records']:
                            # Normalize phone number by removing the '+' prefix
                            phone_directory_record_number = record.get("office_number").replace("+", "")
                            phone_directory_contact_info = Serializer.get_contact_info_by_phone_directory_record(record,
                                                                                                                 directory_info[
                                                                                                                     'name'])

                            if account := number_to_accounts.get(phone_directory_record_number):
                                # If we found a matching account, use its contact info but update with phone directory data
                                contact = Serializer.get_contact_info_by_account(account, i_account)
                                contact.first_name = phone_directory_contact_info.first_name
                                contact.last_name = phone_directory_contact_info.last_name
                                contact.numbers.main = phone_directory_record_number
                            else:
                                # No matching account found, use phone directory contact info as is
                                contact = phone_directory_contact_info
                                if contact.numbers.main:
                                    contact.numbers.main = contact.numbers.main.replace("+", "")

                            if contact.is_current_user is not True:
                                contacts.append(contact)

            # Extend the contact list with custom entries
            contacts.extend([Serializer.get_contact_info_by_custom_entry(entry) for entry in
                             self._portaswitch_settings.CONTACTS_CUSTOM])

            return contacts

        except WebTritErrorException as error:
            fault_code = extract_fault_code(error)
            if fault_code in ("Client.Session.check_auth.failed_to_process_access_token",):
                raise access_token_expired_error()

            raise error

    async def retrieve_contacts_v2(
            self, session: SessionInfo,
            user: UserInfo,
            search: Optional[str] = None,
            phone_numbers: List[str] = [],
            page: Optional[int] = 1,
            items_per_page: Optional[int] = 100,
    ) -> tuple[List[ContactInfo], int]:
        """Returns information about contacts based on the configured selection mode with pagination

        Supports multiple selection modes: EXTENSIONS, ACCOUNTS, PHONEBOOK, or PHONE_DIRECTORY.

        Parameters:
            session (SessionInfo): The session of the PortaSwitch account.
            user (UserInfo): The information about the PortaSwitch account.
            search (str | None): The Value to search specific contact by firstname, lastname, alias, or email address.
            page (int): The page number of the contact list to return.
            items_per_page (int): The number of items per page.

        Returns:
            tuple[List[ContactInfo], int]: List of contacts in WebTrit representation and total count.

        Raises:
            WebTritErrorException: If the user is not found or the session is invalid.
        """
        try:
            access_token = safely_extract_scalar_value(session.access_token)
            account_info = (await self._account_api.get_account_info(access_token))["account_info"]
            i_customer = int(account_info["i_customer"])
            i_account = int(account_info["i_account"])
            main_i_customer, all_i_customers = await self._get_office_customer_ids(i_customer)
            is_hierarchy = len(all_i_customers) > 1

            # Normalize and prepare phone numbers if provided
            normalized_phone_numbers: set[str] = set[str]()
            if phone_numbers:
                for number in phone_numbers:
                    if not number:
                        continue
                    normalized_phone_numbers.add(number.replace("+", "").strip())

            async def _enrich_with_aliases(account: dict) -> dict:
                """Re-fetch account via get_account_list to populate alias_list (additional numbers).
                get_account_info omits alias_list; get_account_list includes it via with_aliases=1."""
                if account.get("id") and account.get("i_customer"):
                    try:
                        enriched = (await self._admin_api.get_account_list(
                            int(account["i_customer"]), id=account["id"]
                        )).get("account_list", [])
                        if enriched:
                            return enriched[0]
                    except Exception as e:
                        logging.debug(f"Failed to enrich account {account.get('i_account')} with aliases: {e}")
                return account

            async def _resolve_master(account: dict) -> dict:
                """Follow i_master_account to the real owner account, enriched with alias_list."""
                if master_id := account.get("i_master_account"):
                    try:
                        master = (await self._admin_api.get_account_info(i_account=master_id)).get("account_info")
                        if master:
                            return await _enrich_with_aliases(master)
                    except Exception as e:
                        logging.debug(f"Failed to resolve master account {master_id}: {e}")
                return account

            # If phone_numbers search is provided, ignore generic `search` and use a unified implementation
            if normalized_phone_numbers:
                # Build extension number → i_account index once for all customers
                ext_number_to_i_account: dict[str, int] = {}
                try:
                    extensions = (await self._admin_api.get_extensions_list(
                        main_i_customer, get_main_office_extensions=is_hierarchy
                    ))["extensions_list"]
                    ext_number_to_i_account = {
                        ext["id"]: int(ext["i_account"])
                        for ext in extensions
                        if ext.get("id") and ext.get("i_account")
                    }
                except Exception as e:
                    logging.debug(f"Failed to fetch extensions for phone_numbers lookup: {e}")

                found_accounts: dict[int, dict] = {}  # keyed by i_account to deduplicate

                async def _lookup_number(number: str) -> dict[int, dict]:
                    result: dict[int, dict] = {}
                    # 1. Search by main number
                    for cust_id in all_i_customers:
                        try:
                            accounts = await self._admin_api.get_account_list(cust_id, id=number)
                            for account in (accounts.get("account_list", []) or []):
                                resolved = await _resolve_master(account)
                                result[int(resolved["i_account"])] = resolved
                        except Exception as e:
                            logging.debug(f"Failed to fetch accounts for phone number {number} in customer {cust_id}: {e}")
                    # 2. Search by extension number (short dial)
                    if number in ext_number_to_i_account:
                        ext_i_account = ext_number_to_i_account[number]
                        if ext_i_account not in result:
                            try:
                                account = (await self._admin_api.get_account_info(i_account=ext_i_account)).get("account_info")
                                if account:
                                    account = await _enrich_with_aliases(account)
                                    result[int(account["i_account"])] = account
                            except Exception as e:
                                logging.debug(f"Failed to fetch account for extension number {number}: {e}")
                    return result

                numbers_list = list(normalized_phone_numbers)
                lookup_results = await _gather_limited(
                    [_lookup_number(n) for n in numbers_list], return_exceptions=True
                )
                for number, res in zip(numbers_list, lookup_results):
                    if isinstance(res, Exception):
                        logging.debug(f"Parallel number lookup error for {number}: {res}")
                        continue
                    found_accounts.update(res)

                # 3. For alias/additional numbers not yet matched, try a direct account info lookup
                found_numbers: set[str] = set()
                for account in found_accounts.values():
                    found_numbers.add(account.get("id", ""))
                    for alias in account.get("alias_list", []):
                        found_numbers.add(alias.get("id", ""))

                async def _lookup_alias(number: str) -> tuple[int, dict] | None:
                    try:
                        account = (await self._admin_api.get_account_info(id=number)).get("account_info")
                        if account:
                            resolved = await _resolve_master(account)
                            return int(resolved["i_account"]), resolved
                    except Exception as e:
                        logging.debug(f"Account not found for alias/additional number {number}: {e}")
                    return None

                remaining = normalized_phone_numbers - found_numbers
                if remaining:
                    alias_results = await _gather_limited(
                        [_lookup_alias(n) for n in remaining], return_exceptions=True
                    )
                    for pair in alias_results:
                        if isinstance(pair, Exception):
                            logging.debug(f"Alias lookup error: {pair}")
                            continue
                        if pair is not None:
                            found_accounts[pair[0]] = pair[1]

                contacts: list[ContactInfo] = [
                    Serializer.get_contact_info_by_account(account, i_account)
                    for account in found_accounts.values()
                ]

                # Add matching custom contacts (check main, ext, and additional numbers)
                custom_contacts = [
                    Serializer.get_contact_info_by_custom_entry(entry)
                    for entry in self._portaswitch_settings.CONTACTS_CUSTOM
                ]
                for contact in custom_contacts:
                    if contact.numbers:
                        contact_numbers = {
                            (contact.numbers.main or "").replace("+", "").strip(),
                            (contact.numbers.ext or "").replace("+", "").strip(),
                            *((n or "").replace("+", "").strip() for n in (contact.numbers.additional or [])),
                        } - {""}
                        if contact_numbers & normalized_phone_numbers:
                            contacts.append(contact)

                total_count = len(contacts)
                start_idx = (page - 1) * items_per_page
                end_idx = start_idx + items_per_page

                return contacts[start_idx:end_idx], total_count

            contacts = []
            match self._portaswitch_settings.CONTACTS_SELECTING:
                case PortaSwitchContactsSelectingMode.EXTENSIONS:
                    allowed_ext_types = {
                        type.value for type in
                        self._portaswitch_settings.CONTACTS_SELECTING_EXTENSION_TYPES
                    }

                    # For EXTENSIONS mode, we need to get extensions first
                    extensions = (await self._admin_api.get_extensions_list(
                        main_i_customer, get_main_office_extensions=is_hierarchy
                    ))["extensions_list"]

                    # Filter extensions by allowed types and exclude current user
                    filtered_extensions = [
                        ext for ext in extensions
                        if ext["type"] in allowed_ext_types and ext.get("i_account") != i_account
                    ]

                    # If search is provided, filter extensions
                    if search:
                        search_fields = ["id", "firstname", "lastname", "name", "email"]

                        filtered_extensions = [
                            ext for ext in filtered_extensions
                            if any(search.lower() in ext.get(field, "").lower() for field in search_fields)
                        ]

                    # Fetch aliases only for extensions that survived filtering
                    async def _get_aliases_for_ext(ext):
                        i_acc = ext.get("i_account")
                        if not i_acc:
                            return []
                        try:
                            account = (await self._admin_api.get_account_info(
                                i_account=int(i_acc)
                            )).get("account_info")
                            if account:
                                return (await _enrich_with_aliases(account)).get("alias_list", [])
                        except Exception as e:
                            logging.debug(f"Failed to fetch aliases for extension {ext.get('id')}: {e}")
                        return []

                    if filtered_extensions:
                        aliases_per_ext = await _gather_limited(
                            [_get_aliases_for_ext(ext) for ext in filtered_extensions]
                        )
                        for ext, aliases in zip(filtered_extensions, aliases_per_ext):
                            contacts.append(Serializer.get_contact_info_by_extension(ext, aliases, i_account))

                    # Add custom contacts before pagination
                    custom_contacts = [Serializer.get_contact_info_by_custom_entry(entry) for entry in
                                       self._portaswitch_settings.CONTACTS_CUSTOM]
                    if search:
                        search_lower = search.lower()
                        custom_contacts = [
                            contact for contact in custom_contacts
                            if (search_lower in (contact.first_name or "").lower() or
                                search_lower in (contact.last_name or "").lower() or
                                search_lower in (contact.alias_name or "").lower() or
                                search_lower in (contact.email or "").lower() or
                                search_lower in (contact.numbers.main or "").lower())
                        ]
                    contacts.extend(custom_contacts)

                    # Apply pagination
                    total_count = len(contacts)
                    start_idx = (page - 1) * items_per_page
                    end_idx = start_idx + items_per_page
                    contacts = contacts[start_idx:end_idx]

                case PortaSwitchContactsSelectingMode.ACCOUNTS:
                    # Get custom contacts (needed for both search and non-search modes)
                    custom_contacts = [Serializer.get_contact_info_by_custom_entry(entry) for entry in
                                       self._portaswitch_settings.CONTACTS_CUSTOM]

                    # When filtering by extension and in a hierarchy, use the unified extensions list
                    # (get_main_office_extensions returns extensions across all offices) as the filter
                    extension_i_accounts: set[int] = set()
                    if self._portaswitch_settings.CONTACTS_SKIP_WITHOUT_EXTENSION and is_hierarchy:
                        ext_list = (await self._admin_api.get_extensions_list(
                            main_i_customer, get_main_office_extensions=True
                        ))["extensions_list"]
                        extension_i_accounts = {ext["i_account"] for ext in ext_list if ext.get("i_account")}

                    MAX_API_LIMIT = 1000
                    FILTER_BUFFER = 10

                    def _passes_filter(account: dict) -> bool:
                        if (status := account.get("status")) and status == "blocked":
                            return False
                        if PortaSwitchDualVersionSystem(account.get("dual_version_system")) == PortaSwitchDualVersionSystem.SOURCE:
                            return False
                        has_extension = account.get("extension_id") or (
                            is_hierarchy and account["i_account"] in extension_i_accounts
                        )
                        if self._portaswitch_settings.CONTACTS_SKIP_WITHOUT_EXTENSION and not has_extension:
                            return False
                        return account["i_account"] != i_account

                    if search:
                        # Search mode: run all (customer × field) combinations in parallel.
                        # Fetch only enough records per field to support in-memory pagination up
                        # to the current page. Without this cap, _get_all_accounts_by_customer
                        # paginates through every matching record — O(matches/1000) sequential
                        # API calls per field — which times out on broad queries against large
                        # accounts (e.g. 7000 matches × 5 fields = 35 sequential API calls).
                        # With this cap, cost is always O(5) parallel API calls regardless of
                        # total match count, matching the WT-1595 pattern.
                        search_fetch_limit = min(page * items_per_page + FILTER_BUFFER, MAX_API_LIMIT)
                        search_pattern = f"%{search}%"
                        accounts_dict: dict[int, dict] = {}
                        search_total_from_api = 0

                        search_tasks = [
                            (cust_id, param, value)
                            for cust_id in all_i_customers
                            for param, value in [
                                ("id", search_pattern),
                                ("firstname", search_pattern),
                                ("lastname", search_pattern),
                                ("extension_name", search_pattern),
                                ("email", search_pattern),
                            ]
                        ]

                        async def _fetch_field(task):
                            cust_id, param, value = task
                            resp = await self._admin_api.get_account_list(
                                cust_id, limit=search_fetch_limit, offset=0, **{param: value}
                            )
                            if isinstance(resp, dict):
                                return resp.get("account_list") or [], resp.get("total", 0)
                            return [], 0

                        for accs, field_total in await _gather_limited(
                            [_fetch_field(t) for t in search_tasks]
                        ):
                            for account in accs:
                                accounts_dict[account["i_account"]] = account
                            if field_total > search_total_from_api:
                                search_total_from_api = field_total

                        # Also search by extension number (short dial / extension_id)
                        try:
                            extensions = (await self._admin_api.get_extensions_list(
                                main_i_customer, get_main_office_extensions=is_hierarchy
                            ))["extensions_list"]
                            search_lower = search.lower()
                            missing_ext_i_accounts = [
                                int(ext["i_account"])
                                for ext in extensions
                                if search_lower in ext.get("id", "").lower()
                                and ext.get("i_account")
                                and int(ext["i_account"]) not in accounts_dict
                            ]

                            async def _fetch_ext_account(i_acc):
                                try:
                                    account = (await self._admin_api.get_account_info(
                                        i_account=i_acc
                                    )).get("account_info")
                                    if account:
                                        return await _enrich_with_aliases(account)
                                except Exception as e:
                                    logging.debug(f"Failed to fetch account for extension i_account={i_acc}: {e}")
                                return None

                            if missing_ext_i_accounts:
                                for account in await _gather_limited(
                                    [_fetch_ext_account(i_acc) for i_acc in missing_ext_i_accounts]
                                ):
                                    if account:
                                        accounts_dict[int(account["i_account"])] = account
                        except Exception as e:
                            logging.debug(f"Failed to fetch extensions for search: {e}")

                        # Also search by alias/additional DID (exact match only —
                        # substring scan would require fetching all accounts)
                        search_stripped = search.replace("+", "").strip()
                        if search_stripped:
                            try:
                                alias_account = (await self._admin_api.get_account_info(
                                    id=search_stripped
                                )).get("account_info")
                                if alias_account and alias_account.get("i_master_account"):
                                    resolved = await _resolve_master(alias_account)
                                    i_acc = int(resolved["i_account"])
                                    if i_acc not in accounts_dict:
                                        accounts_dict[i_acc] = resolved
                            except Exception as e:
                                logging.debug(f"Failed to search by alias DID {search_stripped}: {e}")

                        accounts = list(accounts_dict.values())
                    else:
                        # Non-search: fetch every account of every office in parallel chunks of
                        # 1000 and paginate in-memory. API-level LIMIT/OFFSET cannot be used here
                        # (WT-1774): the offset would have to be expressed in raw PortaBilling
                        # rows, while pages are counted in post-`_passes_filter` contacts. Mixing
                        # the two made consecutive pages overlap by a margin that grew with the
                        # page number. For a customer outside an office hierarchy
                        # all_i_customers == [main_i_customer], so this is a single fan-out.
                        accounts_per_customer = await _gather_limited(
                            [self._get_all_accounts_by_customer(c) for c in all_i_customers]
                        )
                        # Order deterministically: get_account_list is never sent an ORDER BY,
                        # so the row order of separate calls — the parallel chunks here, and the
                        # next page's own request — is unspecified. Sorting on i_account makes
                        # page boundaries reproducible across requests. Search results are left
                        # alone: their order is relevance, the fields being probed in priority
                        # order (id, firstname, lastname, extension_name, email).
                        accounts = sorted(
                            (acc for accs in accounts_per_customer for acc in accs),
                            key=lambda a: int(a["i_account"]),
                        )

                    # Filter accounts
                    filtered_accounts = [a for a in accounts if _passes_filter(a)]

                    # Build contacts from accounts
                    account_contacts = []
                    for account in filtered_accounts:
                        account_contacts.append(Serializer.get_contact_info_by_account(account, i_account))

                    # Filter custom contacts if search is provided
                    if search:
                        search_lower = search.lower()
                        custom_contacts = [
                            contact for contact in custom_contacts
                            if (search_lower in (contact.first_name or "").lower() or
                                search_lower in (contact.last_name or "").lower() or
                                search_lower in (contact.alias_name or "").lower() or
                                search_lower in (contact.email or "").lower() or
                                search_lower in (contact.numbers.main or "").lower())
                        ]

                    # Add custom contacts; they tail the directory on the last page
                    account_contacts.extend(custom_contacts)

                    # Apply pagination. One code path for every sub-mode so that the slice offset
                    # and items_total always describe the same row set (WT-1774): reporting
                    # PortaBilling's unfiltered total made the client build pages that do not
                    # exist, hence the empty last page.
                    # In search mode: use the API-reported total (max across fields) as total_count
                    # rather than len(account_contacts), because the bounded fetch only retrieves
                    # enough records for the current page — len() would severely undercount.
                    if search:
                        total_count = max(search_total_from_api, len(account_contacts))
                    else:
                        total_count = len(account_contacts)
                    start_idx = (page - 1) * items_per_page
                    end_idx = start_idx + items_per_page
                    contacts = account_contacts[start_idx:end_idx]

                case PortaSwitchContactsSelectingMode.PHONEBOOK:
                    custom_contacts = [Serializer.get_contact_info_by_custom_entry(entry) for entry in
                                       self._portaswitch_settings.CONTACTS_CUSTOM]
                    custom_contacts_count = len(custom_contacts)

                    async def _build_phonebook_contacts(phonebook_records):
                        pb_numbers = {
                            r.get("phone_number", "").replace("+", "")
                            for r in phonebook_records if r.get("phone_number")
                        }
                        num_to_acc = await self._get_number_to_customer_accounts_map_for_numbers(pb_numbers)
                        result = []
                        for record in phonebook_records:
                            pb_number = record.get("phone_number").replace("+", "")
                            pb_contact = Serializer.get_contact_info_by_phonebook_record(record)
                            if account := num_to_acc.get(pb_number):
                                contact = Serializer.get_contact_info_by_account(account, i_account)
                                contact.alias_name = pb_contact.alias_name
                                contact.numbers.main = pb_number
                            else:
                                contact = pb_contact
                                if contact.numbers.main:
                                    contact.numbers.main = contact.numbers.main.replace("+", "")
                            if contact.is_current_user is not True:
                                result.append(contact)
                        return result

                    if search:
                        # Fetch all phonebook records for in-memory search
                        phonebook = []
                        pb_page = 1
                        PHONEBOOK_BATCH = 1000
                        while True:
                            batch = (await self._account_api.get_phonebook_list(
                                access_token, pb_page, PHONEBOOK_BATCH
                            )).get('phonebook_rec_list', [])
                            phonebook.extend(batch)
                            if len(batch) < PHONEBOOK_BATCH:
                                break
                            pb_page += 1

                        contacts = await _build_phonebook_contacts(phonebook)
                        search_lower = search.lower()
                        filtered_custom = [
                            c for c in custom_contacts
                            if any(search_lower in str(v or "").lower() for v in [
                                c.numbers.main if c.numbers else None,
                                c.numbers.ext if c.numbers else None,
                                c.first_name, c.last_name, c.alias_name, c.email,
                            ]) or (c.numbers and any(
                                search_lower in str(n or "").lower()
                                for n in (c.numbers.additional or [])
                            ))
                        ]
                        contacts.extend(filtered_custom)
                        total_count = len(contacts)
                        start_idx = (page - 1) * items_per_page
                        end_idx = start_idx + items_per_page
                        contacts = contacts[start_idx:end_idx]
                    else:
                        # API-level pagination: resolve accounts only for the current page.
                        # Custom contacts occupy the first custom_contacts_count slots on page 1,
                        # so the phonebook offset and limit must be adjusted accordingly:
                        #   page 1: offset=0,                    limit=items_per_page-cc
                        #   page N: offset=(N-1)*ipp - cc,       limit=items_per_page
                        if custom_contacts_count > 0:
                            if page == 1:
                                pb_offset = 0
                                pb_limit = max(1, items_per_page - custom_contacts_count)
                            else:
                                pb_offset = (page - 1) * items_per_page - custom_contacts_count
                                pb_limit = items_per_page
                            pb_result = await self._account_api.get_phonebook_list(
                                access_token, page, items_per_page,
                                offset=pb_offset, limit=pb_limit,
                            )
                        else:
                            pb_result = await self._account_api.get_phonebook_list(access_token, page, items_per_page)
                        phonebook = pb_result.get('phonebook_rec_list', [])
                        pb_total = pb_result.get('total', 0)

                        contacts = await _build_phonebook_contacts(phonebook)
                        if page == 1:
                            contacts = custom_contacts + contacts
                        total_count = pb_total + custom_contacts_count

                case PortaSwitchContactsSelectingMode.PHONE_DIRECTORY:
                    phone_directories = (await self._account_api.get_phone_directory_list(access_token, 1, 100))[
                        'phone_directory_list']

                    # Single pass: collect numbers and cache directory infos to avoid double-fetching
                    phone_directory_numbers = set()
                    directory_infos = {}
                    for directory in phone_directories:
                        dir_id = directory['i_ua_config_directory']
                        directory_info = (await self._account_api.get_phone_directory_info(
                            access_token, dir_id, 1, 10_000
                        ))['phone_directory_info']
                        directory_infos[dir_id] = directory_info
                        for record in directory_info['directory_records']:
                            office_number = record.get("office_number", "").replace("+", "")
                            if office_number:
                                phone_directory_numbers.add(office_number)

                    # Get account mapping only for phone directory numbers (on-demand)
                    number_to_accounts = await self._get_number_to_customer_accounts_map_for_numbers(phone_directory_numbers)

                    # Build contacts using cached directory infos — no second API call
                    for directory in phone_directories:
                        directory_info = directory_infos[directory['i_ua_config_directory']]
                        for record in directory_info['directory_records']:
                            phone_directory_record_number = record.get("office_number").replace("+", "")
                            phone_directory_contact_info = Serializer.get_contact_info_by_phone_directory_record(
                                record, directory_info['name']
                            )

                            if account := number_to_accounts.get(phone_directory_record_number):
                                contact = Serializer.get_contact_info_by_account(account, i_account)
                                contact.first_name = phone_directory_contact_info.first_name
                                contact.last_name = phone_directory_contact_info.last_name
                                contact.numbers.main = phone_directory_record_number
                            else:
                                contact = phone_directory_contact_info
                                if contact.numbers.main:
                                    contact.numbers.main = contact.numbers.main.replace("+", "")

                            if contact.is_current_user is not True:
                                contacts.append(contact)

                    # Add custom contacts before filtering and pagination
                    custom_contacts = [Serializer.get_contact_info_by_custom_entry(entry) for entry in
                                       self._portaswitch_settings.CONTACTS_CUSTOM]
                    contacts.extend(custom_contacts)

                    # Apply search filter if provided
                    if search:
                        search_lower = search.lower()
                        contacts = [
                            contact for contact in contacts
                            if any(search_lower in str(value or "").lower() for value in [
                                contact.numbers.main if contact.numbers else None,
                                contact.numbers.ext if contact.numbers else None,
                                contact.first_name,
                                contact.last_name,
                                contact.alias_name,
                                contact.email,
                            ]) or (
                                contact.numbers and any(
                                    search_lower in str(n or "").lower()
                                    for n in (contact.numbers.additional or [])
                                )
                            )
                        ]

                    # Apply pagination
                    total_count = len(contacts)
                    start_idx = (page - 1) * items_per_page
                    end_idx = start_idx + items_per_page
                    contacts = contacts[start_idx:end_idx]

            return contacts, total_count

        except WebTritErrorException as error:
            fault_code = extract_fault_code(error)
            if fault_code in ("Client.Session.check_auth.failed_to_process_access_token",):
                raise access_token_expired_error()

            raise error

    async def retrieve_contact_by_user_id(self, session: SessionInfo, user: UserInfo, user_id: str) -> ContactInfo:
        """Retrieve contact information by user ID in the PortaSwitch system.

        Parameters:
            session (SessionInfo): The session of the PortaSwitch account.
            user (UserInfo): The information about the requesting account.
            user_id (str): The unique identifier of the account to retrieve.

        Returns:
            ContactInfo: Contact information for the specified user.

        Raises:
            WebTritErrorException: If no account exists with the specified ID.
        """
        account_info = (await self._admin_api.get_account_info(i_account=int(user_id))).get("account_info")
        if not account_info:
            raise not_found_contact_error(user_id)

        return Serializer.get_contact_info_by_account(account_info, int(user.user_id))

    async def retrieve_calls(
            self,
            session: SessionInfo,
            user: UserInfo,
            page: Optional[int] = 1,
            items_per_page: Optional[int] = 100,
            time_from: datetime | None = None,
            time_to: datetime | None = None,
    ) -> tuple[list[CDRInfo], int]:
        """Returns the CDR history of the logged-in PortaSwitch account.

        Parameters:
            session (SessionInfo): The session of the PortaSwitch account.
            user (UserInfo): The information about the PortaSwitch account.
            page (int): The page number of the CDR history to return.
            items_per_page (int): The number of items per page.
            time_from (datetime | None): Start of the time range filter. Defaults to 1970-01-01.
            time_to (datetime | None): End of the time range filter. Defaults to year 9000.

        Returns:
            tuple[list[CDRInfo], int]: A tuple containing the list of CDR records and the total
                count of records available (without pagination).

        Raises:
            WebTritErrorException: If the user is not found or the session is invalid.
        """
        try:
            time_from: datetime = time_from if time_from else datetime(1970, 1, 1)
            time_to: datetime = time_to if time_to else datetime(9000, 1, 1)

            result: dict = await self._account_api.get_xdr_list(
                access_token=safely_extract_scalar_value(session.access_token),
                page=page,
                items_per_page=items_per_page,
                time_from=time_from,
                time_to=time_to,
            )

            return [Serializer.get_cdr_info(cdr) for cdr in result["xdr_list"]], result["total"]

        except WebTritErrorException as error:
            fault_code = extract_fault_code(error)
            if fault_code in ("Client.Session.check_auth.failed_to_process_access_token",):
                raise access_token_expired_error()

            raise error

    async def retrieve_call_recording(self, session: SessionInfo, call_recording: CallRecordingId) -> tuple[str, AsyncIterator]:
        """Returns the binary representation of a recorded call.

        Parameters:
            session (SessionInfo): The session of the PortaSwitch account.
            call_recording (CallRecordingId): The identifier of the call recording record.

        Returns:
            tuple[str, Iterator]: A tuple containing the content-type and an iterator over the
                raw bytes of the recording.

        Raises:
            WebTritErrorException: If the recording is not found or the ID is invalid.
        """
        recording_id = safely_extract_scalar_value(call_recording)
        try:
            return await self._account_api.get_call_recording(
                access_token=safely_extract_scalar_value(session.access_token), recording_id=recording_id
            )

        except WebTritErrorException as error:
            fault_code = extract_fault_code(error)
            if fault_code in ("Client.Session.check_auth.failed_to_process_access_token",):
                raise access_token_expired_error()
            if fault_code in ("Server.CDR.xdr_not_found", "Server.CDR.invalid_call_recording_id",):
                raise not_found_recording_error(recording_id)

            raise error

    async def retrieve_voicemails(
        self,
        session: SessionInfo,
        user: UserInfo,
        from_date: Optional[str] = None,
        to_date: Optional[str] = None,
    ) -> UserVoicemailsResponse:
        """Returns the user's voicemail messages.

        Parameters:
            session (SessionInfo): The session of the PortaSwitch account.
            user (UserInfo): The information about the PortaSwitch account.
            from_date (Optional[str]): Return messages delivered on or after this date ("YYYY-MM-DD").
            to_date (Optional[str]): Return messages delivered before this date ("YYYY-MM-DD").

        Returns:
            UserVoicemailsResponse: Structure containing voicemail messages and a new message flag.

        Raises:
            WebTritErrorException: If the user is not found or the session is invalid.
        """
        try:
            mailbox_messages = await self._account_api.get_mailbox_messages(
                safely_extract_scalar_value(session.access_token),
                from_date=from_date,
                to_date=to_date,
            )
            voicemail_messages = [Serializer.get_voicemail_message(message) for message in mailbox_messages]

            return UserVoicemailsResponse(
                messages=voicemail_messages, has_new_messages=any(not message.seen for message in voicemail_messages)
            )

        except WebTritErrorException as error:
            fault_code = extract_fault_code(error)
            if fault_code in ("Client.Session.check_auth.failed_to_process_access_token",):
                raise access_token_expired_error()
            elif fault_code in ("Server.Account.unified_messaging_disabled",):
                raise voicemail_not_configured()

            raise error

    async def retrieve_voicemail_message_details(
            self, session: SessionInfo, user: UserInfo, message_id: str
    ) -> VoicemailMessageDetails:
        """Returns detailed information about a specific voicemail message.

        Parameters:
            session (SessionInfo): The session of the PortaSwitch account.
            user (UserInfo): The information about the PortaSwitch account.
            message_id (str): The unique ID of the voicemail message.

        Returns:
            VoicemailMessageDetails: Detailed information about the voicemail message.

        Raises:
            WebTritErrorException: If the user is not found or the session is invalid.
        """
        try:
            message_details = await self._account_api.get_mailbox_message_details(
                safely_extract_scalar_value(session.access_token), message_id
            )

            return Serializer.get_voicemail_message_details(message_details)

        except WebTritErrorException as error:
            fault_code = extract_fault_code(error)
            if fault_code in ("Client.Session.check_auth.failed_to_process_access_token",):
                raise access_token_expired_error()
            elif fault_code in ("Server.Account.unified_messaging_disabled",):
                raise voicemail_not_configured()

            raise error

    async def retrieve_voicemail_message_attachment(
            self, session: SessionInfo, message_id: str, file_format: str
    ) -> tuple[str, AsyncIterator]:
        """
        Retrieve the binary attachment of a voicemail message.

        Parameters:
            session (SessionInfo): The session object for the PortaSwitch account.
            message_id (str): The unique identifier of the voicemail message.
            file_format (str): The format in which the attachment should be retrieved (e.g., 'wav', 'mp3').

        Returns:
            tuple[str, Iterator]: A tuple containing the content-type and an iterator over the raw bytes of the attachment.
        """

        file_format = file_format and file_format.lower()
        if file_format and not PortaSwitchMailboxMessageAttachmentFormat.has_value(file_format):
            raise unsupported_file_format_error()

        try:
            return await self._account_api.get_mailbox_message_attachment(
                safely_extract_scalar_value(session.access_token),
                message_id,
                file_format or PortaSwitchMailboxMessageAttachmentFormat.WAV.value,
            )

        except WebTritErrorException as error:
            fault_code = extract_fault_code(error)
            if fault_code in ("Client.Session.check_auth.failed_to_process_access_token",):
                raise access_token_expired_error()
            elif fault_code in ("Server.Account.unified_messaging_disabled",):
                raise voicemail_not_configured()

            raise error

    async def patch_voicemail_message(
            self, session: SessionInfo, message_id: str, body: UserVoicemailMessagePatch
    ) -> UserVoicemailMessagePatch:
        """Update attributes for a user's voicemail message.

        Parameters:
            session (SessionInfo): The session of the PortaSwitch account.
            message_id (str): The unique ID of the voicemail message.
            body (UserVoicemailMessagePatch): Attributes to update (e.g., seen status).

        Returns:
            UserVoicemailMessagePatch: The updated message attributes.

        Raises:
            WebTritErrorException: If the user is not found or the session is invalid.
        """
        seen = body.seen

        try:
            await self._account_api.set_mailbox_message_flag(
                safely_extract_scalar_value(session.access_token),
                message_id,
                PortaSwitchMailboxMessageFlag.SEEN,
                PortaSwitchMailboxMessageFlagAction.SET if seen else PortaSwitchMailboxMessageFlagAction.UNSET,
            )

            return UserVoicemailMessagePatch(seen=seen)

        except WebTritErrorException as error:
            fault_code = extract_fault_code(error)
            if fault_code in ("Client.Session.check_auth.failed_to_process_access_token",):
                raise access_token_expired_error()
            elif fault_code in ("Server.Account.unified_messaging_disabled",):
                raise voicemail_not_configured()

            raise error

    async def delete_voicemail_message(self, session: SessionInfo, message_id: str) -> None:
        """Delete an existing voicemail message.

        Parameters:
            session (SessionInfo): The session of the PortaSwitch account.
            message_id (str): The unique ID of the voicemail message.

        Raises:
            WebTritErrorException: If the user is not found or the session is invalid.
        """
        try:
            await self._account_api.delete_mailbox_message(safely_extract_scalar_value(session.access_token), message_id)

        except WebTritErrorException as error:
            fault_code = extract_fault_code(error)
            if fault_code in ("Client.Session.check_auth.failed_to_process_access_token",):
                raise access_token_expired_error()
            elif fault_code in ("Server.Account.unified_messaging_disabled",):
                raise voicemail_not_configured()

            raise error

    def create_user_event(self, user: UserInfo, timestamp: datetime, group: UserEventGroup, type: UserEventType,
                          data: Optional[dict] = None) -> None:
        """Create a user event (not implemented for PortaSwitch adapter).

        Parameters:
            user (UserInfo): The user information.
            timestamp (datetime): The timestamp of the event.
            group (UserEventGroup): The event group.
            type (UserEventType): The event type.
            data (Optional[dict]): Additional event data.

        Raises:
            NotImplementedError: This method is not implemented for PortaSwitch.
        """
        raise NotImplementedError()

    def create_new_user(self, user_data, tenant_id: str = None):
        """Create a new user as part of the sign-up process (not implemented).

        Parameters:
            user_data: The user data for account creation.
            tenant_id (str | None): The tenant identifier.

        Raises:
            NotImplementedError: This method is not implemented for PortaSwitch.
        """
        raise NotImplementedError()

    async def signup(self, user_data, tenant_id: str = None) -> SessionResponse:
        """Complete the sign-up process using existing PortaSwitch access tokens.

        Parameters:
            user_data: User data containing access_token and refresh_token from PortaSwitch.
            tenant_id (str | None): The tenant identifier (unused).

        Returns:
            SessionInfo: Session information including user ID and tokens.

        Raises:
            WebTritErrorException: If required tokens are missing or invalid, or user is not found.
        """
        user_data = user_data.model_dump()
        access_token = user_data.get("access_token")
        refresh_token = user_data.get("refresh_token")

        if not access_token or not refresh_token:
            raise missing_tokens_error()

        try:
            account_info = (await self._account_api.get_account_info(access_token=access_token))["account_info"]

            return SessionResponse(
                user_id=UserId(str(account_info["i_account"])),
                access_token=AccessToken(access_token),
                refresh_token=refresh_token,
            )
        except WebTritErrorException as error:
            if extract_fault_code(error) == "Client.Session.check_auth.failed_to_process_access_token":
                raise access_token_expired_error()

            raise error

    def delete_user(self, user: UserInfo):
        # Session invalidation is handled by close_session in the controller;
        # PortaSwitch accounts cannot be deleted via the Adapter.
        pass

    async def custom_method_public(
            self,
            method_name: str,
            data: CustomRequest,
            headers: Optional[Dict] = None,
            tenant_id: str = None,
            lang: str = None,
    ) -> CustomResponse:
        attr_name = method_name.replace("-", "_")
        if method := getattr(self, attr_name, None):
            logging.debug(f"Processing custom public method {method_name} with {data} request")

            result = method(data=data, lang=lang)
            # Handlers are dispatched dynamically and may be sync or async.
            return await result if isawaitable(result) else result
        else:
            raise method_not_found_error(method_name)

    async def custom_method_private(
            self,
            session: SessionInfo,
            user_id: str,
            method_name: str,
            data: CustomRequest,
            headers: Optional[Dict] = None,
            tenant_id: str = None,
            lang: str = None,
    ) -> CustomResponse:
        attr_name = f"_{method_name.replace('-', '_')}"
        if method := getattr(self, attr_name, None):
            logging.debug(f"Processing custom private method {method_name} from user {user_id} with {data} request")

            result = method(user_id=user_id, data=data, lang=lang)
            # Handlers are dispatched dynamically and may be sync or async.
            return await result if isawaitable(result) else result
        else:
            raise method_not_found_error(method_name)

    # region custom methods handlers

    async def _custom_pages(self, user_id: str, data: CustomRequest, lang: str = None) -> CustomResponse:
        _ = get_translation_func(lang)
        session_data = await self._emulate_account_login(user_id)

        pages = []
        if self._portaswitch_settings.SELF_CONFIG_PORTAL_URL:
            token = session_data['access_token']
            expires_at = datetime.now(UTC) + timedelta(seconds=session_data["expires_in"])

            pages.append(CustomPage(
                title=_("Self-config Portal"),
                url=f"{self._portaswitch_settings.SELF_CONFIG_PORTAL_URL}?token={token}",
                expires_at=expires_at,
                extra_data=dict(token=token, expires_at=expires_at)
            ))

        return CustomResponse(pages=pages)

    async def _external_page_access_token(self, user_id: str, data: CustomRequest, lang: str = None) -> CustomResponse:
        session_data = await self._emulate_account_login(user_id)

        return CustomResponse(
            access_token=AccessToken(session_data['access_token']),
            refresh_token=session_data['refresh_token'],
            expires_at=datetime.now(UTC) + timedelta(seconds=session_data["expires_in"])
        )

    # endregion

    def _check_allowed_addons(self, account_info: dict):
        """Verify that the account has at least one of the required add-ons.

        Parameters:
            account_info (dict): Account information including an assigned_addons list.

        Raises:
            WebTritErrorException: If the account doesn't have any of the required add-ons.
        """
        allowed_addons = set(self._portaswitch_settings.ALLOWED_ADDONS)

        if account_info.get("i_master_account"):
            logging.debug("Account is alias, skipping add-on check...")
            return

        assigned_addons = account_info.get("assigned_addons", [])
        assigned_addon_names = {addon.get("name") for addon in assigned_addons if "name" in addon}

        logging.info(f"Check add-ons {assigned_addon_names} for access. Allowed add-ons: {allowed_addons}")

        if not allowed_addons.intersection(assigned_addon_names):
            raise addon_required_error()

    async def _get_number_to_customer_accounts_map_for_numbers(self, target_numbers: set[str]) -> dict[str, dict]:
        """Return a mapping of phone numbers to customer accounts, optimized for specific numbers.
        
        This method supports two search modes:
        1. If CONTACTS_SELECTING_CUSTOMER_IDS is configured: searches through customer accounts in batches
        2. If CONTACTS_SELECTING_CUSTOMER_IDS is not configured: searches each number individually using get_account_info
        
        Args:
            target_numbers: Set of phone numbers to search for
            
        Returns:
            Dictionary mapping phone numbers to account information
        """
        if not target_numbers:
            return {}

        number_to_accounts = {}

        # Check if CONTACTS_SELECTING_CUSTOMER_IDS is configured
        if self._portaswitch_settings.CONTACTS_SELECTING_CUSTOMER_IDS:
            # Use batch search through customer accounts
            remaining_numbers = target_numbers.copy()

            # Search through each customer's accounts
            for customer_id in self._portaswitch_settings.CONTACTS_SELECTING_CUSTOMER_IDS:
                if not remaining_numbers:
                    break  # All numbers found no need to continue

                try:
                    # Get accounts for this customer in batches
                    offset = 0
                    limit = 1000

                    while remaining_numbers and offset < 10000:  # Safety limit to prevent infinite loops
                        accounts = await self._admin_api.get_account_list(int(customer_id), limit=limit, offset=offset)
                        page = accounts.get("account_list", []) if isinstance(accounts, dict) else []
                        total = accounts.get("total") if isinstance(accounts, dict) else None

                        # Process accounts in this batch
                        for account in page:
                            account_number = account.get("id", "")
                            if account_number in remaining_numbers:
                                number_to_accounts[account_number] = account
                                remaining_numbers.remove(account_number)

                        # Stop if we've processed all accounts or found all target numbers
                        if not remaining_numbers or len(page) < limit:
                            break
                        if total is not None and offset + len(page) >= int(total):
                            break

                        offset += limit

                except Exception as e:
                    logging.warning(f"Error fetching accounts for customer {customer_id}: {e}")
                    continue
        else:
            # Use individual search for each number
            for number in target_numbers:
                try:
                    account_info = (await self._admin_api.get_account_info(id=number, detailed_info=1)).get("account_info")
                    if account_info:
                        number_to_accounts[number] = account_info
                except Exception as e:
                    logging.debug(f"Account not found for number {number}: {e}")
                    continue

        logging.debug(f"Found {len(number_to_accounts)} accounts out of {len(target_numbers)} target numbers")
        return number_to_accounts

    async def _get_office_customer_ids(self, i_customer: int) -> tuple[int, list[int]]:
        """Resolves the main office customer ID and the full list of customer IDs in the hierarchy.

        PortaSwitch supports a hierarchy where a main office manages extensions for all its branch
        offices. Branch offices cannot create their own extensions.

        Office types (i_office_type):
            1 = none (regular customer, no office hierarchy)
            2 = branch_office (extensions managed by main office via i_main_office)
            3 = main_office (manages extensions for itself and all branch offices)

        Parameters:
            i_customer (int): The customer ID of the currently authenticated user.

        Returns:
            tuple[int, list[int]]: A tuple of (main_i_customer, all_i_customers) where:
                - main_i_customer: the main office's i_customer — used for get_extensions_list
                  (with get_main_office_extensions=True) to get extensions across all offices
                - all_i_customers: list of all customer IDs (main + branches) — used to fetch
                  accounts from every office. Contains only [i_customer] when not in a hierarchy.
        """
        try:
            customer_info = (await self._admin_api.get_customer_info(i_customer)).get("customer_info", {})
            i_office_type = customer_info.get("i_office_type")

            if i_office_type == 2:  # branch_office: delegate to main office's hierarchy
                i_main_office = customer_info.get("i_main_office")
                if i_main_office:
                    main_id = int(i_main_office)
                    logging.debug(
                        f"Customer {i_customer} is a branch office; resolving via main office {main_id}"
                    )
                    return await self._get_all_office_customers_for_main(main_id)
            elif i_office_type == 3:  # main_office: collect main + all branches
                logging.debug(f"Customer {i_customer} is a main office; collecting all branch customers")
                return await self._get_all_office_customers_for_main(i_customer)
        except Exception as e:
            logging.warning(f"Failed to resolve office type for i_customer={i_customer}: {e}")

        return i_customer, [i_customer]

    async def _get_all_office_customers_for_main(self, main_i_customer: int) -> tuple[int, list[int]]:
        """Returns (main_i_customer, [main_i_customer] + all branch i_customers).

        Parameters:
            main_i_customer (int): The i_customer of the main office.

        Returns:
            tuple[int, list[int]]: The main office customer ID and the full list of customer IDs
                (main + all branch offices).
        """
        try:
            result = await self._admin_api.get_customer_list(main_i_customer)
            branch_ids = [
                int(c["i_customer"])
                for c in result.get("customer_list", [])
                if c.get("i_customer")
            ]
            all_ids = [main_i_customer] + branch_ids
            logging.debug(f"Main office {main_i_customer} has branch offices: {branch_ids}")
            return main_i_customer, all_ids
        except Exception as e:
            logging.warning(f"Failed to get branch customers for main office {main_i_customer}: {e}")
            return main_i_customer, [main_i_customer]

    async def _get_all_accounts_by_customer(self, i_customer: int, **search_params) -> list[dict]:
        """Fetch all accounts for a customer using parallel pagination.

        Parameters:
            i_customer (int): The unique identifier of the customer.
            **search_params: Optional search parameters forwarded to get_account_list
                (e.g. firstname="%john%", id="%555%").

        Returns:
            list[dict]: List of all account records for the specified customer.
        """
        limit = 1000

        resp = await self._admin_api.get_account_list(i_customer, limit=limit, offset=0, **search_params)
        first_page = resp.get("account_list", []) if isinstance(resp, dict) else []
        total = int(resp["total"]) if isinstance(resp, dict) and resp.get("total") else None

        if not first_page or len(first_page) < limit or total is None or len(first_page) >= total:
            return first_page

        remaining_offsets = list(range(limit, total, limit))

        async def _fetch_page(offset):
            r = await self._admin_api.get_account_list(i_customer, limit=limit, offset=offset, **search_params)
            return r.get("account_list", []) if isinstance(r, dict) else []

        # Own semaphore per call (see _gather_limited) so this nested fan-out —
        # itself invoked concurrently across customers — can't dead-lock.
        remaining_pages = await _gather_limited([_fetch_page(o) for o in remaining_offsets])

        # De-duplicate by i_account: the chunks are separate LIMIT/OFFSET queries and
        # get_account_list is never sent an ORDER BY, so an unstable row order between
        # them could otherwise repeat a record in the assembled list (WT-1774). This
        # bounds the damage but is not a cure — a row that lands in no chunk at all
        # would still be missed; that needs a server-side ORDER BY.
        by_i_account: dict[int, dict] = {}
        for account in first_page + [acc for page in remaining_pages for acc in page]:
            by_i_account[int(account["i_account"])] = account

        return list(by_i_account.values())

    async def _get_or_create_api_token(self, account_info: dict) -> Optional[str]:
        """Return the account's api_token, creating and persisting one if absent."""
        api_token = account_info.get("api_token")
        if not api_token:
            api_token = str(uuid.uuid4())
            try:
                await self._admin_api.update_account(account_info["i_account"], api_token=api_token)
                logging.info(f"Created new api_token for i_account={account_info['i_account']}")
            except Exception as e:
                logging.warning(f"Failed to create new api_token for i_account={account_info['i_account']}: {e}")
                return None
        return api_token

    async def _emulate_account_login(self, i_account: str) -> dict:
        """Emulate a login for a PortaSwitch account."""
        account_info = (await self._admin_api.get_account_info(i_account=i_account)).get("account_info")

        if await self._is_portaswitch_version_with_token():
            token = await self._get_or_create_api_token(account_info)
            if token:
                return await self._account_api.login(account_info["login"], token=token)
            else:
                return await self._account_api.login(account_info["login"], account_info["password"])
        else:
            return await self._account_api.login(account_info["login"], account_info["password"], token=account_info["password"])

    async def _is_portaswitch_version_with_token(self) -> bool:
        """Check if the actual version of PortaSwitch is a version with token support."""
        version = await self._admin_api.get_version()
        actual_portaswitch_mr = [int(d) for d in re.findall(r'\d+', version)]
        expected_portaswitch_mr_with_token_support = [int(d) for d in
                                                      re.findall(r'\d+', PORTASWITCH_VERSION_WITH_TOKEN)]

        return actual_portaswitch_mr >= expected_portaswitch_mr_with_token_support
