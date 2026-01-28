import logging
from datetime import datetime, timedelta, UTC
from typing import Final, Iterator, Optional, Dict, List

from jose.exceptions import ExpiredSignatureError, JWTError

from app_config import AppConfig
from bss.adapters import BSSAdapter
from bss.dbs import TiedKeyValue
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
from .serializer import Serializer
from .types import (
    PortaSwitchSignInCredentialsType,
    PortaSwitchContactsSelectingMode,
    PortaSwitchDualVersionSystem,
    PortaSwitchMailboxMessageFlag,
    PortaSwitchMailboxMessageFlagAction,
    PortaSwitchMailboxMessageAttachmentFormat,
)
from .utils import generate_otp_id, extract_fault_code


class PortaSwitchAdapter(BSSAdapter):
    """Bridges WebTrit Core with PortaSwitch APIs.

    Provides authentication (password, OTP, auto-provision), session lifecycle management,
    SIP credential retrieval, contacts, call history, voicemail, notifications, and other
    capabilities required by WebTrit clients.
    """

    VERSION: Final[str] = "0.3.4"
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
        Capabilities.sip_presence
    ]

    def __init__(self, config: AppConfig):
        super().__init__(config)

        self._settings = Settings()
        self._portaswitch_settings = self._settings.PORTASWITCH_SETTINGS
        self._otp_settings = self._settings.OTP_SETTINGS

        self._admin_api = AdminAPI(self._portaswitch_settings)
        self._account_api = AccountAPI(self._portaswitch_settings)
        self._sip_server = SipServer(
            host=self._portaswitch_settings.SIP_SERVER_HOST, port=self._portaswitch_settings.SIP_SERVER_PORT
        )

        self._cached_otp_ids = TiedKeyValue()
        self._cached_capabilities = self.calculate_capabilities()

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

    def authenticate(self, user: UserInfo, password: str = None) -> SessionInfo:
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

            account_info = self._admin_api.get_account_info(**{login_attr: user.login}).get("account_info")

            # If the provided identifier refers to an alias, resolve to the master account
            if account_info and (master_id := account_info.get("i_master_account")):
                account_info = self._admin_api.get_account_info(i_account=master_id).get("account_info")

            if not account_info or account_info[password_attr] != password:
                raise WebTritErrorException(401, "User authentication error", code="incorrect_credentials")

            if self._portaswitch_settings.ALLOWED_ADDONS:
                self._check_allowed_addons(account_info)

            session_data = self._account_api.login(account_info["login"], account_info["password"])

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
                raise WebTritErrorException(
                    status_code=401,
                    error_message="User authentication error",
                )

            raise error

    def generate_otp(self, user: UserInfo) -> OTPCreateResponse:
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
            account_info = self._admin_api.get_account_info(id=user.user_id).get("account_info")
            if not account_info:
                raise WebTritErrorException(404, f"There is no an account with such id: {user.user_id}")

            if self._portaswitch_settings.ALLOWED_ADDONS:
                self._check_allowed_addons(account_info)

            i_account = account_info.get("i_master_account", account_info["i_account"])
            success: int = self._admin_api.create_otp(i_account, self.OTP_DELIVERY_CHANNEL)["success"]
            if not success:
                raise WebTritErrorException(500, "Unknown error", code="external_api_issue")

            otp_id: str = generate_otp_id()
            self._cached_otp_ids[otp_id] = i_account, user.user_id

            env_info = self._admin_api.get_env_info()

            return OTPCreateResponse(
                otp_id=OtpId(otp_id), delivery_channel=self.OTP_DELIVERY_CHANNEL, delivery_from=env_info.get("email")
            )

        except WebTritErrorException as error:
            fault_code = extract_fault_code(error)
            if fault_code in ("Server.AccessControl.empty_rec_and_bcc",):
                raise WebTritErrorException(422, "Delivery channel unspecified", code="delivery_channel_unspecified")

            raise error

    def validate_otp(self, otp: OTPVerifyRequest) -> SessionInfo:
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

            (i_account, user_ref) = self._cached_otp_ids.get(otp_id, (None, None))
            if not i_account:
                raise WebTritErrorException(status_code=404, error_message=f"Incorrect OTP code: {otp.code}")

            data: dict = self._admin_api.verify_otp(otp_token=otp.code)
            if user_ref not in self._otp_settings.IGNORE_ACCOUNTS and not data["success"]:
                raise WebTritErrorException(status_code=404, error_message=f"Incorrect OTP code: {otp.code}")

            self._cached_otp_ids.pop(otp_id)

            # Emulate account login.
            account_info: dict = self._admin_api.get_account_info(i_account=i_account)["account_info"]
            session_data: dict = self._account_api.login(account_info["login"], account_info["password"])

            return SessionInfo(
                user_id=UserId(str(account_info["i_account"])),
                access_token=session_data["access_token"],
                refresh_token=session_data["refresh_token"],
                expires_at=datetime.now() + timedelta(seconds=session_data["expires_in"]),
            )

        except WebTritErrorException as error:
            fault_code = extract_fault_code(error)
            if fault_code in ("Server.Session.alert_You_must_change_password",):
                raise WebTritErrorException(
                    status_code=422,
                    # code = OTPUserDataErrorCode.validation_error,
                    error_message="Failed to perform authentication using this account."
                                  "Try changing this account web-password.",
                )

            raise error

    def validate_session(self, access_token: str) -> SessionInfo:
        """Validates whether the provided access token is still valid.

        Parameters:
            access_token (str): The token used to access PortaSwitch API.

        Returns:
            SessionInfo: The object containing the validated session information.

        Raises:
            WebTritErrorException: If the token is invalid, expired, or cannot be verified.
        """
        try:
            self._account_api.decode_and_verify_access_token_expiration(access_token)
            session_data: dict = self._account_api.ping(access_token=access_token)
            user_id = session_data["user_id"]

            if not user_id:
                raise WebTritErrorException(
                    status_code=401,
                    error_message="Access token invalid",
                    code="access_token_invalid",
                )

            return SessionInfo(user_id=UserId(str(user_id)), access_token=AccessToken(access_token))
        except ExpiredSignatureError:
            raise WebTritErrorException(
                status_code=401,
                error_message=f"Access token expired",
                code="access_token_expired",
            )
        except JWTError:
            raise WebTritErrorException(
                status_code=401,
                error_message="Access token invalid",
                code="access_token_invalid",
            )
        except WebTritErrorException as error:
            if extract_fault_code(error) in ("Client.Session.ping.failed_to_process_access_token",):
                raise WebTritErrorException(
                    status_code=401,
                    error_message="Access token invalid",
                    code="access_token_invalid",
                )

            raise error

    def refresh_session(self, refresh_token: str) -> SessionInfo:
        """Refreshes the PortaSwitch account session.

        Parameters:
            refresh_token (str): The token used to refresh the session.

        Returns:
            (SessionInfo): The object with the obtained session tokens.

        """
        try:
            session_data: dict = self._account_api.refresh(refresh_token=refresh_token)
            access_token: str = session_data["access_token"]
            account_info: dict = self._account_api.get_account_info(access_token=access_token)["account_info"]

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
                raise WebTritErrorException(
                    status_code=422,
                    code="refresh_token_invalid",
                    error_message=f"Invalid refresh token {refresh_token}",
                )

            raise error

    def close_session(self, access_token: str) -> bool:
        """Closes the PortaSwitch account session.

        Parameters:
            access_token (str): The token used to close the session.

        Returns:
            bool: True if the session was successfully closed, False otherwise.

        Raises:
            WebTritErrorException: If the session is not found or cannot be closed.
        """
        try:
            return self._account_api.logout(access_token=access_token)["success"] == 1

        except WebTritErrorException as error:
            fault_code = extract_fault_code(error)
            if fault_code in ("Client.Session.logout.failed_to_process_access_token",):
                raise WebTritErrorException(
                    status_code=404,
                    # code = UserAccessErrorCode.session_not_found,
                    error_message=f"Error closing the session {access_token}",
                )

            raise error

    def retrieve_user(self, session: SessionInfo, user: UserInfo) -> EndUser:
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
            account_info: dict = self._account_api.get_account_info(
                access_token=safely_extract_scalar_value(session.access_token)
            )["account_info"]

            aliases: list = self._account_api.get_alias_list(
                access_token=safely_extract_scalar_value(session.access_token)
            )["alias_list"]

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
                # Race condition case, when the session is validated, and then the access_token dies.
                raise WebTritErrorException(
                    status_code=404,
                    # code = UserAccessErrorCode.session_not_found,
                    error_message="User not found",
                )

            raise error

    def retrieve_contacts(self, session: SessionInfo, user: UserInfo) -> list[ContactInfo]:
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
            account_info = self._account_api.get_account_info(access_token)["account_info"]
            i_customer = int(account_info["i_customer"])
            i_account = int(account_info["i_account"])

            contacts = []
            match self._portaswitch_settings.CONTACTS_SELECTING:
                case PortaSwitchContactsSelectingMode.EXTENSIONS:
                    allowed_ext_types = {
                        type.value for type in
                        self._portaswitch_settings.CONTACTS_SELECTING_EXTENSION_TYPES
                    }
                    accounts = self._get_all_accounts_by_customer(i_customer)
                    account_to_aliases = {account["i_account"]: account.get("alias_list", []) for account in accounts}
                    extensions = self._admin_api.get_extensions_list(i_customer)["extensions_list"]

                    for ext in extensions:
                        if ext["type"] in allowed_ext_types and ext.get("i_account") != i_account:
                            aliases = account_to_aliases.get(ext.get("i_account"), [])
                            contacts.append(Serializer.get_contact_info_by_extension(ext, aliases, i_account))
                case PortaSwitchContactsSelectingMode.ACCOUNTS:
                    accounts = self._get_all_accounts_by_customer(i_customer)

                    for account in accounts:
                        if (status := account.get("status")) and status == "blocked":
                            continue
                        dual_version_system = PortaSwitchDualVersionSystem(account.get("dual_version_system"))
                        if dual_version_system != PortaSwitchDualVersionSystem.SOURCE:
                            if (not self._portaswitch_settings.CONTACTS_SKIP_WITHOUT_EXTENSION or account.get(
                                    "extension_id")) and account["i_account"] != i_account:
                                contacts.append(Serializer.get_contact_info_by_account(account, i_account))
                case PortaSwitchContactsSelectingMode.PHONEBOOK:
                    phonebook = self._account_api.get_phonebook_list(access_token, 1, 100)['phonebook_rec_list']

                    # Extract phone numbers from phonebook records
                    phonebook_numbers = set()
                    for record in phonebook:
                        phone_number = record.get("phone_number", "").replace("+", "")
                        if phone_number:
                            phonebook_numbers.add(phone_number)

                    # Get account mapping only for phonebook numbers (on-demand)
                    number_to_accounts = self._get_number_to_customer_accounts_map_for_numbers(phonebook_numbers)

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
                    phone_directories = self._account_api.get_phone_directory_list(access_token, 1, 100)[
                        'phone_directory_list']

                    # Extract phone numbers from phone directory records
                    phone_directory_numbers = set()
                    for directory in phone_directories:
                        directory_info = self._account_api.get_phone_directory_info(
                            access_token,
                            directory['i_ua_config_directory'],
                            1,
                            10_000
                        )['phone_directory_info']
                        for record in directory_info['directory_records']:
                            office_number = record.get("office_number", "").replace("+", "")
                            if office_number:
                                phone_directory_numbers.add(office_number)

                    # Get account mapping only for phone directory numbers (on-demand)
                    number_to_accounts = self._get_number_to_customer_accounts_map_for_numbers(phone_directory_numbers)

                    for directory in phone_directories:
                        directory_info = self._account_api.get_phone_directory_info(
                            access_token,
                            directory['i_ua_config_directory'],
                            1,
                            10_000
                        )['phone_directory_info']
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
                # Race condition case, when the session is validated, and then the access_token dies.
                raise WebTritErrorException(
                    status_code=404,
                    # code = UserAccessErrorCode.session_not_found,
                    error_message="User not found",
                )

            raise error

    def retrieve_contacts_v2(
            self, session: SessionInfo,
            user: UserInfo,
            search: Optional[str] = None,
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
            account_info = self._account_api.get_account_info(access_token)["account_info"]
            i_customer = int(account_info["i_customer"])
            i_account = int(account_info["i_account"])

            contacts = []
            match self._portaswitch_settings.CONTACTS_SELECTING:
                case PortaSwitchContactsSelectingMode.EXTENSIONS:
                    allowed_ext_types = {
                        type.value for type in
                        self._portaswitch_settings.CONTACTS_SELECTING_EXTENSION_TYPES
                    }

                    # For EXTENSIONS mode, we need to get extensions first
                    extensions = self._admin_api.get_extensions_list(i_customer)["extensions_list"]

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

                    # Get accounts for these extension account IDs
                    all_accounts = self._get_all_accounts_by_customer(i_customer)
                    account_to_aliases = {account["i_account"]: account.get("alias_list", []) for account in
                                          all_accounts}

                    # Build contacts from filtered extensions
                    for ext in filtered_extensions:
                        aliases = account_to_aliases.get(ext.get("i_account"), [])
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
                    custom_contacts_count = len(custom_contacts)

                    if search:
                        # Search mode: call get_account_list 4 times with different search parameters
                        search_pattern = f"%{search}%"
                        accounts_dict = {}  # Use dict to store unique accounts by i_account

                        # Search by main number
                        result_main_number = self._admin_api.get_account_list(i_customer, id=search_pattern)
                        accounts_main_number = result_main_number.get("account_list", [])
                        for account in accounts_main_number:
                            accounts_dict[account["i_account"]] = account

                        # Search by firstname
                        result_firstname = self._admin_api.get_account_list(i_customer, firstname=search_pattern)
                        accounts_firstname = result_firstname.get("account_list", [])
                        for account in accounts_firstname:
                            accounts_dict[account["i_account"]] = account

                        # Search by lastname
                        result_lastname = self._admin_api.get_account_list(i_customer, lastname=search_pattern)
                        accounts_lastname = result_lastname.get("account_list", [])
                        for account in accounts_lastname:
                            accounts_dict[account["i_account"]] = account

                        # Search by extension_name
                        result_extension = self._admin_api.get_account_list(i_customer, extension_name=search_pattern)
                        accounts_extension = result_extension.get("account_list", [])
                        for account in accounts_extension:
                            accounts_dict[account["i_account"]] = account

                        # Search by email
                        result_email = self._admin_api.get_account_list(i_customer, email=search_pattern)
                        accounts_email = result_email.get("account_list", [])
                        for account in accounts_email:
                            accounts_dict[account["i_account"]] = account

                        # Use accounts directly from search results
                        accounts = list(accounts_dict.values())
                    else:
                        # Calculate pagination parameters
                        if page == 1 and custom_contacts_count > 0:
                            # On first page, request fewer accounts to account for custom contacts
                            api_limit = max(1, items_per_page - custom_contacts_count)
                            offset = 0
                        else:
                            # On other pages, account for custom contacts that were on first page
                            api_limit = items_per_page
                            offset = (page - 1) * items_per_page - custom_contacts_count
                            offset = max(0, offset)  # Ensure offset is not negative

                        # Get accounts from API with pagination
                        result = self._admin_api.get_account_list(
                            i_customer,
                            limit=api_limit,
                            offset=offset
                        )
                        accounts = result.get("account_list", [])
                        total_count_from_api = result.get("total", 0)

                    # Filter accounts
                    filtered_accounts = []
                    for account in accounts:
                        if (status := account.get("status")) and status == "blocked":
                            continue
                        dual_version_system = PortaSwitchDualVersionSystem(account.get("dual_version_system"))
                        if dual_version_system != PortaSwitchDualVersionSystem.SOURCE:
                            if (not self._portaswitch_settings.CONTACTS_SKIP_WITHOUT_EXTENSION or account.get(
                                    "extension_id")) and account["i_account"] != i_account:
                                filtered_accounts.append(account)

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

                    # Add custom contacts (only on first page for non-search mode)
                    if search or page == 1:
                        account_contacts.extend(custom_contacts)

                    # Apply pagination
                    if search:
                        # For search mode, apply manual pagination after filtering
                        total_count = len(account_contacts)
                        start_idx = (page - 1) * items_per_page
                        end_idx = start_idx + items_per_page
                        contacts = account_contacts[start_idx:end_idx]
                    else:
                        # For non-search mode, pagination is already applied through API
                        # But we need to limit to items_per_page in case custom_contacts made it exceed
                        contacts = account_contacts[:items_per_page]
                        # Total count from API plus custom contacts (only count them once)
                        total_count = total_count_from_api + (len(custom_contacts) if page == 1 else 0)

                case PortaSwitchContactsSelectingMode.PHONEBOOK:
                    phonebook = self._account_api.get_phonebook_list(access_token, 1, 100)['phonebook_rec_list']

                    # Extract phone numbers from phonebook records
                    phonebook_numbers = set()
                    for record in phonebook:
                        phone_number = record.get("phone_number", "").replace("+", "")
                        if phone_number:
                            phonebook_numbers.add(phone_number)

                    # Get account mapping only for phonebook numbers (on-demand)
                    number_to_accounts = self._get_number_to_customer_accounts_map_for_numbers(phonebook_numbers)

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

                    # Add custom contacts before filtering and pagination
                    custom_contacts = [Serializer.get_contact_info_by_custom_entry(entry) for entry in
                                       self._portaswitch_settings.CONTACTS_CUSTOM]
                    contacts.extend(custom_contacts)

                    # If search is provided, filter extensions
                    if search:
                        search_lower = search.lower()
                        contacts = [
                            contact for contact in contacts
                            if any(search_lower in str(value or "").lower() for value in [
                                contact.numbers.main if contact.numbers else None,
                                contact.first_name,
                                contact.last_name,
                                contact.alias_name,
                                contact.email
                            ])
                        ]

                    # Apply pagination
                    total_count = len(contacts)
                    start_idx = (page - 1) * items_per_page
                    end_idx = start_idx + items_per_page
                    contacts = contacts[start_idx:end_idx]

                case PortaSwitchContactsSelectingMode.PHONE_DIRECTORY:
                    phone_directories = self._account_api.get_phone_directory_list(access_token, 1, 100)[
                        'phone_directory_list']

                    # Extract phone numbers from phone directory records
                    phone_directory_numbers = set()
                    for directory in phone_directories:
                        directory_info = self._account_api.get_phone_directory_info(
                            access_token,
                            directory['i_ua_config_directory'],
                            1,
                            10_000
                        )['phone_directory_info']
                        for record in directory_info['directory_records']:
                            office_number = record.get("office_number", "").replace("+", "")
                            if office_number:
                                phone_directory_numbers.add(office_number)

                    # Get account mapping only for phone directory numbers (on-demand)
                    number_to_accounts = self._get_number_to_customer_accounts_map_for_numbers(phone_directory_numbers)

                    for directory in phone_directories:
                        directory_info = self._account_api.get_phone_directory_info(
                            access_token,
                            directory['i_ua_config_directory'],
                            1,
                            10_000
                        )['phone_directory_info']
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
                                contact.first_name,
                                contact.last_name,
                                contact.alias_name,
                                contact.email
                            ])
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
                # Race condition case, when the session is validated, and then the access_token dies.
                raise WebTritErrorException(
                    status_code=404,
                    # code = UserAccessErrorCode.session_not_found,
                    error_message="User not found",
                )

            raise error

    def retrieve_contact_by_user_id(self, session: SessionInfo, user: UserInfo, user_id: str) -> ContactInfo:
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
        account_info = self._admin_api.get_account_info(i_account=int(user_id)).get("account_info")
        if not account_info:
            raise WebTritErrorException(404, f"There is no an account with such id: {user_id}",
                                        code="contact_not_found")

        return Serializer.get_contact_info_by_account(account_info, int(user.user_id))

    def retrieve_calls(
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

            result: dict = self._account_api.get_xdr_list(
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
                # Race condition case, when the session is validated, and then the access_token dies.
                raise WebTritErrorException(
                    status_code=404,
                    # code = UserNotFoundCode.user_not_found,
                    error_message="User not found",
                )

            raise error

    def retrieve_call_recording(self, session: SessionInfo, call_recording: CallRecordingId) -> tuple[str, Iterator]:
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
        try:
            recording_id = safely_extract_scalar_value(call_recording)

            return self._account_api.get_call_recording(
                access_token=safely_extract_scalar_value(session.access_token), recording_id=recording_id
            )

        except WebTritErrorException as error:
            fault_code = extract_fault_code(error)
            if fault_code in ("Server.CDR.xdr_not_found", "Server.CDR.invalid_call_recording_id",):
                raise WebTritErrorException(
                    status_code=404,
                    error_message="The recording with such a recording_id is not found.",
                )

            raise error

    def retrieve_voicemails(self, session: SessionInfo, user: UserInfo) -> UserVoicemailsResponse:
        """Returns the user's voicemail messages.

        Parameters:
            session (SessionInfo): The session of the PortaSwitch account.
            user (UserInfo): The information about the PortaSwitch account.

        Returns:
            UserVoicemailsResponse: Structure containing voicemail messages and a new message flag.

        Raises:
            WebTritErrorException: If the user is not found or the session is invalid.
        """
        try:
            mailbox_messages = self._account_api.get_mailbox_messages(
                safely_extract_scalar_value(session.access_token)
            )
            voicemail_messages = [Serializer.get_voicemail_message(message) for message in mailbox_messages]

            return UserVoicemailsResponse(
                messages=voicemail_messages, has_new_messages=any(not message.seen for message in voicemail_messages)
            )

        except WebTritErrorException as error:
            fault_code = extract_fault_code(error)
            if fault_code in ("Client.Session.check_auth.failed_to_process_access_token",):
                raise WebTritErrorException(status_code=404, error_message="User not found")

            raise error

    def retrieve_voicemail_message_details(
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
            message_details = self._account_api.get_mailbox_message_details(
                safely_extract_scalar_value(session.access_token), message_id
            )

            return Serializer.get_voicemail_message_details(message_details)

        except WebTritErrorException as error:
            fault_code = extract_fault_code(error)
            if fault_code in ("Client.Session.check_auth.failed_to_process_access_token",):
                raise WebTritErrorException(status_code=404, error_message="User not found")

            raise error

    def retrieve_voicemail_message_attachment(
            self, session: SessionInfo, message_id: str, file_format: str
    ) -> tuple[str, Iterator]:
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
            raise WebTritErrorException(422, "Not supported file format", code="unsupported_file_format")

        try:
            return self._account_api.get_mailbox_message_attachment(
                safely_extract_scalar_value(session.access_token),
                message_id,
                file_format or PortaSwitchMailboxMessageAttachmentFormat.WAV.value,
            )

        except WebTritErrorException as error:
            fault_code = extract_fault_code(error)
            if fault_code in ("Client.Session.check_auth.failed_to_process_access_token",):
                raise WebTritErrorException(404, "User not found")

            raise error

    def patch_voicemail_message(
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
            self._account_api.set_mailbox_message_flag(
                safely_extract_scalar_value(session.access_token),
                message_id,
                PortaSwitchMailboxMessageFlag.SEEN,
                PortaSwitchMailboxMessageFlagAction.SET if seen else PortaSwitchMailboxMessageFlagAction.UNSET,
            )

            return UserVoicemailMessagePatch(seen=seen)

        except WebTritErrorException as error:
            fault_code = extract_fault_code(error)
            if fault_code in ("Client.Session.check_auth.failed_to_process_access_token",):
                raise WebTritErrorException(status_code=404, error_message="User not found")

            raise error

    def delete_voicemail_message(self, session: SessionInfo, message_id: str) -> None:
        """Delete an existing voicemail message.

        Parameters:
            session (SessionInfo): The session of the PortaSwitch account.
            message_id (str): The unique ID of the voicemail message.

        Raises:
            WebTritErrorException: If the user is not found or the session is invalid.
        """
        try:
            self._account_api.delete_mailbox_message(safely_extract_scalar_value(session.access_token), message_id)

        except WebTritErrorException as error:
            fault_code = extract_fault_code(error)
            if fault_code in ("Client.Session.check_auth.failed_to_process_access_token",):
                raise WebTritErrorException(status_code=404, error_message="User not found")

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

    def signup(self, user_data, tenant_id: str = None) -> SessionResponse:
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
            raise WebTritErrorException(422, "Missing required access or refresh token parameters")

        try:
            account_info = self._account_api.get_account_info(access_token=access_token)["account_info"]

            return SessionResponse(
                user_id=UserId(str(account_info["i_account"])),
                access_token=AccessToken(access_token),
                refresh_token=refresh_token,
            )
        except WebTritErrorException as error:
            if extract_fault_code(error) == "Client.Session.check_auth.failed_to_process_access_token":
                raise WebTritErrorException(status_code=404, error_message="User not found")

            raise error

    def custom_method_public(
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

            return method(data=data, lang=lang)
        else:
            raise WebTritErrorException(
                status_code=404, error_message=f"Method '{method_name}' not found", code="method_not_found"
            )

    def custom_method_private(
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

            return method(user_id=user_id, data=data, lang=lang)
        else:
            raise WebTritErrorException(
                status_code=404, error_message=f"Method '{method_name}' not found", code="method_not_found"
            )

    # region custom methods handlers

    def _custom_pages(self, user_id: str, data: CustomRequest, lang: str = None) -> CustomResponse:
        _ = get_translation_func(lang)
        account_info = self._admin_api.get_account_info(i_account=user_id).get("account_info")
        session_data = self._account_api.login(account_info["login"], account_info["password"])

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

    def _external_page_access_token(self, user_id: str, data: CustomRequest, lang: str = None) -> CustomResponse:
        account_info = self._admin_api.get_account_info(i_account=user_id).get("account_info")
        session_data = self._account_api.login(account_info["login"], account_info["password"])

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
            raise WebTritErrorException(403, "Access denied: required add-on not assigned", code="addon_required")

    def _get_number_to_customer_accounts_map_for_numbers(self, target_numbers: set[str]) -> dict[str, dict]:
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
                        accounts = self._admin_api.get_account_list(int(customer_id), limit=limit, offset=offset)
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
                    account_info = self._admin_api.get_account_info(id=number, detailed_info=1).get("account_info")
                    if account_info:
                        number_to_accounts[number] = account_info
                except Exception as e:
                    logging.debug(f"Account not found for number {number}: {e}")
                    continue

        logging.debug(f"Found {len(number_to_accounts)} accounts out of {len(target_numbers)} target numbers")
        return number_to_accounts

    def _get_all_accounts_by_customer(self, i_customer: int) -> list[dict]:
        """Fetch all accounts for a customer using pagination.

        Parameters:
            i_customer (int): The unique identifier of the customer.

        Returns:
            list[dict]: List of all account records for the specified customer.
        """
        all_accounts: list[dict] = []
        offset = 0
        limit = 1000

        while True:
            resp = self._admin_api.get_account_list(i_customer, limit=limit, offset=offset)
            page = resp.get("account_list", []) if isinstance(resp, dict) else []
            total = resp.get("total") if isinstance(resp, dict) else None

            all_accounts.extend(page)

            # Stop if we've reached the total or the page is shorter than the limit
            if total is not None and len(all_accounts) >= int(total):
                break
            if len(page) < limit:
                break

            offset += limit

        return all_accounts
