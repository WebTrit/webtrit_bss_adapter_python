import logging
import uuid
from pprint import pformat
from datetime import datetime, timedelta

from app_config import AppConfig
from bss.adapters import BSSAdapter
from bss.dbs import TiedKeyValue
from bss.sessions import SessionInfo
from bss.types import (
    CallRecordingId, Capabilities, CDRInfo, ContactInfo, EndUser,
    OTPCreateResponse, OTPVerifyRequest,
    SessionInfo, UserInfo, 
    safely_extract_scalar_value)
from report_error import raise_webtrit_error, WebTritErrorException

from .account_api import AccountAPI
from .admin_api import AdminAPI
from .serializer import Serializer


# class FreePBXAdapter(BSSAdapter, SampleOTPHandler):
class Adapter(BSSAdapter):
    """Connects WebTrit and PortaSwitch. Authenticate a user using his/her data in PortaSwitch,
    retrieve user's SIP credentials to be used by WebTrit and return a list of other configured
    extenstions (to be provided as 'Cloud PBX' contacts).
    Currently does not support OTP login.

    """
    #: str: The version of the adapter.
    VERSION = "0.0.1"

    def __init__(self, config: AppConfig):
        super().__init__(config)

        self.__admin_api: AdminAPI = AdminAPI(config)
        self.__account_api: AccountAPI = AccountAPI(config)

        sip_server_host = config.get_conf_val('PortaSwitch', 'SIP', 'Server', 'host',
                                              default='127.0.0.1')
        sip_server_port = config.get_conf_val('PortaSwitch', 'SIP', 'Server', 'port',
                                              default=5060)

        self.__serializer = Serializer(sip_server_host = sip_server_host,
                                       sip_server_port = sip_server_port)

        # No need to store it in a DB.
        # The currect realization of PortaSwitch token validation depends on session.
        # If we need to verify the OTP token after this service restart - we also need to store
        # the admin API session into the DB.
        self.__opt_id_storage = TiedKeyValue()

    @staticmethod
    def name() -> str:
        """Returns the name of the adapter."""
        return 'PortaSwitch adapter'

    @staticmethod
    def version() -> str:
        """Returns the version of the adapter."""
        return Adapter.VERSION

    def get_capabilities(self) -> list[str]:
        """Returns the capabilities of this API adapter."""
        return [
            # log in user using one-time-password generated on the BSS side
            Capabilities.otpSignin,

            # log in user with username / password
            Capabilities.passwordSignin,

            # download call recordings - currently not supported
            Capabilities.recordings,

            # obtain user's call history
            Capabilities.callHistory,

            # obtain the list of other extensions in the PBX
            Capabilities.extensions,
        ]

    def __extract_faultcode(self, error: WebTritErrorException) -> str:
        """Extracts API faultcode from the input exception.

        Parameters:
            :error (WebTritErrorException): An exception to be analyzed.

        Returns:
            :(str): The parsed faultcode.

        """
        bss_response_trace = error.bss_response_trace
        if not bss_response_trace:
            # Exception not from http_api.HTTPAPIConnector. Why?
            raise error

        response_content = bss_response_trace['response_content']
        if not response_content:
            # No response from the server.
            raise error

        faultcode = response_content.get('faultcode')
        if not faultcode:
            # No faultcode, Why?
            raise error

        return faultcode

    def authenticate(self, user: UserInfo, password: str = None) -> SessionInfo:
        """Authenticate a PortaSwitch account with login and password and obtain an API token for
        further requests.

        Parameters:
            :user (UserInfo): The information about the account to be logged in.
            :password (str): The password of the account to be verified.

        Returns:
            :(SessionInfo): The object with the obtained session tokens.

        """
        try:
            session_data: dict = self.__account_api.login(user.login, password)
            access_token: str = session_data['access_token']
            account_info: dict = self.__account_api.get_account_info(
                    access_token = access_token)['account_info']

            return SessionInfo(
                user_id = account_info['i_account'],
                access_token = session_data['access_token'],
                refresh_token = session_data['refresh_token'],
                expires_at = datetime.now() + timedelta(seconds = session_data['expires_in']),
            )

        except WebTritErrorException as error:
            faultcode = self.__extract_faultcode(error)
            if faultcode in ('Server.Session.auth_failed',
                             'Server.Session.cannot_login_brute_force_activity',
                             'Client.Session.check_auth.failed_to_process_access_token'):

                raise WebTritErrorException(
                    status_code = 401,
                    # code = FailedAuthCode.incorrect_credentials,
                    error_message = "User authentication error",
                )

            raise error

        except (KeyError, TypeError):
            ## Incorrect data from PortaSwitch API. Has the backward compatibility been broken?
            raise WebTritErrorException(
                status_code = 500,
                # code = APIAccessErrorCode.external_api_issue,
                error_message = "Incorrect data from the Adaptee system",
            )

    def validate_session(self, access_token: str) -> SessionInfo:
        """Checks whether the input access_token is valid.

        Parameters:
            :access_token (str): The token used to access PortaSwitch API.

        Returns:
            :(SessionInfo): The object with the obtained session tokens.

        """
        try:
            session_data: dict = self.__account_api.ping(access_token = access_token)

            return SessionInfo(
                user_id = session_data['user_id'],
                access_token = access_token,
            )

        except WebTritErrorException as error:
            faultcode = self.__extract_faultcode(error)
            if faultcode in ('Client.Session.ping.failed_to_process_access_token',):
                raise WebTritErrorException(
                    status_code = 401,
                    # code = APIAccessErrorCode.authorization_header_missing,
                    error_message = f"Invalid access token {access_token}",
                )

            raise error

        except (KeyError, TypeError):
            ## Incorrect data from PortaSwitch API. Has the backward compatibility been broken?
            raise WebTritErrorException(
                status_code = 500,
                # code = APIAccessErrorCode.external_api_issue,
                error_message = "Incorrect data from the Adaptee system",
            )

    def refresh_session(self, refresh_token: str) -> SessionInfo:
        """Refreshes the PortaSwitch account session.

        Parameters:
            :refresh_token (str): The token used to refresh the session.

        Returns:
            :(SessionInfo): The object with the obtained session tokens.

        """
        try:
            session_data: dict = self.__account_api.refresh(refresh_token = refresh_token)
            access_token: str = session_data['access_token']
            account_info: dict = self.__account_api.get_account_info(
                    access_token = access_token)['account_info']

            return SessionInfo(
                user_id = account_info['i_account'],
                access_token = session_data['access_token'],
                refresh_token = session_data['refresh_token'],
                expires_at = datetime.now() + timedelta(seconds = session_data['expires_in']),
            )

        except WebTritErrorException as error:
            faultcode = self.__extract_faultcode(error)
            if faultcode in ('Server.Session.refresh_access_token.refresh_failed',
                             'Client.Session.check_auth.failed_to_process_access_token'):
                raise WebTritErrorException(
                    status_code = 404,
                    # code = SessionNotFoundCode.session_not_found,
                    error_message = f"Invalid refresh token {refresh_token}",
                )

            raise error

        except (KeyError, TypeError):
            ## Incorrect data from PortaSwitch API. Has the backward compatibility been broken?
            raise WebTritErrorException(
                status_code = 500,
                # code = APIAccessErrorCode.external_api_issue,
                error_message = "Incorrect data from the Adaptee system",
            )

    def close_session(self, access_token: str) -> bool:
        """Closes the PortaSwitch account session.

        Parameters:
            :access_token (str): The token used to close the session.

        Returns:
            :(bool): Shows whether is succeeded to close the session.

        """
        try:
            return self.__account_api.logout(access_token = access_token)['success'] == 1

        except WebTritErrorException as error:
            faultcode = self.__extract_faultcode(error)
            if faultcode in ('Client.Session.logout.failed_to_process_access_token',):
                raise WebTritErrorException(
                    status_code = 404,
                    # code = UserAccessErrorCode.session_not_found,
                    error_message = f'Error closing the session {access_token}',
                )

            raise error

        except (KeyError, TypeError):
            ## Incorrect data from PortaSwitch API. Has the backward compatibility been broken?
            raise WebTritErrorException(
                status_code = 500,
                # code = APIAccessErrorCode.external_api_issue,
                error_message = "Incorrect data from the Adaptee system",
            )

    def retrieve_user(self, session: SessionInfo, user: UserInfo) -> EndUser:
        """Returns information about the PortaSwitch account in WebTrit representation.

        Parameters:
            :session (SessionInfo): The session of the PortaSwitch account.
            :user (UserInfo): The information about the PortaSwitch account.

        Returns:
            :(EndUser): Fetched information about the PortaSwitch account in WebTrit representation.

        """
        try:
            account_info: dict = self.__account_api.get_account_info(
                    access_token = safely_extract_scalar_value(session.access_token))['account_info']

            aliases: list = self.__account_api.get_alias_list(
                    access_token = safely_extract_scalar_value(session.access_token))['alias_list']

            return self.__serializer.get_end_user(account_info, aliases)

        except WebTritErrorException as error:
            faultcode = self.__extract_faultcode(error)
            if faultcode in ('Client.Session.check_auth.failed_to_process_access_token',):
                # Race condition case, when session is validated and then the access_token dies.
                raise WebTritErrorException(
                    status_code = 404,
                    # code = UserAccessErrorCode.session_not_found,
                    error_message ="User not found"
                )

            raise error

        except (KeyError, TypeError) as e:
            ## Incorrect data from PortaSwitch API. Has the backward compatibility been broken?
            raise WebTritErrorException(
                status_code = 500,
                # code = APIAccessErrorCode.external_api_issue,
                error_message = f"Incorrect data from the Adaptee system {e}",
            )

    def retrieve_contacts(self, session: SessionInfo, user: UserInfo) -> list[ContactInfo]:
        """Returns information about other extentions of the same PortaSwitch customer.

        Parameters:
            :session (SessionInfo): The session of the PortaSwitch account.
            :user (UserInfo): The information about the PortaSwitch account.

        Returns:
            :(list[ContactInfo]): Fetched information about other extentions of the same PortaSwitch
                customer in the WebTrit representation.

        """
        try:
            ## Extract i_customer
            account_info: dict = self.__account_api.get_account_info(
                    access_token = safely_extract_scalar_value(session.access_token))['account_info']

            accounts: list = self.__admin_api.get_account_list(
                    i_customer= int(account_info['i_customer']))['account_list']

            return [self.__serializer.get_contact_info(account) for account in accounts]

        except WebTritErrorException as error:
            faultcode = self.__extract_faultcode(error)
            if faultcode in ('Client.Session.check_auth.failed_to_process_access_token',):
                # Race condition case, when session is validated and then the access_token dies.
                raise WebTritErrorException(
                    status_code = 404,
                    # code = UserAccessErrorCode.session_not_found,
                    error_message ="User not found"
                )

            raise error

        except (KeyError, TypeError):
            ## Incorrect data from PortaSwitch API. Has the backward compatibility been broken?
            raise WebTritErrorException(
                status_code = 500,
                # code = APIAccessErrorCode.external_api_issue,
                error_message = "Incorrect data from the Adaptee system",
            )

    def retrieve_calls(self, session: SessionInfo, user: UserInfo, page: int,
                       items_per_page: int, time_from: datetime|None = None,
                       time_to: datetime|None = None,) -> tuple[list[CDRInfo], int]:
        """Returns the CDR history of the logged in PortaSwitch account.

        Parameters:
            :session (SessionInfo): The session of the PortaSwitch account.
            :user (UserInfo): The information about the PortaSwitch account.
            :page (int): Shows what page of the CDR history to return.
            :items_per_page (int): Shows the number of items to return.
            :time_from (datetime|None): Filters the time frame of the CDR history.
            :time_to (datetime|None): Filters the time frame of the CDR history.

        Returns:
            :(tuple[list[CDRInfo], int]): Fetched CDR history and the number of total records
                that are located in the DB without taking into account the pagination.

        """
        try:
            time_from: datetime = time_from if time_from else datetime(1970, 1, 1)
            time_to: datetime = time_to if time_to else datetime(9000, 1, 1)

            result: dict = self.__account_api.get_xdr_list(
                    access_token = safely_extract_scalar_value(session.access_token),
                    page = page,
                    items_per_page = items_per_page,
                    time_from = time_from,
                    time_to = time_to)

            return ([self.__serializer.get_cdr_info(cdr) for cdr in result['xdr_list']],
                    result['total'])

        except WebTritErrorException as error:
            faultcode = self.__extract_faultcode(error)
            if faultcode in ('Client.Session.check_auth.failed_to_process_access_token',):
                # Race condition case, when session is validated and then the access_token dies.
                raise WebTritErrorException(
                    status_code = 404,
                    # code = UserNotFoundCode.user_not_found,
                    error_message ="User not found"
                )

            raise error

        except (KeyError, TypeError):
            ## Incorrect data from PortaSwitch API. Has the backward compatibility been broken?
            raise WebTritErrorException(
                status_code = 500,
                # code = APIAccessErrorCode.external_api_issue,
                error_message = "Incorrect data from the Adaptee system",
            )

    def retrieve_call_recording(self, session: SessionInfo,
                                call_recording: CallRecordingId) -> bytes:
        """Returns the binary representation of the recorded call.

        Parameters:
            :session (SessionInfo): The session of the PortaSwitch account.
            :call_recording (CallRecordingId): Contains an identifier of a call recording record.

        Returns:
            :(bytes): Raw bytes of a call recording file.

        """
        try:
            recording_id = safely_extract_scalar_value(call_recording)

            return self.__account_api.get_call_recording(
                    access_token = safely_extract_scalar_value(session.access_token),
                    recording_id = recording_id)

        except WebTritErrorException as error:
            faultcode = self.__extract_faultcode(error)
            if faultcode in ('Server.CDR.xdr_not_found',):
                # Race condition case, when session is validated and then the access_token dies.
                raise WebTritErrorException(
                    status_code = 404,
                    # code = UserAccessErrorCode.session_not_found,
                    error_message = "The recording with such a recording_id is not found."
                )

            raise error

        except (KeyError, TypeError):
            ## Incorrect data from PortaSwitch API. Has the backward compatibility been broken?
            raise WebTritErrorException(
                status_code = 500,
                # code = APIAccessErrorCode.external_api_issue,
                error_message = "Incorrect data from the Adaptee system",
            )

    def __generate_otp_id(self) -> str:
        """Generate a new unique ID for the session"""
        return str(uuid.uuid1()).replace("-", "") + str(uuid.uuid4()).replace("-", "")

    def generate_otp(self, user: UserInfo) -> OTPCreateResponse:
        """Requests PortaSwitch to generate OTP.

        Parameters:
            :user (UserInfo): The object containing user_ref.

        Returns:
            :(OTPCreateResponse): Information about the created OTP.
                In our case, PortaSwitch does not return any valueable info.
                We return here a dummy otp_id. So, when PortaSwitch supported returning the
                otp_id, we would not break the interface.

        """
        try:
            success: int = self.__admin_api.create_otp(user_ref = user.user_id)['success']

            if success == 0:
                raise WebTritErrorException(
                    status_code = 500,
                    # code = APIAccessErrorCode.external_api_issue,
                    error_message = 'Unknown error',
                )

            otp_id: str = self.__generate_otp_id()
            self.__opt_id_storage[otp_id] = int(user.user_id)

            return OTPCreateResponse(otp_id = otp_id)

        except WebTritErrorException as error:
            faultcode = self.__extract_faultcode(error)
            if faultcode in ('Server.AccessControl.empty_rec_and_bcc',):
                raise WebTritErrorException(
                    status_code = 404,
                    # code = UserAccessErrorCode.user_not_found,
                    error_message = f"There is no an account with such a i_account: {user.user_id}"
                )

            raise error

        except (KeyError, TypeError):
            ## Incorrect data from PortaSwitch API. Has the backward compatibility been broken?
            raise WebTritErrorException(
                status_code = 500,
                # code = APIAccessErrorCode.external_api_issue,
                error_message = "Incorrect data from the Adaptee system",
            )

    def validate_otp(self, otp: OTPVerifyRequest) -> SessionInfo:
        """Requests PortaSwitch to generate OTP.

        Parameters:
            :otp (OTPVerifyRequest): The object containing OTP token to be verified.

        Returns:
            :(OTPCreateResponse): Information about the created OTP.
                In our case, PortaSwitch does not return any valueable info.
                We return here a dummy otp_id. So, when PortaSwitch supported returning the
                otp_id, we would not break the interface.

        """
        try:
            # PortaSwitch API does not operate with otp_id.
            # We need the otp_id only for storing the i_account.
            otp_id = safely_extract_scalar_value(otp.otp_id)

            if not otp_id in self.__opt_id_storage:
                raise WebTritErrorException(
                    status_code = 404,
                    # code = OTPNotFoundErrorCode.otp_not_found,
                    error_message = f"Incorrect OTP code: {otp.code}"
                )

            data: dict = self.__admin_api.verify_otp(otp_token = otp.code)
            success: int = data['success']

            if success == 0:
                raise WebTritErrorException(
                    status_code = 404,
                    # code = OTPNotFoundErrorCode.otp_not_found,
                    error_message = f"Incorrect OTP code: {otp.code}"
                )

            i_account: int = self.__opt_id_storage.pop(otp_id)

            # Emulate account login.
            account_info: dict = self.__admin_api.get_account_info(
                    i_account = i_account)['account_info']

            session_data: dict = self.__account_api.login(
                    account_info['login'], account_info['password'])

            return SessionInfo(
                user_id = account_info['i_account'],
                access_token = session_data['access_token'],
                refresh_token = session_data['refresh_token'],
                expires_at = datetime.now() + timedelta(seconds = session_data['expires_in']),
            )

        except WebTritErrorException as error:
            faultcode = self.__extract_faultcode(error)
            if faultcode in ('Server.Session.alert_You_must_change_password',):
                raise WebTritErrorException(
                    status_code = 422,
                    # code = OTPUserDataErrorCode.validation_error,
                    error_message = "Failed to perform authentication using this account."
                        "Try changing this account web-password."
                )

            raise error

        except (KeyError, TypeError):
            ## Incorrect data from PortaSwitch API. Has the backward compatibility been broken?
            raise WebTritErrorException(
                status_code = 500,
                # code = APIAccessErrorCode.external_api_issue,
                error_message = "Incorrect data from the Adaptee system",
            )

    def create_new_user(self, user_data, tenant_id: str = None):
        """Create a new user as a part of the sign-up process - not supported yet"""
        raise NotImplementedError()
