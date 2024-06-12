import datetime
from typing import Optional

from .types import PortaSwitchMailboxMessageFlag
from bss.types import (
    Balance, BalanceType, CDRInfo, ConnectStatus, ContactInfo, Direction, EndUser, Numbers, SIPInfo,
    SIPRegistrationStatus, SIPServer, UserServiceActiveStatus, VoicemailMessage, VoicemailMessageType)

#: dict: Contains a map between a PortaSwitch AccountInfo.billing_model and BalanceType.
BILLING_MODEL_MAP: dict = {
    -1: BalanceType.prepaid,  # debit account
    0: BalanceType.inapplicable,  # voucher
    1: BalanceType.postpaid,  # credit account
    2: BalanceType.unknown,  # alias
    4: BalanceType.unknown,  # beneficiary
}


class Serializer:
    """Convers PortaSwitch API objects to WebTrit ones."""
    #: str: The hostname of the related PortaSIP server.
    __sip_server_host = ''
    #: int: The port address of the related PortaSIP server.
    __sip_server_port = 5060

    def __init__(self, sip_server_host: str, sip_server_port: int):
        """The class constructor.

        Parameters:
            :sip_server_host (str): The hostname of the related PortaSIP server.
            :sip_server_port (str): The port address of the related PortaSIP server.

        """
        self.__sip_server_host = sip_server_host
        self.__sip_server_port = sip_server_port

    def get_end_user(self, account_info: dict, aliases: list) -> EndUser:
        """Forms EndUser based on the input account_info and its aliases.

        Parameters:
            account_info :dict: The information about the account to be added to EndUser.
            aliases :list: The information about aliases of the account to be added to EndUser.

        Returns:
            Response :EndUser: The filled structure of EndUser.
        """
        return EndUser(
            alias_name=None,  # TODO: shall we fill it?
            balance=Balance(
                amount=account_info['balance'],
                balance_type=BILLING_MODEL_MAP.get(account_info['billing_model'],
                                                   BalanceType.unknown),
                credit_limit=account_info.get('credit_limit'),
                currency=account_info['iso_4217'],
            ),
            company_name=account_info.get('customer_name'),
            email=account_info.get('email'),
            first_name=account_info.get('firstname'),
            last_name=account_info.get('lastname'),
            numbers=Numbers(
                additional=[alias['id'] for alias in aliases],
                ext=account_info.get('extension_id'),
                main=account_info['id'],
            ),
            sip=SIPInfo(
                auth_username=account_info['id'],
                display_name=self.compose_display_name(account_info.get('firstname'), account_info.get('lastname')),
                password=account_info['h323_password'],
                sip_server=SIPServer(
                    force_tcp=False,
                    host=self.__sip_server_host,
                    port=self.__sip_server_port,
                ),
                username=account_info['id'],
            ),
            status=UserServiceActiveStatus.active
            if account_info['is_active'] == 1
            else UserServiceActiveStatus.blocked,
            time_zone=account_info['time_zone_name'],
        )

    @staticmethod
    def get_contact_info_by_account(account_info: dict, current_user: int) -> ContactInfo:
        """Forms ContactInfo based on the input account_info.
            Parameters:
                account_info: dict: The information about the account to be added to ContactInfo.
                current_user: int: i_account of the current user who making the request.

            Returns:
                ContactInfo: The filled structure of ContactInfo.
        """

        return ContactInfo(
            alias_name='',  # TODO: shall we fill it?
            company_name=account_info.get('companyname', ''),  # TODO: PortaSwitch sometimes does
            # not return it. Why?
            email=account_info.get('email', None),
            first_name=account_info.get('firstname', ''),
            last_name=account_info.get('lastname', ''),
            numbers=Numbers(
                additional=[alias['id'] for alias in account_info.get('alias_list', [])],
                ext=account_info.get('extension_id', ''),
                main=account_info['id'],
            ),
            sip_status=SIPRegistrationStatus.registered
            if account_info['sip_status'] == 1
            else SIPRegistrationStatus.notregistered,
            is_current_user=account_info['i_account'] == current_user,
        )

    @staticmethod
    def get_contact_info_by_extension(extension_info: dict, aliases: list, current_user: int) -> ContactInfo:
        """Forms ContactInfo based on the input extension_info.
            Parameters:
                extension_info: dict: The information about the extensions to be added to ContactInfo.
                aliases: list: List of additional numbers.
                current_user: int: i_account of the current user who making the request.

            Returns:
                ContactInfo: The filled structure of ContactInfo.
        """

        return ContactInfo(
            alias_name=extension_info.get('name', ''),
            first_name=extension_info.get('firstname', ''),
            last_name=extension_info.get('lastname', ''),
            numbers=Numbers(
                additional=aliases,
                ext=extension_info.get('id'),
                main=extension_info.get('id'),
            ),
            is_current_user=extension_info.get('i_account') == current_user
        )

    @staticmethod
    def get_voicemail_message(mailbox_message: dict) -> VoicemailMessage:
        """
        Forms VoicemailMessage based on the input mailbox_message.
            Parameters:
                mailbox_message: dict: The message from the account mailbox.

             Returns:
                VoicemailMessage: The filled structure of VoicemailMessage.
        """

        return VoicemailMessage(
            id=str(mailbox_message['message_uid']),
            type=VoicemailMessageType.FAX if mailbox_message.get('fax_pages') else VoicemailMessageType.VOICE,
            duration=mailbox_message.get('voicemail_duration'),
            date=datetime.datetime.strptime(mailbox_message['delivery_date'], "%d-%b-%Y %H:%M:%S %z"),
            seen=PortaSwitchMailboxMessageFlag.SEEN.value in mailbox_message.get('flags', [])
        )

    @staticmethod
    def get_cdr_info(cdr_info: dict) -> CDRInfo:
        """Forms CDRInfo based on the input cdr_info.

        Parameters:
            :cdr_info (dict): The information about the CDR to be added to CDRInfo.

        Returns:
            :(CDRInfo): The filled structure of CDRInfo.

        """
        return CDRInfo(
            call_id=cdr_info['call_id'],
            caller=cdr_info['CLI'],
            callee=cdr_info['CLD'],
            connect_time=datetime.datetime.fromtimestamp(int(cdr_info['unix_connect_time']),
                                                         datetime.timezone.utc),
            direction=Direction.incoming,  # TODO determine the value according to CDR.
            disconnect_reason=cdr_info['disconnect_reason'],
            disconnect_time=datetime.datetime.fromtimestamp(int(cdr_info['unix_disconnect_time']),
                                                            datetime.timezone.utc),
            duration=cdr_info['charged_quantity'],
            recording_id=cdr_info['i_xdr'],  # our Admin UI downloads recordings by this.
            status=ConnectStatus.accepted,  # TODO determine the value according to CDR.
        )

    @staticmethod
    def compose_display_name(first_name: Optional[str], last_name: Optional[str]) -> str:
        """Forms display name based on the input first_name and last_name.

            Parameters:
                first_name :str: Account first name.
                last_name :str: Account last name.

            Returns:
                Response :str: The formed display name string.
        """
        return f"{first_name or ''} {last_name or ''}".strip()
