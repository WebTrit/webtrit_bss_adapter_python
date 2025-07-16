from datetime import datetime, timezone
from typing import Optional

from bss.models import SIPTransport
from bss.types import (
    Balance,
    BalanceType,
    CDRInfo,
    ConnectStatus,
    ContactInfo,
    EndUser,
    Numbers,
    SIPInfo,
    SIPRegistrationStatus,
    SIPServer,
    UserServiceActiveStatus,
    VoicemailMessage,
    VoicemailMessageType,
    VoicemailMessageDetails,
    VoicemailMessageAttachment,
    Direction,
)

from .types import PortaSwitchMailboxMessageFlag

#: dict: Contains a map between a PortaSwitch AccountInfo.billing_model and BalanceType.
BILLING_MODEL_MAP: dict = {
    -1: BalanceType.prepaid,  # debit account
    0: BalanceType.inapplicable,  # voucher
    1: BalanceType.postpaid,  # credit account
    2: BalanceType.unknown,  # alias
    4: BalanceType.unknown,  # beneficiary
}


class Serializer:
    """Converts PortaSwitch API objects to WebTrit ones."""

    @staticmethod
    def get_end_user(
            account_info: dict, aliases: list, sip_server: SIPServer, hide_balance: bool, force_tcp: bool
    ) -> EndUser:
        """Forms EndUser based on the input account_info and its aliases.

        Parameters:
            account_info :dict: The information about the account to be added to EndUser.
            aliases :list: The information about aliases of the account to be added to EndUser.
            hide_balance :bool: Ensures that the end user object hides balance

        Returns:
            Response :EndUser: The filled structure of EndUser.
        """
        return EndUser(
            alias_name=None,  # TODO: shall we fill it?
            balance=(
                None
                if hide_balance
                else Balance(
                    amount=account_info["balance"],
                    balance_type=BILLING_MODEL_MAP.get(account_info["billing_model"], BalanceType.unknown),
                    credit_limit=account_info.get("credit_limit"),
                    currency=account_info["iso_4217"],
                )
            ),
            company_name=account_info.get("customer_name"),
            email=account_info.get("email"),
            first_name=account_info.get("firstname"),
            last_name=account_info.get("lastname"),
            numbers=Numbers(
                additional=[alias["id"] for alias in aliases],
                ext=account_info.get("extension_id"),
                main=account_info["id"],
                sms=[number["did_number"] for number in account_info.get("alias_did_number_list", [])],
            ),
            sip=SIPInfo(
                username=account_info["id"],
                auth_username=account_info["id"],
                password=account_info["h323_password"],
                display_name=Serializer.compose_display_name(
                    account_info.get("firstname"), account_info.get("lastname")
                ),
                sip_server=sip_server,
                transport=SIPTransport.TCP if force_tcp else SIPTransport.UDP,
            ),
            status=(
                UserServiceActiveStatus.active if account_info["is_active"] == 1 else UserServiceActiveStatus.blocked
            ),
            time_zone=account_info["time_zone_name"],
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
            user_id=account_info["i_account"],
            is_current_user=account_info["i_account"] == current_user,
            alias_name="",  # TODO: shall we fill it?
            company_name=account_info.get("companyname", ""),  # TODO: PortaSwitch sometimes does
            email=account_info.get("email", None),
            first_name=account_info.get("firstname", ""),
            last_name=account_info.get("lastname", ""),
            numbers=Numbers(
                additional=[alias["id"] for alias in account_info.get("alias_list", [])],
                ext=account_info.get("extension_id", ""),
                main=account_info["id"],
                sms=[number["did_number"] for number in account_info.get("alias_did_number_list", [])],
            ),
            sip_status=(
                SIPRegistrationStatus.registered
                if account_info["sip_status"] == 1
                else SIPRegistrationStatus.notregistered
            ),
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
            user_id=extension_info.get("i_account"),
            is_current_user=extension_info.get("i_account") == current_user,
            alias_name=extension_info.get("name", ""),
            first_name=extension_info.get("firstname", ""),
            last_name=extension_info.get("lastname", ""),
            numbers=Numbers(
                additional=aliases,
                ext=extension_info.get("id"),
                main=extension_info.get("id"),
                sms=[number["did_number"] for number in extension_info.get("alias_did_number_list", [])],
            ),
        )

    @staticmethod
    def get_contact_info_by_phonebook_record(phonebook_record_info: dict) -> ContactInfo:
        """Forms ContactInfo based on the input phonebook_record.
        Parameters:
            phonebook_record_info: dict: The information about the phonebook record to be added to ContactInfo.

        Returns:
            ContactInfo: The filled structure of ContactInfo.
        """

        return ContactInfo(
            alias_name=phonebook_record_info.get("name", ""),
            numbers=Numbers(
                main=phonebook_record_info.get("phone_number"),
            ),
        )

    @staticmethod
    def get_contact_info_by_custom_entry(custom_entry: dict) -> ContactInfo:
        """Forms ContactInfo based on the input custom_entry.
        Parameters:
            custom_entry: dict: The information about the custom entry to be added to ContactInfo.

        Returns:
            ContactInfo: The filled structure of ContactInfo.
        """

        return ContactInfo(
            alias_name=custom_entry.get("name", ""),
            numbers=Numbers(
                main=custom_entry.get("number"),
            ),
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
            id=str(mailbox_message["message_uid"]),
            type=VoicemailMessageType.FAX if mailbox_message.get("fax_pages") else VoicemailMessageType.VOICE,
            duration=mailbox_message.get("voicemail_duration"),
            size=mailbox_message["size"],
            date=datetime.strptime(mailbox_message["delivery_date"], "%d-%b-%Y %H:%M:%S %z"),
            seen=f"\\{PortaSwitchMailboxMessageFlag.SEEN.value}" in mailbox_message.get("flags", []),
        )

    @staticmethod
    def get_voicemail_message_details(mailbox_message_details: dict) -> VoicemailMessageDetails:
        """
        Forms VoicemailMessageDetails based on the input mailbox_message_details.
            Parameters:
                mailbox_message_details: dict: The unique ID of the message.

             Returns:
                VoicemailMessageDetails: The filled structure of VoicemailMessageDetails.
        """
        voicemail_message = Serializer.get_voicemail_message(mailbox_message_details)

        return VoicemailMessageDetails(
            **voicemail_message.dict(),
            sender=Serializer.parse_voicemail_message_sender_user_ref(mailbox_message_details["from"]),
            receiver=Serializer.parse_voicemail_message_receiver_user_ref(mailbox_message_details["to"]),
            attachments=[
                Serializer.get_voicemail_message_attachment(att) for att in mailbox_message_details["body_structures"]
            ],
        )

    @staticmethod
    def get_voicemail_message_attachment(attachment_body_structure: dict) -> VoicemailMessageAttachment:
        """
        Forms VoicemailMessageAttachment based on the input attachment_body_structure.
            Parameters:
                attachment_body_structure: dict: Details of all message attachments.

             Returns:
                VoicemailMessageAttachment: The filled structure of VoicemailMessageAttachment.
        """

        return VoicemailMessageAttachment(
            type=attachment_body_structure["bodytype"],
            subtype=attachment_body_structure["bodysubtype"],
            size=attachment_body_structure["bodysize"],
            filename=attachment_body_structure["file_name"],
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
            call_id=cdr_info.get("call_id", None),  # sometimes 'call_id' field may be missing in cdr_info
            caller=cdr_info["CLI"],
            callee=cdr_info["CLD"],
            connect_time=datetime.fromtimestamp(int(cdr_info["unix_connect_time"]), timezone.utc),
            direction=Serializer.parse_cdr_direction(cdr_info),
            disconnect_reason=cdr_info["disconnect_reason"],
            disconnect_time=datetime.fromtimestamp(
                int(cdr_info["unix_disconnect_time"]), timezone.utc
            ),
            duration=cdr_info["charged_quantity"],
            recording_id=cdr_info["i_xdr"] if Serializer._call_recording_exist(cdr_info) else None,
            status=Serializer.parse_call_status(cdr_info)
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

    @staticmethod
    def parse_voicemail_message_sender_user_ref(sender: str) -> str:
        return sender.split(" ")[1][1:]

    @staticmethod
    def parse_voicemail_message_receiver_user_ref(receiver: str) -> str:
        return receiver.split(" ")[0]

    @staticmethod
    def parse_cdr_direction(cdr) -> str:
        bit_flags = cdr["bit_flags"]

        masked_value = bit_flags & 12

        if masked_value == 4:
            return Direction.outgoing
        elif masked_value == 8:
            return Direction.incoming
        elif masked_value == 12:
            return Direction.forwarded
        else:
            return Direction.unknown

    @staticmethod
    def parse_call_status(cdr) -> str:
        """
        Determines call status based on CDR data.

        Returns: 'accepted', 'declined', 'missed', or 'error'
        """
        disconnect_cause = cdr["disconnect_cause"]
        if isinstance(disconnect_cause, (int, float)):
            cause = disconnect_cause
        else:
            cause = int(disconnect_cause)

        failed = cdr["failed"] == 1

        return Serializer._xdr_to_call_status(failed, cause)

    @staticmethod
    def _xdr_to_call_status(failed: bool, disconnect_cause: int) -> str:
        """
        Maps CDR parameters to call status using pattern matching logic.

        Args:
            failed: Whether the call failed
            disconnect_cause: Numeric disconnect cause code

        Returns: 'accepted', 'declined', 'missed', or 'error'
        """
        if failed and disconnect_cause == 16:
            return "declined"
        elif failed and disconnect_cause == 19:
            return "missed"
        elif not failed and disconnect_cause == 16:
            return "accepted"
        else:
            return "error"
        
    @staticmethod
    def _call_recording_exist(cdr) -> bool:
        bit_flags = cdr["bit_flags"]

        return (bit_flags & 64) != 0
