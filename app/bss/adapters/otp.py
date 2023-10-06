from abc import ABC, abstractmethod
from datetime import datetime, timedelta
import random
import uuid
from bss.types import (UserInfo, OTP,
                       OTPCreateResponse, OTPVerifyRequest, OTPDeliveryChannel, 
                       OTPExtAPIErrorCode, OTPValidationErrCode,
                       OTPNotFoundErrorCode, OTPUserDataErrorCode,
                       UserNotFoundCode, safely_extract_scalar_value)
from bss.sessions import SessionInfo
from report_error import WebTritErrorException
import logging

class OTPHandler(ABC):
    @abstractmethod
    def generate_otp(self, user: UserInfo) -> OTPCreateResponse:
        """Request that the remote hosted PBX system / BSS generates a new
        one-time-password (OTP) and sends it to the user via the
        configured communication channel (e.g. SMS)"""
        pass

    @abstractmethod
    def validate_otp(self, otp: OTPVerifyRequest) -> SessionInfo:
        """Verify that the OTP code, provided by the user, is correct."""
        pass

class SampleOTPHandler(OTPHandler):
    """This is a demo class for handling OTPs, it does not send any
    data to the end-user (only prints it in the log), so it is useful
    for debugging your own application while you are working on establishing
    a way to send real OTPs via SMS or other channel."""

    def extract_user_email(self, user_data: object) -> str:
        """Extract user's email to be used for sending one-time-password
        
        Please override it in your sub-class"""
        if hasattr(user_data, "email"):
            return user_data.email
        elif isinstance(user_data, dict):
            return user_data.get("email", None)
        
        return None

    def send_otp_email(self, email_address: str, otp: OTP, from_address: str) -> bool:
        """Send an email message with the OTP code to the user.

        Returns: True if the message was sent successfully, False otherwise.
        
        Please override it in your sub-class"""
        logging.error(f"Was supposed to send to {email_address} a message " +
                      f"about OTP {otp.otp_expected_code} - but you have not " +
                      "implemented the actual method to do so in your sub-class. " +
                      "Let's assume you are just debugging your application now and " +
                      "consiser an email has been sent.")
        return True
    
    DEFAULT_OTP_LENGTH = 6 # digits. 6 = from 100000 to 999999
    DEFAULT_OTP_VALIDITY = 15 # minutes
    def generate_otp(self, user: UserInfo) -> OTPCreateResponse:
        """Request that the remote hosted PBX system / BSS generates a new
        one-time-password (OTP) and sends it to the user via the
        configured communication channel (e.g. SMS)"""

        # here we are relying on methods provided by BSSAdapterExternalDB
        # or your subclass, since OTPHandler does not have access to
        # the DB with user data
        user_data = self.retrieve_user_info(user)
        if user_data is None:
            raise WebTritErrorException(
                status_code=404,
                code=UserNotFoundCode.user_not_found,
                error_message="User does not have a valid email to receive OTP",
            )
        email = self.extract_user_email(user_data) if user_data else None
        if not email:
            raise WebTritErrorException(
                status_code=422,
                code=OTPUserDataErrorCode.validation_error,
                error_message="User does not have a valid email to receive OTP",
            )

        # the code that the user should provide to prove that
        # he/she is who he/she claims to be
        otp_length = int(self.config.get_conf_val("OTP", "Length",
                                                default=self.DEFAULT_OTP_LENGTH))
        if otp_length < 3:
            logging.error(f"OTP length is too short, setting it to {self.DEFAULT_OTP_LENGTH}")
            otp_length = self.DEFAULT_OTP_LENGTH

        code = random.randrange(10**(otp_length-1), 10**(otp_length) - 1)
        code_for_tests = self.config.get_conf_val("PERMANENT_OTP_CODE")
        if code_for_tests:
            # while running automated tests, we have to produce the
            # same OTP as configured in the test suite. make sure
            # this env var is NOT set in production!
            code = int(code_for_tests)
        # so we can see it and use during debug
        logging.info(f"OTP code {code}")

        otp_id = str(uuid.uuid1())
        otp_validity = int(self.config.get_conf_val("OTP", "Validity",
                                                default=self.DEFAULT_OTP_VALIDITY))
        otp = OTP(
            user_id=user.user_id,
            attempts=0,
            otp_expected_code="{:06d}".format(code),
            expires_at=datetime.now() + timedelta(minutes=otp_validity),
        )
        # memorize it
        self.otp_db[otp_id] = otp

        sender_email = self.config.get_conf_val("Email", "Sender",
                                                default="sample@webtrit.com")
        if not self.send_otp_email(email_address = email,
                                   from_address = sender_email,
                                   otp = otp):
            raise WebTritErrorException(
                status_code=500,
                code=OTPExtAPIErrorCode.external_api_issue,
                error_message="Could not send an OTP email",
            )

        return OTPCreateResponse(
            # OTP sender's address so the user can find it easier in his/her inbox
            delivery_from=sender_email,
            otp_id=otp_id,
            delivery_channel=OTPDeliveryChannel.email,
        )

    MAX_ATTEMPTS = 5 # how many times the user can try to enter the OTP code
    def validate_otp(self, otp: OTPVerifyRequest) -> SessionInfo:
        """Verify that the OTP code, provided by the user, is correct."""

        otp_id = safely_extract_scalar_value(otp.otp_id)
        original = self.otp_db.get(otp_id, None)
        if not original:
            logging.debug(f"OTP ID={otp_id} does not exist")
            raise WebTritErrorException(
                status_code=404,
                code=OTPNotFoundErrorCode.otp_not_found,
                error_message="Invalid OTP ID",
            )
        # to avoid problems with comparing datetimes with different timezones
        # we assume that in DB they are stored in the same TZ as we have here 
        # on the server
        expiration = original.expires_at.replace(tzinfo=None)
        if expiration < datetime.now():
            # remove OTP to clean up space in DB
            logging.debug(f"OTP ID={otp_id} has expired at {expiration.isoformat()}")
            del self.otp_db[otp_id]
            raise WebTritErrorException(
                status_code=422,
                code=OTPValidationErrCode.otp_expired,
                error_message="OTP has expired",
            )

        if original.otp_expected_code != otp.code:
            if original.attempts > self.MAX_ATTEMPTS:
                # too many failed attempts to enter OTP - someone is trying to brute-force?
                logging.debug("User already attempted to enter the code " +
                            f"for OTP ID={otp_id} {original.attempts} - erasing OTP")
                del self.otp_db[otp_id]
                raise WebTritErrorException(
                    status_code=422,
                    code=OTPValidationErrCode.otp_verification_attempts_exceeded,
                    error_message="Too many incorrect attempts to enter OTP",
                )
            else:
                # update the counter of failed attempts
                original.attempts += 1
                self.otp_db[otp_id] = original

            raise WebTritErrorException(
                status_code=401,
                code=OTPValidationErrCode.incorrect_otp_code,
                error_message="Invalid OTP",
            )

        # everything is in order, create a session
        session = self.sessions.create_session(UserInfo(user_id = original.user_id))
        self.sessions.store_session(session)
        # delete the OTP to avoid accumulating junk in the DB
        del self.otp_db[otp_id]

        return session
