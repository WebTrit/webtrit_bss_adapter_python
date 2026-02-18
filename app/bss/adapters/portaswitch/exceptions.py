from report_error import WebTritErrorException


def access_token_invalid_error():
    return WebTritErrorException(401, "Access token invalid", "access_token_invalid")


def access_token_expired_error():
    return WebTritErrorException(401, "Access token expired", "access_token_expired")


def session_upgrade_needed_error():
    return WebTritErrorException(401, "Token format is outdated. Migration required.", "session_upgrade_needed")


def user_authentication_error():
    return WebTritErrorException(401, "User authentication error")


def method_not_found_error(method_name: str):
    return WebTritErrorException(404, f"Method '{method_name}' not found", "method_not_found")


def not_found_user_error(user_id: str):
    return WebTritErrorException(404, f"There is no an account with such id: {user_id}")


def not_found_contact_error(contact_id: str):
    return WebTritErrorException(404, f"There is no an account with such id: {contact_id}", "contact_not_found")


def not_found_otp_code_error(code: str):
    return WebTritErrorException(404, f"Incorrect OTP code: {code}")


def not_found_recording_error(recording_id: str):
    return WebTritErrorException(404, f"There is no a recording with such id: {recording_id}")


def external_api_issue_error():
    return WebTritErrorException(500, "Unknown error", "external_api_issue")


def incorrect_credentials_error():
    return WebTritErrorException(401, "User authentication error", "incorrect_credentials")


def addon_required_error():
    return WebTritErrorException(403, "Access denied: required add-on not assigned", "addon_required")


def delivery_channel_unspecified_error():
    return WebTritErrorException(422, "Delivery channel unspecified", "delivery_channel_unspecified")


def password_change_required_error():
    return WebTritErrorException(
        422,
        "Failed to perform authentication using this account. Try changing this account web-password.",
    )


def refresh_token_invalid_error():
    return WebTritErrorException(422, "refresh_token_invalid", "Invalid refresh token")


def session_close_error():
    return WebTritErrorException(422, "Error closing the session")


def missing_tokens_error():
    return WebTritErrorException(422, "Missing required access or refresh token parameters")


def unsupported_file_format_error():
    return WebTritErrorException(422, "Not supported file format", "unsupported_file_format")
