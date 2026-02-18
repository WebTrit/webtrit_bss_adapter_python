import base64
import hashlib
import uuid

from report_error import WebTritErrorException


def extract_fault_code(error: WebTritErrorException) -> str:
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

    fault_code = response_content.get('faultcode')
    if not fault_code:
        # No faultcode. Why?
        raise error

    return fault_code


def generate_otp_id() -> str:
    """Generate a new unique ID for the session"""
    return str(uuid.uuid1()).replace("-", "") + str(uuid.uuid4()).replace("-", "")


def generate_hash(value) -> str:
    """Generates a SHA256 hash encoded in Base64 without padding."""
    hash_bytes = hashlib.sha256(str(value).encode("utf-8")).digest()

    return base64.b64encode(hash_bytes).decode("utf-8").rstrip("=")


def generate_hash_dictionary(max_value: int = 1_000_000) -> dict[str, int]:
    """Generates a hash dictionary for a specific range."""
    hash_dict = {}

    for user_id in range(1, max_value + 1):
        hash_value = generate_hash(user_id)
        hash_dict[hash_value] = user_id

    return hash_dict
