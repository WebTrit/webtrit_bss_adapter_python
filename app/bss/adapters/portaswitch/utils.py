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
