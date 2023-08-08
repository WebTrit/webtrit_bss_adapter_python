from dataclasses import dataclass

TENANT_ID_HEADER = 'X-WebTrit-Tenant-ID'

@dataclass
class Attr:
    name: str
    type: str = type("")
    expected: object = None
    mandatory: bool = False

def verify_attribute_in_json(attr: Attr, attr_dict: dict):
    if attr.mandatory:
        # is present if it should be
        assert attr.name in attr_dict
        assert attr_dict[attr.name] is not None  # not empty
    if attr.name in attr_dict and attr_dict[attr.name] is not None:
        verify_attribute_value(attr, attr_dict[attr.name])

def verify_attribute_value(attr: Attr, value):
    assert isinstance(value, attr.type)  # same type
    if attr.expected:
        expected_value = attr.expected() if callable(attr.expected) else attr.expected
        assert value == expected_value

def compose_headers(access_token: str = None, tenant_id: str = None, other: dict = {}):
    """Create a proper structure of HTTP headers for the request."""
    h = other
    if access_token:
        h["Authorization"] = "Bearer " + access_token
    if tenant_id:
        h[TENANT_ID_HEADER] = tenant_id

    return h

def extract_err_msg(response):
    try:
        body = response.json()
        return body['details']['reason']
    except:
        return None
