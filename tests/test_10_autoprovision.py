import requests
import pytest
from utils4testing import Attr, verify_attribute_in_json, compose_headers
import random

response = None


def test_wrong_token(api_url, autoprovision_path, config_token, tenant_id):
    response = requests.post(
        api_url + autoprovision_path,
        json={"config_token": 'bla-blah-bla'},
        headers=compose_headers(tenant_id=tenant_id)
    )

    assert response.status_code == 401


def test_login_token(api_url, autoprovision_path, config_token, tenant_id):
    global response, body
    response = requests.post(
        api_url + autoprovision_path,
        json={"config_token": config_token},
        headers=compose_headers(tenant_id=tenant_id)
    )

    assert response.status_code == 200
    # memorize
    body = response.json()
    assert isinstance(body, dict)


# required response attributes
@pytest.mark.parametrize(
    "attr",
    [
        Attr(name="access_token", type=str, mandatory=True),
        Attr(name="expires_at", type=str),
        Attr(name="refresh_token", type=str),
    ],
)
def test_login_attr(api_url, login_path, attr):
    global body

    print('attr = ', attr)
    verify_attribute_in_json(attr, body)
