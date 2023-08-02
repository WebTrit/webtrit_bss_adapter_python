import requests
import pytest
from utils4testing import Attr, verify_attribute_in_json, compose_headers

response = None
access_token = None


def test_login(api_url, login_path, username, password, tenant_id):
    global response, access_token  # so we can re-use it in later tests
    response = requests.post(
        api_url + login_path,
        json={"login": username, "password": password},
        headers=compose_headers(tenant_id=tenant_id)
    )
    assert response.status_code == 200
    body = response.json()
    access_token = body.get("access_token", None)


response2 = None


def test_logout(api_url, login_path, tenant_id):
    global access_token

    response2 = requests.delete(
        api_url + login_path,
        headers=compose_headers(tenant_id=tenant_id, access_token=access_token),
        json={},
    )
    assert response2.status_code == 204
