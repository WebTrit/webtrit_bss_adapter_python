import requests
import pytest
from utils4testing import Attr, verify_attribute_in_json


def test_failed_login(api_url, login_path):
    response = requests.post(
        api_url + login_path, json={"login": "hacker", "password": "12345"}
    )
    assert response.status_code == 401


response = None


def test_login(api_url, login_path, username, password):
    global response, body  # so we can re-use it in later tests
    response = requests.post(
        api_url + login_path, json={"login": username, "password": password}
    )
    assert response.status_code == 200
    assert isinstance(body := response.json(), dict)


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


# required response attributes
@pytest.mark.parametrize(
    "attr",
    [
        Attr(name="user_id", type=str, mandatory = True)
    ],
)
def test_login_userid(api_url, login_path, username, attr):
    global body

    attr.expected = username
    print('attr = ', attr)
    verify_attribute_in_json(attr, body)

response2 = None


def test_refresh(api_url, login_path):
    global response, response2
    body = response.json()

    response2 = requests.put(
        api_url + login_path,
        json={"refresh_token": body["refresh_token"], "user_id": body["user_id"]},
    )
    print(response2.content)
    assert response2.status_code == 200
    assert isinstance(body := response2.json(), dict)


@pytest.mark.parametrize(
    "attr",
    [
        Attr(name="access_token", type=str, mandatory=True),
        Attr(name="expires_at", type=str),
        Attr(name="refresh_token", type=str),
    ],
)
def test_refresh_attr(api_url, login_path, attr):
    global body

    print('attr = ', attr)
    verify_attribute_in_json(attr, body)

@pytest.mark.parametrize(
    "attr",
    [
        Attr(name="user_id", type=str, mandatory = True)
    ],
)
def test_refresh_userid(api_url, login_path, username, attr):
    global body

    attr.expected = username
    print('attr = ', attr)
    verify_attribute_in_json(attr, body)
