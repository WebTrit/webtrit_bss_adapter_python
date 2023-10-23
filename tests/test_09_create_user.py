import requests
import pytest
import logging
import json
from utils4testing import Attr, verify_attribute_in_json, compose_headers

response = None

user_info = {
            "user_id": "peter",
            "password": "qwerty",
            "firstname": "Peter",
            "lastname": "Smith",
            "email": "contact@webtrit.com",
            "status": "active",
            "company_name": "WebTrit, Inc",
            "sip": {
                "username": "12065551235",
                "password": "SlavaUkraini!",
                "display_name": "Geroyam Slava!",
                "sip_server": {"host": "127.0.0.1", "port": 5060},
            },
            "balance": {"amount": 50.00, "balance_type": "prepaid", "currency": "USD"},
            "numbers": {
                "ext": "2712",
                "main": "120655512345",
                "additional": ["380441234568", "34001235670"],
            },
            "time_zone": "Europe/Kyiv",
        }

def test_create(api_url, userinfo_path):
    global response, body, access_token  # so we can re-use it in later tests
    response = requests.post(
        api_url + userinfo_path, json= user_info
    )
    print(response.content)
    assert response.status_code == 200
    assert isinstance(body := response.json(), dict)
    assert (access_token := body.get("access_token", None)) is not None

# required response attributes
@pytest.mark.parametrize(
    "attr",
    [
        Attr(name="access_token", type=str, mandatory=True),
        Attr(name="expires_at", type=str),
        Attr(name="refresh_token", type=str),
    ],
)
def test_returned_attr(api_url, login_path, attr):
    global body

    print('attr = ', attr)
    verify_attribute_in_json(attr, body)


def test_returned_userid(api_url, login_path):
    global body

    attr = Attr(name="user_id", type=str, mandatory = True)
    attr.expected = user_info['user_id']

    verify_attribute_in_json(attr, body)

def test_login_after_Creation(api_url, login_path):
    global response, access_token, user_info
    response = requests.post(
        api_url + login_path,
        json={"login": user_info['user_id'], "password": user_info['password']},

    )

    print(response.content)
    assert response.status_code == 200
    assert isinstance(body := response.json(), dict)
    assert (access_token := body.get("access_token", None)) is not None


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

response2 = None


def test_userinfo(api_url, userinfo_path):
    global response2, access_token

    response2 = requests.get(
        api_url + userinfo_path,
        headers=compose_headers(access_token=access_token),
    )

    assert response2.status_code == 200


# required response attributes
@pytest.mark.parametrize(
    "attr",
    [
        Attr(name="balance", type=type({})),
        Attr(name="sip", type=type({}), mandatory=True),
        Attr(name="company_name", type=str),
        Attr(name="email", type=str),
        Attr(name="firstname", type=str),
        Attr(name="lastname", type=str),
        Attr(name="time_zone", type=str),
        Attr(name="numbers", type=dict)
    ],
)
def test_user_info_attr(api_url, login_path, attr):
    global response2
    assert len(response2.content) > 0
    try:
        body = response2.json()
    except json.JSONDecodeError as e:
        body = {}

    verify_attribute_in_json(attr, body)

def test_delete_user(api_url, userinfo_path, login_path):
    global response, body, user_info, access_token  # so we can re-use it in later tests
    response = requests.delete(
        api_url + userinfo_path, 
        headers=compose_headers(access_token=access_token)
    )

    assert response.status_code == 204

    # ensure that the session is closed
    response2 = requests.get(
        api_url + userinfo_path,
        headers=compose_headers(access_token=access_token),
    )

    assert response2.status_code == 401

    # ensure we cannot re-login
    response2 = requests.post(
        api_url + login_path,
        json={"login": user_info['user_id'], "password": user_info['password']},
    )

    assert response2.status_code == 401
