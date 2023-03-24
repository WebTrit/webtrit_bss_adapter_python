import requests
import pytest
import datetime
import logging
import pprint
import json

from utils4testing import Attr, verify_attribute_in_json

pp = pprint.PrettyPrinter(indent=4)

response = None
access_token = None


def test_do_login(api_url, login_path, username, password):
    global response, access_token, pp  # so we can re-use it in later tests
    response = requests.post(
        api_url + login_path, json={"login": username, "password": password}
    )

    assert response.status_code == 200
    # memorize
    body = response.json()
    access_token = body.get("access_token", None)


response2 = None


def test_userinfo(api_url, userinfo_path):
    global response2, access_token, pp

    response2 = requests.get(
        api_url + userinfo_path,
        headers={"Authorization": "Bearer " + access_token},
    )
    if len(response2.content) > 0:
        logging.warning("Reply from the server:" + response2.content.decode("utf-8"))
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
    global response2, pp
    assert len(response2.content) > 0
    try:
        body = response2.json()
    except json.JSONDecodeError as e:
        body = {}

    logging.warning("Reply from the server:" + pp.pformat(body))
    verify_attribute_in_json(attr, body)



@pytest.mark.parametrize(
    "attr",
    [
        Attr(name="display_name", type=str),
        Attr(name="login", type=str, mandatory=True),
        Attr(name="password", type=str, mandatory=True),
        Attr(name="sip_server", type=dict, mandatory=True),
        Attr(name="registration_server", type=dict)
    ],
)
def test_user_info_sip_attr(api_url, login_path, attr):
    global response2
    try:
        body = response2.json()
    except json.JSONDecodeError as e:
        body = {}
    sip = body["sip"]

    verify_attribute_in_json(attr, sip)

@pytest.mark.parametrize(
    "attr",
    [
        Attr(name="host", type=str, mandatory=True),
        Attr(name="port", type=int ),
        Attr(name="sip_over_tls", type=bool)
    ],
)
def test_user_info_sip_server_attr(api_url, login_path, attr):
    global response2
    try:
        body = response2.json()
    except json.JSONDecodeError as e:
        body = {}
    sip = body["sip"]["sip_server"]

    verify_attribute_in_json(attr, sip)
