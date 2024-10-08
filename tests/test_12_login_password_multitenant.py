import requests
import pytest
from utils4testing import Attr, verify_attribute_in_json, compose_headers

# OBSOLETE - added multi-tenant to standard tests

# def test_missing_data(api_url, login_path):
#     global body    
#     response = requests.post(
#         api_url + login_path, json={"abc": "123", "xyz": "12345"}
#     )
#     print(response.content)
#     assert response.status_code == 422
#     assert isinstance(body := response.json(), dict)

# required response attributes
# TODO: fix error handler in FastAPI so it returns the response in the correct format
# @pytest.mark.parametrize(
#     "attr",
#     [
#         Attr(name="code", type=str, mandatory=True, expected="validation_error"),
#         Attr(name="message", type=str),
#         Attr(name="details", type=list),
#     ],
# )
# def test_missing_data_response(api_url, login_path, attr):
#     global body

#     print('attr = ', attr)
#     verify_attribute_in_json(attr, body)

# this should generate an error on the remote BSS side since
# login contains spaces and non-latin characters
# def test_incorrect_data(api_url, login_path):
#     response = requests.post(
#         api_url + login_path, json={"login": "$ 252 Слава Україні!", "password": "12345"}
#     )
#     print(response.content)
#     assert response.status_code == 500


def test_failed_login(api_url, login_path, tenant_id):
    response = requests.post(
        api_url + login_path, json={"login": "hacker", "password": "12345"},
        headers=compose_headers( tenant_id = tenant_id )
    )
    print(response.content)
    assert response.status_code == 401


response = None


def test_login(api_url, login_path, username, password,  tenant_id):
    global response, body  # so we can re-use it in later tests
    response = requests.post(
        api_url + login_path, json={"login": username, "password": password},
        headers=compose_headers( tenant_id = tenant_id )
    )
    print(response.content)
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
def test_login_userid(api_url, login_path, username, tenant_id, attr):
    global body

    attr.expected = tenant_id + ':*:' + username
    #attr.expected = username
    print('attr = ', attr)
    verify_attribute_in_json(attr, body)

response2 = None


def test_refresh(api_url, login_path, tenant_id):
    global response, response2, access_token
    body = response.json()

    response2 = requests.patch(
        api_url + login_path,
        json={"refresh_token": body["refresh_token"], "user_id": body["user_id"]},
        headers=compose_headers( tenant_id = tenant_id )
    )
    print(response2.content)
    assert response2.status_code == 200
    assert isinstance(body := response2.json(), dict)
    access_token = body["access_token"]


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
def test_refresh_userid(api_url, login_path, username, tenant_id, attr):
    global body

    attr.expected = tenant_id + ':*:' + username
    print('attr = ', attr)
    verify_attribute_in_json(attr, body)


def test_extensions(api_url, tenant_id, extensions_path):
    global response2, body, access_token
    response2 = requests.get(
        api_url + extensions_path,
        headers=compose_headers( access_token = access_token, tenant_id = tenant_id )
    )

    assert response2.status_code == 200
    print(response2.content)
    assert isinstance(body := response2.json(), dict)
    assert 'items' in body
