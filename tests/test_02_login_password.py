import requests
import pytest
from utils4testing import Attr, verify_attribute_in_json, compose_headers

def test_missing_data(api_url, login_path):
    global body    
    response = requests.post(
        api_url + login_path, json={"abc": "123", "xyz": "12345"}
    )
    #print(response.content)
    assert response.status_code == 422
    assert isinstance(body := response.json(), dict)

def test_failed_login(api_url, login_path):
    global body
    response = requests.post(
        api_url + login_path, json={"login": "hacker", "password": "12345"}
    )
    #print(response.content)
    assert response.status_code == 401
    assert isinstance(body := response.json(), dict)

def test_wrong_password(api_url, login_path, username, password, tenant_id):
    global response, body  # so we can re-use it in later tests
    response = requests.post(
       api_url + login_path,
       json={"login": username, "password": "WRONG"},
       headers=compose_headers(tenant_id=tenant_id)

    )
    #print(response.content)
    assert response.status_code == 401
    assert isinstance(body := response.json(), dict)
    print(body)


# required response attributes
# TODO: fix error handler in FastAPI so it returns the response in the correct format
@pytest.mark.parametrize(
    "attr",
    [
        Attr(name="code", type=str, mandatory=True, expected="incorrect_credentials"),
        Attr(name="message", type=str),
        Attr(name="details", type=dict),
    ],
)
def test_wrong_auth_response(api_url, login_path, attr):
    global body

    #print('attr = ', attr)
    verify_attribute_in_json(attr, body)

# check that the server does not crash on non-Latin characters
def test_incorrect_data(api_url, login_path):
    response = requests.post(
        api_url + login_path, json={"login": "$ 252 Слава Україні!", "password": "12345"}
    )
    #print(response.content)
    assert response.status_code == 401

def test_login(api_url, login_path, username, password, tenant_id):
    global response, body  # so we can re-use it in later tests
    response = requests.post(
       api_url + login_path,
       json={"login": username, "password": password},
       headers=compose_headers(tenant_id=tenant_id)

    )
    #print(response.content)
    assert response.status_code == 200
    assert isinstance(body := response.json(), dict)
    print(response.headers)

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

    #print('attr = ', attr)
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
    #print('attr = ', attr)
    verify_attribute_in_json(attr, body)

response2 = None


def test_refresh(api_url, login_path, tenant_id):
    global response, response2
    body = response.json()

    response2 = requests.patch(
        api_url + login_path,
        json={"refresh_token": body["refresh_token"], "user_id": body["user_id"]},
        headers=compose_headers(tenant_id=tenant_id),
    )
    #print(response2.content)
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

    #print('attr = ', attr)
    verify_attribute_in_json(attr, body)


def test_logout(api_url, login_path, tenant_id):
    global response, response2, body
    body = response2.json()

    response = requests.delete(
        api_url + login_path,
        json={},
        headers=compose_headers(tenant_id=tenant_id, access_token=body["access_token"]),
    )
    #print(response2.content)
    assert response.status_code == 204
    print(response.headers)
    print(f"content = '{response.content}'")

# @pytest.mark.parametrize(
#     "attr",
#     [
#         Attr(name="user_id", type=str, mandatory = True)
#     ],
# )
# def test_refresh_userid(api_url, login_path, username, attr):
#     global body

#     attr.expected = username
#     print('attr = ', attr)
#     verify_attribute_in_json(attr, body)
