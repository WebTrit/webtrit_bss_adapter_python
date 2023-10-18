import requests
import pytest
from random import randint
import datetime
from utils4testing import Attr, verify_attribute_in_json, compose_headers, extract_err_msg

response = None

def test_otp_create_nonexisting_user(api_url, otp_create_path, username, tenant_id):
    global response  # so we can re-use it in later tests
    response = requests.post(api_url + otp_create_path,
                             json={"user_ref": username + 'XYZ' + str(randint(10000, 999900))},
                             headers=compose_headers(tenant_id=tenant_id))
    assert response.status_code == 404
    body = response.json()
    print(f"body_ne = {body}")
    assert 'code' in body and body['code'] == "user_not_found"


def test_otp_create1(api_url, otp_create_path, username, tenant_id):
    global response  # so we can re-use it in later tests
    response = requests.post(api_url + otp_create_path,
                             json={"user_ref": username},
                             headers=compose_headers(tenant_id=tenant_id))
    assert response.status_code == 200


# required response attributes
@pytest.mark.parametrize(
    "attr, expected", [("otp_id", ""), ("otp_sent_from", ""), ("otp_sent_type", "")]
)
def test_gen_otp_attr(api_url, otp_create_path, attr, expected):
    global response

    body = response.json()

    # if the value is provided - ensure it matches
    if expected:
        assert attr in body
        assert body[attr]  # not empty
        assert type(expected) == type(body[attr])  # same type
        assert body[attr] == expected


def test_verify_otp_wrong_id(api_url, otp_verify_path, tenant_id):
    global response
    body = response.json()
    response2 = requests.post(
        api_url + otp_verify_path,
        json={"otp_id": body["otp_id"] + 'XYZ', "code": "wrong"},
        headers=compose_headers(tenant_id=tenant_id)
    )
    assert response2.status_code == 404
    body = response.json()
    print(f"body = {body}")
    assert 'code' in body and body['code'] == "incorrect_otp_code"

def test_verify_otp_fail(api_url, otp_verify_path, tenant_id):
    global response
    body = response.json()
    response2 = requests.post(
        api_url + otp_verify_path,
        json={"otp_id": body["otp_id"], "code": "wrong"},
        headers=compose_headers(tenant_id=tenant_id)
    )
    assert response2.status_code == 401

def test_verify_otp_fail_too_many_tries(api_url, otp_verify_path, tenant_id):
    global response
    body = response.json()
    for i in range(1, 10):
        response2 = requests.post(
            api_url + otp_verify_path,
            json={"otp_id": body["otp_id"], "code": "wrong"},
            headers=compose_headers(tenant_id=tenant_id)
        )
        print(f"attempt {i} response: {response2.content}")
        body2 = response.json()
        if response2.status_code == 422:
             break
    assert response2.status_code == 422 and \
            extract_err_msg(response2) == "Too many incorrect attempts to enter OTP"
    # ensure the code was deleted
    response2 = requests.post(
            api_url + otp_verify_path,
            json={"otp_id": body["otp_id"], "code": "wrong"},
            headers=compose_headers(tenant_id=tenant_id)
        )    
    assert response2.status_code == 404

response2 = None

def test_otp_create2(api_url, otp_create_path, username, tenant_id):
    global response  # so we can re-use it in later tests
    response = requests.post(api_url + otp_create_path,
                             json={"user_ref": username},
                             headers=compose_headers(tenant_id=tenant_id))
    assert response.status_code == 200


def test_verify_otp(api_url, otp_verify_path, otp_code, tenant_id):
    global response, response2

    body = response.json()
    json_data = {"otp_id": body["otp_id"], "code": otp_code}
    print(f"sending req to {api_url + otp_verify_path} with {json_data}")
    response2 = requests.post(
        api_url + otp_verify_path,
        json=json_data,
        headers=compose_headers(tenant_id=tenant_id)
    )
    assert response2.status_code == 200

def test_reuse_otp(api_url, otp_verify_path, otp_code, tenant_id):

    body = response.json()
    json_data = {"otp_id": body["otp_id"], "code": otp_code}
    print(f"sending req to {api_url + otp_verify_path} with {json_data}")
    response3 = requests.post(
        api_url + otp_verify_path,
        json=json_data,
        headers=compose_headers(tenant_id=tenant_id)
    )
    assert response3.status_code == 404

@pytest.mark.parametrize(
    "attr, expected",
    [
        ("access_token", ""),
        ("expires_at", ""),
        ("refresh_token", None),
     ],
)
def test_verify_otp_attr(api_url, login_path, attr, expected):
    global response2
    body = response2.json()

    # if the value is provided - ensure it matches
    if expected:
        assert attr in body
        assert body[attr]  # not empty
        assert type(expected) == type(body[attr])  # same type
        assert body[attr] == expected

def test_verify_otp_userid(api_url, login_path, userid):
    global response2
    body = response2.json()

    assert 'user_id' in body
    assert body['user_id']  == userid
