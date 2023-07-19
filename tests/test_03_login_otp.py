import requests
import pytest
import datetime


response = None


def test_otp_create(api_url, otp_create_path, username):
    global response  # so we can re-use it in later tests
    response = requests.post(api_url + otp_create_path, json={"user_ref": username})
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


def test_verify_otp_fail(api_url, otp_verify_path):
    global response
    body = response.json()
    response2 = requests.post(
        api_url + otp_verify_path, json={"otp_id": body["otp_id"], "code": "wrong"}
    )
    assert response2.status_code == 401


response2 = None


def test_verify_otp(api_url, otp_verify_path, otp_code):
    global response2
    body = response.json()
    json_data = {"otp_id": body["otp_id"], "code": otp_code}
    print(f"sending req to {api_url + otp_verify_path} with {json_data}")
    response2 = requests.post(
        api_url + otp_verify_path, json=json_data
    )
    assert response2.status_code == 200


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
