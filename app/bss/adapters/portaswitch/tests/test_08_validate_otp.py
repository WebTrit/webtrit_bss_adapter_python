import requests


class TestValidateOtp:

    def test_unknown_token(self, api_url: str, otp_verify_path: str) -> None:
        invalid_token: str = 'hacker_token'
        invalid_otp_id: str = 'hacker_id'
        response: requests.models.Response = requests.post(
            api_url + otp_verify_path,
            json = {"code": invalid_token, # Validating token
                    "otp_id": invalid_otp_id,
                    },
        )
        assert response.status_code == 404

        body: dict = response.json()

        assert body.get('code') == 'otp_not_found'
        assert body.get('details').get('reason') == \
                f'Incorrect OTP code: {invalid_token}'

    # Check this manually specifying token and otp_id acquired:
    # from test_07_generate_otp.py (otp_id) + OTP email/sms (token)
    def test_validate_otp(self, api_url: str, otp_verify_path: str, otp_token: str,
                          otp_id: str) -> None:
        response: requests.models.Response = requests.post(
            api_url + otp_verify_path,
            json = {"code": otp_token, # Validating token acquired from SMS / EMAIL.
                    "otp_id": otp_id,
                    },
        )
        assert response.status_code == 200

        body: dict = response.json()

        assert body['refresh_token']
        assert body['access_token']
        assert body['expires_at']
        assert body['user_id']

        from pprint import pprint
        pprint(body)