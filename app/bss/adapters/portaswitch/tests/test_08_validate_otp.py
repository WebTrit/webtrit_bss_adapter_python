import requests


class TestValidateOtp:

    def test_unknown_token(self, api_url: str, otp_verify_path: str):
        invalid_token: str = 'hacker_token'
        invalid_otp_id: str = 'hacker_id'
        response: requests.models.Response = requests.post(
            api_url + otp_verify_path,
            json={
                "code": invalid_token,  # Validating token
                "otp_id": invalid_otp_id,
            },
        )

        assert response.status_code == 404
        assert response.json()['message'] == f'Incorrect OTP code: {invalid_token}'

    def test_validate_otp(self, valid_otp_id: str, valid_otp_code: str, api_url: str, otp_verify_path: str):
        response: requests.models.Response = requests.post(
            api_url + otp_verify_path,
            json={
                "code": valid_otp_code,
                "otp_id": valid_otp_id,
            }
        )

        body: dict = response.json()

        assert response.status_code == 200
        assert body['refresh_token']
        assert body['access_token']
        assert body['expires_at']
        assert body['user_id']
