import requests


class TestGenerateOtp:

    def test_unknown_user(self, api_url: str, otp_create_path: str) -> None:
        user_ref = '123'
        response: requests.models.Response = requests.post(
            api_url + otp_create_path,
            json = {"user_ref": user_ref}, ## i_account
        )
        assert response.status_code == 404

        body: dict = response.json()

        assert body.get('code') == 'user_not_found'
        assert body.get('details').get('reason') == \
                f'There is no an account with such a i_account: {user_ref}'

    def test_create_otp(self, api_url: str, userid: str, otp_create_path: str) -> None:
        response: requests.models.Response = requests.post(
            api_url + otp_create_path,
            json = {"user_ref": userid}, ## i_account
        )
        assert response.status_code == 200

        body: dict = response.json()
        assert body.get('otp_id') is not None

        from pprint import pprint
        pprint(body)

