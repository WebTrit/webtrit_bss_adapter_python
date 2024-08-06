import requests


class TestGenerateOtp:

    def test_unknown_user(self, api_url: str, otp_create_path: str) -> None:
        user_ref = '123'
        response: requests.models.Response = requests.post(
            api_url + otp_create_path,
            json={"user_ref": user_ref}
        )

        assert response.status_code == 404
        assert response.json()['message'] == f'There is no an account with such a i_account: {user_ref}'

    def test_create_otp(self, api_url: str, userid: str, otp_create_path: str) -> None:
        response: requests.models.Response = requests.post(
            api_url + otp_create_path,
            json={"user_ref": userid},  # i_account
        )

        otp_id = response.json()["otp_id"]

        print(f'\nGenerated otp id - {otp_id}')

        assert response.status_code == 200
        assert otp_id is not None
