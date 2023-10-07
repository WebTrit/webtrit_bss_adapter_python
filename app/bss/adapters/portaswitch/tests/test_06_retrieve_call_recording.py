import requests


class TestRetrieveCallRecording:

    #: str: The token used to perform API requests.
    access_token: str = ''

    def test_login(self, api_url: str, login_path: str, username: str, password: str) -> None:
        response: requests.models.Response = requests.post(
            api_url + login_path,
            json = {"login": username, "password": password},
        )
        assert response.status_code == 200

        body: dict = response.json()
        TestRetrieveCallRecording.access_token = body.get('access_token')
        assert self.access_token

    def test_absent_token(self, api_url: str, recordings_path: str) -> None:
        response: requests.models.Response = requests.get(
            api_url + recordings_path + '12345',
            headers = {},
        )
        body: dict = response.json()

        assert response.status_code == 403
        assert body.get('detail') == 'Not authenticated'

    def test_invalid_token(self, api_url: str, recordings_path: str) -> None:
        access_token: str = 'qq'

        response: requests.models.Response = requests.get(
            api_url + recordings_path + '12345',
            headers = {
                'Authorization': f"Bearer {access_token}"
            },
        )

        assert response.status_code == 401

        body: dict = response.json()

        assert body.get('code') == 'authorization_header_missing'
        assert body.get('details').get('reason') == f'Invalid access token {access_token}'

    def test_invalid_recording(self, api_url: str, recordings_path: str) -> None:
        response: requests.models.Response = requests.get(
            api_url + recordings_path + '12345123123',
            headers = {
                'Authorization': f"Bearer {self.access_token}"
            },
        )

        assert response.status_code == 404

        body: dict = response.json()

        assert body.get('code') == 'session_not_found'
        assert body.get('details').get('reason') == \
                f'The recording with such a recording_id is not found.'

    def test_recording(self, api_url: str, recordings_path: str, recording_id: str) -> None:
        response: requests.models.Response = requests.get(
            api_url + recordings_path + recording_id,
            headers = {
                'Authorization': f"Bearer {self.access_token}"
            },
        )

        assert response.status_code == 200
        assert response.content

        # filename = f'call_recording_{recording_id}.wav'
        # with open(f"/tmp/{filename}", 'wb') as f:
        #     f.write(response.content)
