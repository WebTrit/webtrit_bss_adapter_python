import requests


class TestRetrieveCallRecording:
    def test_absent_token(self, api_url: str, recordings_path: str) -> None:
        response: requests.models.Response = requests.get(
            api_url + recordings_path + '12345',
            headers={},
        )

        assert response.status_code == 403
        assert response.json()['message'] == 'Server error: Not authenticated'

    def test_invalid_token(self, invalid_access_token: str, api_url: str, recordings_path: str) -> None:
        response: requests.models.Response = requests.get(
            api_url + recordings_path + '12345',
            headers={
                'Authorization': f"Bearer {invalid_access_token}"
            },
        )

        assert response.status_code == 401
        assert response.json()['message'] == f'Invalid access token {invalid_access_token}'

    def test_invalid_recording(self, valid_access_token: str, api_url: str, recordings_path: str) -> None:
        response: requests.models.Response = requests.get(
            api_url + recordings_path + '12345123123',
            headers={
                'Authorization': f"Bearer {valid_access_token}"
            },
        )

        assert response.status_code == 404
        assert response.json()['message'] == f'The recording with such a recording_id is not found.'

    def test_recording(self, valid_access_token: str, api_url: str, recordings_path: str, recording_id: str) -> None:
        response: requests.models.Response = requests.get(
            api_url + recordings_path + recording_id,
            headers={
                'Authorization': f"Bearer {valid_access_token}"
            },
        )

        assert response.status_code == 200
        assert response.content
