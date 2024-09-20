import requests


class TestRetrieveCalls:
    def test_absent_token(self, api_url: str, history_path: str) -> None:
        response: requests.models.Response = requests.get(
            api_url + history_path,
            headers={},
        )

        assert response.status_code == 403
        assert response.json()['message'] == 'Server error: Not authenticated'

    def test_invalid_token(self, invalid_access_token: str, api_url: str, history_path: str) -> None:
        response: requests.models.Response = requests.get(
            api_url + history_path,
            headers={
                'Authorization': f"Bearer {invalid_access_token}"
            },
        )

        assert response.status_code == 401
        assert response.json()['message'] == f'Invalid access token {invalid_access_token}'

    def test_contacts_retrieved(self, valid_access_token: str, api_url: str, history_path: str) -> None:
        response: requests.models.Response = requests.get(
            api_url + history_path,
            headers={
                'Authorization': f"Bearer {valid_access_token}"
            },
        )

        assert response.status_code == 200

        body: dict = response.json()
        pagination: dict = body.get('pagination')

        assert pagination.get('items_per_page') is not None
        assert pagination.get('items_total') is not None
        assert pagination.get('page') is not None

        items: list = body.get('items')
        assert items is not None
        assert len(items)

        item: dict = items[0]

        assert item.get('callee') is not None
        assert item.get('caller') is not None
        assert item.get('connect_time') is not None
        assert item.get('direction') is not None
        assert item.get('disconnect_reason') is not None
        assert item.get('disconnect_time') is not None
        assert item.get('duration') is not None
        assert item.get('recording_id') is not None
        assert item.get('status') is not None
