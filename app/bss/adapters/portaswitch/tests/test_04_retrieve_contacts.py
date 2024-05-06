import requests


class TestRetrieveContacts:
    def test_absent_token(self, api_url: str, contacts_path: str) -> None:
        response: requests.models.Response = requests.get(
            api_url + contacts_path,
            headers={},
        )

        assert response.status_code == 403
        assert response.json()['message'] == 'Server error: Not authenticated'

    def test_invalid_token(self, invalid_access_token: str, api_url: str, contacts_path: str) -> None:
        response: requests.models.Response = requests.get(
            api_url + contacts_path,
            headers={
                'Authorization': f"Bearer {invalid_access_token}"
            },
        )

        assert response.status_code == 401
        assert response.json()['message'] == f'Invalid access token {invalid_access_token}'

    def test_contacts_retrieved(self, valid_access_token: str, api_url: str, contacts_path: str) -> None:
        response: requests.models.Response = requests.get(
            api_url + contacts_path,
            headers={
                'Authorization': f"Bearer {valid_access_token}"
            },
        )

        assert response.status_code == 200

        items: list = response.json().get('items')
        assert items is not None
        assert len(items)

        item = items[0]
        assert item.get('alias_name') is not None
        assert item.get('company_name') is not None
        assert item.get('email') is not None
        assert item.get('first_name') is not None
        assert item.get('last_name') is not None
        assert item.get('numbers') is not None
        assert item.get('numbers').get('additional') is not None
        assert item.get('numbers').get('ext') is not None
        assert item.get('numbers').get('main') is not None
        assert item.get('sip_status') is not None
