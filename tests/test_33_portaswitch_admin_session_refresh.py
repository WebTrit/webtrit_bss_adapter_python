import sys
import os
import types
import importlib.util
from datetime import datetime, timedelta

_app_path = os.path.join(os.path.dirname(__file__), '..', 'app')
sys.path.insert(0, _app_path)

_ps_path = os.path.join(_app_path, 'bss', 'adapters', 'portaswitch')

# Register stub packages so relative imports inside admin.py resolve correctly,
# without executing __init__.py (which loads PortaSwitchAdapter and requires env vars).
_ps_pkg = types.ModuleType('bss.adapters.portaswitch')
_ps_pkg.__path__ = [_ps_path]
_ps_pkg.__package__ = 'bss.adapters.portaswitch'
sys.modules['bss.adapters.portaswitch'] = _ps_pkg

_api_pkg = types.ModuleType('bss.adapters.portaswitch.api')
_api_pkg.__path__ = [os.path.join(_ps_path, 'api')]
_api_pkg.__package__ = 'bss.adapters.portaswitch.api'
sys.modules['bss.adapters.portaswitch.api'] = _api_pkg


def _load(full, filename):
    spec = importlib.util.spec_from_file_location(full, os.path.join(_ps_path, filename))
    mod = importlib.util.module_from_spec(spec)
    mod.__package__ = full.rsplit('.', 1)[0]
    sys.modules[full] = mod
    spec.loader.exec_module(mod)
    return mod


_load('bss.adapters.portaswitch.config', 'config.py')
_load('bss.adapters.portaswitch.types', 'types.py')
_load('bss.adapters.portaswitch.exceptions', 'exceptions.py')
_load('bss.adapters.portaswitch.utils', 'utils.py')
_admin = _load('bss.adapters.portaswitch.api.admin', os.path.join('api', 'admin.py'))

from bss.http_api import HTTPAPIConnectorWithLogin, OAuthSessionData
from bss.adapters.portaswitch.config import PortaSwitchSettings

AdminAPI = _admin.AdminAPI


def make_api():
    settings = PortaSwitchSettings(
        ADMIN_API_URL='https://pbx.example.com',
        ACCOUNT_API_URL='https://pbx.example.com',
        SIP_SERVER_HOST='1.2.3.4',
        ADMIN_API_LOGIN='admin',
        ADMIN_API_TOKEN='token',
    )
    api = AdminAPI(settings)
    api.refresh_calls = 0
    api.login_calls = 0

    def fake_refresh(user=None, auth_session=None):
        api.refresh_calls += 1
        return OAuthSessionData(access_token='new', access_token_expires_at=datetime.now() + timedelta(seconds=900))

    def fake_login(user=None):
        api.login_calls += 1
        return OAuthSessionData(access_token='new', access_token_expires_at=datetime.now() + timedelta(seconds=900))

    api.refresh = fake_refresh
    api.login = fake_login
    return api


class TestAdminSessionRefresh:
    def test_proactive_refresh_disabled_for_portaswitch(self):
        assert AdminAPI.REFRESH_TOKEN_IN_ADVANCE == 0

    def test_base_class_default_untouched(self):
        assert HTTPAPIConnectorWithLogin.REFRESH_TOKEN_IN_ADVANCE == 15

    def test_valid_short_ttl_token_is_reused(self):
        """A live token with TTL below the old 15-min threshold (PortaSwitch
        expires_in=900) must be reused as is, without a new Session/login."""
        api = make_api()
        session = OAuthSessionData(
            access_token='current',
            access_token_expires_at=datetime.now() + timedelta(seconds=600),
            refresh_token='rt',
        )
        result = api.session_in_progress(None, session)
        assert result is not None
        assert result.access_token == 'current'
        assert api.refresh_calls == 0
        assert api.login_calls == 0

    def test_expired_token_still_relogins(self):
        api = make_api()
        session = OAuthSessionData(
            access_token='old',
            access_token_expires_at=datetime.now() - timedelta(seconds=1),
        )
        result = api.session_in_progress(None, session)
        assert result is not None
        assert result.access_token == 'new'
        assert api.login_calls == 1

    def test_other_adapters_still_refresh_in_advance(self):
        class Dummy(HTTPAPIConnectorWithLogin):
            def __init__(self):
                super().__init__('https://x')
                self.refreshed = 0

            def login(self, user=None):
                return OAuthSessionData(access_token='new')

            def refresh(self, user=None, auth_session=None):
                self.refreshed += 1
                return OAuthSessionData(access_token='refreshed')

        d = Dummy()
        session = OAuthSessionData(
            access_token='current',
            access_token_expires_at=datetime.now() + timedelta(minutes=10),
            refresh_token='rt',
        )
        result = d.session_in_progress(None, session)
        assert result.access_token == 'refreshed'
        assert d.refreshed == 1
