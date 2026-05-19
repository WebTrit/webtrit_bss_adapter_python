import sys
import os
import types
import importlib.util

_app_path = os.path.join(os.path.dirname(__file__), '..', 'app')
sys.path.insert(0, _app_path)

_ps_path = os.path.join(_app_path, 'bss', 'adapters', 'portaswitch')

# Register a stub package so relative imports inside serializer.py resolve correctly,
# without executing __init__.py (which loads PortaSwitchAdapter and requires env vars).
_ps_pkg = types.ModuleType('bss.adapters.portaswitch')
_ps_pkg.__path__ = [_ps_path]
_ps_pkg.__package__ = 'bss.adapters.portaswitch'
sys.modules['bss.adapters.portaswitch'] = _ps_pkg


def _load(name, filename):
    full = f'bss.adapters.portaswitch.{name}'
    spec = importlib.util.spec_from_file_location(full, os.path.join(_ps_path, filename))
    mod = importlib.util.module_from_spec(spec)
    mod.__package__ = 'bss.adapters.portaswitch'
    sys.modules[full] = mod
    spec.loader.exec_module(mod)
    return mod


_load('types', 'types.py')
_serializer = _load('serializer', 'serializer.py')
Serializer = _serializer.Serializer

import pytest
from bss.models import ConnectStatus, Direction


class TestXdrToCallStatus:
    def test_outgoing_failed_cause1_returns_failed(self):
        assert Serializer._xdr_to_call_status(True, 1, Direction.outgoing) == ConnectStatus.failed

    def test_incoming_failed_cause1_returns_error(self):
        assert Serializer._xdr_to_call_status(True, 1, Direction.incoming) == ConnectStatus.error

    def test_failed_cause16_returns_declined(self):
        assert Serializer._xdr_to_call_status(True, 16, Direction.incoming) == ConnectStatus.declined
        assert Serializer._xdr_to_call_status(True, 16, Direction.outgoing) == ConnectStatus.declined

    def test_failed_cause19_returns_missed(self):
        assert Serializer._xdr_to_call_status(True, 19, Direction.incoming) == ConnectStatus.missed
        assert Serializer._xdr_to_call_status(True, 19, Direction.outgoing) == ConnectStatus.missed

    def test_failed_cause13_returns_completed_elsewhere(self):
        assert Serializer._xdr_to_call_status(True, 13, Direction.incoming) == ConnectStatus.completed_elsewhere
        assert Serializer._xdr_to_call_status(True, 13, Direction.outgoing) == ConnectStatus.completed_elsewhere

    def test_not_failed_cause16_returns_accepted(self):
        assert Serializer._xdr_to_call_status(False, 16, Direction.incoming) == ConnectStatus.accepted
        assert Serializer._xdr_to_call_status(False, 16, Direction.outgoing) == ConnectStatus.accepted

    def test_unknown_cause_returns_error(self):
        assert Serializer._xdr_to_call_status(True, 99, Direction.incoming) == ConnectStatus.error
        assert Serializer._xdr_to_call_status(False, 99, Direction.outgoing) == ConnectStatus.error


class TestParseCallStatus:
    def _make_cdr(self, failed: int, disconnect_cause, bit_flags: int = 0) -> dict:
        return {
            "failed": failed,
            "disconnect_cause": disconnect_cause,
            "bit_flags": bit_flags,
        }

    def test_accepted_call(self):
        cdr = self._make_cdr(failed=0, disconnect_cause=16)
        assert Serializer.parse_call_status(cdr) == ConnectStatus.accepted

    def test_declined_call(self):
        cdr = self._make_cdr(failed=1, disconnect_cause=16)
        assert Serializer.parse_call_status(cdr) == ConnectStatus.declined

    def test_missed_call(self):
        cdr = self._make_cdr(failed=1, disconnect_cause=19)
        assert Serializer.parse_call_status(cdr) == ConnectStatus.missed

    def test_completed_elsewhere(self):
        # call answered by another extension in a hunt group (disconnect_cause=13)
        cdr = self._make_cdr(failed=1, disconnect_cause=13)
        assert Serializer.parse_call_status(cdr) == ConnectStatus.completed_elsewhere

    def test_completed_elsewhere_string_cause(self):
        # disconnect_cause may come as string from the API
        cdr = self._make_cdr(failed=1, disconnect_cause="13")
        assert Serializer.parse_call_status(cdr) == ConnectStatus.completed_elsewhere

    def test_failed_outgoing_call(self):
        # bit_flags & 12 == 4 → outgoing direction
        cdr = self._make_cdr(failed=1, disconnect_cause=1, bit_flags=4)
        assert Serializer.parse_call_status(cdr) == ConnectStatus.failed

    def test_unknown_cause_returns_error(self):
        cdr = self._make_cdr(failed=1, disconnect_cause=99)
        assert Serializer.parse_call_status(cdr) == ConnectStatus.error
