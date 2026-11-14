"""Tests package for basic_firewall."""
import os
import sys
import types

_TEST_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_TEST_DIR)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

if "basic_firewall" not in sys.modules:
    try:
        import basic_firewall
    except ModuleNotFoundError:
        pkg = types.ModuleType("basic_firewall")
        pkg.__path__ = [_PROJECT_ROOT]
        sys.modules["basic_firewall"] = pkg
