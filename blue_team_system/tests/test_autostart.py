import sys
import os
import pytest
from core.autostart import (enable_autostart, disable_autostart,
                             is_autostart_enabled)

def test_enable_and_detect_autostart():
    result = enable_autostart(minimized=True)
    assert result is True
    assert is_autostart_enabled() is True

def test_disable_autostart():
    enable_autostart()
    result = disable_autostart()
    assert result is True
    assert is_autostart_enabled() is False

def test_disable_when_not_enabled():
    disable_autostart()  # ensure clean state
    result = disable_autostart()
    # should return False gracefully, not crash
    assert result is False