# -*- coding: utf-8 -*-

import pytest
from nuls2_python.skeleton import fib

__author__ = "Jonathan Schemoul"
__copyright__ = "Jonathan Schemoul"
__license__ = "mit"


def test_fib():
    assert fib(1) == 1
    assert fib(2) == 1
    assert fib(7) == 13
    with pytest.raises(AssertionError):
        fib(-10)
