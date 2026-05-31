"""RED test — HIGH-03: input_text must enforce max_length=50000.

Plan: Passo 5. DecideRequest.input_text is currently an unbounded str.
"""
import pytest
from pydantic import ValidationError

from buildtovalue.api._models import DecideRequest

pytestmark = pytest.mark.security


def test_input_text_at_limit_is_accepted():
    DecideRequest(input_text="x" * 50_000)  # must not raise


def test_input_text_over_limit_is_rejected():
    with pytest.raises(ValidationError):
        DecideRequest(input_text="x" * 50_001)
