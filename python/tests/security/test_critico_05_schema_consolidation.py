"""RED test — CRITICO-05: the orphaned schemas.py must be removed.

Plan: Passo 5 (user decision: delete the dead module; _models.py is canonical).
Today `buildtovalue.api.schemas` still imports successfully.
"""
import importlib

import pytest

pytestmark = pytest.mark.security


def test_orphaned_schemas_module_is_gone():
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module("buildtovalue.api.schemas")


def test_canonical_models_keep_extended_fields():
    """The surviving module must retain the richer appeal fields."""
    from buildtovalue.api._models import AppealResponse
    fields = set(AppealResponse.model_fields)
    assert {"evidence_hash", "grounds", "mediator_recommendation"} <= fields
