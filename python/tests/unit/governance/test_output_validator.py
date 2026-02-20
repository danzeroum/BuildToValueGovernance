"""
Tests for Output Schema Validator v1.0.0.
"""

import pytest
from buildtovalue.governance.output_validator import (
    OutputSchemaValidator,
    SchemaValidationResult,
)


@pytest.fixture
def validator():
    return OutputSchemaValidator()


class TestValidJSON:

    def test_valid_object(self, validator):
        schema = {
            "type": "object",
            "required": ["answer", "sources"],
            "properties": {
                "answer": {"type": "string", "maxLength": 2000},
                "sources": {"type": "array", "minItems": 1},
            },
        }
        output = '{"answer": "Hello world", "sources": ["doc1.pdf"]}'
        result = validator.validate(output, schema)
        assert result.valid
        assert result.schema_used
        assert len(result.violations) == 0

    def test_missing_required_field(self, validator):
        schema = {
            "type": "object",
            "required": ["answer", "sources"],
        }
        output = '{"answer": "Hello"}'
        result = validator.validate(output, schema)
        assert not result.valid
        assert any(v.rule == "required" for v in result.violations)

    def test_wrong_type(self, validator):
        schema = {"type": "object"}
        output = '"just a string"'
        result = validator.validate(output, schema)
        assert not result.valid
        assert result.violations[0].rule == "type"

    def test_string_too_long(self, validator):
        schema = {
            "type": "object",
            "properties": {
                "answer": {"type": "string", "maxLength": 10},
            },
        }
        output = '{"answer": "this is way too long for the limit"}'
        result = validator.validate(output, schema)
        assert not result.valid
        assert result.violations[0].rule == "maxLength"

    def test_string_too_short(self, validator):
        schema = {
            "type": "object",
            "properties": {
                "answer": {"type": "string", "minLength": 5},
            },
        }
        output = '{"answer": "hi"}'
        result = validator.validate(output, schema)
        assert not result.valid

    def test_array_min_items(self, validator):
        schema = {
            "type": "object",
            "properties": {
                "sources": {"type": "array", "minItems": 2},
            },
        }
        output = '{"sources": ["only_one"]}'
        result = validator.validate(output, schema)
        assert not result.valid

    def test_array_max_items(self, validator):
        schema = {
            "type": "object",
            "properties": {
                "items": {"type": "array", "maxItems": 1},
            },
        }
        output = '{"items": [1, 2, 3]}'
        result = validator.validate(output, schema)
        assert not result.valid

    def test_number_minimum(self, validator):
        schema = {
            "type": "object",
            "properties": {
                "score": {"type": "number", "minimum": 0.0},
            },
        }
        output = '{"score": -1.5}'
        result = validator.validate(output, schema)
        assert not result.valid

    def test_number_maximum(self, validator):
        schema = {
            "type": "object",
            "properties": {
                "score": {"type": "number", "maximum": 1.0},
            },
        }
        output = '{"score": 5.5}'
        result = validator.validate(output, schema)
        assert not result.valid

    def test_enum_valid(self, validator):
        schema = {
            "type": "object",
            "properties": {
                "status": {"type": "string", "enum": ["ok", "error"]},
            },
        }
        output = '{"status": "ok"}'
        result = validator.validate(output, schema)
        assert result.valid

    def test_enum_invalid(self, validator):
        schema = {
            "type": "object",
            "properties": {
                "status": {"type": "string", "enum": ["ok", "error"]},
            },
        }
        output = '{"status": "unknown"}'
        result = validator.validate(output, schema)
        assert not result.valid

    def test_nested_object(self, validator):
        schema = {
            "type": "object",
            "properties": {
                "meta": {
                    "type": "object",
                    "required": ["version"],
                    "properties": {
                        "version": {"type": "string"},
                    },
                },
            },
        }
        output = '{"meta": {"version": "1.0"}}'
        result = validator.validate(output, schema)
        assert result.valid

    def test_nested_missing_required(self, validator):
        schema = {
            "type": "object",
            "properties": {
                "meta": {
                    "type": "object",
                    "required": ["version"],
                },
            },
        }
        output = '{"meta": {}}'
        result = validator.validate(output, schema)
        assert not result.valid

    def test_array_items_validation(self, validator):
        schema = {
            "type": "object",
            "properties": {
                "scores": {
                    "type": "array",
                    "items": {"type": "number", "minimum": 0, "maximum": 1},
                },
            },
        }
        output = '{"scores": [0.5, 1.5]}'
        result = validator.validate(output, schema)
        assert not result.valid


class TestInvalidJSON:

    def test_not_json(self, validator):
        schema = {"type": "object"}
        result = validator.validate("this is not json", schema)
        assert not result.valid
        assert result.violations[0].rule == "json_parse"

    def test_empty_string(self, validator):
        schema = {"type": "object"}
        result = validator.validate("", schema)
        assert not result.valid


class TestNoSchema:

    def test_no_schema_passes(self, validator):
        result = validator.validate("anything", {})
        assert result.valid
        assert not result.schema_used

    def test_none_output(self, validator):
        result = validator.validate(None, {"type": "object"})
        assert not result.valid


class TestExplain:

    def test_explain_valid(self, validator):
        result = validator.validate('{"a": 1}', {})
        assert "conforms" in result.explain()

    def test_explain_violations(self, validator):
        result = validator.validate("bad", {"type": "object"})
        assert "violation" in result.explain().lower()


class TestPerformance:

    def test_latency_under_1ms(self, validator):
        schema = {
            "type": "object",
            "required": ["answer"],
            "properties": {"answer": {"type": "string"}},
        }
        result = validator.validate('{"answer": "hello"}', schema)
        assert result.latency_ms < 1.0