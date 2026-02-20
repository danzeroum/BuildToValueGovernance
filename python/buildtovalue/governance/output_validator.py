"""
Output Schema Validator v1.0.0 — Validates LLM output against profile-defined JSON Schema.

Filosofia (Levinas): Protect the user from malformed or unsafe LLM output.
Filosofia (Rawls): Same schema rules regardless of identity.

Usage:
    validator = OutputSchemaValidator()
    result = validator.validate(output_text, schema_dict)
    if not result.valid:
        # action = REDACT
"""

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger("btv.governance.output_validator")


@dataclass
class SchemaViolation:
    """Single schema violation."""
    path: str
    rule: str
    message: str


@dataclass
class SchemaValidationResult:
    """Result of output schema validation."""
    valid: bool
    violations: List[SchemaViolation] = field(default_factory=list)
    latency_ms: float = 0.0
    schema_used: bool = False

    def explain(self) -> str:
        """explain_decision() — obrigatório per invariant."""
        if self.valid:
            return "Output conforms to schema."
        parts = [f"Schema violation: {v.path} — {v.message}" for v in self.violations]
        return "; ".join(parts)


class OutputSchemaValidator:
    """
    Validates LLM output against JSON Schema defined in profile YAML.

    Supports a subset of JSON Schema:
    - type (object, array, string, number, integer, boolean)
    - required
    - properties (recursive)
    - items (for arrays)
    - minItems, maxItems
    - minLength, maxLength
    - minimum, maximum
    - enum

    No external dependencies (no jsonschema library).
    """

    def validate(
        self,
        output: str,
        schema: Dict[str, Any],
    ) -> SchemaValidationResult:
        """Validate output string against schema. Output must be valid JSON."""
        start = time.perf_counter()

        if not schema:
            return SchemaValidationResult(valid=True, schema_used=False)

        try:
            data = json.loads(output)
        except (json.JSONDecodeError, TypeError):
            latency = (time.perf_counter() - start) * 1000
            return SchemaValidationResult(
                valid=False,
                violations=[SchemaViolation(
                    path="$",
                    rule="json_parse",
                    message="Output is not valid JSON",
                )],
                latency_ms=latency,
                schema_used=True,
            )

        violations: List[SchemaViolation] = []
        self._validate_node(data, schema, "$", violations)

        latency = (time.perf_counter() - start) * 1000
        return SchemaValidationResult(
            valid=len(violations) == 0,
            violations=violations,
            latency_ms=latency,
            schema_used=True,
        )

    def _validate_node(
        self,
        data: Any,
        schema: Dict[str, Any],
        path: str,
        violations: List[SchemaViolation],
    ) -> None:
        """Recursively validate a node against schema."""

        # Type check
        expected_type = schema.get("type")
        if expected_type and not self._check_type(data, expected_type):
            violations.append(SchemaViolation(
                path=path,
                rule="type",
                message=f"Expected {expected_type}, got {type(data).__name__}",
            ))
            return

        # Enum check
        if "enum" in schema:
            if data not in schema["enum"]:
                violations.append(SchemaViolation(
                    path=path,
                    rule="enum",
                    message=f"Value must be one of {schema['enum']}",
                ))

        # String constraints
        if isinstance(data, str):
            if "minLength" in schema and len(data) < schema["minLength"]:
                violations.append(SchemaViolation(
                    path=path,
                    rule="minLength",
                    message=f"Length {len(data)} < minimum {schema['minLength']}",
                ))
            if "maxLength" in schema and len(data) > schema["maxLength"]:
                violations.append(SchemaViolation(
                    path=path,
                    rule="maxLength",
                    message=f"Length {len(data)} > maximum {schema['maxLength']}",
                ))

        # Number constraints
        if isinstance(data, (int, float)):
            if "minimum" in schema and data < schema["minimum"]:
                violations.append(SchemaViolation(
                    path=path,
                    rule="minimum",
                    message=f"Value {data} < minimum {schema['minimum']}",
                ))
            if "maximum" in schema and data > schema["maximum"]:
                violations.append(SchemaViolation(
                    path=path,
                    rule="maximum",
                    message=f"Value {data} > maximum {schema['maximum']}",
                ))

        # Object constraints
        if isinstance(data, dict):
            for req_field in schema.get("required", []):
                if req_field not in data:
                    violations.append(SchemaViolation(
                        path=f"{path}.{req_field}",
                        rule="required",
                        message="Required field missing",
                    ))

            for prop_name, prop_schema in schema.get("properties", {}).items():
                if prop_name in data:
                    self._validate_node(
                        data[prop_name],
                        prop_schema,
                        f"{path}.{prop_name}",
                        violations,
                    )

        # Array constraints
        if isinstance(data, list):
            if "minItems" in schema and len(data) < schema["minItems"]:
                violations.append(SchemaViolation(
                    path=path,
                    rule="minItems",
                    message=f"Array length {len(data)} < minimum {schema['minItems']}",
                ))
            if "maxItems" in schema and len(data) > schema["maxItems"]:
                violations.append(SchemaViolation(
                    path=path,
                    rule="maxItems",
                    message=f"Array length {len(data)} > maximum {schema['maxItems']}",
                ))
            if "items" in schema:
                for i, item in enumerate(data):
                    self._validate_node(
                        item,
                        schema["items"],
                        f"{path}[{i}]",
                        violations,
                    )

    @staticmethod
    def _check_type(data: Any, expected: str) -> bool:
        """Check if data matches expected JSON Schema type."""
        type_map = {
            "object": dict,
            "array": list,
            "string": str,
            "number": (int, float),
            "integer": int,
            "boolean": bool,
        }
        expected_type = type_map.get(expected)
        if expected_type is None:
            return True
        return isinstance(data, expected_type)