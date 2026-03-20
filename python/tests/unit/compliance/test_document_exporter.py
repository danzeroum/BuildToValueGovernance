"""Tests for Document Exporter (ADR-048)."""

import json
import os
import pytest
import tempfile
from pathlib import Path

from buildtovalue.compliance.document_exporter import DocumentExporter


class TestDocumentExporter:
    def test_list_templates(self):
        exporter = DocumentExporter()
        templates = exporter.list_templates()
        assert "ropa" in templates
        assert "fria" in templates
        assert "art20" in templates

    def test_export_json(self):
        exporter = DocumentExporter()
        data = {"document_type": "TEST", "content": "test data"}

        with tempfile.TemporaryDirectory() as tmpdir:
            path = exporter.export_json(
                data=data,
                output_dir=tmpdir,
                template_name="test",
            )

            assert os.path.isfile(path)
            with open(path) as f:
                loaded = json.load(f)
            assert loaded["document_type"] == "TEST"

    def test_export_json_custom_filename(self):
        exporter = DocumentExporter()
        data = {"test": True}

        with tempfile.TemporaryDirectory() as tmpdir:
            path = exporter.export_json(
                data=data,
                output_dir=tmpdir,
                filename="custom_report.json",
            )
            assert path.endswith("custom_report.json")

    def test_export_pdf_requires_weasyprint(self):
        """PDF export should fail gracefully if weasyprint not installed."""
        exporter = DocumentExporter()
        data = {"document_type": "TEST"}

        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                exporter.export_pdf(
                    data=data,
                    template_name="ropa",
                    output_dir=tmpdir,
                )
                # If weasyprint is installed, should succeed
            except ImportError as e:
                assert "weasyprint" in str(e).lower()

    def test_missing_template_raises(self):
        exporter = DocumentExporter()
        data = {"test": True}

        with tempfile.TemporaryDirectory() as tmpdir:
            with pytest.raises((FileNotFoundError, ImportError)):
                exporter.export_pdf(
                    data=data,
                    template_name="nonexistent",
                    output_dir=tmpdir,
                )
