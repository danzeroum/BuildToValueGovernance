"""
Document Exporter v1.0 — JSON to PDF conversion (ADR-048).

Converts compliance reports (ROPA, FRIA, Art. 20) from JSON/dict format
to professional PDF documents using Jinja2 templates + weasyprint.

Dependencies (optional):
    pip install weasyprint>=60 Jinja2>=3.1

Fail-secure: if dependencies not installed, raises ImportError with
clear install instructions.
"""

import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger("btv.compliance.exporter")

TEMPLATES_DIR = Path(__file__).parent / "templates"


class DocumentExporter:
    """
    Exports compliance documents to PDF.

    Usage:
        exporter = DocumentExporter()
        pdf_path = exporter.export_pdf(
            data=ropa.to_dict(),
            template_name="ropa",
            output_dir="data/compliance/documents",
        )
    """

    def __init__(self, templates_dir: Optional[str] = None) -> None:
        self._templates_dir = Path(templates_dir) if templates_dir else TEMPLATES_DIR
        self._jinja_env = None

    def _get_jinja_env(self):
        """Lazy-load Jinja2 environment."""
        if self._jinja_env is None:
            try:
                from jinja2 import Environment, FileSystemLoader
            except ImportError:
                raise ImportError(
                    "Jinja2 is required for document export. "
                    "Install with: pip install Jinja2>=3.1"
                )
            self._jinja_env = Environment(
                loader=FileSystemLoader(str(self._templates_dir)),
                autoescape=True,
            )
        return self._jinja_env

    def export_pdf(
        self,
        data: Dict[str, Any],
        template_name: str,
        output_dir: str = "data/compliance/documents",
        filename: Optional[str] = None,
    ) -> str:
        """
        Export data to PDF using named template.

        Args:
            data: Dict with report data (from .to_dict())
            template_name: Template name without extension (ropa, fria, art20)
            output_dir: Directory for output PDF
            filename: Custom filename (auto-generated if None)

        Returns:
            Path to generated PDF file.
        """
        try:
            from weasyprint import HTML
        except ImportError:
            raise ImportError(
                "weasyprint is required for PDF export. "
                "Install with: pip install weasyprint>=60"
            )

        env = self._get_jinja_env()
        template_file = f"{template_name}.html.j2"

        try:
            template = env.get_template(template_file)
        except Exception as e:
            raise FileNotFoundError(
                f"Template '{template_file}' not found in {self._templates_dir}: {e}"
            )

        html_content = template.render(
            data=data,
            generated_at=datetime.now(timezone.utc).isoformat(),
        )

        out_dir = Path(output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        if filename is None:
            doc_id = uuid.uuid4().hex[:12]
            filename = f"{template_name}_{doc_id}.pdf"

        output_path = out_dir / filename

        HTML(string=html_content).write_pdf(str(output_path))
        logger.info("PDF exported: %s", output_path)

        return str(output_path)

    def export_json(
        self,
        data: Dict[str, Any],
        output_dir: str = "data/compliance/documents",
        filename: Optional[str] = None,
        template_name: str = "report",
    ) -> str:
        """Export data as formatted JSON file."""
        out_dir = Path(output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        if filename is None:
            doc_id = uuid.uuid4().hex[:12]
            filename = f"{template_name}_{doc_id}.json"

        output_path = out_dir / filename

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        logger.info("JSON exported: %s", output_path)
        return str(output_path)

    def list_templates(self) -> list:
        """List available templates."""
        if not self._templates_dir.is_dir():
            return []
        return [
            p.stem.replace(".html", "")
            for p in self._templates_dir.glob("*.html.j2")
        ]
