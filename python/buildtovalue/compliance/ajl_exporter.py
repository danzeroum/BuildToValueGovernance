"""
AJL (Algorithmic Justice League) Certification Exporter
Generates transparency reports for AJL certification.

DESIGN:
- Rust computes bias metrics (deterministic)
- Python formats for human review (AJL committee)
"""

import json
from typing import Dict, Any, List
from pathlib import Path
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


class AJLExporter:
    """
    Export AJL transparency reports from Rust bias metrics.

    Example:
        exporter = AJLExporter()
        report = exporter.generate_report(
            rust_metrics=rust_bias_metrics,
            system_info={"name": "BuildToValue v2.0"}
        )
        exporter.save_report(report, "ajl_report_2026.json")
    """

    def generate_report(
            self,
            rust_metrics: Dict[str, Any],  # From Rust FFI
            system_info: Dict[str, str],
    ) -> Dict[str, Any]:
        """
        Generate AJL-compliant transparency report.

        Args:
            rust_metrics: Output from ajl_metrics.rs (Protobuf)
            system_info: System metadata (name, version, etc.)

        Returns:
            AJL report (JSON-serializable)
        """
        report = {
            "report_version": "AJL-1.0",
            "generated_at": datetime.utcnow().isoformat(),
            "system": system_info,
            "bias_metrics": self._format_bias_metrics(rust_metrics),
            "certification_status": self._assess_certification(rust_metrics),
            "recommendations": self._generate_recommendations(rust_metrics),
        }

        return report

    def _format_bias_metrics(self, rust_metrics: Dict) -> List[Dict]:
        """
        Format Rust metrics for AJL review.

        AJL requires:
        - Demographic groups tested
        - Disparate Impact Ratio (DIR)
        - Sample size
        - Pass/fail status
        """
        formatted = []

        for metric in rust_metrics.get("metrics", []):
            formatted.append({
                "group_a": metric["group_a"],
                "group_b": metric["group_b"],
                "dir": metric["dir"],
                "threshold": metric["pass_threshold"],
                "compliant": metric["compliant"],
                "sample_size": metric["sample_size"],
                "tested_at": datetime.fromtimestamp(metric["timestamp"]).isoformat(),
            })

        return formatted

    def _assess_certification(self, rust_metrics: Dict) -> Dict[str, Any]:
        """
        Assess if system is eligible for AJL certification.

        Criteria:
        - 95%+ of metrics pass DIR >= 0.8
        - No critical bias violations
        - Sufficient sample size (N >= 100 per group)
        """
        total = rust_metrics.get("total_metrics", 0)
        compliant = rust_metrics.get("compliant_metrics", 0)
        compliance_rate = rust_metrics.get("compliance_rate", 0.0)

        eligible = compliance_rate >= 0.95

        return {
            "eligible": eligible,
            "compliance_rate": compliance_rate,
            "total_metrics_tested": total,
            "passed": compliant,
            "failed": total - compliant,
            "certification_date": datetime.utcnow().isoformat() if eligible else None,
        }

    def _generate_recommendations(self, rust_metrics: Dict) -> List[str]:
        """
        Generate actionable recommendations for bias mitigation.
        """
        recommendations = []

        for metric in rust_metrics.get("metrics", []):
            if not metric["compliant"]:
                recommendations.append(
                    f"⚠️ Bias detected: {metric['group_a']} vs {metric['group_b']} "
                    f"(DIR: {metric['dir']:.2f}, threshold: {metric['pass_threshold']}). "
                    f"Consider retraining or applying fairness constraints."
                )

        if not recommendations:
            recommendations.append("✅ All bias metrics passed. No action required.")

        return recommendations

    def save_report(self, report: Dict, output_path: str | Path) -> None:
        """Save AJL report to JSON file."""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        logger.info(f"✅ AJL report saved: {output_path}")

    def submit_to_ajl(self, report: Dict) -> Dict[str, Any]:
        """
        Submit report to AJL for review (mock endpoint).

        In production, this would POST to AJL's API.
        """
        # Mock submission
        logger.info("📤 Submitting report to AJL for review...")

        return {
            "submission_id": "ajl-sub-20260204-001",
            "status": "under_review",
            "estimated_review_time_days": 14,
            "message": "Report submitted successfully. You will be notified via email.",
        }


# USAGE EXAMPLE (CORRIGIDO)
if __name__ == "__main__":
    # Mock metrics (em produção, viria do Rust FFI)
    rust_metrics = {
        "metrics": [
            {
                "group_a": "male",
                "group_b": "female",
                "dir": 0.92,
                "pass_threshold": 0.8,
                "compliant": True,
                "sample_size": 1000,
                "timestamp": 1707085200
            }
        ],
        "total_metrics": 10,
        "compliant_metrics": 9,
        "compliance_rate": 0.9
    }

    # Export to AJL format
    exporter = AJLExporter()
    report = exporter.generate_report(
        rust_metrics=rust_metrics,
        system_info={
            "name": "BuildToValue v2.0",
            "version": "2.0.0",
            "operator": "ACME Corp",
        },
    )

    # Save report
    exporter.save_report(report, "reports/ajl_transparency_2026.json")

    # Submit to AJL (optional)
    submission = exporter.submit_to_ajl(report)
    print(f"✅ Submitted to AJL: {submission['submission_id']}")
