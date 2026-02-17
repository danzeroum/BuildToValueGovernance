"""
Sector Pattern Loader v1.0 — False Positive Reduction.

Loads sector safe patterns from data/policies/sectors/.
Applies context-aware whitelisting to reduce FPR from ~15% to ~2%.

Philosophy: Gilligan — context of care reduces severity.
Compliance: EU AI Act Annex III (sector-specific risk).

Gate: v1.5.0 (Gap #4 — Profile-aware PolicyEngine)
"""

import yaml
import logging
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════
# TYPES
# ═══════════════════════════════════════════════════════════════


@dataclass
class SectorPatterns:
    """Loaded sector safe patterns."""

    sector_id: str
    risk_classification: str
    risk_multiplier: float
    patterns: Dict[str, List[str]] = field(default_factory=dict)


# ═══════════════════════════════════════════════════════════════
# SECTOR LOADER
# ═══════════════════════════════════════════════════════════════


class SectorLoader:
    """
    Loads and applies sector-specific safe patterns.

    Reduces false positive rate by whitelisting legitimate
    domain operations. A hospital mentioning "medical diagnosis"
    with PII is legitimate — not a leak.

    Usage:
        loader = SectorLoader()
        multiplier = loader.apply_whitelist(
            input_text="medical diagnosis for patient",
            findings=["PII_DETECTED"],
            sector_id="healthcare",
        )
        # multiplier = 0.7 → reduce risk by 30%
    """

    # Default risk multiplier for high-risk sectors (EU AI Act)
    HIGH_RISK_MULTIPLIER = 0.7

    def __init__(self, sectors_dir: Optional[Path] = None):
        """
        Initialize loader.

        Args:
            sectors_dir: Path to data/policies/sectors/.
                         Auto-detected if None.
        """
        if sectors_dir is None:
            root = Path(__file__).resolve().parent.parent.parent.parent
            sectors_dir = root / "data" / "policies" / "sectors"

        self.sectors_dir = Path(sectors_dir)
        self._index: Dict[str, dict] = {}
        self._cache: Dict[str, SectorPatterns] = {}
        self._load_index()

    def _load_index(self) -> None:
        """Load _index.yaml mapping sectors to files."""
        index_path = self.sectors_dir / "_index.yaml"
        if not index_path.exists():
            logger.warning(f"Sector index not found: {index_path}")
            return

        with open(index_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        self._index = data.get("sectors", {})
        logger.info(
            f"Sector index loaded: {len(self._index)} sectors"
        )

    def load_sector(self, sector_id: str) -> Optional[SectorPatterns]:
        """
        Load patterns for a sector.

        Returns None if sector has no patterns (e.g. general).
        Uses cache for repeated lookups.
        """
        if sector_id in self._cache:
            return self._cache[sector_id]

        entry = self._index.get(sector_id)
        if not entry or entry.get("file") is None:
            return None

        yaml_path = self.sectors_dir / entry["file"]
        if not yaml_path.exists():
            logger.error(f"Sector file missing: {yaml_path}")
            return None

        with open(yaml_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        # Parse patterns: trigger → [keywords]
        patterns = {}
        for trigger, config in data.get("safe_patterns", {}).items():
            keywords = config.get("keywords", [])
            patterns[trigger.lower()] = [k.lower() for k in keywords]

        # Determine risk multiplier
        risk_class = entry.get("risk_classification", "minimal_risk")
        multiplier = (
            self.HIGH_RISK_MULTIPLIER
            if risk_class == "high_risk"
            else 1.0
        )

        result = SectorPatterns(
            sector_id=sector_id,
            risk_classification=risk_class,
            risk_multiplier=multiplier,
            patterns=patterns,
        )

        self._cache[sector_id] = result
        logger.debug(
            f"Sector loaded: {sector_id} "
            f"({len(patterns)} patterns, "
            f"multiplier={multiplier})"
        )
        return result

    def apply_whitelist(
        self,
        input_text: str,
        findings: List[str],
        sector_id: str,
    ) -> float:
        """
        Check if findings are whitelisted in sector context.

        Returns risk_multiplier:
        - 1.0 = no reduction (no whitelist match)
        - < 1.0 = risk reduced (e.g. 0.7 for healthcare)

        Matching logic:
        1. Lowercase input_text
        2. For each trigger in sector patterns:
           a. If trigger substring found in text
           b. AND any finding type contains a whitelisted keyword
           c. → return sector risk_multiplier

        Args:
            input_text: Original user input
            findings: List of finding type strings from kernel
            sector_id: Sector to check against
        """
        sector = self.load_sector(sector_id)
        if sector is None:
            return 1.0

        text_lower = input_text.lower()
        findings_lower = [f.lower() for f in findings]

        for trigger, keywords in sector.patterns.items():
            if trigger not in text_lower:
                continue

            # Trigger found — check keyword overlap with findings
            for kw in keywords:
                if any(kw in finding for finding in findings_lower):
                    logger.info(
                        f"Sector whitelist hit: "
                        f"trigger='{trigger}', "
                        f"keyword='{kw}', "
                        f"sector={sector_id}"
                    )
                    return sector.risk_multiplier

        return 1.0

    def get_metrics(self) -> Dict[str, int]:
        """Return loader metrics."""
        return {
            "sectors_indexed": len(self._index),
            "sectors_cached": len(self._cache),
        }