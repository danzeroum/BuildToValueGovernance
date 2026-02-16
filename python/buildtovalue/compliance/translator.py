"""
Compliance Translator v2.0
Converts regulatory text into YAML Policy Cards.
No LLM dependency — rule-based extraction for determinism.
"""

import yaml
import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional


@dataclass
class RegulatoryArticle:
    framework: str
    article_id: str
    title: str
    text: str
    keywords: List[str] = field(default_factory=list)


@dataclass
class PolicyCard:
    id: str
    name: str
    framework: str
    article: str
    description: str
    severity: str
    action: str
    patterns: List[str]
    references: List[str]

    def to_yaml(self) -> str:
        doc = {
            "id": self.id,
            "name": self.name,
            "framework": self.framework,
            "article": self.article,
            "description": self.description,
            "severity": self.severity,
            "action": self.action,
            "patterns": self.patterns,
            "references": self.references,
        }
        return yaml.dump(doc, default_flow_style=False, sort_keys=False)


# Keyword → severity/action mapping
KEYWORD_RULES = {
    "dados pessoais": {"severity": "HIGH", "action": "REDACT", "pattern": r"\b(cpf|cnpj|rg|nome completo)\b"},
    "dados sensíveis": {"severity": "CRITICAL", "action": "BLOCK", "pattern": r"\b(saúde|religião|orientação sexual|biometria)\b"},
    "consentimento": {"severity": "HIGH", "action": "LOG", "pattern": r"\b(consent|autorização|opt.?in)\b"},
    "transferência internacional": {"severity": "HIGH", "action": "BLOCK", "pattern": r"\b(transfer|cross.?border|internacional)\b"},
    "anonimização": {"severity": "MEDIUM", "action": "REDACT", "pattern": r"\b(anoni|pseudoni|mask)\b"},
    "direito de acesso": {"severity": "MEDIUM", "action": "LOG", "pattern": r"\b(acesso|portabilidade|retificação)\b"},
    "personal data": {"severity": "HIGH", "action": "REDACT", "pattern": r"\b(name|email|phone|address|ssn)\b"},
    "automated decision": {"severity": "HIGH", "action": "LOG", "pattern": r"\b(automated|profiling|algorithm)\b"},
    "right to explanation": {"severity": "HIGH", "action": "LOG", "pattern": r"\b(explain|transparency|interpretab)\b"},
}


class ComplianceTranslator:
    """
    Rule-based translator: regulatory text → YAML policy cards.
    Deterministic (no LLM). Matches keywords to generate policies.
    """

    def __init__(self) -> None:
        self.rules = KEYWORD_RULES.copy()

    def translate(self, article: RegulatoryArticle) -> List[PolicyCard]:
        cards: List[PolicyCard] = []
        text_lower = article.text.lower()

        for keyword, rule in self.rules.items():
            if keyword in text_lower:
                card = PolicyCard(
                    id=f"compliance-{article.framework.lower()}-{article.article_id}-{len(cards)+1:03d}",
                    name=f"{article.framework} {article.article_id}: {keyword.title()}",
                    framework=article.framework,
                    article=article.article_id,
                    description=f"Enforces {keyword} requirement from {article.framework} {article.article_id}",
                    severity=rule["severity"],
                    action=rule["action"],
                    patterns=[rule["pattern"]],
                    references=[f"{article.framework} {article.article_id}"],
                )
                cards.append(card)

        return cards

    def translate_batch(self, articles: List[RegulatoryArticle]) -> str:
        all_cards = []
        for article in articles:
            all_cards.extend(self.translate(article))

        doc = {
            "version": "2.0",
            "metadata": {
                "name": "Compliance Policies",
                "source": "ComplianceTranslator",
                "frameworks": list(set(c.framework for c in all_cards)),
            },
            "policies": [yaml.safe_load(c.to_yaml()) for c in all_cards],
        }
        return yaml.dump(doc, default_flow_style=False, sort_keys=False)