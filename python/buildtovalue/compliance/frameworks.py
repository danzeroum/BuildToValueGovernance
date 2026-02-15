"""
Framework Registry v2.0
Predefined regulatory frameworks with sample articles.
"""

from dataclasses import dataclass
from typing import List, Dict
from .translator import RegulatoryArticle


@dataclass
class Framework:
    name: str
    jurisdiction: str
    description: str
    articles: List[RegulatoryArticle]


class FrameworkRegistry:
    """Registry of supported regulatory frameworks."""

    def __init__(self) -> None:
        self._frameworks: Dict[str, Framework] = {}
        self._register_defaults()

    def _register_defaults(self) -> None:
        self.register(Framework(
            name="LGPD",
            jurisdiction="Brazil",
            description="Lei Geral de Proteção de Dados",
            articles=[
                RegulatoryArticle(
                    framework="LGPD",
                    article_id="Art.7",
                    title="Bases Legais",
                    text="O tratamento de dados pessoais somente poderá ser realizado mediante consentimento do titular.",
                    keywords=["dados pessoais", "consentimento"],
                ),
                RegulatoryArticle(
                    framework="LGPD",
                    article_id="Art.11",
                    title="Dados Sensíveis",
                    text="O tratamento de dados pessoais sensíveis como saúde, religião, orientação sexual somente com consentimento específico.",
                    keywords=["dados sensíveis", "consentimento"],
                ),
                RegulatoryArticle(
                    framework="LGPD",
                    article_id="Art.20",
                    title="Direito à Explicação",
                    text="O titular dos dados tem direito a solicitar a revisão de decisões tomadas unicamente com base em tratamento automatizado.",
                    keywords=["automated decision", "right to explanation"],
                ),
            ],
        ))

        self.register(Framework(
            name="GDPR",
            jurisdiction="European Union",
            description="General Data Protection Regulation",
            articles=[
                RegulatoryArticle(
                    framework="GDPR",
                    article_id="Art.22",
                    title="Automated Decision Making",
                    text="The data subject shall have the right not to be subject to a decision based solely on automated processing including profiling.",
                    keywords=["automated decision"],
                ),
                RegulatoryArticle(
                    framework="GDPR",
                    article_id="Art.17",
                    title="Right to Erasure",
                    text="The data subject shall have the right to obtain the erasure of personal data without undue delay.",
                    keywords=["personal data"],
                ),
            ],
        ))

        self.register(Framework(
            name="EU_AI_ACT",
            jurisdiction="European Union",
            description="EU Artificial Intelligence Act",
            articles=[
                RegulatoryArticle(
                    framework="EU_AI_ACT",
                    article_id="Art.14",
                    title="Human Oversight",
                    text="High-risk AI systems shall be designed to allow for effective human oversight and the ability to explain automated decisions.",
                    keywords=["automated decision", "right to explanation"],
                ),
            ],
        ))

    def register(self, framework: Framework) -> None:
        self._frameworks[framework.name] = framework

    def get(self, name: str) -> Framework:
        if name not in self._frameworks:
            raise KeyError(f"Framework not found: {name}")
        return self._frameworks[name]

    def list_frameworks(self) -> List[str]:
        return list(self._frameworks.keys())

    def get_all_articles(self) -> List[RegulatoryArticle]:
        articles = []
        for fw in self._frameworks.values():
            articles.extend(fw.articles)
        return articles