"""Tests for Compliance Translator v2.0."""

import pytest
from python.buildtovalue.compliance.translator import ComplianceTranslator, RegulatoryArticle
from python.buildtovalue.compliance.frameworks import FrameworkRegistry


@pytest.fixture
def translator():
    return ComplianceTranslator()


@pytest.fixture
def registry():
    return FrameworkRegistry()


class TestComplianceTranslator:

    def test_translate_lgpd_article(self, translator):
        article = RegulatoryArticle(
            framework="LGPD",
            article_id="Art.7",
            title="Bases Legais",
            text="O tratamento de dados pessoais somente poderá ser realizado mediante consentimento do titular.",
        )
        cards = translator.translate(article)
        assert len(cards) >= 1
        frameworks = [c.framework for c in cards]
        assert "LGPD" in frameworks

    def test_translate_generates_yaml(self, translator):
        article = RegulatoryArticle(
            framework="GDPR",
            article_id="Art.22",
            title="Automated Decisions",
            text="The data subject has the right regarding automated decision making and profiling.",
        )
        cards = translator.translate(article)
        assert len(cards) >= 1
        yaml_out = cards[0].to_yaml()
        assert "GDPR" in yaml_out

    def test_no_match_returns_empty(self, translator):
        article = RegulatoryArticle(
            framework="TEST",
            article_id="Art.99",
            title="Nothing",
            text="This text has no matching keywords whatsoever.",
        )
        cards = translator.translate(article)
        assert len(cards) == 0

    def test_translate_batch(self, translator):
        articles = [
            RegulatoryArticle(framework="LGPD", article_id="Art.11",
                title="Dados Sensíveis", text="Tratamento de dados sensíveis como saúde requer consentimento."),
            RegulatoryArticle(framework="GDPR", article_id="Art.17",
                title="Erasure", text="Erasure of personal data without undue delay."),
        ]
        yaml_out = translator.translate_batch(articles)
        assert "policies:" in yaml_out


class TestFrameworkRegistry:

    def test_default_frameworks(self, registry):
        frameworks = registry.list_frameworks()
        assert "LGPD" in frameworks
        assert "GDPR" in frameworks
        assert "EU_AI_ACT" in frameworks

    def test_get_framework(self, registry):
        lgpd = registry.get("LGPD")
        assert lgpd.jurisdiction == "Brazil"
        assert len(lgpd.articles) >= 2

    def test_get_all_articles(self, registry):
        articles = registry.get_all_articles()
        assert len(articles) >= 4

    def test_missing_framework_raises(self, registry):
        with pytest.raises(KeyError):
            registry.get("NONEXISTENT")
