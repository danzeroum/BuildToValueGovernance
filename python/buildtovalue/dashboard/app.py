"""
BuildToValue Dashboard MVP v2.0 — Streamlit
Run: streamlit run python/buildtovalue/dashboard/app.py
"""

try:
    import streamlit as st
except ImportError:
    raise ImportError("Install streamlit: pip install streamlit")

import sys
import os
import json
import time

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..'))

from python.buildtovalue.governance.ethical_context_engine import EthicalContextEngineV3
from python.buildtovalue.governance.types import EthicalContext, ActionType
from python.buildtovalue.governance.contestability_loop import ContestabilityLoop, AppealStatus
from python.buildtovalue.governance.trust_score import TrustScoreCalculator
from python.buildtovalue.intelligence.misp_ingestor import MispIngestor, ThreatEvent
from python.buildtovalue.intelligence.threat_classifier import ThreatClassifier
from python.buildtovalue.intelligence.policy_generator import PolicyGenerator
from python.buildtovalue.compliance.translator import ComplianceTranslator
from python.buildtovalue.compliance.frameworks import FrameworkRegistry


# ═══════════════════════════════════════════════════════════════════
# STATE INIT
# ═══════════════════════════════════════════════════════════════════

@st.cache_resource
def init_engine():
    return EthicalContextEngineV3()

@st.cache_resource
def init_loop():
    return ContestabilityLoop(sla_hours=24)

@st.cache_resource
def init_intelligence():
    return MispIngestor(), ThreatClassifier(), PolicyGenerator()

@st.cache_resource
def init_compliance():
    return ComplianceTranslator(), FrameworkRegistry()


def main():
    st.set_page_config(page_title="BuildToValue — Trust OS", layout="wide")
    st.title("BuildToValue — Sovereign Trust OS")
    st.caption("v2.0 Dashboard MVP")

    engine = init_engine()
    loop = init_loop()
    ingestor, classifier, generator = init_intelligence()
    translator, registry = init_compliance()

    tab1, tab2, tab3, tab4 = st.tabs([
        "Governance", "Intelligence", "Compliance", "Metrics"
    ])

    # ─── TAB 1: GOVERNANCE ───────────────────────────────────────
    with tab1:
        st.header("Ethical Decision Engine")

        col1, col2 = st.columns(2)
        with col1:
            risk = st.slider("Composite Risk", 0.0, 1.0, 0.6, 0.05)
            findings = st.number_input("Finding Count", 0, 20, 2)
            critical = st.number_input("Critical Count", 0, 10, 0)
        with col2:
            trust = st.slider("Trust Score", 0.0, 1.0, 0.5, 0.05)
            first_offense = st.checkbox("First Offense", True)
            educational = st.checkbox("Educational Mode", False)

        if st.button("Run Decision", type="primary"):
            evidence = {
                'composite_risk': risk,
                'finding_count': findings,
                'critical_count': critical,
                'entropy': 5.0,
            }
            ctx = EthicalContext(
                trust_score=trust,
                is_first_offense=first_offense,
                educational_mode=educational,
            )
            start = time.perf_counter()
            decision = engine.decide(evidence, ctx)
            latency = (time.perf_counter() - start) * 1000

            col_r1, col_r2 = st.columns(2)
            with col_r1:
                color = {"ALLOW": "green", "LOG": "blue", "EDUCATE": "orange", "REDACT": "orange", "BLOCK": "red"}
                st.markdown(f"### Verdict: :{color.get(decision.verdict.value, 'gray')}[{decision.verdict.value}]")
                st.metric("Adjusted Severity", f"{decision.adjusted_severity:.2f}")
                st.metric("Latency", f"{latency:.2f}ms")
            with col_r2:
                st.metric("Mercy Applied", "Yes" if decision.mercy_applied else "No")
                st.metric("Contestable", "Yes" if decision.contestable else "No")
                if decision.signature:
                    st.code(f"HMAC: {decision.signature[:32]}...")

            st.text_area("Rationale", decision.rationale, height=100, disabled=True)

    # ─── TAB 2: INTELLIGENCE ─────────────────────────────────────
    with tab2:
        st.header("Threat Intelligence Hub")

        threat_type = st.selectbox("Threat Type", [
            "prompt_injection", "pii_leakage", "data_exfiltration",
            "model_extraction", "denial_of_service", "social_engineering",
        ])
        severity = st.slider("Severity", 1, 10, 8)

        if st.button("Ingest Threat"):
            event = ThreatEvent(
                id=f"threat-{int(time.time())}",
                threat_type=threat_type,
                severity=severity,
                source="Dashboard",
                indicators=["manual_entry"],
            )
            ingested = ingestor.ingest(event)
            st.success(f"Ingested: {ingested.id} (hash: {ingested.hash[:16]}...)")

        if st.button("Generate Policies from Threats"):
            events = ingestor.export_batch(50)
            if events:
                classifications = classifier.classify_batch(events)
                yaml_out = generator.generate_batch(classifications)
                st.code(yaml_out, language="yaml")
            else:
                st.warning("No threats ingested yet.")

        st.metric("Total Threats", ingestor.count())

    # ─── TAB 3: COMPLIANCE ───────────────────────────────────────
    with tab3:
        st.header("Compliance Translator")

        fw_name = st.selectbox("Framework", registry.list_frameworks())

        if st.button("Generate Policies"):
            fw = registry.get(fw_name)
            yaml_out = translator.translate_batch(fw.articles)
            st.code(yaml_out, language="yaml")
            st.info(f"Generated {len(fw.articles)} policy cards from {fw_name}")

    # ─── TAB 4: METRICS ──────────────────────────────────────────
    with tab4:
        st.header("System Metrics")

        col1, col2, col3 = st.columns(3)
        with col1:
            m = engine.get_metrics()
            st.metric("Total Decisions", m['decisions_total'])
            st.metric("Mercy Rate", f"{m['mercy_applied'] / max(m['decisions_total'], 1) * 100:.1f}%")
        with col2:
            lm = loop.get_metrics()
            st.metric("Appeals Submitted", lm['appeals_submitted'])
            st.metric("SLA Compliance", f"{loop.get_sla_compliance_rate() * 100:.0f}%")
        with col3:
            st.metric("Threats Ingested", ingestor.count())
            st.metric("Frameworks", len(registry.list_frameworks()))

        bias = engine.get_bias_declaration()
        st.json(bias)


if __name__ == "__main__":
    main()