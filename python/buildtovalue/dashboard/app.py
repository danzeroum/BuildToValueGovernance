"""
BuildToValue Streamlit Dashboard v1.0
Visual interface for the República Algorítmica.
"""

import streamlit as st
import requests
import json
import time
import os

GATEWAY_URL = os.environ.get("BTV_GATEWAY_URL", "http://localhost:8080")
GOVERNANCE_URL = os.environ.get("BTV_GOVERNANCE_URL", "http://localhost:8000")

st.set_page_config(page_title="BuildToValue — Sovereign Trust OS", layout="wide")

# ═══════════════════════════════════════════════════════════════
# SIDEBAR
# ═══════════════════════════════════════════════════════════════

st.sidebar.title("BuildToValue")
st.sidebar.caption("Sovereign Trust OS v2.0")

page = st.sidebar.radio("Navigation", [
    "Validate",
    "Sanitize",
    "Trust Score",
    "Compliance",
    "Intelligence",
    "Metrics",
])

# ═══════════════════════════════════════════════════════════════
# VALIDATE
# ═══════════════════════════════════════════════════════════════

if page == "Validate":
    st.title("Validate Input")
    st.caption("Scan + Policy + Governance (Republica Algoritmica)")

    col1, col2 = st.columns([3, 1])
    with col1:
        user_input = st.text_area("Input text", height=100, placeholder="Type or paste text to validate...")
    with col2:
        session_id = st.text_input("Session ID", value="dashboard-user")

    if st.button("Validate", type="primary"):
        if user_input:
            with st.spinner("Scanning..."):
                try:
                    resp = requests.post(f"{GATEWAY_URL}/v1/validate", json={
                        "input": user_input,
                        "session_id": session_id,
                    }, timeout=5)
                    data = resp.json()

                    # Action badge
                    action = data.get("action", "UNKNOWN")
                    colors = {"ALLOW": "green", "LOG": "blue", "EDUCATE": "orange", "REDACT": "orange", "BLOCK": "red"}
                    st.markdown(f"### :{colors.get(action, 'gray')}[{action}]")

                    # Key metrics
                    c1, c2, c3, c4 = st.columns(4)
                    c1.metric("Findings", data.get("finding_count", 0))
                    c2.metric("Critical", data.get("critical_count", 0))
                    c3.metric("Risk", f"{data.get('composite_risk', 0) * 100:.0f}%")
                    c4.metric("Latency", f"{data.get('latency_ms', 0):.1f}ms")

                    # Mercy
                    if data.get("mercy_applied"):
                        st.success(f"Mercy applied: {data.get('original_action')} -> {action}")

                    # Hard block
                    if data.get("hard_blocked"):
                        st.error("HARD BLOCK: Dangerous content detected")

                    # Details
                    with st.expander("Full Response"):
                        st.json(data)

                except Exception as e:
                    st.error(f"Error: {e}")

# ═══════════════════════════════════════════════════════════════
# SANITIZE
# ═══════════════════════════════════════════════════════════════

elif page == "Sanitize":
    st.title("PII Sanitizer")
    st.caption("Mask sensitive data in LLM output")

    text = st.text_area("Text to sanitize", height=100, placeholder="Paste LLM output containing PII...")

    if st.button("Sanitize", type="primary"):
        if text:
            try:
                resp = requests.post(f"{GATEWAY_URL}/v1/sanitize", json={"text": text}, timeout=5)
                data = resp.json()

                st.markdown("### Result")
                st.code(data.get("sanitized_text", ""), language=None)

                c1, c2, c3 = st.columns(3)
                c1.metric("Masked", data.get("masked_count", 0))
                c2.metric("Types", ", ".join(data.get("masked_types", [])) or "None")
                c3.metric("Latency", f"{data.get('latency_ms', 0):.1f}ms")

            except Exception as e:
                st.error(f"Error: {e}")

# ═══════════════════════════════════════════════════════════════
# TRUST SCORE
# ═══════════════════════════════════════════════════════════════

elif page == "Trust Score":
    st.title("Trust Score Lookup")

    session_id = st.text_input("Session ID", value="dashboard-user")

    if st.button("Lookup", type="primary"):
        try:
            resp = requests.get(f"{GOVERNANCE_URL}/v1/trust/{session_id}", timeout=5)
            data = resp.json()

            trust = data.get("trust_score", 0.5)
            color = "green" if trust > 0.6 else "orange" if trust > 0.3 else "red"

            st.markdown(f"### :{color}[Trust: {trust:.2f}]")

            c1, c2, c3 = st.columns(3)
            c1.metric("Trust Score", f"{trust:.2f}")
            c2.metric("Offenses", data.get("offenses", 0))
            c3.metric("Total Requests", data.get("total_requests", 0))

            # Trust bar
            st.progress(min(trust, 1.0))

        except Exception as e:
            st.error(f"Error: {e}")

# ═══════════════════════════════════════════════════════════════
# COMPLIANCE
# ═══════════════════════════════════════════════════════════════

elif page == "Compliance":
    st.title("Compliance Reports")

    framework = st.selectbox("Framework", ["LGPD", "EU_AI_ACT"])

    if st.button("Generate Report", type="primary"):
        try:
            resp = requests.get(f"{GOVERNANCE_URL}/v1/compliance/report/{framework}", timeout=5)
            data = resp.json()

            rate = data.get("compliance_rate", 0)
            st.markdown(f"### {'green' if rate == 1.0 else 'orange'}[{framework} — {rate:.0%} Compliant]")

            c1, c2, c3 = st.columns(3)
            c1.metric("Compliant", data.get("compliant", 0))
            c2.metric("Partial", data.get("partial", 0))
            c3.metric("Non-Compliant", data.get("non_compliant", 0))

            st.divider()

            for artifact in data.get("artifacts", []):
                status = artifact.get("status", "")
                icon = {"COMPLIANT": "white_check_mark", "PARTIAL": "warning", "NON_COMPLIANT": "x"}.get(status, "question")
                with st.expander(f":{icon}: {artifact['article']} — {artifact['requirement']}"):
                    st.markdown(f"**Status:** {status}")
                    st.markdown(f"**Evidence:** {artifact.get('evidence', '')}")
                    st.markdown(f"**Recommendation:** {artifact.get('recommendation', '')}")

        except Exception as e:
            st.error(f"Error: {e}")

# ═══════════════════════════════════════════════════════════════
# INTELLIGENCE
# ═══════════════════════════════════════════════════════════════

elif page == "Intelligence":
    st.title("Threat Intelligence Hub")

    tab1, tab2 = st.tabs(["Browse", "Ingest"])

    with tab1:
        col1, col2 = st.columns(2)
        with col1:
            filter_type = st.text_input("Filter by type", placeholder="prompt_injection")
        with col2:
            min_sev = st.slider("Min severity", 0, 10, 0)

        if st.button("Search"):
            try:
                resp = requests.post(f"{GOVERNANCE_URL}/v1/intelligence/query", json={
                    "threat_type": filter_type or None,
                    "min_severity": min_sev,
                }, timeout=5)
                data = resp.json()
                st.metric("Results", data.get("count", 0))
                for t in data.get("threats", []):
                    sev = t.get("severity", 0)
                    color = "red" if sev >= 8 else "orange" if sev >= 5 else "blue"
                    with st.expander(f":{color}_circle: [{t['source']}] {t['threat_type']} (severity {sev})"):
                        st.markdown(f"**ID:** {t['id']}")
                        st.markdown(f"**Description:** {t.get('description', 'N/A')}")
                        st.markdown(f"**MITRE:** {t.get('mitre_id', 'N/A')}")
                        st.markdown(f"**Indicators:** {', '.join(t.get('indicators', []))}")
                        st.markdown(f"**Hash:** `{t['hash']}`")
            except Exception as e:
                st.error(f"Error: {e}")

        # Stats
        try:
            stats = requests.get(f"{GOVERNANCE_URL}/v1/intelligence/stats", timeout=5).json()
            st.divider()
            c1, c2, c3 = st.columns(3)
            c1.metric("Total Threats", stats.get("total_threats", 0))
            c2.metric("Avg Severity", stats.get("avg_severity", 0))
            c3.metric("Sources", len(stats.get("by_source", {})))
        except:
            pass

    with tab2:
        with st.form("ingest_form"):
            tid = st.text_input("Threat ID", placeholder="T004")
            ttype = st.selectbox("Type", ["prompt_injection", "pii_leakage", "data_exfiltration", "social_engineering", "other"])
            severity = st.slider("Severity", 1, 10, 5)
            source = st.selectbox("Source", ["OWASP", "MISP", "STIX", "manual"])
            indicators = st.text_input("Indicators (comma-separated)", placeholder="keyword1, keyword2")
            description = st.text_input("Description")
            mitre = st.text_input("MITRE ATT&CK ID", placeholder="T1059")

            if st.form_submit_button("Ingest"):
                try:
                    resp = requests.post(f"{GOVERNANCE_URL}/v1/intelligence/ingest", json={
                        "id": tid,
                        "threat_type": ttype,
                        "severity": severity,
                        "source": source,
                        "indicators": [i.strip() for i in indicators.split(",") if i.strip()],
                        "description": description,
                        "mitre_id": mitre,
                    }, timeout=5)
                    st.success(f"Ingested: {resp.json()}")
                except Exception as e:
                    st.error(f"Error: {e}")

# ═══════════════════════════════════════════════════════════════
# METRICS
# ═══════════════════════════════════════════════════════════════

elif page == "Metrics":
    st.title("System Metrics")

    try:
        gw = requests.get(f"{GATEWAY_URL}/health", timeout=5).json()
        gov = requests.get(f"{GOVERNANCE_URL}/health", timeout=5).json()

        c1, c2 = st.columns(2)
        with c1:
            st.markdown("### Rust Gateway")
            st.json(gw)
        with c2:
            st.markdown("### Python Governance")
            st.json(gov)

        st.divider()
        st.markdown("### Prometheus Metrics")
        metrics = requests.get(f"{GATEWAY_URL}/metrics", timeout=5).text
        st.code(metrics, language=None)

    except Exception as e:
        st.error(f"Error: {e}")