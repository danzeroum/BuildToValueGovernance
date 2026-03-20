"""
BuildToValue Governance Playground

Try the BTV governance gateway interactively — no installation needed.
Paste any text and see the ethical governance verdict in real time.

Run with:
    streamlit run playground/app.py

Environment variables:
    BTV_API_KEY       — Your BTV API key (default: dev-key for local testing)
    BTV_GATEWAY_URL   — Gateway URL (default: http://localhost:8080)
"""
from __future__ import annotations

import os
import time
import uuid
import streamlit as st
from buildtovalue import BTVClient
from buildtovalue.exceptions import BTVAuthError, BTVGatewayError

# ─── Page config ─────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="BuildToValue Playground",
    page_icon="⚖️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─── Client initialization ───────────────────────────────────────────────────

@st.cache_resource
def get_client() -> BTVClient:
    api_key = os.environ.get("BTV_API_KEY", "dev-key")
    gateway_url = os.environ.get("BTV_GATEWAY_URL", "http://localhost:8080")
    return BTVClient(api_key=api_key, gateway_url=gateway_url)


# ─── Session state ───────────────────────────────────────────────────────────

if "session_id" not in st.session_state:
    st.session_state.session_id = f"playground-{uuid.uuid4().hex[:8]}"

if "history" not in st.session_state:
    st.session_state.history = []

if "show_appeal_form" not in st.session_state:
    st.session_state.show_appeal_form = False

if "last_verdict" not in st.session_state:
    st.session_state.last_verdict = None

# ─── Sidebar ─────────────────────────────────────────────────────────────────

with st.sidebar:
    st.title("⚖️ BuildToValue")
    st.caption("Ethical AI Governance Playground")
    st.divider()

    profile = st.selectbox(
        "Governance Profile",
        ["general", "healthcare", "finance", "legal", "research", "education"],
        help="Sector-specific policies and risk thresholds",
    )

    use_decide = st.toggle(
        "Full ethical pipeline",
        value=True,
        help="ON: /v1/decide (Rawls→Levinas→Jonas→Gilligan)\nOFF: /v1/validate (Rust only, faster)",
    )

    st.divider()
    st.markdown("**Session**")
    st.code(st.session_state.session_id, language=None)
    if st.button("New Session"):
        st.session_state.session_id = f"playground-{uuid.uuid4().hex[:8]}"
        st.session_state.history = []
        st.session_state.last_verdict = None
        st.rerun()

    # Trust score
    st.divider()
    if st.button("Check Trust Score"):
        try:
            ts = get_client().trust_score(st.session_state.session_id)
            level = "🟢" if ts.trust_score >= 0.8 else ("🟡" if ts.trust_score >= 0.5 else "🔴")
            st.metric("Trust Score", f"{ts.trust_score:.3f}", label_visibility="visible")
            st.caption(f"{level} {ts.level} trust | {ts.total_requests} requests | {ts.offenses} offenses")
        except Exception as e:
            st.warning(f"Trust score unavailable: {e}")

    st.divider()
    st.caption("Gateway: " + os.environ.get("BTV_GATEWAY_URL", "http://localhost:8080"))

# ─── Main area ───────────────────────────────────────────────────────────────

st.title("⚖️ BuildToValue Governance Playground")
st.markdown(
    "Test the BTV ethical governance gateway. Paste any text and see the verdict — "
    "PII detection, compliance checks, philosophical rationale, and more."
)

# Input
col1, col2 = st.columns([3, 1])
with col1:
    input_text = st.text_area(
        "Input Text",
        placeholder=(
            "Try:\n"
            "• Meu CPF é 123.456.789-09\n"
            "• SELECT * FROM users WHERE 1=1\n"
            "• My credit card is 4111-1111-1111-1111\n"
            "• Hello, how can I help you today?"
        ),
        height=120,
        label_visibility="collapsed",
    )

with col2:
    st.markdown("<br>", unsafe_allow_html=True)
    analyze_btn = st.button("Analyze ⚖️", type="primary", use_container_width=True)
    sanitize_btn = st.button("Sanitize 🧹", use_container_width=True, help="Mask PII in text")

# ─── Analyze ─────────────────────────────────────────────────────────────────

ACTION_COLORS = {
    "ALLOW": "🟢",
    "BLOCK": "🔴",
    "EDUCATE": "🟡",
    "REDACT": "🟠",
    "INSPECT": "🔵",
    "LOG": "⚪",
}

if analyze_btn and input_text.strip():
    btv = get_client()
    with st.spinner("Analyzing..."):
        try:
            t0 = time.time()
            if use_decide:
                verdict = btv.decide(
                    input_text,
                    session_id=st.session_state.session_id,
                    profile=profile,
                )
            else:
                verdict = btv.validate(
                    input_text,
                    session_id=st.session_state.session_id,
                    profile=profile,
                )
            elapsed = (time.time() - t0) * 1000
            st.session_state.last_verdict = verdict
            st.session_state.history.insert(0, {
                "input": input_text[:80] + ("..." if len(input_text) > 80 else ""),
                "action": verdict.action,
                "verdict_id": verdict.verdict_id,
            })

        except BTVAuthError:
            st.error("Authentication failed. Check BTV_API_KEY environment variable.")
            st.stop()
        except BTVGatewayError as e:
            st.error(f"Gateway error: {e}. Is the BTV gateway running?")
            st.stop()
        except Exception as e:
            st.error(f"Error: {e}")
            st.stop()

    verdict = st.session_state.last_verdict
    icon = ACTION_COLORS.get(str(verdict.action), "⚪")

    # Verdict header
    st.divider()
    vcol1, vcol2, vcol3, vcol4 = st.columns(4)
    with vcol1:
        st.metric("Decision", f"{icon} {verdict.action}")
    with vcol2:
        st.metric("Risk Score", f"{verdict.composite_risk:.2f}")
    with vcol3:
        st.metric("Findings", f"{verdict.finding_count} ({verdict.critical_count} critical)")
    with vcol4:
        st.metric("Latency", f"{verdict.latency_ms:.1f}ms")

    # Verdict details
    st.code(verdict.verdict_id, language=None)

    if verdict.mercy_applied:
        st.info(f"⚡ Mercy applied: original decision was **{verdict.original_action}**, "
                f"softened to **{verdict.action}** (Gilligan ethics of care)")

    if verdict.hard_blocked:
        st.error("🚫 Hard block: this verdict cannot be appealed.")

    # Rationale
    st.markdown(f"**Rationale**: {verdict.rationale}")

    # Philosophical analysis (decide only)
    if use_decide and hasattr(verdict, "explain"):
        with st.expander("📖 Philosophical Analysis (Rawls→Levinas→Jonas→Gilligan)"):
            st.markdown(f"**Summary**: {verdict.explain.summary}")
            cols = st.columns(2)
            with cols[0]:
                st.markdown(f"**Rawls** *(fairness)*: {verdict.explain.rawls_rationale}")
                st.markdown(f"**Jonas** *(responsibility)*: {verdict.explain.jonas_rationale}")
            with cols[1]:
                st.markdown(f"**Levinas** *(duty of care)*: {verdict.explain.levinas_rationale}")
                st.markdown(f"**Gilligan** *(mercy)*: {verdict.explain.gilligan_rationale}")
            st.progress(verdict.explain.trust_score, text=f"Trust: {verdict.explain.trust_score:.2f}")
            st.progress(verdict.explain.mercy_score, text=f"Mercy: {verdict.explain.mercy_score:.2f}")

    # Appeal button
    if verdict.contestable and not verdict.hard_blocked:
        st.divider()
        if st.button(f"⚖️ Contest this verdict (deadline: {verdict.appeal_deadline_hours}h)"):
            st.session_state.show_appeal_form = True

# ─── Sanitize ────────────────────────────────────────────────────────────────

if sanitize_btn and input_text.strip():
    btv = get_client()
    with st.spinner("Sanitizing..."):
        try:
            result = btv.sanitize(input_text, session_id=st.session_state.session_id)
        except Exception as e:
            st.error(f"Sanitize error: {e}")
            st.stop()

    st.divider()
    st.markdown(f"**Redactions applied**: {result.redactions}")
    st.text_area("Sanitized Output", result.sanitized, height=80)

# ─── Appeal form ─────────────────────────────────────────────────────────────

if st.session_state.show_appeal_form and st.session_state.last_verdict:
    verdict = st.session_state.last_verdict
    st.divider()
    st.subheader("⚖️ Submit Appeal")
    st.caption(f"Contesting verdict: `{verdict.verdict_id}`")

    reason = st.text_area(
        "Reason (minimum 20 characters)",
        placeholder="Explain why this verdict is incorrect...",
        height=80,
    )
    grounds = st.multiselect(
        "Grounds",
        ["rawls_equity", "levinas_protection", "gilligan_mercy",
         "jonas_responsibility", "technical_error", "scope_mismatch", "false_positive"],
        default=["false_positive"],
        help="Select the philosophical/legal grounds for your appeal",
    )

    acol1, acol2 = st.columns(2)
    with acol1:
        if st.button("Submit Appeal", type="primary"):
            if len(reason) < 20:
                st.warning("Reason must be at least 20 characters (Levinas articulation principle).")
            else:
                try:
                    appeal = get_client().appeal(
                        verdict.verdict_id,
                        reason=reason,
                        grounds=grounds or ["false_positive"],
                    )
                    st.success(f"Appeal submitted! ID: `{appeal.appeal_id}` | Status: {appeal.status}")
                    st.session_state.show_appeal_form = False
                except Exception as e:
                    st.error(f"Appeal error: {e}")
    with acol2:
        if st.button("Cancel"):
            st.session_state.show_appeal_form = False
            st.rerun()

# ─── History ─────────────────────────────────────────────────────────────────

if st.session_state.history:
    st.divider()
    st.markdown("**Recent verdicts (this session)**")
    for item in st.session_state.history[:10]:
        icon = ACTION_COLORS.get(str(item["action"]), "⚪")
        st.caption(f"{icon} `{item['verdict_id']}` — {item['input']}")
