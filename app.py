"""
app.py  –  AI Security Threat Monitoring Agent
Run:  streamlit run app.py
Env:  ANTHROPIC_API_KEY must be set
"""

import os, json, time
from pathlib import Path

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px

from engine import AnomalyDetector, KillChainBuilder, MITRE_PATTERNS
from narrator import generate_narrative, generate_summary_headline

# ── Page config ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="ThreatWatch AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Load External CSS ────────────────────────────────────────────────────────
def load_css(file_path):
    with open(file_path) as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

load_css("style.css")

# ── Helpers ───────────────────────────────────────────────────────────────────
PRIORITY_COLORS = {
    "P0 – CRITICAL": "#E24B4A",
    "P1 – HIGH":     "#EF9F27",
    "P2 – MEDIUM":   "#378ADD",
    "P3 – LOW":      "#1D9E75",
}

def priority_badge(priority: str) -> str:
    color = PRIORITY_COLORS.get(priority, "#888")
    return (
        f'<span class="badge" style="background:{color}22;'
        f'color:{color};border:1px solid {color}44">{priority}</span>'
    )

def fmt_bytes(n: int) -> str:
    if n >= 1_000_000: return f"{n/1_000_000:.1f} MB"
    if n >= 1_000:     return f"{n/1_000:.1f} KB"
    return f"{n} B"

def load_and_analyze():
    """Load logs, run detection pipeline, cache in session state."""
    logs_path = Path("sample_logs.json")
    if not logs_path.exists():
        st.error("sample_logs.json not found. Run `python generate_logs.py` first.")
        st.stop()

    raw = json.loads(logs_path.read_text())
    df  = pd.DataFrame(raw)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df = df.sort_values("timestamp").reset_index(drop=True)

    detector = AnomalyDetector()
    detector.fit(df)
    scored   = detector.score(df)

    builder  = KillChainBuilder(threshold=20)
    chains   = builder.build(scored)

    return df, scored, chains

# ── Session state ─────────────────────────────────────────────────────────────
if "chains" not in st.session_state:
    with st.spinner("Running threat analysis pipeline…"):
        df, scored, chains = load_and_analyze()
        st.session_state.df     = df
        st.session_state.scored = scored
        st.session_state.chains = chains

df     = st.session_state.df
scored = st.session_state.scored
chains = st.session_state.chains

# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🛡️ ThreatWatch AI")
    st.caption("AI-powered security monitoring")
    st.divider()

    priority_filter = st.multiselect(
        "Filter by priority",
        options=["P0 – CRITICAL", "P1 – HIGH", "P2 – MEDIUM", "P3 – LOW"],
        default=["P0 – CRITICAL", "P1 – HIGH", "P2 – MEDIUM", "P3 – LOW"],
    )
    min_score = st.slider("Min anomaly score", 0, 100, 0, step=5)
    st.divider()

    if st.button("🔄  Re-run analysis"):
        for k in ["df", "scored", "chains", "narratives"]:
            st.session_state.pop(k, None)
        st.rerun()

    st.caption(f"Log events loaded: **{len(df):,}**")
    st.caption(f"High-risk events : **{(scored['anomaly_score'] >= 50).sum()}**")
    st.caption(f"Attack chains    : **{len(chains)}**")

# ── Apply filters ─────────────────────────────────────────────────────────────
filtered_chains = [
    c for c in chains
    if c["priority"] in priority_filter and c["max_score"] >= min_score
]

# ── Title row ─────────────────────────────────────────────────────────────────
st.markdown("""
    <div style='margin-bottom: 2rem;'>
        <h1 style='margin-bottom: 0;'>🛡️ ThreatWatch <span style='color:#7f77dd'>AI</span></h1>
        <p style='color:#a0a0c0; font-size: 1.1rem; margin-top: 0.5rem;'>
            Autonomous Security Monitoring & Behavioral Analysis
        </p>
    </div>
""", unsafe_allow_html=True)

# ── KPI row ───────────────────────────────────────────────────────────────────
k1, k2, k3, k4, k5 = st.columns(5)

p0_count = sum(1 for c in chains if c["priority"] == "P0 – CRITICAL")
p1_count = sum(1 for c in chains if c["priority"] == "P1 – HIGH")
total_high = (scored["anomaly_score"] >= 50).sum()
false_pos_rate = round(
    100 * (1 - len([e for s in chains for e in s["events"]]) / max(len(scored), 1)), 1
)
unique_attack_ips = len(set(c["source_ip"] for c in chains))

def styled_metric(label, value, color="#fff"):
    st.markdown(f"""
        <div class="metric-card">
            <div style="color:#a0a0c0; font-size: 0.8rem; font-weight: 600; text-transform: uppercase; letter-spacing: 1px;">{label}</div>
            <div style="color:{color}; font-size: 1.8rem; font-weight: 700; margin-top: 5px;">{value}</div>
        </div>
    """, unsafe_allow_html=True)

with k1: styled_metric("RED ALERT (P0)", p0_count, "#E24B4A")
with k2: styled_metric("HIGH RISK (P1)", p1_count, "#EF9F27")
with k3: styled_metric("TOTAL ANOMALIES", total_high, "#7f77dd")
with k4: styled_metric("THREAT VECTORS", unique_attack_ips, "#378ADD")
with k5: styled_metric("FP REDUCTION", f"{false_pos_rate}%", "#1D9E75")

st.markdown("<div style='margin-bottom: 2.5rem;'></div>", unsafe_allow_html=True)

# ── Main tabs ─────────────────────────────────────────────────────────────────
tab_chains, tab_events, tab_analytics, tab_mitre = st.tabs([
    "🔗  Kill-chain alerts",
    "📋  Event feed",
    "📊  Analytics",
    "🗺️  MITRE coverage",
])

# ═══════════════════════════════════════════════════════════════════════════════
# TAB 1 – Kill-chain alerts
# ═══════════════════════════════════════════════════════════════════════════════
with tab_chains:
    if not filtered_chains:
        st.info("No chains match current filters.")
    else:
        st.markdown(f"**{len(filtered_chains)} attack chain(s) detected**")

        for i, chain in enumerate(filtered_chains):
            color = chain["priority_color"]
            header = (
                f"{priority_badge(chain['priority'])}  "
                f"**{chain['user']}** from `{chain['source_ip']}`  "
                f"· score **{chain['max_score']}/100**  "
                f"· {chain['start_time'].strftime('%H:%M')}–{chain['end_time'].strftime('%H:%M')} UTC"
            )
            with st.expander(
                f"{chain['priority']}  |  {chain['user']}  |  {chain['event_count']} events  |  score {chain['max_score']}",
                expanded=(i == 0),
            ):
                st.markdown(header, unsafe_allow_html=True)

                # Tactic pills
                tactics_html = "  ".join(
                    f"<span class='tactic-pill'>{'→ ' if j else ''}{t}</span>"                    for j, t in enumerate(chain["tactics"])
                )
                st.markdown(tactics_html, unsafe_allow_html=True)
                st.markdown("")

                # Event timeline table
                ev_df = pd.DataFrame(chain["events"])
                ev_df["time"] = ev_df["timestamp"].dt.strftime("%H:%M:%S")
                ev_df["bytes"] = ev_df.get("bytes_transferred", pd.Series(dtype=int)).apply(
                    lambda x: fmt_bytes(int(x)) if pd.notna(x) and int(x) > 0 else "—"
                )
                st.dataframe(
                    ev_df[["time", "event_type", "tactic", "technique",
                            "target_system", "anomaly_score"]].rename(columns={
                        "time": "Time", "event_type": "Event",
                        "tactic": "MITRE Tactic", "technique": "Technique",
                        "target_system": "System", "anomaly_score": "Score",
                    }),
                    hide_index=True, use_container_width=True,
                )

                # AI narrative
                narrative_key = f"narrative_{chain['user']}_{i}"
                st.markdown("---")
                col_btn, col_status = st.columns([1, 3])
                with col_btn:
                    gen_btn = st.button(
                        "🤖  Generate AI report", key=f"gen_{i}",
                        type="primary",
                    )
                if gen_btn or narrative_key in st.session_state:
                    if narrative_key not in st.session_state:
                        with st.spinner("Claude is analysing the attack chain…"):
                            narrative = generate_narrative(chain)
                            st.session_state[narrative_key] = narrative
                    narrative = st.session_state[narrative_key]
                    st.markdown("#### 🤖 AI Analyst Report")
                    st.markdown(
                        f'<div class="narrative-box">{narrative.replace(chr(10), "<br>")}</div>',
                        unsafe_allow_html=True,
                    )

# ═══════════════════════════════════════════════════════════════════════════════
# TAB 2 – Event feed
# ═══════════════════════════════════════════════════════════════════════════════
with tab_events:
    show_high_only = st.toggle("Show high-risk events only (score ≥ 50)", value=False)
    feed_df = scored[scored["anomaly_score"] >= 50] if show_high_only else scored

    display = feed_df[[
        "timestamp", "user", "source_ip", "event_type",
        "resource", "target_system", "anomaly_score", "flags",
    ]].copy()
    display["timestamp"] = display["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")
    display["flags"]     = display["flags"].apply(
        lambda f: ", ".join(f) if isinstance(f, list) else str(f)
    )
    display.columns = [
        "Timestamp", "User", "Source IP", "Event",
        "Resource", "System", "Score", "Flags",
    ]

    # Color score column
    def color_score(val):
        if val >= 80: return "background-color:#E24B4A22;color:#E24B4A"
        if val >= 60: return "background-color:#EF9F2722;color:#EF9F27"
        if val >= 40: return "background-color:#378ADD22;color:#378ADD"
        return ""

    st.dataframe(
        display.style.map(color_score, subset=["Score"]),
        hide_index=True, use_container_width=True, height=500,
    )

# ═══════════════════════════════════════════════════════════════════════════════
# TAB 3 – Analytics
# ═══════════════════════════════════════════════════════════════════════════════
with tab_analytics:
    col_left, col_right = st.columns(2)

    with col_left:
        st.markdown("#### Events over time")
        time_df = scored.copy()
        time_df["minute"] = time_df["timestamp"].dt.floor("5min")
        time_agg = time_df.groupby(["minute", "event_type"]).size().reset_index(name="count")
        fig_time = px.bar(
            time_agg, x="minute", y="count", color="event_type",
            color_discrete_sequence=px.colors.qualitative.Pastel,
            labels={"minute": "Time", "count": "Events", "event_type": "Type"},
        )
        fig_time.update_layout(
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            font_color="#c0c0d0", legend_title_text="", height=300,
        )
        st.plotly_chart(fig_time, use_container_width=True)

    with col_right:
        st.markdown("#### Anomaly score distribution")
        fig_hist = px.histogram(
            scored, x="anomaly_score", nbins=20,
            color_discrete_sequence=["#7f77dd"],
            labels={"anomaly_score": "Anomaly score"},
        )
        fig_hist.add_vline(x=50, line_dash="dash", line_color="#EF9F27",
                           annotation_text="Alert threshold")
        fig_hist.update_layout(
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            font_color="#c0c0d0", height=300,
        )
        st.plotly_chart(fig_hist, use_container_width=True)

    st.markdown("#### Top users by risk score")
    user_risk = (
        scored.groupby("user")["anomaly_score"]
        .agg(["max", "mean", "count"])
        .reset_index()
        .rename(columns={"max": "Peak score", "mean": "Avg score", "count": "Events"})
        .sort_values("Peak score", ascending=False)
    )
    user_risk["Avg score"] = user_risk["Avg score"].round(1)

    fig_users = px.bar(
        user_risk.head(10), x="user", y="Peak score",
        color="Peak score",
        color_continuous_scale=["#1D9E75", "#378ADD", "#EF9F27", "#E24B4A"],
        labels={"user": "User", "Peak score": "Peak anomaly score"},
    )
    fig_users.update_layout(
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font_color="#c0c0d0", coloraxis_showscale=False, height=280,
    )
    st.plotly_chart(fig_users, use_container_width=True)

# ═══════════════════════════════════════════════════════════════════════════════
# TAB 4 – MITRE ATT&CK coverage
# ═══════════════════════════════════════════════════════════════════════════════
with tab_mitre:
    st.markdown("#### MITRE ATT&CK tactics detected in this session")

    all_flags = [
        flag
        for _, row in scored.iterrows()
        for flag in (row["flags"] if isinstance(row["flags"], list) else [])
    ]
    flag_counts = pd.Series(all_flags).value_counts()

    rows = []
    for flag, count in flag_counts.items():
        if flag in MITRE_PATTERNS:
            pat = MITRE_PATTERNS[flag]
            rows.append({
                "Flag":       flag,
                "Tactic":     pat["tactic"],
                "Technique":  pat["technique"],
                "Severity":   pat["severity"],
                "Occurrences":count,
            })

    if rows:
        mitre_df = pd.DataFrame(rows).sort_values("Occurrences", ascending=False)

        fig_mitre = px.bar(
            mitre_df, x="Technique", y="Occurrences",
            color="Severity",
            color_discrete_map={
                "CRITICAL": "#E24B4A", "HIGH": "#EF9F27",
                "MEDIUM":   "#378ADD", "LOW":  "#1D9E75",
            },
            labels={"Technique": "MITRE Technique", "Occurrences": "Event count"},
        )
        fig_mitre.update_layout(
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            font_color="#c0c0d0", xaxis_tickangle=-30, height=340,
        )
        st.plotly_chart(fig_mitre, use_container_width=True)

        st.dataframe(
            mitre_df.style.map(
                lambda v: {
                    "CRITICAL": "color:#E24B4A",
                    "HIGH":     "color:#EF9F27",
                    "MEDIUM":   "color:#378ADD",
                    "LOW":      "color:#1D9E75",
                }.get(v, ""),
                subset=["Severity"],
            ),
            hide_index=True, use_container_width=True,
        )
    else:
        st.info("No MITRE patterns detected yet.")
