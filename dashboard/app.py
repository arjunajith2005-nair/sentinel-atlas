import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import sqlite3
import httpx
import os
import sys
from datetime import datetime

# Set page configuration
st.set_page_config(
    page_title="Sentinel ATLAS | Operations Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Resolve database path relative to workspace
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DB_PATH = os.path.join(BASE_DIR, "sentinel_sessions.db")
GATEWAY_URL = os.getenv("GATEWAY_URL", "http://127.0.0.1:8000")
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://127.0.0.1:11434")

# Custom CSS for dark cybersecurity dashboard aesthetic
st.markdown("""
<style>
    .metric-card {
        background-color: #1e222d;
        border: 1px solid #2d3342;
        border-radius: 8px;
        padding: 16px;
        margin-bottom: 12px;
    }
    .badge-success {
        background-color: #0e4429;
        color: #3fb950;
        padding: 4px 8px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 12px;
    }
    .badge-blocked {
        background-color: #490202;
        color: #f85149;
        padding: 4px 8px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 12px;
    }
    .chat-bubble-user {
        background-color: #1f293d;
        border-left: 4px solid #388bfd;
        padding: 12px 16px;
        border-radius: 6px;
        margin-bottom: 8px;
    }
    .chat-bubble-ai {
        background-color: #161b22;
        border-left: 4px solid #3fb950;
        padding: 12px 16px;
        border-radius: 6px;
        margin-bottom: 16px;
    }
    .chat-bubble-blocked {
        background-color: #2b1114;
        border-left: 4px solid #f85149;
        padding: 12px 16px;
        border-radius: 6px;
        margin-bottom: 16px;
    }
</style>
""", unsafe_allow_html=True)


# ================= CACHED RESOURCE: HTTP CLIENT POOL =================
@st.cache_resource
def get_http_client():
    """Shared connection-pooled HTTP client — avoids recreating sockets on every Streamlit rerun."""
    return httpx.Client(
        timeout=2.0,
        limits=httpx.Limits(max_keepalive_connections=5, max_connections=10)
    )


# ================= CACHED DATA FUNCTIONS =================
def get_db_connection():
    return sqlite3.connect(DB_PATH, timeout=5)


@st.cache_data(ttl=10)
def fetch_overview_metrics():
    """Cached overview metrics — refreshes every 10 seconds instead of every rerun."""
    conn = get_db_connection()
    c = conn.cursor()
    
    # Total sessions
    c.execute("SELECT COUNT(DISTINCT session_id) FROM session_turns")
    total_sessions = c.fetchone()[0] or 0
    
    # Total valid turns
    c.execute("SELECT COUNT(*) FROM session_turns")
    total_turns = c.fetchone()[0] or 0
    
    # Average similarity score (if available)
    try:
        c.execute("SELECT AVG(similarity_score) FROM session_turns WHERE similarity_score IS NOT NULL")
        avg_score = c.fetchone()[0]
        avg_score = round(avg_score, 3) if avg_score else 1.0
    except sqlite3.OperationalError:
        avg_score = 1.0
        
    # Blocked incidents
    try:
        c.execute("SELECT COUNT(*) FROM security_events")
        blocked_count = c.fetchone()[0] or 0
    except sqlite3.OperationalError:
        blocked_count = 0
        
    conn.close()
    return total_sessions, total_turns, blocked_count, avg_score


@st.cache_data(ttl=5)
def fetch_all_sessions():
    """Cached session list — refreshes every 5 seconds."""
    conn = get_db_connection()
    query = """
    SELECT 
        s.session_id, 
        COUNT(s.id) as valid_turns, 
        MAX(s.timestamp) as last_seen
    FROM session_turns s
    GROUP BY s.session_id
    ORDER BY last_seen DESC
    """
    df = pd.read_sql_query(query, conn)
    conn.close()
    return df


@st.cache_data(ttl=5)
def fetch_session_timeline(session_id):
    """Cached per-session timeline — refreshes every 5 seconds."""
    conn = get_db_connection()
    
    # Valid turns
    turns_query = """
    SELECT 
        turn_number, 
        message_text, 
        COALESCE(similarity_score, 1.0) as similarity_score,
        COALESCE(llm_response, '') as llm_response,
        'success' as status,
        timestamp
    FROM session_turns
    WHERE session_id = ?
    """
    df_turns = pd.read_sql_query(turns_query, conn, params=(session_id,))
    
    # Blocked incidents for this session
    try:
        events_query = """
        SELECT 
            turn_number, 
            message_text, 
            similarity_score, 
            reason as llm_response,
            'blocked' as status,
            timestamp
        FROM security_events
        WHERE session_id = ?
        """
        df_blocked = pd.read_sql_query(events_query, conn, params=(session_id,))
    except sqlite3.OperationalError:
        df_blocked = pd.DataFrame()
        
    conn.close()
    
    combined = pd.concat([df_turns, df_blocked], ignore_index=True)
    if not combined.empty:
        combined = combined.sort_values(by=["turn_number", "timestamp"]).reset_index(drop=True)
    return combined


@st.cache_data(ttl=10)
def fetch_all_security_events():
    """Cached security events — refreshes every 10 seconds."""
    conn = get_db_connection()
    try:
        query = """
        SELECT id, session_id, turn_number, message_text, similarity_score, threshold, reason, timestamp
        FROM security_events
        ORDER BY timestamp DESC
        """
        df = pd.read_sql_query(query, conn)
    except sqlite3.OperationalError:
        df = pd.DataFrame()
    conn.close()
    return df


# Rule-engine and safety-model blocks never reach the ATLAS classifier (they are
# refused on the fast path, before embedding), so they carry no technique label.
# They are still attack types, and they are the MAJORITY of interceptions -- a
# chart drawn only from ATLAS matches would omit most of what the gateway stops.
# These patterns fold those blocks into the same taxonomy.
RULE_LABELS = [
    ("prompt injection attempt", "Prompt Injection", "Rule Engine"),
    ("high-entropy secret", "Secret / Token Exposure", "Rule Engine"),
    ("weapons or dangerous substances", "Harmful: Weapons", "Rule Engine"),
    ("unauthorized system access", "Harmful: Unauthorized Access", "Rule Engine"),
    ("cyberattack technique", "Harmful: Cyberattack Technique", "Rule Engine"),
    ("credential theft", "Harmful: Credential Theft", "Rule Engine"),
    ("malicious software", "Harmful: Malware", "Rule Engine"),
    ("weapons of mass destruction", "Harmful: WMD", "Rule Engine"),
    ("harmful content", "Harmful: Other", "Rule Engine"),
    ("llm safety classifier", "Unsafe Content", "Safety Model"),
    ("dual-agent consensus", "Consensus Misalignment", "Auditor Agent"),
    ("intent drift", "Intent Drift", "Drift Detector"),
    ("session memory and intent anchor", "Intent Drift", "Risk Engine"),
    ("access revocation", "Critical Risk Escalation", "Risk Engine"),
]


def _label_unclassified(reason: str):
    """Maps a non-ATLAS block reason onto an attack-type label and its detecting gate."""
    text = (reason or "").lower()
    for needle, label, source in RULE_LABELS:
        if needle in text:
            return label, source
    return "Unclassified", "Other"


@st.cache_data(ttl=10)
def fetch_attack_matrix():
    """
    Attack type x playbook response matrix, refreshed every 10 seconds.

    Unions both tables on purpose. Blocked attacks live only in security_events
    (the session-reset playbook wipes session_turns), while sanitized and allowed
    turns live only in session_turns -- reading either alone drops half the picture.
    Rows without an ATLAS technique are labelled from their block reason so that
    fast-path refusals are represented too.
    """
    conn = get_db_connection()
    try:
        query = """
        SELECT attack_technique, tactic, reason,
               COALESCE(playbook_action, 'blocked') AS playbook_action,
               timestamp
        FROM security_events
        UNION ALL
        SELECT attack_technique, NULL AS tactic, NULL AS reason,
               COALESCE(playbook_action, 'allow') AS playbook_action,
               timestamp
        FROM session_turns
        WHERE attack_technique IS NOT NULL
        """
        df = pd.read_sql_query(query, conn)
    except sqlite3.OperationalError:
        conn.close()
        return pd.DataFrame(columns=["attack_type", "tactic", "playbook_action", "detected_by", "timestamp"])
    conn.close()

    if df.empty:
        df["attack_type"] = []
        df["detected_by"] = []
        return df

    labelled = df["attack_technique"].notna()
    df.loc[labelled, "attack_type"] = df.loc[labelled, "attack_technique"]
    df.loc[labelled, "detected_by"] = "ATLAS Classifier"

    if (~labelled).any():
        derived = df.loc[~labelled, "reason"].apply(_label_unclassified)
        df.loc[~labelled, "attack_type"] = [d[0] for d in derived]
        df.loc[~labelled, "detected_by"] = [d[1] for d in derived]

    return df


@st.cache_data(ttl=5)
def fetch_live_alerts(limit: int = 25):
    """Most recent security interceptions across all sessions, newest first."""
    conn = get_db_connection()
    try:
        query = """
        SELECT timestamp, session_id, turn_number, message_text, reason,
               attack_technique, tactic, risk_score,
               COALESCE(playbook_action, 'blocked') AS playbook_action
        FROM security_events
        ORDER BY id DESC
        LIMIT ?
        """
        df = pd.read_sql_query(query, conn, params=(limit,))
    except sqlite3.OperationalError:
        df = pd.DataFrame()
    conn.close()
    return df


@st.cache_data(ttl=8)
def check_service_health_cached():
    """
    Cached health check for both services — refreshes every 8 seconds.
    Uses fast 1.5s timeouts instead of blocking 5s per service.
    """
    client = get_http_client()
    
    gateway_healthy = False
    try:
        res = client.get(f"{GATEWAY_URL}/health", timeout=1.5)
        gateway_healthy = res.status_code == 200
    except Exception:
        pass
    
    ollama_healthy = False
    try:
        res = client.get(f"{OLLAMA_URL}/", timeout=1.5)
        ollama_healthy = res.status_code == 200
    except Exception:
        pass
    
    return gateway_healthy, ollama_healthy


@st.cache_data(ttl=10)
def fetch_persistence_data(session_id):
    """Cached persistence data — avoids HTTP call on every rerun."""
    client = get_http_client()
    try:
        res = client.get(f"{GATEWAY_URL}/attribution/persistence/{session_id}", timeout=2.0)
        if res.status_code == 200:
            return res.json()
    except Exception:
        pass
    return {"current_streak": 0, "max_streak": 0, "sustained_intent": False}


@st.cache_data(ttl=5)
def fetch_consensus_events(session_id):
    """Cached consensus events for attribution tab."""
    conn = get_db_connection()
    try:
        df = pd.read_sql_query(
            "SELECT turn_number, iaa_score, auditor_verdict, auditor_reason, timestamp FROM consensus_events WHERE session_id = ? ORDER BY turn_number DESC",
            conn,
            params=(session_id,)
        )
    except Exception:
        df = pd.DataFrame()
    conn.close()
    return df


# ================= SIDEBAR =================
st.sidebar.title("🛡️ Sentinel ATLAS")
st.sidebar.caption("Real-Time AI Security Operations Gateway")

# System health indicators (cached — no blocking on every rerun)
gateway_healthy, ollama_healthy = check_service_health_cached()

st.sidebar.markdown("### Service Telemetry")
col_s1, col_s2 = st.sidebar.columns(2)
with col_s1:
    if gateway_healthy:
        st.success("Gateway: 🟢 Online")
    else:
        st.error("Gateway: 🔴 Offline")
with col_s2:
    if ollama_healthy:
        st.success("Ollama: 🟢 Online")
    else:
        st.warning("Ollama: 🟡 Offline")

st.sidebar.divider()

# Session Selector
sessions_df = fetch_all_sessions()
session_list = sessions_df["session_id"].tolist() if not sessions_df.empty else []

selected_session = None
if session_list:
    selected_session = st.sidebar.selectbox(
        "Select Active Session",
        options=session_list,
        index=0,
        help="Select a session ID from SQLite to analyze its conversation timeline and drift graph."
    )
    if selected_session:
        session_info = sessions_df[sessions_df["session_id"] == selected_session].iloc[0]
        st.sidebar.info(f"**Valid Turns:** {session_info['valid_turns']}\n\n**Last Active:** {session_info['last_seen']}")
else:
    st.sidebar.warning("No sessions found in SQLite. Send prompts via the Playground tab to start.")

st.sidebar.divider()
if st.sidebar.button("🔄 Refresh Data", use_container_width=True):
    # Clear all caches to force fresh data
    st.cache_data.clear()
    st.rerun()

st.sidebar.caption("Threshold: **0.35** (Cosine Similarity)")

# ================= TOP KPI METRICS =================
st.title("🛡️ Sentinel ATLAS Operations Center")
st.caption("Live monitoring of intent drift, session vectors, and adversarial prompt detection.")

tot_sessions, tot_turns, tot_blocked, mean_sim = fetch_overview_metrics()

kpi1, kpi2, kpi3, kpi4 = st.columns(4)
kpi1.metric("Monitored Sessions", tot_sessions)
kpi2.metric("Total Valid Turns", tot_turns)
kpi3.metric("Blocked Incidents", tot_blocked, delta=f"{tot_blocked} Intercepted" if tot_blocked > 0 else None, delta_color="inverse")
kpi4.metric("Avg Similarity Score", f"{mean_sim:.3f}")

st.markdown("---")

# ================= MAIN TABS =================
ALERT_CARD_TEMPLATE = """
<div style="border-left:4px solid {colour}; background:#161b22;
            padding:8px 12px; margin-bottom:6px; border-radius:4px;">
  <div style="font-size:12px; color:#8b949e;">
    {icon} <b style="color:{colour};">{action}</b>
    &nbsp;&middot;&nbsp; {timestamp}
    &nbsp;&middot;&nbsp; session <code>{session}</code>
    &nbsp;&middot;&nbsp; risk <b>{risk}</b>
  </div>
  <div style="margin:4px 0; color:#e6edf3;">{message}</div>
  <div style="font-size:12px; color:#8b949e;">
    <b>{technique}</b> &mdash; {reason}
  </div>
</div>
"""


tab_monitor, tab_analytics, tab_audit, tab_attribution, tab_playground = st.tabs([
    "📈 Session Drift Monitor", 
    "🎯 Attack Analytics",
    "🚨 Security Incidents Audit", 
    "📑 Threat Attribution & AI Reports",
    "🧪 Live Gateway Playground"
])

# ------------- TAB 1: SESSION DRIFT MONITOR -------------
with tab_monitor:
    if not selected_session:
        st.info("Select a session in the sidebar to inspect its timeline and vector similarity trajectory.")
    else:
        timeline_df = fetch_session_timeline(selected_session)
        
        st.subheader(f"Session: `{selected_session}`")
        
        # Plotly Cosine Similarity Timeline
        if not timeline_df.empty:
            fig = go.Figure()
            
            # 0.35 Threshold Boundary
            max_turn = max(timeline_df["turn_number"].max(), 1)
            fig.add_shape(
                type="line",
                x0=0.5,
                x1=max_turn + 0.5,
                y0=0.35,
                y1=0.35,
                line=dict(color="#f85149", width=2, dash="dash"),
                name="Drift Cutoff (0.35)"
            )
            fig.add_annotation(
                x=max_turn + 0.5,
                y=0.35,
                text="<b>Threshold (0.35)</b>",
                showarrow=False,
                yshift=10,
                font=dict(color="#f85149", size=11)
            )
            
            # Safe turns
            safe_df = timeline_df[timeline_df["status"] == "success"]
            if not safe_df.empty:
                fig.add_trace(go.Scatter(
                    x=safe_df["turn_number"],
                    y=safe_df["similarity_score"],
                    mode="lines+markers",
                    name="Allowed Turn",
                    line=dict(color="#3fb950", width=3),
                    marker=dict(size=10, color="#3fb950", symbol="circle"),
                    hovertext=[f"Turn {row.turn_number}: {row.message_text[:60]}... (Score: {row.similarity_score})" for _, row in safe_df.iterrows()],
                    hoverinfo="text"
                ))
                
            # Blocked turns
            blocked_df = timeline_df[timeline_df["status"] == "blocked"]
            if not blocked_df.empty:
                fig.add_trace(go.Scatter(
                    x=blocked_df["turn_number"],
                    y=blocked_df["similarity_score"],
                    mode="markers",
                    name="Blocked (Drift)",
                    marker=dict(size=14, color="#f85149", symbol="x", line=dict(width=2, color="#ffffff")),
                    hovertext=[f"Turn {row.turn_number}: BLOCKED '{row.message_text[:60]}...' (Score: {row.similarity_score})" for _, row in blocked_df.iterrows()],
                    hoverinfo="text"
                ))
                
            fig.update_layout(
                title="Intent Anchor Cosine Similarity Across Turns",
                xaxis_title="Turn Number",
                yaxis_title="Cosine Similarity",
                yaxis=dict(range=[-0.05, 1.05], gridcolor="#2d3342"),
                xaxis=dict(tickmode="linear", dtick=1, gridcolor="#2d3342"),
                template="plotly_dark",
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
                margin=dict(l=40, r=40, t=60, b=40),
                height=350
            )
            st.plotly_chart(fig, use_container_width=True)
            
            # Conversation Transcript
            st.markdown("### Conversation Transcript")
            for _, row in timeline_df.iterrows():
                is_safe = (row["status"] == "success")
                badge_html = (
                    f"<span class='badge-success'>✅ Turn {row['turn_number']} — Allowed (Score: {row['similarity_score']:.4f})</span>"
                    if is_safe else
                    f"<span class='badge-blocked'>🚨 Turn {row['turn_number']} — BLOCKED DRIFT (Score: {row['similarity_score']:.4f})</span>"
                )
                
                st.markdown(f"""
                <div style="margin-bottom: 6px;">
                    {badge_html} <span style="font-size:11px; color:#8b949e; margin-left: 8px;">{row['timestamp']}</span>
                </div>
                <div class="chat-bubble-user">
                    <b>User:</b> {row['message_text']}
                </div>
                """, unsafe_allow_html=True)
                
                if is_safe:
                    st.markdown(f"""
                    <div class="chat-bubble-ai">
                        <b>Gateway Response (LLM):</b><br>{row['llm_response']}
                    </div>
                    """, unsafe_allow_html=True)
                else:
                    st.markdown(f"""
                    <div class="chat-bubble-blocked">
                        <b>Interception Reason:</b> {row['llm_response']}
                    </div>
                    """, unsafe_allow_html=True)
        else:
            st.warning("No records found for this session.")

# ------------- TAB 2: ATTACK ANALYTICS (heatmap + live alerts) -------------
with tab_analytics:
    matrix_df = fetch_attack_matrix()

    st.subheader("🎯 Attack Type Frequency")
    st.caption(
        "Which attack types the gateway flags most often, and how it responded. Combines "
        "MITRE ATLAS classifier matches with fast-path rule and safety refusals, which "
        "never reach the classifier but are the majority of interceptions."
    )

    if matrix_df.empty:
        st.info(
            "No classified attacks recorded yet. Send an adversarial prompt through the "
            "Live Gateway Playground, or run `python tests/test_payloads.py`, and this "
            "populates within 10 seconds."
        )
    else:
        # Ranked frequency: the direct answer to "which types get flagged most often".
        freq = (
            matrix_df.groupby("attack_type")
            .size()
            .reset_index(name="count")
            .sort_values("count", ascending=True)
        )

        c1, c2, c3 = st.columns(3)
        c1.metric("Attack Types Observed", freq.shape[0])
        c2.metric("Total Detections", int(freq["count"].sum()))
        c3.metric("Most Frequent", str(freq.iloc[-1]["attack_type"]).split(" - ")[-1][:22])

        fig_freq = go.Figure(go.Bar(
            x=freq["count"],
            y=freq["attack_type"],
            orientation="h",
            marker=dict(color=freq["count"], colorscale="Reds", showscale=False),
            hovertemplate="%{y}<br>Detections: %{x}<extra></extra>",
        ))
        fig_freq.update_layout(
            title="Detections per Attack Type",
            xaxis_title="Times Flagged",
            yaxis_title="",
            template="plotly_dark",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            xaxis=dict(gridcolor="#2d3342", dtick=1),
            margin=dict(l=10, r=30, t=60, b=40),
            height=max(260, 60 + 42 * freq.shape[0]),
        )
        st.plotly_chart(fig_freq, use_container_width=True)

        # Heatmap: technique x autonomous playbook response.
        st.subheader("🔥 Attack Type × Playbook Response Heatmap")
        st.caption(
            "How severely each technique is handled. Reading across a row shows whether a "
            "technique is consistently escalated or split across responses — the signal for "
            "whether the risk weights are calibrated."
        )

        ACTION_ORDER = ["allow", "sanitize", "reset", "revoke", "blocked"]
        pivot = matrix_df.pivot_table(
            index="attack_type",
            columns="playbook_action",
            aggfunc="size",
            fill_value=0,
        )
        pivot = pivot[[a for a in ACTION_ORDER if a in pivot.columns]]
        pivot = pivot.loc[pivot.sum(axis=1).sort_values(ascending=True).index]

        fig_heat = go.Figure(go.Heatmap(
            z=pivot.values,
            x=[a.upper() for a in pivot.columns],
            y=list(pivot.index),
            colorscale="Reds",
            showscale=True,
            colorbar=dict(title="Count"),
            hovertemplate="%{y}<br>Response: %{x}<br>Count: %{z}<extra></extra>",
            text=pivot.values,
            texttemplate="%{text}",
            textfont=dict(size=13),
            xgap=3,
            ygap=3,
        ))
        fig_heat.update_layout(
            title="Detections by Attack Type and Autonomous Response",
            template="plotly_dark",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            xaxis=dict(side="top"),
            margin=dict(l=10, r=30, t=90, b=30),
            height=max(280, 90 + 52 * pivot.shape[0]),
        )
        st.plotly_chart(fig_heat, use_container_width=True)

        # Which gate caught what. Most interceptions never reach the ATLAS
        # classifier because the rule engine refuses them on the fast path first,
        # so this is the defence-in-depth view the heatmap alone does not show.
        by_gate = matrix_df.groupby("detected_by").size().reset_index(name="count")
        fig_gate = go.Figure(go.Bar(
            x=by_gate["count"],
            y=by_gate["detected_by"],
            orientation="h",
            marker=dict(color="#58a6ff"),
            hovertemplate="%{y}<br>Interceptions: %{x}<extra></extra>",
        ))
        fig_gate.update_layout(
            title="Which Gate Caught It",
            xaxis_title="Interceptions",
            yaxis_title="",
            template="plotly_dark",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            xaxis=dict(gridcolor="#2d3342"),
            margin=dict(l=10, r=30, t=60, b=40),
            height=300,
        )
        st.plotly_chart(fig_gate, use_container_width=True)

        tactic_df = matrix_df[matrix_df["tactic"].notna()]
        if not tactic_df.empty:
            tactics = tactic_df.groupby("tactic").size().reset_index(name="count")
            fig_tac = go.Figure(go.Bar(
                x=tactics["tactic"],
                y=tactics["count"],
                marker=dict(color="#f85149"),
                hovertemplate="%{x}<br>Detections: %{y}<extra></extra>",
            ))
            fig_tac.update_layout(
                title="Adversarial Tactics Observed (MITRE ATLAS)",
                xaxis_title="",
                yaxis_title="Detections",
                template="plotly_dark",
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                yaxis=dict(gridcolor="#2d3342", dtick=1),
                margin=dict(l=40, r=30, t=60, b=60),
                height=320,
            )
            st.plotly_chart(fig_tac, use_container_width=True)

    st.divider()
    st.subheader("🔔 Live Alert Feed")
    st.caption("Most recent interceptions across all sessions. Refreshes every 5 seconds.")

    alerts_df = fetch_live_alerts(25)
    if alerts_df.empty:
        st.success("No security interceptions recorded.")
    else:
        SEVERITY_STYLE = {
            "revoke": ("🟥", "#f85149"),
            "reset": ("🟧", "#db6d28"),
            "sanitize": ("🟨", "#d29922"),
            "blocked": ("🟥", "#f85149"),
            "allow": ("🟩", "#3fb950"),
        }
        for _, row in alerts_df.iterrows():
            action = str(row["playbook_action"] or "blocked")
            icon, colour = SEVERITY_STYLE.get(action, ("⬜", "#8b949e"))
            technique = row["attack_technique"] or _label_unclassified(row["reason"])[0]
            risk = f"{row['risk_score']:.4f}" if pd.notna(row["risk_score"]) else "n/a"
            st.markdown(
                ALERT_CARD_TEMPLATE.format(
                    colour=colour,
                    icon=icon,
                    action=action.upper(),
                    timestamp=row["timestamp"],
                    session=str(row["session_id"])[:8],
                    risk=risk,
                    message=str(row["message_text"])[:150],
                    technique=technique,
                    reason=str(row["reason"])[:110],
                ),
                unsafe_allow_html=True,
            )

# ------------- TAB 3: SECURITY AUDIT LOG -------------
with tab_audit:
    st.subheader("Security Incidents & Adversarial Interception Log")
    st.caption("Historical log of all prompts blocked by the cosine similarity intent guardrail.")
    
    events_df = fetch_all_security_events()
    if events_df.empty:
        st.success("No security incidents recorded yet. All sessions are compliant with established intent anchors.")
    else:
        st.dataframe(
            events_df,
            column_config={
                "id": st.column_config.NumberColumn("ID", width="small"),
                "session_id": st.column_config.TextColumn("Session ID", width="medium"),
                "turn_number": st.column_config.NumberColumn("Turn #", width="small"),
                "message_text": st.column_config.TextColumn("Intercepted Prompt", width="large"),
                "similarity_score": st.column_config.NumberColumn("Similarity", format="%.4f"),
                "threshold": st.column_config.NumberColumn("Threshold", format="%.2f"),
                "reason": st.column_config.TextColumn("Reason", width="medium"),
                "timestamp": st.column_config.DatetimeColumn("Timestamp", width="medium")
            },
            hide_index=True,
            use_container_width=True
        )
        
        csv_data = events_df.to_csv(index=False)
        st.download_button(
            label="📥 Export Audit Log (CSV)",
            data=csv_data,
            file_name=f"sentinel_security_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv"
        )

# ------------- TAB 3: THREAT ATTRIBUTION & AI REPORTS -------------
with tab_attribution:
    st.subheader("📑 Threat Attribution & Dual-Agent Consensus")
    st.caption("Traces sustained attack paths (Persistence Score), dual-agent consensus verdicts, and AI-synthesized incident reports.")

    if not selected_session:
        st.info("Select a session in the sidebar to view its threat attribution analysis.")
    else:
        # Fetch persistence data (cached)
        persistence_data = fetch_persistence_data(selected_session)

        col_p1, col_p2, col_p3 = st.columns(3)
        col_p1.metric("Persistence Streak", f"{persistence_data['max_streak']} Turns", help="Maximum consecutive turns exhibiting semantic drift or security flags.")
        col_p2.metric("Sustained Exploit Intent", "🚨 YES" if persistence_data['sustained_intent'] else "✅ NO", help="Flagged if 3 or more consecutive turns show anomalous semantic drift.")
        col_p3.metric("Selected Session", f"`{selected_session[:14]}...`")

        st.markdown("---")

        # Dual-Agent Consensus Events (cached)
        st.markdown("### 🤝 Dual-Agent Consensus (ATLAS Bridge)")
        st.caption("Worker Agent proposed action vs. Asynchronous Auditor Agent alignment verdict.")
        
        consensus_df = fetch_consensus_events(selected_session)

        if consensus_df.empty:
            st.info("No dual-agent consensus events recorded for this session yet.")
        else:
            st.dataframe(
                consensus_df,
                column_config={
                    "turn_number": st.column_config.NumberColumn("Turn #", width="small"),
                    "iaa_score": st.column_config.NumberColumn("IAA Alignment", format="%.4f"),
                    "auditor_verdict": st.column_config.TextColumn("Auditor Verdict", width="small"),
                    "auditor_reason": st.column_config.TextColumn("Auditor Rationale", width="large"),
                    "timestamp": st.column_config.DatetimeColumn("Timestamp", width="medium"),
                },
                hide_index=True,
                use_container_width=True
            )

        st.markdown("---")

        # Executive Incident Report Generation
        st.markdown("### 📝 Plain-English SOC Threat Attribution Report")
        st.caption("Generates a comprehensive incident report using local Ollama, detailing attacker progression across MITRE ATLAS tactics over time.")

        if st.button("⚡ Generate AI Threat Attribution Report", key="btn_gen_report", use_container_width=True):
            with st.spinner("Local Ollama analyzing session progression and generating report..."):
                try:
                    client = get_http_client()
                    rep_res = client.get(f"{GATEWAY_URL}/attribution/report/{selected_session}", timeout=45.0)
                    if rep_res.status_code == 200:
                        report_content = rep_res.json().get("report", "No report generated.")
                        st.session_state[f"report_{selected_session}"] = report_content
                    else:
                        st.error(f"Error from report API: HTTP {rep_res.status_code}")
                except Exception as ex:
                    st.error(f"Could not connect to Gateway: {ex}")

        saved_report = st.session_state.get(f"report_{selected_session}")
        if saved_report:
            st.markdown(f"""
            <div style="background-color:#161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; margin-top: 15px;">
                {saved_report}
            </div>
            """, unsafe_allow_html=True)

# ------------- TAB 4: LIVE GATEWAY PLAYGROUND -------------
with tab_playground:
    st.subheader("Interactive Security Gateway Playground")
    st.caption("Test prompts directly against your running FastAPI security proxy (`http://127.0.0.1:8000/chat`).")
    
    p_col1, p_col2 = st.columns([2, 1])
    with p_col1:
        session_choice = st.radio(
            "Session Context Mode:",
            ["Active Selected Session", "New Anonymous Session"],
            horizontal=True
        )
    with p_col2:
        target_session = selected_session if (session_choice == "Active Selected Session" and selected_session) else None
        st.text_input("Active Target Session ID", value=target_session or "(Auto-generate new UUID)", disabled=True)

    with st.form("playground_form", clear_on_submit=False):
        prompt_input = st.text_area(
            "Enter prompt to test:",
            placeholder="Type a test prompt (e.g. cloud security question, or an off-topic question like baking brownies)...",
            height=100
        )
        submit_btn = st.form_submit_button("🚀 Submit to Gateway", use_container_width=True)

    if submit_btn and prompt_input.strip():
        payload = {"message": prompt_input.strip()}
        if target_session:
            payload["session_id"] = target_session
            
        try:
            with st.spinner("Evaluating prompt with Sentinel ATLAS..."):
                client = get_http_client()
                resp = client.post(f"{GATEWAY_URL}/chat", json=payload, timeout=65.0)
                
            if resp.status_code == 200:
                data = resp.json()
                status = data.get("status")
                sim_score = data.get("similarity_score", 0.0)
                playbook_act = data.get("playbook_action", "allow")
                is_sanitized = data.get("sanitized", False)
                
                if status == "success":
                    if is_sanitized:
                        st.warning(f"🛡️ **Playbook: Context Sanitisation Applied!** (Score 26–45). Adversarial framing stripped; forwarded clean intent.")
                    else:
                        st.success(f"✅ **Request Allowed!** Cosine Similarity: `{sim_score:.4f}` >= `0.35` | Playbook: `{playbook_act}`")
                    
                    with st.chat_message("assistant"):
                        st.markdown(f"**LLM Output:**\n\n{data.get('llm_response')}")
                else:
                    st.error(f"🚨 **Request Blocked!** Intercepted at Gate: `{data.get('gate')}` | Playbook: `{playbook_act}`")
                    st.warning(f"**Reason:** {data.get('reason')}")
                
                st.json(data)
                if st.button("🔄 Refresh Timeline to View Turn in Monitor"):
                    st.cache_data.clear()
                    st.rerun()
            else:
                st.error(f"Gateway Error: Received HTTP status code {resp.status_code}")
                st.code(resp.text)
        except Exception as e:
            st.error(f"Could not connect to Gateway at {GATEWAY_URL}. Is `python main.py` running?")
            st.caption(str(e))
