import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
import sqlite3
import requests
import os
import sys
from datetime import datetime

# Set page configuration
st.set_page_config(
    page_title="Sentinel ATLAS | SOC Operations Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Resolve paths
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DB_PATH = os.path.join(BASE_DIR, "sentinel_sessions.db")
GATEWAY_URL = os.getenv("GATEWAY_URL", "http://127.0.0.1:8000")
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://127.0.0.1:11434")

# Custom CSS for dark cybersecurity dashboard aesthetic
st.markdown("""
<style>
    .metric-card {
        background-color: #161b22;
        border: 1px solid #30363d;
        border-radius: 8px;
        padding: 14px;
        margin-bottom: 12px;
    }
    .badge-allow {
        background-color: #0e4429;
        color: #3fb950;
        padding: 4px 8px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 12px;
    }
    .badge-sanitize {
        background-color: #4d3800;
        color: #d29922;
        padding: 4px 8px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 12px;
    }
    .badge-reset {
        background-color: #5a1e02;
        color: #f0883e;
        padding: 4px 8px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 12px;
    }
    .badge-revoke {
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
    .trajectory-step {
        background-color: #0d1117;
        border: 1px solid #30363d;
        border-radius: 6px;
        padding: 10px 14px;
        margin-bottom: 8px;
    }
</style>
""", unsafe_allow_html=True)


def get_db_connection():
    return sqlite3.connect(DB_PATH, timeout=10)


def fetch_overview_metrics():
    """Fetches top-level KPIs per Section 22."""
    conn = get_db_connection()
    c = conn.cursor()
    
    # Active Sessions
    try:
        c.execute("SELECT COUNT(*) FROM sessions WHERE status = 'ACTIVE'")
        active_sessions = c.fetchone()[0] or 0
    except Exception:
        active_sessions = 0

    # Total Requests
    try:
        c.execute("SELECT COUNT(*) FROM session_turns")
        total_requests = c.fetchone()[0] or 0
    except Exception:
        total_requests = 0

    # Active Threats (Score > 25)
    try:
        c.execute("SELECT COUNT(*) FROM session_turns WHERE risk_score > 25")
        active_threats = c.fetchone()[0] or 0
    except Exception:
        active_threats = 0

    # Critical Threats (Score >= 71)
    try:
        c.execute("SELECT COUNT(*) FROM session_turns WHERE risk_score >= 71")
        critical_threats = c.fetchone()[0] or 0
    except Exception:
        critical_threats = 0

    # Average Risk
    try:
        c.execute("SELECT AVG(risk_score) FROM session_turns WHERE risk_score IS NOT NULL")
        avg_risk = c.fetchone()[0]
        avg_risk = round(avg_risk, 1) if avg_risk is not None else 0.0
    except Exception:
        avg_risk = 0.0

    # Blocked Sessions (Status = 'REVOKED')
    try:
        c.execute("SELECT COUNT(*) FROM sessions WHERE status = 'REVOKED'")
        blocked_sessions = c.fetchone()[0] or 0
    except Exception:
        blocked_sessions = 0

    conn.close()
    return active_sessions, total_requests, active_threats, critical_threats, avg_risk, blocked_sessions


def fetch_all_sessions_df():
    conn = get_db_connection()
    query = """
    SELECT 
        s.session_id, 
        COUNT(t.id) as valid_turns, 
        COALESCE(s.status, 'ACTIVE') as status,
        COALESCE(s.session_risk, 0.0) as session_risk,
        MAX(t.timestamp) as last_seen
    FROM session_turns t
    LEFT JOIN sessions s ON t.session_id = s.session_id
    GROUP BY s.session_id
    ORDER BY last_seen DESC
    """
    try:
        df = pd.read_sql_query(query, conn)
    except Exception:
        df = pd.DataFrame()
    conn.close()
    return df


def fetch_session_turns_df(session_id):
    conn = get_db_connection()
    query = """
    SELECT 
        turn_number, 
        message_text, 
        COALESCE(similarity_score, 1.0) as similarity_score,
        COALESCE(drift_score, 0.0) as drift_score,
        COALESCE(risk_score, 0.0) as risk_score,
        COALESCE(attack_technique, 'None') as attack_technique,
        COALESCE(attack_confidence, 0.0) as attack_confidence,
        COALESCE(topic_id, 'General') as topic_id,
        COALESCE(llm_response, '') as llm_response,
        timestamp
    FROM session_turns
    WHERE session_id = ?
    ORDER BY turn_number ASC
    """
    try:
        df = pd.read_sql_query(query, conn, params=(session_id,))
    except Exception:
        df = pd.DataFrame()
    conn.close()
    return df


def fetch_session_topics_df(session_id):
    conn = get_db_connection()
    try:
        query = "SELECT topic_id, topic_name, first_turn, last_turn, is_benign, created_at FROM topics WHERE session_id = ? ORDER BY first_turn ASC"
        df = pd.read_sql_query(query, conn, params=(session_id,))
    except Exception:
        df = pd.DataFrame()
    conn.close()
    return df


def fetch_atlas_frequency_df():
    conn = get_db_connection()
    try:
        query = """
        SELECT technique_id, technique_name, COUNT(*) as occurrences, AVG(confidence) as avg_confidence
        FROM atlas_matches
        GROUP BY technique_id, technique_name
        ORDER BY occurrences DESC
        """
        df = pd.read_sql_query(query, conn)
    except Exception:
        df = pd.DataFrame()
    conn.close()
    return df


def check_service_health(url):
    try:
        res = requests.get(url, timeout=1.5)
        return res.status_code in [200, 404, 307]
    except Exception:
        return False


# ================= SIDEBAR =================
st.sidebar.title("🛡️ Sentinel ATLAS")
st.sidebar.caption("Stateful AI Security Operations Gateway")

# Service health
gateway_healthy = check_service_health(f"{GATEWAY_URL}/health")
ollama_healthy = check_service_health(f"{OLLAMA_URL}/")

st.sidebar.markdown("### Infrastructure Health")
c1, c2 = st.sidebar.columns(2)
with c1:
    if gateway_healthy:
        st.success("Gateway: 🟢 Online")
    else:
        st.error("Gateway: 🔴 Offline")
with c2:
    if ollama_healthy:
        st.success("Ollama: 🟢 Online")
    else:
        st.warning("Ollama: 🟡 Offline")

st.sidebar.divider()

# Session Selector
sessions_df = fetch_all_sessions_df()
session_list = sessions_df["session_id"].tolist() if not sessions_df.empty else []

selected_session = None
if session_list:
    selected_session = st.sidebar.selectbox(
        "Select Monitored Session",
        options=session_list,
        index=0,
        help="Select a session ID to inspect its risk timeline, topic segmentation, and auditor verdict."
    )
    if selected_session:
        s_info = sessions_df[sessions_df["session_id"] == selected_session].iloc[0]
        status_color = "🔴" if s_info["status"] == "REVOKED" else ("🟡" if s_info["status"] == "RESET" else "🟢")
        st.sidebar.info(
            f"**Status:** {status_color} `{s_info['status']}`\n\n"
            f"**Current Risk:** `{s_info['session_risk']:.1f}/100`\n\n"
            f"**Turns:** {s_info['valid_turns']}\n\n"
            f"**Last Activity:** {s_info['last_seen']}"
        )
        
        # Section 22: Human Analyst Override Mechanism
        st.sidebar.markdown("### 🧑‍💼 Human Override")
        if s_info["status"] in ["REVOKED", "RESET"]:
            st.sidebar.warning(f"Session is currently **{s_info['status']}**.")
            override_reason = st.sidebar.text_input("Override Reason:", value="Analyst verified benign false alarm")
            if st.sidebar.button("🔓 Unblock / Override Session", use_container_width=True):
                try:
                    oresp = requests.post(
                        f"{GATEWAY_URL}/sessions/{selected_session}/override",
                        json={"analyst_id": "SOC_ANALYST", "reason": override_reason},
                        timeout=5.0
                    )
                    if oresp.status_code == 200:
                        st.sidebar.success("Session unblocked successfully!")
                        st.rerun()
                    else:
                        st.sidebar.error(f"Error: HTTP {oresp.status_code}")
                except Exception as ex:
                    st.sidebar.error(f"Override failed: {ex}")
        else:
            st.sidebar.caption("Session is active. Overrides apply when sessions are restricted.")
else:
    st.sidebar.warning("No sessions found. Send prompts in Playground tab to begin monitoring.")

st.sidebar.divider()
if st.sidebar.button("🔄 Refresh Data", use_container_width=True):
    st.rerun()

st.sidebar.caption("Response Tiers: 0–25 Allow · 26–45 Sanitize · 46–70 Reset · 71–100 Revoke")


# ================= TOP KPI METRICS =================
st.title("🛡️ Sentinel ATLAS SOC Operations Center")
st.caption("Real-Time Multi-Turn Semantic Gateway & Threat Defense")

act_sess, tot_reqs, act_thr, crit_thr, avg_risk, blk_sess = fetch_overview_metrics()

k1, k2, k3, k4, k5, k6 = st.columns(6)
k1.metric("Active Sessions", act_sess)
k2.metric("Total Requests", tot_reqs)
k3.metric("Active Threats", act_thr, delta=f"{act_thr} turns > 25" if act_thr > 0 else None, delta_color="inverse")
k4.metric("Critical Threats", crit_thr, delta=f"{crit_thr} turns >= 71" if crit_thr > 0 else None, delta_color="inverse")
k5.metric("Average Risk", f"{avg_risk:.1f}/100")
k6.metric("Blocked Sessions", blk_sess)

st.markdown("---")


# ================= MAIN TABS =================
tab_monitor, tab_topics, tab_atlas, tab_auditor, tab_attribution, tab_playground = st.tabs([
    "📈 Risk & Drift Timeline",
    "🏷️ Topic Segmentation",
    "🎯 MITRE ATLAS Intelligence",
    "🤝 Dual-Agent Auditor",
    "📑 Threat Attribution & Reports",
    "🧪 Live Gateway Playground"
])


# ------------- TAB 1: RISK & DRIFT TIMELINE -------------
with tab_monitor:
    if not selected_session:
        st.info("Select a session in the sidebar to inspect its security timeline.")
    else:
        turns_df = fetch_session_turns_df(selected_session)
        st.subheader(f"Session Timeline: `{selected_session}`")

        if turns_df.empty:
            st.warning("No turns recorded for this session.")
        else:
            # 1. Plotly Risk Score Progression Chart (0 - 100)
            fig_risk = go.Figure()

            # Shaded tier bands
            fig_risk.add_hrect(y0=0, y1=25, fillcolor="#0e4429", opacity=0.25, line_width=0, annotation_text="ALLOW (0–25)", annotation_position="top left")
            fig_risk.add_hrect(y0=26, y1=45, fillcolor="#4d3800", opacity=0.25, line_width=0, annotation_text="SANITIZE (26–45)", annotation_position="top left")
            fig_risk.add_hrect(y0=46, y1=70, fillcolor="#5a1e02", opacity=0.25, line_width=0, annotation_text="RESET (46–70)", annotation_position="top left")
            fig_risk.add_hrect(y0=71, y1=100, fillcolor="#490202", opacity=0.25, line_width=0, annotation_text="REVOKE (71–100)", annotation_position="top left")

            fig_risk.add_trace(go.Scatter(
                x=turns_df["turn_number"],
                y=turns_df["risk_score"],
                mode="lines+markers",
                name="Risk Score (0–100)",
                line=dict(color="#f85149", width=3),
                marker=dict(size=10, color="#f85149", symbol="circle"),
                hovertext=[f"Turn {r.turn_number}: Risk {r.risk_score} | Technique: {r.attack_technique}" for _, r in turns_df.iterrows()],
                hoverinfo="text"
            ))

            fig_risk.update_layout(
                title="Dynamic Composite Risk Score Trajectory (0–100)",
                xaxis_title="Conversation Turn",
                yaxis_title="Risk Score",
                yaxis=dict(range=[-2, 102], gridcolor="#2d3342"),
                xaxis=dict(tickmode="linear", dtick=1, gridcolor="#2d3342"),
                template="plotly_dark",
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                height=340
            )
            st.plotly_chart(fig_risk, use_container_width=True)

            # 2. Semantic Drift Timeline Chart
            fig_drift = go.Figure()
            fig_drift.add_trace(go.Scatter(
                x=turns_df["turn_number"],
                y=turns_df["drift_score"],
                mode="lines+markers",
                name="Rolling 4-Turn Drift",
                line=dict(color="#388bfd", width=2),
                marker=dict(size=8, color="#388bfd")
            ))
            fig_drift.add_trace(go.Scatter(
                x=turns_df["turn_number"],
                y=turns_df["similarity_score"],
                mode="lines+markers",
                name="Anchor Similarity",
                line=dict(color="#3fb950", width=2, dash="dot"),
                marker=dict(size=8, color="#3fb950")
            ))
            fig_drift.update_layout(
                title="Semantic Drift & Session Intent Similarity Progression",
                xaxis_title="Conversation Turn",
                yaxis_title="Score (0.0 to 1.0)",
                yaxis=dict(range=[-0.05, 1.05], gridcolor="#2d3342"),
                xaxis=dict(tickmode="linear", dtick=1, gridcolor="#2d3342"),
                template="plotly_dark",
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                height=280
            )
            st.plotly_chart(fig_drift, use_container_width=True)

            # 3. Transparent Turn-by-Turn Inspection
            st.markdown("### 💬 Conversation Transcript & Security Verdicts")
            for _, r in turns_df.iterrows():
                score = r["risk_score"]
                if score >= 71:
                    badge_cls = "badge-revoke"
                    action_lbl = "REVOKED"
                elif score >= 46:
                    badge_cls = "badge-reset"
                    action_lbl = "RESET"
                elif score >= 26:
                    badge_cls = "badge-sanitize"
                    action_lbl = "SANITIZED"
                else:
                    badge_cls = "badge-allow"
                    action_lbl = "ALLOWED"

                st.markdown(f"""
                <div style="margin-bottom: 6px;">
                    <span class='{badge_cls}'>Turn {r['turn_number']} · {action_lbl} (Risk: {score:.0f}/100)</span>
                    <span style="font-size:12px; color:#8b949e; margin-left: 10px;">Topic: <b>{r['topic_id']}</b> · Technique: <b>{r['attack_technique']}</b></span>
                </div>
                <div class="chat-bubble-user">
                    <b>User:</b> {r['message_text']}
                </div>
                <div class="chat-bubble-ai">
                    <b>Worker AI Response:</b><br>{r['llm_response']}
                </div>
                """, unsafe_allow_html=True)


# ------------- TAB 2: TOPIC SEGMENTATION -------------
with tab_topics:
    st.subheader("🏷️ Local Topic Anchors & Topic Timeline")
    st.caption("Tracks how conversation branches into distinct local topics, separating legitimate topic changes from semantic attack drift.")

    if not selected_session:
        st.info("Select a session in sidebar to inspect topic segmentation.")
    else:
        topics_df = fetch_session_topics_df(selected_session)
        if topics_df.empty:
            st.info("No topic segments registered for this session yet.")
        else:
            st.dataframe(
                topics_df,
                column_config={
                    "topic_id": st.column_config.TextColumn("Topic ID", width="small"),
                    "topic_name": st.column_config.TextColumn("Topic Title", width="medium"),
                    "first_turn": st.column_config.NumberColumn("Start Turn", width="small"),
                    "last_turn": st.column_config.NumberColumn("End Turn", width="small"),
                    "is_benign": st.column_config.CheckboxColumn("Benign Intent", width="small"),
                    "created_at": st.column_config.DatetimeColumn("Established At", width="medium"),
                },
                hide_index=True,
                use_container_width=True
            )

            # Visual Topic Timeline Cards per Section 22
            st.markdown("### 🗺️ Topic Evolution Timeline")
            for _, top in topics_df.iterrows():
                icon = "🟢" if top["is_benign"] else "🚨"
                turns_span = f"Turns T{top['first_turn']} → T{top['last_turn']}" if top['first_turn'] != top['last_turn'] else f"Turn T{top['first_turn']}"
                st.markdown(f"""
                <div class="trajectory-step">
                    <b>{icon} {top['topic_name']}</b> &nbsp; · &nbsp; <code>{top['topic_id']}</code> &nbsp; · &nbsp; <span style="color:#58a6ff;">{turns_span}</span>
                </div>
                """, unsafe_allow_html=True)


# ------------- TAB 3: MITRE ATLAS INTELLIGENCE -------------
with tab_atlas:
    st.subheader("🎯 MITRE ATLAS Attack Attribution")
    st.caption("Vector similarity mapping against known adversarial techniques (ChromaDB index).")

    atlas_df = fetch_atlas_frequency_df()
    if atlas_df.empty:
        st.info("No MITRE ATLAS matches recorded in gateway database yet.")
    else:
        col_a1, col_a2 = st.columns([2, 1])
        with col_a1:
            fig_bar = px.bar(
                atlas_df,
                x="technique_name",
                y="occurrences",
                color="occurrences",
                labels={"technique_name": "MITRE ATLAS Technique", "occurrences": "Detected Occurrences"},
                title="Top MITRE ATLAS Techniques Flagged Across Gateway",
                template="plotly_dark"
            )
            fig_bar.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
            st.plotly_chart(fig_bar, use_container_width=True)

        with col_a2:
            st.markdown("### Technique Breakdown")
            st.dataframe(atlas_df, hide_index=True, use_container_width=True)


# ------------- TAB 4: DUAL-AGENT AUDITOR -------------
with tab_auditor:
    st.subheader("🤝 ATLAS Bridge (Dual-Agent Consensus)")
    st.caption("Independent Auditor Agent evaluating Worker proposed actions against original user intent.")

    if not selected_session:
        st.info("Select a session in sidebar to view Auditor decisions.")
    else:
        conn = get_db_connection()
        try:
            auditor_df = pd.read_sql_query(
                "SELECT turn_number, verdict, confidence, reason, timestamp FROM auditor_decisions WHERE session_id = ? ORDER BY turn_number DESC",
                conn,
                params=(selected_session,)
            )
        except Exception:
            auditor_df = pd.DataFrame()
        conn.close()

        if auditor_df.empty:
            st.info("No structured auditor decisions recorded for this session yet.")
        else:
            st.dataframe(
                auditor_df,
                column_config={
                    "turn_number": st.column_config.NumberColumn("Turn #", width="small"),
                    "verdict": st.column_config.TextColumn("Auditor Verdict", width="small"),
                    "confidence": st.column_config.NumberColumn("Confidence", format="%.2f"),
                    "reason": st.column_config.TextColumn("Auditor Rationale", width="large"),
                    "timestamp": st.column_config.DatetimeColumn("Timestamp", width="medium"),
                },
                hide_index=True,
                use_container_width=True
            )


# ------------- TAB 5: THREAT ATTRIBUTION & AI REPORTS -------------
with tab_attribution:
    st.subheader("📑 Threat Attribution & Attack Trajectory")
    st.caption("Traces sustained attack paths, persistence scores, and plain-English SOC threat attribution reports.")

    if not selected_session:
        st.info("Select a session in sidebar to view its threat attribution.")
    else:
        try:
            pers_res = requests.get(f"{GATEWAY_URL}/attribution/persistence/{selected_session}", timeout=3.0)
            persistence_data = pers_res.json() if pers_res.status_code == 200 else {"current_streak": 0, "max_streak": 0, "sustained_intent": False}
        except Exception:
            persistence_data = {"current_streak": 0, "max_streak": 0, "sustained_intent": False}

        cp1, cp2, cp3 = st.columns(3)
        cp1.metric("Threat Persistence Streak", f"{persistence_data.get('max_streak', 0)} Turns", help="Consecutive turns exhibiting anomalous drift or technique matches.")
        cp2.metric("Sustained Attack Detected", "🚨 YES" if persistence_data.get("sustained_intent") else "✅ NO", help="Triggered if 3 or more consecutive turns exhibit anomalous signals.")
        cp3.metric("Selected Session", f"`{selected_session[:14]}...`")

        st.markdown("---")

        # Step-by-Step Attack Trajectory per Section 22
        st.markdown("### 🪜 Attack Trajectory Walkthrough")
        try:
            traj_res = requests.get(f"{GATEWAY_URL}/sessions/{selected_session}/trajectory", timeout=3.0)
            trajectory_list = traj_res.json().get("trajectory", []) if traj_res.status_code == 200 else []
        except Exception:
            trajectory_list = []

        if not trajectory_list:
            st.info("No multi-turn trajectory available for this session.")
        else:
            for step in trajectory_list:
                r_val = step.get("risk_score") or 0.0
                step_status = "CRITICAL" if r_val >= 71 else ("HIGH" if r_val >= 46 else ("MEDIUM" if r_val >= 26 else "NORMAL"))
                st.markdown(f"""
                <div class="trajectory-step">
                    <b>Turn {step['turn']}:</b> <code>{step_status}</code> (Risk {r_val:.0f}/100) &nbsp; | &nbsp; 
                    Prompt: <i>"{step['prompt'][:80]}..."</i> &nbsp; | &nbsp; 
                    Technique: <b>{step['technique']}</b>
                </div>
                """, unsafe_allow_html=True)

        st.markdown("---")
        st.markdown("### 📝 Plain-English SOC Threat Attribution Report")
        if st.button("⚡ Generate AI Threat Attribution Report", key="btn_report", use_container_width=True):
            with st.spinner("Local Ollama analyzing session progression across MITRE ATLAS tactics..."):
                try:
                    rep_res = requests.get(f"{GATEWAY_URL}/attribution/report/{selected_session}", timeout=45.0)
                    if rep_res.status_code == 200:
                        report_content = rep_res.json().get("report", "No report generated.")
                        st.session_state[f"rep_{selected_session}"] = report_content
                    else:
                        st.error(f"Report API returned HTTP {rep_res.status_code}")
                except Exception as ex:
                    st.error(f"Could not connect to Gateway: {ex}")

        saved_rep = st.session_state.get(f"rep_{selected_session}")
        if saved_rep:
            st.markdown(f"""
            <div style="background-color:#161b22; border: 1px solid #30363d; border-radius: 8px; padding: 18px; margin-top: 15px;">
                {saved_rep}
            </div>
            """, unsafe_allow_html=True)


# ------------- TAB 6: LIVE GATEWAY PLAYGROUND -------------
with tab_playground:
    st.subheader("Interactive Security Gateway Playground")
    st.caption("Test prompts directly against your running FastAPI security proxy (`http://127.0.0.1:8000/chat`).")

    p1, p2 = st.columns([2, 1])
    with p1:
        session_choice = st.radio("Session Context:", ["Active Selected Session", "New Anonymous Session"], horizontal=True)
    with p2:
        target_session = selected_session if (session_choice == "Active Selected Session" and selected_session) else None
        st.text_input("Active Target Session ID", value=target_session or "(Auto-generate new UUID)", disabled=True)

    with st.form("pg_form", clear_on_submit=False):
        prompt_input = st.text_area(
            "Enter prompt to test:",
            placeholder="Type a prompt (e.g. cloud security question, baking brownies, or adversarial prompt)...",
            height=90
        )
        submit_btn = st.form_submit_button("🚀 Submit to Gateway", use_container_width=True)

    if submit_btn and prompt_input.strip():
        payload = {"message": prompt_input.strip()}
        if target_session:
            payload["session_id"] = target_session

        try:
            with st.spinner("Sentinel ATLAS processing intent, topics, and risk factors..."):
                resp = requests.post(f"{GATEWAY_URL}/chat", json=payload, timeout=65.0)

            if resp.status_code == 200:
                data = resp.json()
                decision = data.get("decision", "ALLOW")
                risk_score = data.get("risk_score", 0)
                topic_changed = data.get("topic_changed", False)
                breakdown = data.get("risk_breakdown", {})

                if decision == "ALLOW":
                    st.success(f"✅ **Request ALLOWED!** Risk Score: `{risk_score}/100` | Topic Changed: `{topic_changed}`")
                elif decision == "SANITIZE":
                    st.warning(f"🛡️ **Playbook: CONTEXT SANITISATION Applied!** (Risk: `{risk_score}/100`). Adversarial framing neutralized.")
                elif decision == "RESET":
                    st.error(f"⚠️ **Playbook: SESSION RESET Triggered!** (Risk: `{risk_score}/100`). Conversational memory reset.")
                else: # REVOKE
                    st.error(f"🚨 **Playbook: ACCESS REVOCATION!** (Risk: `{risk_score}/100`). Session terminated.")

                with st.chat_message("assistant"):
                    st.markdown(f"**AI Response:**\n\n{data.get('response')}")

                # Section 19: Transparent Risk Breakdown Card
                st.markdown("### 🧮 Transparent Risk Calculation Breakdown")
                st.json(breakdown)

                st.json(data)
                if st.button("🔄 Refresh View to Display Turn"):
                    st.rerun()
            else:
                st.error(f"Gateway Error: Received HTTP status code {resp.status_code}")
                st.code(resp.text)
        except Exception as e:
            st.error(f"Could not connect to Gateway at {GATEWAY_URL}: {e}")
