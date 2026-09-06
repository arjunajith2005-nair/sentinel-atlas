import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import sqlite3
import requests
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
GATEWAY_URL = os.getenv("GATEWAY_URL", "http://127.0.0.1:8001")
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

def get_db_connection():
    return sqlite3.connect(DB_PATH, timeout=10)

def fetch_overview_metrics():
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

def fetch_all_sessions():
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

def fetch_session_timeline(session_id):
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

def fetch_all_security_events():
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

def check_service_health(url):
    try:
        res = requests.get(url, timeout=1.5)
        return res.status_code in [200, 404, 307]
    except Exception:
        return False

# ================= SIDEBAR =================
st.sidebar.title("🛡️ Sentinel ATLAS")
st.sidebar.caption("Real-Time AI Security Operations Gateway")

# System health indicators
gateway_healthy = check_service_health(f"{GATEWAY_URL}/docs")
ollama_healthy = check_service_health(f"{OLLAMA_URL}/")

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
tab_monitor, tab_audit, tab_attribution, tab_playground = st.tabs([
    "📈 Session Drift Monitor", 
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

# ------------- TAB 2: SECURITY AUDIT LOG -------------
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
        # Fetch persistence and path data via API or DB
        try:
            pers_res = requests.get(f"{GATEWAY_URL}/attribution/persistence/{selected_session}", timeout=3.0)
            persistence_data = pers_res.json() if pers_res.status_code == 200 else {"current_streak": 0, "max_streak": 0, "sustained_intent": False}
        except Exception:
            persistence_data = {"current_streak": 0, "max_streak": 0, "sustained_intent": False}

        col_p1, col_p2, col_p3 = st.columns(3)
        col_p1.metric("Persistence Streak", f"{persistence_data['max_streak']} Turns", help="Maximum consecutive turns exhibiting semantic drift or security flags.")
        col_p2.metric("Sustained Exploit Intent", "🚨 YES" if persistence_data['sustained_intent'] else "✅ NO", help="Flagged if 3 or more consecutive turns show anomalous semantic drift.")
        col_p3.metric("Selected Session", f"`{selected_session[:14]}...`")

        st.markdown("---")

        # Dual-Agent Consensus Events
        st.markdown("### 🤝 Dual-Agent Consensus (ATLAS Bridge)")
        st.caption("Worker Agent proposed action vs. Asynchronous Auditor Agent alignment verdict.")
        conn = get_db_connection()
        try:
            consensus_df = pd.read_sql_query(
                "SELECT turn_number, iaa_score, auditor_verdict, auditor_reason, timestamp FROM consensus_events WHERE session_id = ? ORDER BY turn_number DESC",
                conn,
                params=(selected_session,)
            )
        except Exception:
            consensus_df = pd.DataFrame()
        conn.close()

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
                    rep_res = requests.get(f"{GATEWAY_URL}/attribution/report/{selected_session}", timeout=45.0)
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
                resp = requests.post(f"{GATEWAY_URL}/chat", json=payload, timeout=65.0)
                
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
                    st.rerun()
            else:
                st.error(f"Gateway Error: Received HTTP status code {resp.status_code}")
                st.code(resp.text)
        except Exception as e:
            st.error(f"Could not connect to Gateway at {GATEWAY_URL}. Is `python main.py` running?")
            st.caption(str(e))
