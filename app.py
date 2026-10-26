
"""ApexNexus AI — polished defensive cybersecurity workspace."""

from __future__ import annotations

import html
import streamlit as st
from dotenv import load_dotenv

load_dotenv()

from agent import ApexNexusAgent
from tools import generate_security_report


st.set_page_config(
    page_title="ApexNexus AI | Security Operations",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Premium dark emerald visual system.
st.markdown(
    r"""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&display=swap');
:root{--bg:#050908;--panel:#0b1310;--panel2:#101c17;--emerald:#35f0a0;--mint:#8affcf;--text:#edf8f2;--muted:#81958a;--border:rgba(130,255,196,.12)}
html,body,[class*="css"]{font-family:'Inter',sans-serif!important}
.stApp{color:var(--text);background:radial-gradient(ellipse at 50% -20%,rgba(20,160,100,.19),transparent 48%),radial-gradient(ellipse at 100% 38%,rgba(20,110,90,.08),transparent 35%),#050908!important}
header[data-testid="stHeader"]{background:rgba(5,9,8,.72)!important}
[data-testid="stDecoration"],#MainMenu,footer{display:none!important}
.block-container{max-width:1240px!important;padding-top:1rem!important;padding-bottom:3rem!important}
[data-testid="stSidebar"]{background:linear-gradient(180deg,#0a120e 0%,#070c09 62%,#050806 100%)!important;border-right:1px solid rgba(120,255,190,.10)}
[data-testid="stSidebar"] *{color:#e5f4eb}
.brand{display:flex;align-items:center;gap:13px;padding:8px 4px 24px}
.brand-icon{display:flex;align-items:center;justify-content:center;width:47px;height:47px;flex-shrink:0;border-radius:15px;font-size:25px;background:linear-gradient(145deg,rgba(53,240,160,.20),rgba(10,80,55,.25));border:1px solid rgba(90,255,180,.35);box-shadow:0 0 18px rgba(53,240,160,.15),inset 0 0 15px rgba(53,240,160,.05)}
.brand-name{font-size:19px;font-weight:900;letter-spacing:-.7px;color:#f4fff8}.brand-name span{color:var(--emerald)}
.brand-subtitle{margin-top:4px;color:#769587;font-size:9px;letter-spacing:1.5px;font-weight:700}
.side-label{margin:18px 4px 9px;color:#668273;font-size:10px;letter-spacing:1.7px;font-weight:800}
[data-testid="stSidebar"] .stButton button{color:#a1b7a9!important;background:transparent!important;border:1px solid transparent!important;border-radius:11px!important;min-height:43px;font-size:12px!important;font-weight:600!important;box-shadow:none!important;transition:all .2s ease!important}
[data-testid="stSidebar"] .stButton button:hover{color:#eafff2!important;background:rgba(53,240,160,.075)!important;border-color:rgba(53,240,160,.15)!important;transform:translateX(2px)}
.engine-card{margin-top:10px;padding:15px;border:1px solid var(--border);border-radius:14px;background:rgba(255,255,255,.025)}
.engine-label{font-size:9px;color:#769587;letter-spacing:1.5px;font-weight:800}.engine-name{margin-top:7px;font-size:12px;font-weight:700;color:#c8f9dc}.engine-note{margin-top:8px;color:#74897d;font-size:10px;line-height:1.6}
.topbar{display:flex;justify-content:space-between;align-items:center;gap:12px;padding:8px 0 18px;margin-bottom:10px;border-bottom:1px solid rgba(130,255,196,.10)}
.topbar-section{color:#81978b;font-size:11px;font-weight:600;letter-spacing:.5px}.topbar-status{display:flex;align-items:center;gap:8px;color:#a7c6b4;font-size:10px;letter-spacing:.6px;white-space:nowrap}
.status-dot{width:7px;height:7px;border-radius:50%;background:#35f0a0;box-shadow:0 0 12px rgba(53,240,160,.75)}
.hero{position:relative;overflow:hidden;padding:45px 22px 26px;text-align:center}
.hero-orbit{display:flex;align-items:center;justify-content:center;width:76px;height:76px;margin:0 auto 24px;font-size:34px;border-radius:24px;background:linear-gradient(145deg,rgba(53,240,160,.17),rgba(12,63,45,.25));border:1px solid rgba(80,255,174,.35);box-shadow:0 0 25px rgba(53,240,160,.13),0 0 65px rgba(53,240,160,.07),inset 0 0 25px rgba(53,240,160,.05);animation:softGlow 3s ease-in-out infinite alternate}
@keyframes softGlow{from{box-shadow:0 0 18px rgba(53,240,160,.10),0 0 45px rgba(53,240,160,.05)}to{box-shadow:0 0 28px rgba(53,240,160,.22),0 0 65px rgba(53,240,160,.10)}}
.hero h1{margin:0;font-size:clamp(34px,5vw,57px);line-height:1.09;letter-spacing:-2.7px;font-weight:900;color:#f4fff8}.hero h1 span{color:#55f5ad;text-shadow:0 0 30px rgba(53,240,160,.12)}
.hero-description{max-width:670px;margin:17px auto 0;color:#94a99c;font-size:14px;line-height:1.9}.hero-caption{margin-top:20px;color:#71917f;font-size:10px;letter-spacing:1.8px;font-weight:700}
.section-label{margin:20px 0 13px;color:#789486;font-size:10px;font-weight:800;letter-spacing:1.8px}
.feature-card{min-height:132px;padding:18px;border:1px solid rgba(130,255,196,.105);border-radius:17px;background:linear-gradient(145deg,rgba(17,31,24,.90),rgba(8,14,11,.90));transition:all .2s ease}
.feature-card:hover{border-color:rgba(53,240,160,.30);box-shadow:0 8px 28px rgba(0,0,0,.20)}.feature-icon{margin-bottom:12px;font-size:23px}.feature-title{color:#e8fff0;font-size:12px;font-weight:800}.feature-description{margin-top:7px;color:#82978a;font-size:10px;line-height:1.7}
.workspace-banner{margin:24px 0 16px;padding:19px 21px;border:1px solid rgba(130,255,196,.12);border-radius:16px;background:linear-gradient(110deg,rgba(18,43,30,.65),rgba(9,17,12,.80))}
.workspace-eyebrow{color:#59db9c;font-size:9px;letter-spacing:1.8px;font-weight:800}.workspace-title{margin-top:7px;color:#effff5;font-size:19px;font-weight:800;letter-spacing:-.4px}.workspace-copy{margin-top:6px;color:#90a899;font-size:11px;line-height:1.7}
[data-testid="stChatMessage"]{border:1px solid rgba(130,255,196,.09);border-radius:17px;background:rgba(10,18,13,.84);padding:15px 18px;margin-bottom:14px}
[data-testid="stChatMessage"] p,[data-testid="stChatMessage"] li{color:#dcebe2;font-size:13px;line-height:1.85}
[data-testid="stChatMessage"] h1,[data-testid="stChatMessage"] h2,[data-testid="stChatMessage"] h3{color:#8affc1;letter-spacing:-.4px}
[data-testid="stChatMessage"] code{color:#9bffcc;background:#111e16;border-radius:5px}
.composer-heading{margin:24px 0 10px;color:#c9e8d4;font-size:11px;font-weight:800;letter-spacing:1.1px}
[data-testid="stForm"]{padding:15px 17px 13px;border:1px solid rgba(75,246,166,.25);border-radius:19px;background:linear-gradient(145deg,rgba(14,28,20,.98),rgba(7,13,9,.98));box-shadow:0 15px 45px rgba(0,0,0,.20),0 0 28px rgba(53,240,160,.035)}
[data-testid="stTextArea"] textarea{color:#f1fff6!important;background:rgba(2,8,5,.35)!important;border:1px solid rgba(130,255,196,.08)!important;border-radius:12px!important;font-size:13px!important;line-height:1.8!important;padding:14px!important;caret-color:#35f0a0!important}
[data-testid="stTextArea"] textarea:focus{border-color:rgba(53,240,160,.48)!important;box-shadow:0 0 0 1px rgba(53,240,160,.08)!important}
[data-testid="stTextArea"] textarea::placeholder{color:#6d8575!important}
[data-testid="stFormSubmitButton"] button{min-height:43px;color:#03150b!important;background:linear-gradient(135deg,#54f5a9,#27d98b)!important;border:1px solid rgba(137,255,199,.30)!important;border-radius:11px!important;font-size:12px!important;font-weight:900!important;box-shadow:0 0 22px rgba(53,240,160,.11);transition:all .2s ease!important}
[data-testid="stFormSubmitButton"] button:hover{transform:translateY(-1px);box-shadow:0 0 30px rgba(53,240,160,.22)}
.composer-footnote{padding-top:7px;color:#70877a;font-size:10px;line-height:1.7}
.stButton>button,[data-testid="stDownloadButton"] button{border-radius:10px;transition:all .2s ease}
[data-testid="stExpander"]{border:1px solid rgba(130,255,196,.11);border-radius:12px;background:rgba(8,16,11,.6)}
.footer{margin-top:38px;padding-top:16px;border-top:1px solid rgba(130,255,196,.08);color:#60776a;text-align:center;font-size:10px;line-height:1.8}
@media(max-width:800px){.hero{padding:28px 8px 20px}.hero h1{letter-spacing:-1.5px}.feature-card{min-height:145px;padding:14px}}
@media(prefers-reduced-motion:reduce){*,*::before,*::after{animation-duration:.01ms!important;transition-duration:.01ms!important}}
</style>
""",
    unsafe_allow_html=True,
)

WORKSPACES = [
    ("⌂", "Command Center"),
    ("◎", "Website Security"),
    ("⌘", "Code Security"),
    ("☁", "Cloud & IAM"),
    ("▤", "Log Analysis"),
    ("◈", "Threat Intelligence"),
    ("⚠", "Incident Response"),
    ("✦", "Vulnerability Fixer"),
    ("▧", "Security Reports"),
]

WORKSPACE_INFO = {
    "Command Center": (
        "Your security, understood.",
        "Ask questions naturally, review suspicious evidence, and get practical defensive guidance.",
        "Describe your security problem or ask a cybersecurity question...",
    ),
    "Website Security": (
        "Website Security",
        "Review basic website posture and response headers. Only assess sites you own or are authorized to check.",
        "Enter the website URL you are authorized to assess...",
    ),
    "Code Security": (
        "Code Security",
        "Review supplied source code for common security warning signs and safer alternatives.",
        "Paste your code and describe what you want reviewed...",
    ),
    "Cloud & IAM": (
        "Cloud & Identity Security",
        "Review cloud policies, broad permissions, and least-privilege concerns.",
        "Paste an IAM policy or describe your access-control concern...",
    ),
    "Log Analysis": (
        "Security Log Analysis",
        "Triage authentication failures and suspicious patterns in security logs.",
        "Paste relevant logs and explain what concerns you...",
    ),
    "Threat Intelligence": (
        "Threat Intelligence",
        "Classify an indicator and plan further investigation. Live reputation is not assumed unless a provider is configured.",
        "Enter an IP address, domain, or file hash...",
    ),
    "Incident Response": (
        "Incident Response",
        "Organize investigation, evidence preservation, containment, and recovery priorities.",
        "Describe what happened and which systems may be affected...",
    ),
    "Vulnerability Fixer": (
        "Vulnerability Remediation",
        "Understand a security weakness and identify safer implementation options.",
        "Describe the vulnerability or paste code you want help fixing...",
    ),
    "Security Reports": (
        "Security Reports",
        "Review or export the most recent assessment generated during this session.",
        "Ask a follow-up question about your security assessment...",
    ),
}

# A separate agent instance is maintained for each Streamlit session.
if "apex_agent" not in st.session_state:
    st.session_state.apex_agent = ApexNexusAgent()

agent: ApexNexusAgent = st.session_state.apex_agent

if "messages" not in st.session_state:
    st.session_state.messages = []
if "mode" not in st.session_state:
    st.session_state.mode = "Command Center"
if "last_assessment" not in st.session_state:
    st.session_state.last_assessment = None

# --------------------------- Sidebar ---------------------------
with st.sidebar:
    st.markdown(
        """
        <div class="brand"><div class="brand-icon">🛡️</div><div>
        <div class="brand-name">APEX<span>NEXUS</span></div>
        <div class="brand-subtitle">AI SECURITY OPERATIONS</div></div></div>
        """,
        unsafe_allow_html=True,
    )
    st.markdown(
        '<div class="side-label">YOUR WORKSPACE</div>',
        unsafe_allow_html=True,
    )

    for icon, name in WORKSPACES:
        if st.button(
            f"{icon}   {name}",
            key=f"workspace_{name}",
            use_container_width=True,
        ):
            st.session_state.mode = name
            st.rerun()

    st.markdown(
        '<div class="side-label">ENGINE INFORMATION</div>',
        unsafe_allow_html=True,
    )
    provider = html.escape(
        str(getattr(agent, "provider", "Local Defensive Engine"))
    )
    st.markdown(
        f"""
        <div class="engine-card">
            <div class="engine-label">CURRENT AI ENGINE</div>
            <div class="engine-name">✦ {provider}</div>
            <div class="engine-note">
                Defensive analysis and natural-language guidance.
                External checks are only reported when actually performed.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.markdown("<br>", unsafe_allow_html=True)

    if st.button(
        "↻  New Conversation",
        key="clear_conversation",
        use_container_width=True,
    ):
        st.session_state.messages = []
        st.session_state.last_assessment = None
        if hasattr(agent, "history"):
            agent.history = []
        st.rerun()

# --------------------------- Main header ---------------------------
mode = st.session_state.mode
st.markdown(
    f"""
    <div class="topbar">
        <div class="topbar-section">WORKSPACE / {html.escape(mode.upper())}</div>
        <div class="topbar-status"><span class="status-dot"></span>
        INTERFACE READY</div>
    </div>
    """,
    unsafe_allow_html=True,
)

if not st.session_state.messages:
    if mode == "Command Center":
        st.markdown(
            """
            <div class="hero">
                <div class="hero-orbit">🛡️</div>
                <h1>Think clearly.<br><span>Defend intelligently.</span></h1>
                <div class="hero-description">
                    Meet your cybersecurity operations assistant. Ask questions
                    naturally, investigate suspicious activity, review code and
                    logs, and get practical defensive guidance.
                </div>
                <div class="hero-caption">
                    INTELLIGENCE&nbsp; · &nbsp;CLARITY&nbsp; · &nbsp;DEFENSE
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.markdown(
            '<div class="section-label">EXPLORE YOUR SECURITY WORKSPACE</div>',
            unsafe_allow_html=True,
        )

        cards = [
            ("🌐", "Website Security", "Review website posture and common response headers."),
            ("💻", "Code Security", "Identify potential code weaknesses and safer alternatives."),
            ("📊", "Log Analysis", "Interpret suspicious events and authentication patterns."),
            ("☁️", "Cloud & IAM", "Review policies and overly broad permissions."),
        ]
        cols = st.columns(2, gap="medium")
        for i, (icon, title, desc) in enumerate(cards):
            with cols[i % 2]:
                st.markdown(
                    f"""
                    <div class="feature-card">
                        <div class="feature-icon">{icon}</div>
                        <div class="feature-title">{title}</div>
                        <div class="feature-description">{desc}</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
    else:
        title, description, _ = WORKSPACE_INFO[mode]
        st.markdown(
            f"""
            <div class="workspace-banner">
                <div class="workspace-eyebrow">APEXNEXUS / SPECIALIZED WORKSPACE</div>
                <div class="workspace-title">{html.escape(title)}</div>
                <div class="workspace-copy">{html.escape(description)}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

# --------------------------- Reports ---------------------------
if mode == "Security Reports":
    st.markdown("### Latest Assessment")
    latest = st.session_state.last_assessment

    if latest:
        st.info(
            f"**Risk:** {latest.get('risk', 'UNKNOWN')}\n\n"
            f"{latest.get('summary', 'Assessment available.')}"
        )
        try:
            report = generate_security_report(latest)
            st.download_button(
                "⬇  Download Security Report",
                data=report,
                file_name="ApexNexus_Security_Report.md",
                mime="text/markdown",
                use_container_width=True,
            )
        except Exception as exc:
            st.warning(
                "The report could not be generated. "
                "The saved assessment is still available."
            )
            with st.expander("Technical details"):
                st.code(str(exc))
    else:
        st.caption(
            "Your latest assessment will appear here after you submit "
            "a security request."
        )

# --------------------------- Conversation history ---------------------------
for message in st.session_state.messages:
    role = message.get("role", "assistant")
    avatar = "👤" if role == "user" else "🛡️"

    with st.chat_message(role, avatar=avatar):
        st.markdown(message.get("content", ""))
        details = message.get("details")

        if role == "assistant" and isinstance(details, dict):
            findings = details.get("findings") or []
            evidence = details.get("evidence") or []

            if findings:
                with st.expander(f"Review findings ({len(findings)})"):
                    for finding in findings:
                        if isinstance(finding, dict):
                            st.markdown(
                                f"**{finding.get('severity', 'INFO')} — "
                                f"{finding.get('title', 'Finding')}**"
                            )
                            if finding.get("description"):
                                st.write(finding["description"])
                            if finding.get("recommendation"):
                                st.write(
                                    "Recommended action: "
                                    f"{finding['recommendation']}"
                                )
                        else:
                            st.write(str(finding))

            if evidence:
                with st.expander("View technical evidence"):
                    for item in evidence:
                        st.markdown(f"- {item}")

# --------------------------- Input composer ---------------------------
_, composer, _ = st.columns([0.035, 0.93, 0.035])

with composer:
    st.markdown(
        '<div class="composer-heading">✦  TALK TO APEXNEXUS</div>',
        unsafe_allow_html=True,
    )
    _, _, placeholder = WORKSPACE_INFO[mode]

    with st.form("apexnexus_message_form", clear_on_submit=True):
        prompt = st.text_area(
            "Message ApexNexus",
            placeholder=placeholder,
            height=118,
            label_visibility="collapsed",
            key="apexnexus_prompt",
        )

        left, right = st.columns([0.74, 0.26])

        with left:
            st.markdown(
                """
                <div class="composer-footnote">
                    Describe the problem naturally. Add relevant evidence
                    when available. ApexNexus focuses on defensive security.
                </div>
                """,
                unsafe_allow_html=True,
            )

        with right:
            submitted = st.form_submit_button(
                "Analyze  ↗",
                use_container_width=True,
            )

if submitted:
    clean_prompt = (prompt or "").strip()

    if not clean_prompt:
        st.warning(
            "Please type a question or describe a security problem first."
        )
    else:
        st.session_state.messages.append(
            {"role": "user", "content": clean_prompt}
        )

        try:
            with st.spinner("ApexNexus is reviewing your request..."):
                result = agent.analyze(clean_prompt, category=mode)

            response = str(
                getattr(
                    result,
                    "response",
                    "The analysis finished, but no text response was returned.",
                )
            )

            details = {
                "request_type": getattr(result, "request_type", "general"),
                "risk": getattr(result, "risk", "UNKNOWN"),
                "summary": getattr(result, "summary", ""),
                "findings": getattr(result, "findings", []) or [],
                "recommendations": getattr(result, "recommendations", []) or [],
                "evidence": getattr(result, "evidence", []) or [],
            }

            st.session_state.messages.append(
                {
                    "role": "assistant",
                    "content": response,
                    "details": details,
                }
            )

            if hasattr(result, "to_dict"):
                st.session_state.last_assessment = result.to_dict()
            else:
                st.session_state.last_assessment = details

        except Exception as exc:
            st.session_state.messages.append(
                {
                    "role": "assistant",
                    "content": (
                        "I couldn't complete that request because an internal "
                        "error occurred. No security action has been claimed "
                        "as completed."
                    ),
                }
            )
            st.session_state.last_error = (
                f"{type(exc).__name__}: {exc}"
            )

        st.rerun()

if st.session_state.get("last_error"):
    with st.expander("Troubleshoot the latest error"):
        st.code(st.session_state.pop("last_error"))

st.markdown(
    """
    <div class="footer">
        <strong style="color:#8ba897">APEXNEXUS AI</strong><br>
        Clear thinking for safer systems.<br>
        Defensive analysis only. Findings depend on the evidence available.
    </div>
    """,
    unsafe_allow_html=True,
)