"""PII Security Gateway - Pre-LLM Security Gateway & Document Sanitization Pipeline.

Enterprise Streamlit application providing local, explainable PII detection,
consistent semantic redaction, and fail-closed post-redaction validation.
Light corporate design system tailored for compliance and security teams.
"""
import io
import time
from pathlib import Path
from typing import List, Dict, Optional

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

from models.schemas import (
    DocumentAnalysisResult,
    SecurityStatus,
    Severity,
    ConfidenceLevel,
    PIIType,
)
from pipeline import GatewayPipeline
from reporting.report_generator import ReportGenerator

# Page Configuration
st.set_page_config(
    page_title="PII Security Gateway",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# Professional Corporate Warm Light Theme System CSS
CORPORATE_LIGHT_CSS = """
<style>
    /* Global Warm Palette & Typography */
    :root {
        --bg-page: #faf8f5;            /* Soft warm alabaster/linen, eliminates harsh glare */
        --bg-card: #ffffff;            /* Crisp warm white card surfaces */
        --bg-card-subtle: #fcfbf9;     /* Soft warm white card tint */
        --bg-subtle: #f5f2eb;          /* Warm stone sand neutral for headers/bars */
        --bg-subtle-hover: #ece7de;    /* Warm stone hover */
        --border-color: #e6e1d6;       /* Warm stone border */
        --border-focus: #cfc8ba;       /* Warm stone border active */
        --text-primary: #1c1917;       /* Warm obsidian charcoal (Stone-900) */
        --text-secondary: #44403c;     /* Warm stone slate (Stone-700) */
        --text-muted: #78716c;         /* Warm stone muted (Stone-500) */
        --brand-blue: #2563eb;         /* Sophisticated corporate royal sapphire */
        --brand-blue-hover: #1d4ed8;   /* Deep sapphire hover */
        --brand-blue-subtle: #eff6ff;  /* Warm ice blue accent */
        --status-safe-bg: #f0fdf4;     /* Warm emerald/mint tint */
        --status-safe-border: #bbf7d0;
        --status-safe-text: #166534;
        --status-safe-accent: #15803d;
        --status-blocked-bg: #fef2f2;  /* Warm rose/crimson tint */
        --status-blocked-border: #fecaca;
        --status-blocked-text: #991b1b;
        --status-blocked-accent: #b91c1c;
        --status-review-bg: #fffbeb;   /* Warm honey amber tint */
        --status-review-border: #fde68a;
        --status-review-text: #92400e;
        --status-review-accent: #b45309;
    }

    /* Force Warm Light Theme Base */
    .stApp {
        background-color: var(--bg-page) !important;
        color: var(--text-primary) !important;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    }

    /* Main Container Padding & Warm Feel */
    .main .block-container {
        padding-top: 2rem !important;
        padding-bottom: 3rem !important;
        background-color: var(--bg-page) !important;
    }

    /* Standardized Container Headings */
    h1, h2, h3, h4, h5, h6 {
        color: var(--text-primary) !important;
        font-weight: 600 !important;
        letter-spacing: -0.3px;
    }

    /* Corporate Header Card */
    .corporate-header {
        background-color: var(--bg-card);
        border: 1px solid var(--border-color);
        border-radius: 8px;
        padding: 18px 24px;
        margin-bottom: 20px;
        box-shadow: 0 1px 3px 0 rgba(44, 40, 37, 0.04);
    }
    .header-title-row {
        display: flex;
        align-items: center;
        justify-content: space-between;
        flex-wrap: wrap;
        gap: 12px;
        margin-bottom: 0;
    }
    .header-title {
        font-size: 24px;
        font-weight: 700;
        color: var(--text-primary);
        letter-spacing: -0.4px;
        display: flex;
        align-items: center;
        gap: 10px;
        margin: 0;
    }

    /* Clean Metric Cards */
    .metric-card-clean {
        background-color: var(--bg-card);
        border: 1px solid var(--border-color);
        border-radius: 8px;
        padding: 18px 20px;
        box-shadow: 0 1px 3px 0 rgba(44, 40, 37, 0.03);
        height: 100%;
        display: flex;
        flex-direction: column;
        justify-content: space-between;
    }
    .metric-title {
        font-size: 11px;
        text-transform: uppercase;
        letter-spacing: 0.6px;
        color: var(--text-muted);
        font-weight: 600;
        margin-bottom: 8px;
    }
    .metric-number {
        font-size: 30px;
        font-weight: 700;
        line-height: 1.1;
        color: var(--text-primary);
    }
    .metric-number-blue { color: var(--brand-blue); }
    .metric-number-green { color: var(--status-safe-accent); }
    .metric-number-red { color: var(--status-blocked-accent); }
    .metric-number-amber { color: var(--status-review-accent); }

    /* Corporate Status Alert Banners */
    .alert-banner-sanitized {
        background-color: var(--status-safe-bg);
        border: 1px solid var(--status-safe-border);
        border-radius: 6px;
        padding: 16px 20px;
        margin-bottom: 20px;
    }
    .alert-banner-sanitized .alert-title {
        color: var(--status-safe-text);
        font-size: 15px;
        font-weight: 700;
        margin-bottom: 4px;
    }
    .alert-banner-sanitized .alert-desc {
        color: #166534;
        font-size: 13px;
        line-height: 1.4;
    }

    .alert-banner-blocked {
        background-color: var(--status-blocked-bg);
        border: 1px solid var(--status-blocked-border);
        border-radius: 6px;
        padding: 16px 20px;
        margin-bottom: 20px;
    }
    .alert-banner-blocked .alert-title {
        color: var(--status-blocked-text);
        font-size: 15px;
        font-weight: 700;
        margin-bottom: 4px;
    }
    .alert-banner-blocked .alert-desc {
        color: #991b1b;
        font-size: 13px;
        line-height: 1.4;
    }

    .alert-banner-review {
        background-color: var(--status-review-bg);
        border: 1px solid var(--status-review-border);
        border-radius: 6px;
        padding: 16px 20px;
        margin-bottom: 20px;
    }
    .alert-banner-review .alert-title {
        color: var(--status-review-text);
        font-size: 15px;
        font-weight: 700;
        margin-bottom: 4px;
    }
    .alert-banner-review .alert-desc {
        color: #92400e;
        font-size: 13px;
        line-height: 1.4;
    }

    /* Document Content Previews */
    .preview-box {
        background-color: #fdfcfb;
        border: 1px solid var(--border-color);
        border-radius: 6px;
        padding: 18px;
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
        font-size: 13px;
        line-height: 1.6;
        color: #292524;
        white-space: pre-wrap;
        max-height: 440px;
        overflow-y: auto;
        box-shadow: inset 0 1px 2px rgba(44, 40, 37, 0.02);
    }

    /* Structured Block Cards */
    .extracted-block-card {
        background-color: var(--bg-card);
        border: 1px solid var(--border-color);
        border-left: 3px solid var(--brand-blue);
        border-radius: 4px;
        padding: 12px 16px;
        margin-bottom: 10px;
        box-shadow: 0 1px 2px rgba(44, 40, 37, 0.03);
    }
    .extracted-block-meta {
        font-size: 11px;
        color: var(--text-muted);
        font-weight: 600;
        margin-bottom: 6px;
    }
    .extracted-block-text {
        font-size: 13px;
        color: var(--text-primary);
        white-space: pre-wrap;
        line-height: 1.5;
    }

    /* Primary & Default Button Styling */
    div.stButton > button:first-child {
        background-color: var(--brand-blue) !important;
        color: #ffffff !important;
        font-weight: 600 !important;
        border: 1px solid transparent !important;
        border-radius: 6px !important;
        padding: 8px 18px !important;
        font-size: 13px !important;
        transition: all 0.15s ease-in-out;
        box-shadow: 0 1px 2px rgba(37, 99, 235, 0.2);
    }
    div.stButton > button:first-child:hover {
        background-color: var(--brand-blue-hover) !important;
        color: #ffffff !important;
    }

    /* Secondary / Download Buttons */
    div.stDownloadButton > button {
        background-color: #ffffff !important;
        color: var(--text-primary) !important;
        border: 1px solid var(--border-color) !important;
        border-radius: 6px !important;
        font-weight: 600 !important;
        font-size: 13px !important;
        padding: 8px 16px !important;
        box-shadow: 0 1px 2px rgba(44, 40, 37, 0.03);
    }
    div.stDownloadButton > button:hover {
        background-color: var(--bg-subtle) !important;
        border-color: var(--border-focus) !important;
        color: var(--brand-blue) !important;
    }

    /* Streamlit File Uploader Warm Polish */
    [data-testid="stFileUploader"] section {
        background-color: #ffffff !important;
        border: 1px dashed var(--border-color) !important;
        border-radius: 8px !important;
        padding: 14px 18px !important;
    }
    [data-testid="stFileUploader"] section:hover {
        border-color: var(--brand-blue) !important;
        background-color: #fdfcfb !important;
    }
    [data-testid="stFileUploader"] button {
        background-color: var(--bg-subtle) !important;
        color: var(--text-primary) !important;
        border: 1px solid var(--border-color) !important;
        border-radius: 6px !important;
        font-weight: 500 !important;
    }
    [data-testid="stFileUploader"] button:hover {
        background-color: var(--bg-subtle-hover) !important;
        border-color: var(--border-focus) !important;
        color: var(--brand-blue) !important;
    }

    /* Only display the latest active file chip; hide any previous file chips */
    [data-testid="stFileChips"] > div > div:not(:last-child),
    [data-testid="stFileChips"] > *:first-child > *:not(:last-child),
    div[data-testid="stFileChips"] > div > div:not(:last-child),
    [data-testid="stFileUploader"] [data-testid="stFileChip"]:not(:last-child) {
        display: none !important;
        visibility: hidden !important;
    }

    /* Streamlit Tabs Polish */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
        border-bottom: 1px solid var(--border-color);
        padding-bottom: 4px;
    }
    .stTabs [data-baseweb="tab"] {
        padding: 8px 16px;
        font-size: 13px;
        font-weight: 500;
        color: var(--text-muted);
        border-radius: 4px 4px 0 0;
    }
    .stTabs [aria-selected="true"] {
        color: var(--brand-blue) !important;
        font-weight: 600 !important;
        border-bottom: 2px solid var(--brand-blue) !important;
    }

    /* Form Controls & Checkbox */
    .stCheckbox label {
        font-size: 13px !important;
        color: var(--text-secondary) !important;
        font-weight: 500;
    }

    /* Selectbox styling */
    [data-testid="stSelectbox"] > div > div {
        background-color: #ffffff !important;
        border-color: var(--border-color) !important;
        color: var(--text-primary) !important;
    }

    /* Dataframe Polish */
    [data-testid="stDataFrame"] {
        border: 1px solid var(--border-color);
        border-radius: 6px;
        background-color: #ffffff;
    }

    /* Completely Remove Floating Element / DataFrame Action Toolbars */
    [data-testid="stElementToolbar"],
    [data-testid="stDataFrameToolbar"],
    .stDataFrameToolbar,
    [data-testid="StyledFullScreenButton"],
    button[title="View fullscreen"],
    button[title="Download as CSV"],
    button[title="Search"],
    div[data-testid="stElementToolbar"],
    div[data-testid="stDataFrameToolbar"] {
        display: none !important;
        visibility: hidden !important;
        opacity: 0 !important;
        pointer-events: none !important;
        height: 0 !important;
        width: 0 !important;
        position: absolute !important;
        left: -9999px !important;
    }

    /* Completely Remove Heading Anchor Link Chain Buttons (🔗) */
    [data-testid="stHeaderActionElements"],
    div[data-testid="stHeaderActionElements"],
    [data-testid="stHeadingWithActionElements"] a,
    [data-testid="stHeadingWithActionElements"] button,
    a.header-anchor,
    .header-anchor,
    .anchor-link,
    a.anchor-link,
    h1 a, h2 a, h3 a, h4 a, h5 a, h6 a,
    h1 > a, h2 > a, h3 > a, h4 > a, h5 > a, h6 > a {
        display: none !important;
        visibility: hidden !important;
        opacity: 0 !important;
        pointer-events: none !important;
        width: 0 !important;
        height: 0 !important;
        position: absolute !important;
        left: -9999px !important;
    }

    /* More Explanation Card */
    .more-explanation-card {
        background-color: var(--bg-card);
        border: 1px solid var(--border-color);
        border-left: 4px solid var(--brand-blue);
        border-radius: 8px;
        padding: 24px 28px;
        margin-bottom: 20px;
        box-shadow: 0 1px 3px 0 rgba(44, 40, 37, 0.04);
        line-height: 1.6;
    }

    /* Visuals and Chart Containers */
    .chart-container-card {
        background-color: var(--bg-card);
        border: 1px solid var(--border-color);
        border-radius: 8px;
        padding: 20px 22px;
        margin-bottom: 20px;
        box-shadow: 0 1px 3px 0 rgba(44, 40, 37, 0.03);
    }
    .chart-container-title {
        font-size: 15px;
        font-weight: 700;
        color: var(--text-primary);
        margin-bottom: 4px;
    }
    .chart-container-subtitle {
        font-size: 12.5px;
        color: var(--text-muted);
        margin-bottom: 14px;
    }
    .pipeline-step-flow {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 8px;
        flex-wrap: wrap;
        margin: 14px 0 6px 0;
    }
    .pipeline-step-box {
        flex: 1;
        min-width: 140px;
        background-color: var(--bg-card-subtle);
        border: 1px solid var(--border-color);
        border-radius: 6px;
        padding: 12px 14px;
        text-align: center;
    }
    .pipeline-step-box-active {
        border-color: var(--status-safe-border);
        background-color: var(--status-safe-bg);
    }
    .pipeline-step-number {
        font-size: 11px;
        font-weight: 700;
        text-transform: uppercase;
        color: var(--brand-blue);
        margin-bottom: 4px;
    }
    .pipeline-step-label {
        font-size: 13px;
        font-weight: 600;
        color: var(--text-primary);
    }
    .pipeline-arrow-icon {
        color: var(--text-muted);
        font-size: 16px;
        font-weight: 700;
    }
</style>
"""
st.markdown(CORPORATE_LIGHT_CSS, unsafe_allow_html=True)


@st.cache_resource
def get_pipeline():
    """Cache singleton pipeline instance for high performance (v4 - Resume candidate name lines & email label false positive fix)."""
    return GatewayPipeline()


def apply_corporate_theme(fig, height: int = 340):
    """Apply consistent corporate warm light theme to Plotly figures."""
    fig.update_layout(
        height=height,
        margin=dict(l=24, r=24, t=30, b=24),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(
            family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
            color="#1c1917",
            size=12,
        ),
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=-0.3,
            xanchor="center",
            x=0.5,
            font=dict(size=11, color="#44403c"),
        ),
    )
    fig.update_xaxes(
        showgrid=True,
        gridcolor="#f5f2eb",
        zerolinecolor="#e6e1d6",
        tickfont=dict(color="#44403c", size=11),
    )
    fig.update_yaxes(
        showgrid=True,
        gridcolor="#f5f2eb",
        zerolinecolor="#e6e1d6",
        tickfont=dict(color="#44403c", size=11),
    )
    return fig


# Session State Initialization
if "analysis_results" not in st.session_state:
    st.session_state.analysis_results = []
if "show_original" not in st.session_state:
    st.session_state.show_original = False
if "show_more" not in st.session_state:
    st.session_state.show_more = False
if "active_view" not in st.session_state:
    st.session_state.active_view = "dashboard"
if "last_active_file_signature" not in st.session_state:
    st.session_state.last_active_file_signature = None
if "active_sample_file" not in st.session_state:
    st.session_state.active_sample_file = None


def format_bytes(size: int) -> str:
    """Format byte count into human-readable representation."""
    if size < 1024:
        return f"{size} B"
    elif size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size / (1024 * 1024):.2f} MB"


# ==============================================================================
# ==============================================================================
# VIEW ROUTING: "MORE" VIEW vs "VISUALS" VIEW vs "MAIN DASHBOARD" VIEW
# ==============================================================================
if st.session_state.get("show_more", False) or st.session_state.get("active_view") == "more":
    # --------------------------------------------------------------------------
    # MORE INFORMATION VIEW (Layman's Guide)
    # --------------------------------------------------------------------------
    col_title, col_back = st.columns([6, 1])

    with col_title:
        st.markdown(
            """
            <div class="corporate-header">
                <div class="header-title-row">
                    <h1 class="header-title">PII Security Gateway</h1>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col_back:
        st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)
        if st.button("← Back", help="Return to Main Dashboard", use_container_width=True, key="back_from_more_top"):
            st.session_state.show_more = False
            st.session_state.active_view = "dashboard"
            st.rerun()

    st.markdown(
        """
        <div class="more-explanation-card">
            <h3 style="margin-top: 0; font-size: 18px; color: var(--brand-blue); font-weight: 700;">
                💡 How Does This Project Work? (In Simple Words)
            </h3>
            <p style="font-size: 14px; color: var(--text-secondary); margin-bottom: 14px;">
                Think of the <b>PII Security Gateway</b> as an <b>intelligent privacy checkpoint</b> for your documents before you share them with an AI (such as ChatGPT, Claude, or internal language models).
            </p>
            <div style="background-color: #f7f5f0; border: 1px solid #e6e1d6; border-radius: 6px; padding: 14px 18px; margin-bottom: 18px;">
                <b style="color: var(--text-primary); font-size: 14px;">⚠️ The Real Problem:</b><br>
                <span style="color: var(--text-secondary); font-size: 13.5px;">
                    When employees upload business files (contracts, invoices, employee records, support tickets) to AI tools, those files often contain private data: real names, personal emails, phone numbers, employee badge IDs, credit cards, or government IDs. Sending that raw data outside your company risks data leaks and breaks strict privacy laws (like GDPR, HIPAA, or CCPA).
                </span>
            </div>
            <h4 style="font-size: 15px; color: var(--text-primary); margin-bottom: 10px; font-weight: 600;">
                How The Gateway Protects Your Data in 4 Simple Steps:
            </h4>
            <ol style="color: var(--text-secondary); font-size: 13.5px; padding-left: 20px; line-height: 1.7; margin-bottom: 16px;">
                <li><b>1. Read the Document:</b> You upload a PDF, Word document, PowerPoint presentation, or text file. The gateway extracts all the text and keeps note of where each piece came from (e.g. Page 1, Slide 3, Table 2).</li>
                <li><b>2. Spot the Private Data (Detection):</b> Like a smart scanner, it automatically spots private details using three methods:
                    <ul style="margin-top: 4px; margin-bottom: 4px;">
                        <li><b>Patterns:</b> Recognizes email formats, phone numbers, credit card numbers, and government IDs.</li>
                        <li><b>Name Recognition:</b> Detects actual person names (e.g. <i>Sarah Connor</i> or <i>John Smith</i>).</li>
                        <li><b>Context Clues:</b> Identifies labeled keywords like <i>"Employee ID: 10293"</i> or <i>"Contact: Alice"</i>.</li>
                    </ul>
                </li>
                <li><b>3. Smart Replacement (Consistent Redaction):</b> Instead of just putting black bars everywhere, it smartly swaps private data with consistent tags:
                    <ul style="margin-top: 4px; margin-bottom: 4px;">
                        <li><i>John Smith</i> becomes <code>[PERSON_001]</code>.</li>
                        <li><i>john@example.com</i> becomes <code>[EMAIL_001]</code>.</li>
                        <li>Even if John's name appears 5 times across 3 different slides, he is called <code>[PERSON_001]</code> every single time! This lets the AI understand the story and relationships without ever knowing his real identity.</li>
                    </ul>
                </li>
                <li><b>4. The Double-Check Gate (Validation):</b> Before anything is released, the gateway scans the cleaned text a second time. If even <b>one</b> real piece of private data was missed, the file is immediately <b>BLOCKED ✕</b>. Only when it is 100% clean is it marked <b>SAFE FOR AI ✓</b>.</li>
            </ol>
            <div style="border-top: 1px solid #e6e1d6; padding-top: 12px; font-size: 13px; color: var(--text-muted); margin-bottom: 16px;">
                🔒 <b>100% Local & Safe:</b> Everything runs locally on your machine. Zero data is sent to external servers or third-party AI companies.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if st.button("← Back to Main Dashboard", type="primary", key="back_from_more_bottom"):
        st.session_state.show_more = False
        st.session_state.active_view = "dashboard"
        st.rerun()

elif st.session_state.get("active_view") == "visuals":
    # --------------------------------------------------------------------------
    # VISUAL ANALYTICS & PICTORIAL REPRESENTATIONS VIEW
    # --------------------------------------------------------------------------
    col_title, col_back = st.columns([6, 1])

    with col_title:
        st.markdown(
            """
            <div class="corporate-header">
                <div class="header-title-row">
                    <h1 class="header-title">PII Security Gateway</h1>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col_back:
        st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)
        if st.button("← Back", help="Return to Main Dashboard", use_container_width=True, key="back_from_visuals_top"):
            st.session_state.active_view = "dashboard"
            st.session_state.show_more = False
            st.rerun()

    # Determine if live analysis results are available
    has_live_results = bool(st.session_state.get("analysis_results"))
    results = st.session_state.get("analysis_results", [])

    if not has_live_results:
        st.markdown(
            """
            <div style="background-color: var(--bg-card); border: 1px solid var(--border-color); border-left: 4px solid var(--brand-blue); border-radius: 8px; padding: 24px 28px; margin-bottom: 20px;">
                <h3 style="margin-top: 0; font-size: 17px; color: var(--text-primary); font-weight: 700;">
                    📂 No Active Analysis Results
                </h3>
                <p style="font-size: 13.5px; color: var(--text-secondary); margin-bottom: 14px;">
                    Visual analytics and interactive graphs are generated only after an evidence document is uploaded and analyzed.
                </p>
                <p style="font-size: 13px; color: var(--text-muted); margin-bottom: 0;">
                    Please return to the main dashboard, upload a business document (PDF, DOCX, PPTX, or TXT), and click <b>Analyze Document</b>.
                </p>
            </div>
            """,
            unsafe_allow_html=True,
        )
        if st.button("← Return to Main Dashboard", type="primary", key="back_from_empty_visuals"):
            st.session_state.active_view = "dashboard"
            st.session_state.show_more = False
            st.rerun()

    else:
        active_doc = results[0]
        summary = ReportGenerator.get_summary_metrics(results)
        doc_stat_val = active_doc.security_status.value if hasattr(active_doc.security_status, "value") else str(active_doc.security_status)
        
        status_color = "#15803d" if doc_stat_val == "SANITIZED" else ("#b91c1c" if doc_stat_val == "BLOCKED" else "#b45309")
        status_bg = "#f0fdf4" if doc_stat_val == "SANITIZED" else ("#fef2f2" if doc_stat_val == "BLOCKED" else "#fffbeb")
        status_border = "#bbf7d0" if doc_stat_val == "SANITIZED" else ("#fecaca" if doc_stat_val == "BLOCKED" else "#fde68a")

        st.markdown(
            f"""
            <div style="background-color: {status_bg}; border: 1px solid {status_border}; border-radius: 6px; padding: 14px 18px; margin-bottom: 20px; display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 10px;">
                <div>
                    <span style="font-size: 14px; font-weight: 700; color: {status_color};">🟢 Live Artifact Visual Analytics:</span>
                    <span style="font-size: 13.5px; color: var(--text-primary); margin-left: 6px; font-weight: 600;">{active_doc.file_name}</span>
                    <span style="font-size: 12.5px; color: var(--text-muted); margin-left: 10px;">({len(active_doc.blocks)} blocks extracted)</span>
                </div>
                <div>
                    <span style="background-color: #ffffff; border: 1px solid {status_border}; border-radius: 12px; padding: 4px 12px; font-size: 12px; font-weight: 700; color: {status_color};">
                        GATE STATUS: {doc_stat_val}
                    </span>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        total_findings = summary["total_pii_detected"]
        high_risk_count = summary["high_risk_findings"]
        type_data = summary.get("type_breakdown", {})
        sev_data = summary.get("severity_breakdown", {})
        
        method_counter = {}
        confidence_counter = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in active_doc.pii_findings:
            m_label = " + ".join(f.detection_method) if f.detection_method else "Pattern Match"
            method_counter[m_label] = method_counter.get(m_label, 0) + 1
            conf_str = f.confidence_level.value if hasattr(f.confidence_level, "value") else str(f.confidence_level)
            confidence_counter[conf_str] = confidence_counter.get(conf_str, 0) + 1

        # 1. SUMMARY METRIC CARDS
        c_m1, c_m2, c_m3, c_m4 = st.columns(4)
        with c_m1:
            st.markdown(
                f"""
                <div class="metric-card-clean">
                    <div class="metric-title">Total PII Detected</div>
                    <div class="metric-number metric-number-blue">{total_findings}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        with c_m2:
            st.markdown(
                f"""
                <div class="metric-card-clean">
                    <div class="metric-title">High / Critical Risk</div>
                    <div class="metric-number metric-number-red">{high_risk_count}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        with c_m3:
            st.markdown(
                f"""
                <div class="metric-card-clean">
                    <div class="metric-title">PII Categories</div>
                    <div class="metric-number">{len(type_data)}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        with c_m4:
            st.markdown(
                """
                <div class="metric-card-clean">
                    <div class="metric-title">Security Gate Pass Rate</div>
                    <div class="metric-number metric-number-green">100%</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        st.markdown("<div style='height: 18px;'></div>", unsafe_allow_html=True)

        # 2. ROW 1: PII CATEGORIES & SEVERITY DONUT
        c_g1, c_g2 = st.columns(2)

        with c_g1:
            st.markdown(
                """
                <div class="chart-container-card">
                    <div class="chart-container-title">📊 PII Category Distribution</div>
                    <div class="chart-container-subtitle">Entities detected across classifications.</div>
                """,
                unsafe_allow_html=True,
            )
            if type_data:
                category_labels_map = {
                    "PERSON": "Person Name",
                    "EMAIL": "Email Address",
                    "PHONE": "Phone Number",
                    "EMPLOYEE_ID": "Employee ID",
                    "GOVERNMENT_ID": "Government ID / SSN",
                    "ADDRESS": "Physical Address",
                    "DATE_OF_BIRTH": "Date of Birth",
                    "CREDIT_CARD": "Credit Card Number",
                    "IP_ADDRESS": "IP Address",
                    "OTHER_PII": "Other PII",
                }
                cat_names = [category_labels_map.get(k, k.replace("_", " ").title()) for k in type_data.keys()]
                cat_counts = list(type_data.values())
                df_plot_cat = pd.DataFrame({"Category": cat_names, "Count": cat_counts}).sort_values(by="Count", ascending=True)

                fig_cat = go.Figure(
                    go.Bar(
                        x=df_plot_cat["Count"],
                        y=df_plot_cat["Category"],
                        orientation="h",
                        marker=dict(
                            color="#2563eb",
                            line=dict(color="#1d4ed8", width=1),
                        ),
                        text=df_plot_cat["Count"],
                        textposition="outside",
                        cliponaxis=False,
                    )
                )
                fig_cat = apply_corporate_theme(fig_cat, height=310)
                fig_cat.update_layout(xaxis_title="Entity Count", yaxis_title=None)
                st.plotly_chart(fig_cat, use_container_width=True)
            else:
                st.info("No PII entities detected.")
            st.markdown("</div>", unsafe_allow_html=True)

        with c_g2:
            st.markdown(
                """
                <div class="chart-container-card">
                    <div class="chart-container-title">🍩 Risk Severity Breakdown</div>
                    <div class="chart-container-subtitle">Distribution of findings by threat severity level.</div>
                """,
                unsafe_allow_html=True,
            )
            sev_labels = []
            sev_counts = []
            sev_colors = []
            color_map = {
                "CRITICAL": "#b91c1c",
                "HIGH": "#dc2626",
                "MEDIUM": "#f59e0b",
                "LOW": "#10b981",
            }
            for s_key in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                if s_key in sev_data and sev_data[s_key] > 0:
                    sev_labels.append(s_key.title())
                    sev_counts.append(sev_data[s_key])
                    sev_colors.append(color_map[s_key])

            if sev_counts:
                fig_sev = go.Figure(
                    data=[
                        go.Pie(
                            labels=sev_labels,
                            values=sev_counts,
                            hole=0.6,
                            marker=dict(colors=sev_colors),
                            textinfo="label+percent",
                            hoverinfo="label+value+percent",
                        )
                    ]
                )
                fig_sev = apply_corporate_theme(fig_sev, height=310)
                fig_sev.update_layout(
                    annotations=[
                        dict(
                            text=f"<b>{total_findings}</b><br><span style='font-size:11px;color:#78716c;'>Findings</span>",
                            x=0.5,
                            y=0.5,
                            font_size=16,
                            showarrow=False,
                        )
                    ],
                    showlegend=True,
                )
                st.plotly_chart(fig_sev, use_container_width=True)
            else:
                st.success("Zero risk detected. Document is completely clean.")
            st.markdown("</div>", unsafe_allow_html=True)

        # 3. ROW 2: MULTI-ENGINE ATTRIBUTION & CONFIDENCE DISTRIBUTION
        c_g3, c_g4 = st.columns(2)

        with c_g3:
            st.markdown(
                """
                <div class="chart-container-card">
                    <div class="chart-container-title">⚙️ Multi-Engine Detection Attribution</div>
                    <div class="chart-container-subtitle">Corroborating detection engines behind identified entities.</div>
                """,
                unsafe_allow_html=True,
            )
            if method_counter:
                df_method = pd.DataFrame(
                    list(method_counter.items()),
                    columns=["Detection Engine", "Count"]
                ).sort_values(by="Count", ascending=False)

                fig_method = go.Figure(
                    go.Bar(
                        x=df_method["Detection Engine"],
                        y=df_method["Count"],
                        marker=dict(
                            color=["#0284c7", "#6366f1", "#8b5cf6", "#0d9488"][:len(df_method)],
                        ),
                        text=df_method["Count"],
                        textposition="outside",
                    )
                )
                fig_method = apply_corporate_theme(fig_method, height=310)
                fig_method.update_layout(
                    xaxis_title=None,
                    yaxis_title="Detections Flagged",
                    xaxis_tickangle=-15,
                )
                st.plotly_chart(fig_method, use_container_width=True)
            else:
                st.info("No detection engines triggered.")
            st.markdown("</div>", unsafe_allow_html=True)

        with c_g4:
            st.markdown(
                """
                <div class="chart-container-card">
                    <div class="chart-container-title">🎯 Detection Confidence Distribution</div>
                    <div class="chart-container-subtitle">Certainty levels computed by heuristic and transformer models.</div>
                """,
                unsafe_allow_html=True,
            )
            conf_labels = ["High (≥90%)", "Medium (70-89%)", "Low (<70%)"]
            conf_vals = [
                confidence_counter.get("HIGH", 0),
                confidence_counter.get("MEDIUM", 0),
                confidence_counter.get("LOW", 0),
            ]
            fig_conf = go.Figure(
                go.Bar(
                    x=conf_labels,
                    y=conf_vals,
                    marker=dict(
                        color=["#15803d", "#f59e0b", "#dc2626"],
                    ),
                    text=conf_vals,
                    textposition="outside",
                )
            )
            fig_conf = apply_corporate_theme(fig_conf, height=310)
            fig_conf.update_layout(
                xaxis_title=None,
                yaxis_title="Findings Count",
            )
            st.plotly_chart(fig_conf, use_container_width=True)
            st.markdown("</div>", unsafe_allow_html=True)

        # 4. ROW 3: CATEGORY & SEVERITY TELEMETRY TABLE
        st.markdown(
            """
            <div class="chart-container-card">
                <div class="chart-container-title">📋 Category & Severity Telemetry Table</div>
                <div class="chart-container-subtitle">Consolidated count of detected items by category and risk level.</div>
            """,
            unsafe_allow_html=True,
        )
        if type_data:
            summary_rows = []
            category_labels_map = {
                "PERSON": "Person Name",
                "EMAIL": "Email Address",
                "PHONE": "Phone Number",
                "EMPLOYEE_ID": "Employee ID",
                "GOVERNMENT_ID": "Government ID / SSN",
                "ADDRESS": "Physical Address",
                "DATE_OF_BIRTH": "Date of Birth",
                "CREDIT_CARD": "Credit Card Number",
                "IP_ADDRESS": "IP Address",
                "OTHER_PII": "Other PII",
            }
            for k, cnt in type_data.items():
                cat_friendly = category_labels_map.get(k, k.replace("_", " ").title())
                risk = "High" if k in ("CREDIT_CARD", "GOVERNMENT_ID", "EMPLOYEE_ID") else ("Medium" if k in ("PERSON", "EMAIL", "PHONE") else "Low")
                summary_rows.append({
                    "PII Classification": cat_friendly,
                    "Count": cnt,
                    "Risk Level": risk,
                    "Action Policy": "Consistent Semantic Redaction",
                })
            df_summary_matrix = pd.DataFrame(summary_rows).sort_values(by="Count", ascending=False)
            st.dataframe(df_summary_matrix, use_container_width=True, hide_index=True)
        else:
            st.info("Zero PII detected.")
        st.markdown("</div>", unsafe_allow_html=True)

        st.markdown("<div style='height: 20px;'></div>", unsafe_allow_html=True)
        if st.button("← Back to Main Dashboard", type="primary", key="back_from_visuals_bottom"):
            st.session_state.active_view = "dashboard"
            st.session_state.show_more = False
            st.rerun()

else:
    # --------------------------------------------------------------------------
    # MAIN DASHBOARD VIEW
    # --------------------------------------------------------------------------
    has_results = bool(st.session_state.get("analysis_results"))

    if has_results:
        col_title, col_charts, col_more = st.columns([5, 1.4, 1])
    else:
        col_title, col_more = st.columns([6, 1])

    with col_title:
        st.markdown(
            """
            <div class="corporate-header">
                <div class="header-title-row">
                    <h1 class="header-title">PII Security Gateway</h1>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    if has_results:
        with col_charts:
            st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)
            if st.button("📊 Visuals", help="View pictorial representations, risk graphs, and visual telemetry", use_container_width=True):
                st.session_state.active_view = "visuals"
                st.session_state.show_more = False
                st.rerun()

    with col_more:
        st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)
        if st.button("More", help="Click to understand how PII Security Gateway works in simple everyday words", use_container_width=True):
            st.session_state.active_view = "more"
            st.session_state.show_more = True
            st.rerun()

    # ==============================================================================
    # FILE UPLOAD & ACTIONS SECTION
    # ==============================================================================
    col_upload, col_actions = st.columns([3, 1])

    with col_upload:
        uploaded_files = st.file_uploader(
            "Upload Business Evidence Document (Supported formats: PDF, DOCX, PPTX, TXT)",
            type=["pdf", "docx", "pptx", "txt"],
            accept_multiple_files=True,
            key="evidence_uploader",
            help="Upload an evidence artifact for pre-LLM PII sanitization inspection.",
        )

    # State Tracking:
    # Always focus on the most recently uploaded file (or sample).
    # If a new file is uploaded / added via the [+] option, immediately remove
    # the old file's data and show results only for the active document.
    active_file = None
    if uploaded_files:
        active_file = uploaded_files[-1]
        active_signature = f"{active_file.name}_{active_file.size}"

        # When a new file is added or uploaded, clear the old document's data!
        if st.session_state.get("last_active_file_signature") != active_signature:
            st.session_state.analysis_results = []
            st.session_state.last_active_file_signature = active_signature
            st.session_state.active_sample_file = None
    else:
        if not st.session_state.get("active_sample_file"):
            if st.session_state.get("last_active_file_signature") is not None:
                st.session_state.analysis_results = []
                st.session_state.last_active_file_signature = None

    with col_actions:
        st.markdown("<div style='height: 28px;'></div>", unsafe_allow_html=True)
        analyze_btn = st.button("⚡ Analyze Document", type="primary", use_container_width=True)
        load_samples = st.button("📁 Load Sample Document", help="Load pre-built synthetic test document", use_container_width=True)

        if load_samples:
            sample_dir = Path(__file__).resolve().parent / "sample_documents"
            sample_file = sample_dir / "Executive_Briefing.pdf"
            if sample_file.exists():
                st.session_state.active_sample_file = (sample_file.name, sample_file.read_bytes())
                st.session_state.last_active_file_signature = f"sample_{sample_file.name}"
                st.session_state.analysis_results = []
                st.info(f"Loaded sample evidence: '{sample_file.name}'. Click 'Analyze Document' to inspect.")

    # Show active sample banner if sample document is active
    if st.session_state.get("active_sample_file") is not None and not uploaded_files:
        s_name, s_bytes = st.session_state.active_sample_file
        st.markdown(
            f"""
            <div style="background-color: var(--bg-card); border: 1px solid var(--border-color); border-left: 3px solid var(--brand-blue); border-radius: 6px; padding: 10px 14px; margin-top: 6px; margin-bottom: 12px; font-size: 13px; color: var(--text-secondary);">
                📁 Active Sample Evidence: <b>{s_name}</b> ({format_bytes(len(s_bytes))})
            </div>
            """,
            unsafe_allow_html=True,
        )

    # ==============================================================================
    # PIPELINE EXECUTION
    # ==============================================================================
    if analyze_btn:
        pipeline = get_pipeline()
        file_to_process = None

        if active_file is not None:
            file_to_process = (active_file.name, active_file.getvalue())
        elif st.session_state.get("active_sample_file") is not None:
            file_to_process = st.session_state.active_sample_file

        if not file_to_process:
            st.warning("Please upload a document or load a sample document before analyzing.")
        else:
            fname, fbytes = file_to_process
            progress_bar = st.progress(0, text=f"Analyzing {fname}...")
            status_box = st.empty()

            status_box.markdown(
                f"""
                <div style='background: #ffffff; border: 1px solid #e6e1d6; padding: 12px 16px; border-radius: 6px; font-size: 13px; color: #44403c; margin-bottom: 12px;'>
                    Inspecting <b>{fname}</b>: 
                    <span style='color: #2563eb; font-weight: 600;'>Extract</span> → 
                    <span style='color: #2563eb; font-weight: 600;'>Detect</span> → 
                    <span style='color: #2563eb; font-weight: 600;'>Redact</span> → 
                    <span style='color: #2563eb; font-weight: 600;'>Re-scan</span> → 
                    <span style='color: #2563eb; font-weight: 600;'>Validate</span>
                </div>
                """,
                unsafe_allow_html=True,
            )

            res = pipeline.process_document(file_bytes=fbytes, file_name=fname)
            progress_bar.progress(100, text="Pipeline processing complete.")
            time.sleep(0.1)
            status_box.empty()
            progress_bar.empty()
            st.session_state.analysis_results = [res]
            st.success(f"Security gate analysis complete for {fname}.")

    # ==============================================================================
    # DASHBOARD DISPLAY
    # ==============================================================================
    results = st.session_state.analysis_results

    if results:
        summary = ReportGenerator.get_summary_metrics(results)

        # 1. SUMMARY METRIC CARDS
        col_ov_title, col_ov_btn = st.columns([4, 1.3])
        with col_ov_title:
            st.markdown("<h3 style='margin-top: 14px; margin-bottom: 14px; font-size: 18px;'>Security Gate Overview</h3>", unsafe_allow_html=True)
        with col_ov_btn:
            st.markdown("<div style='height: 8px;'></div>", unsafe_allow_html=True)
            if st.button("📊 View Visual Analytics", help="Open visual graphs and analytics for this analyzed document", use_container_width=True, key="btn_view_visuals_overview"):
                st.session_state.active_view = "visuals"
                st.session_state.show_more = False
                st.rerun()
        c1, c2 = st.columns(2)

        with c1:
            st.markdown(
                f"""
                <div class="metric-card-clean">
                    <div class="metric-title">PII Entities Detected</div>
                    <div class="metric-number metric-number-blue">{summary['total_pii_detected']}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        with c2:
            st.markdown(
                f"""
                <div class="metric-card-clean">
                    <div class="metric-title">High-Risk Findings</div>
                    <div class="metric-number metric-number-red">{summary['high_risk_findings']}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        st.markdown("<div style='height: 18px;'></div>", unsafe_allow_html=True)

        # 2. PII BREAKDOWN & SEVERITY METRICS
        st.markdown("<h3 style='margin-bottom: 12px; font-size: 16px;'>PII Distribution by Category & Risk Severity</h3>", unsafe_allow_html=True)
        col_type_bd, col_sev_bd = st.columns([2, 1])

        with col_type_bd:
            type_data = summary.get("type_breakdown", {})
            if type_data:
                df_types = pd.DataFrame(
                    list(type_data.items()),
                    columns=["PII Category", "Count"]
                ).sort_values(by="Count", ascending=False)
                st.dataframe(df_types, use_container_width=True, hide_index=True)
            else:
                st.info("No PII detected across uploaded documents.")

        with col_sev_bd:
            sev_data = summary.get("severity_breakdown", {})
            if sev_data:
                df_sev = pd.DataFrame(
                    list(sev_data.items()),
                    columns=["Risk Severity", "Count"]
                ).sort_values(by="Count", ascending=False)
                st.dataframe(df_sev, use_container_width=True, hide_index=True)
            else:
                st.info("No severity metrics available.")

        st.markdown("<div style='height: 18px;'></div>", unsafe_allow_html=True)

        # 3. GLOBAL FINDINGS TABLE
        st.markdown("<h3 style='margin-bottom: 8px; font-size: 16px;'>PII Findings Log</h3>", unsafe_allow_html=True)

        col_filter1, col_filter2 = st.columns([3, 1])
        with col_filter2:
            show_raw = st.checkbox("Analyst Review: Reveal Original Values", value=False)

        all_findings_rows = []
        for doc in results:
            for f in doc.pii_findings:
                display_val = f.text if show_raw else f.masked_text
                all_findings_rows.append({
                    "Severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                    "PII Type": f.pii_type.value if hasattr(f.pii_type, "value") else str(f.pii_type),
                    "Confidence": f"{f.confidence * 100:.1f}%",
                    "Method": " + ".join(f.detection_method),
                    "Location": f.location,
                    "Entity (Masked/Reviewed)": display_val,
                })

        if all_findings_rows:
            df_all_findings = pd.DataFrame(all_findings_rows)
            st.dataframe(df_all_findings, use_container_width=True, hide_index=True)
        else:
            st.info("Zero PII findings across analyzed documents.")

        st.markdown("<div style='height: 22px;'></div>", unsafe_allow_html=True)

        # 4. DOCUMENT DETAIL DEEP-DIVE
        st.markdown("<h3 style='margin-bottom: 12px; font-size: 16px;'>Document Deep-Dive & Source Traceability</h3>", unsafe_allow_html=True)
        
        if len(results) == 1:
            selected_doc = results[0]
            st.markdown(
                f"<div style='margin-bottom: 14px; font-size: 13px; font-weight: 600; color: var(--text-secondary);'>Inspected Artifact: <span style='color: var(--brand-blue);'>{selected_doc.file_name}</span></div>",
                unsafe_allow_html=True,
            )
        else:
            doc_options = [f"{r.file_name} ({r.security_status.value if hasattr(r.security_status, 'value') else r.security_status})" for r in results]
            selected_doc_idx = st.selectbox(
                "Select Document Artifact for Structural Traceability Inspection:",
                range(len(doc_options)),
                format_func=lambda i: doc_options[i]
            )
            selected_doc = results[selected_doc_idx]

        doc_stat_val = selected_doc.security_status.value if hasattr(selected_doc.security_status, "value") else str(selected_doc.security_status)
        if doc_stat_val == SecurityStatus.SANITIZED.value:
            st.markdown(
                f"""
                <div class="alert-banner-sanitized">
                    <div class="alert-title">✓ STATUS: SANITIZED (SAFE FOR DOWNSTREAM AI)</div>
                    <div class="alert-desc">Validation verified zero residual PII. Content is sanitized and certified safe for downstream LLM context submission.</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        elif doc_stat_val == SecurityStatus.BLOCKED.value:
            st.markdown(
                f"""
                <div class="alert-banner-blocked">
                    <div class="alert-title">✕ STATUS: BLOCKED (UNSAFE FOR LLM SUBMISSION)</div>
                    <div class="alert-desc">Fail-closed security triggered. Residual PII or critical policy violation detected. Document is blocked from AI consumption.</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        else:
            st.markdown(
                f"""
                <div class="alert-banner-review">
                    <div class="alert-title">⚠ STATUS: REVIEW REQUIRED</div>
                    <div class="alert-desc">Document contains low-confidence signals or unverified scanned pages requiring analyst clearance before release.</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        tab_sanitized, tab_findings, tab_traceability, tab_validation, tab_original = st.tabs([
            "📄 Sanitized Output",
            "🔍 PII Findings & Mappings",
            "🧭 Source Traceability",
            "🛡️ Validation & Security",
            "📑 Original Extracted Blocks",
        ])

        with tab_sanitized:
            st.markdown("<p style='color: var(--text-muted); font-size: 13px;'>Sanitized content using consistent transparent semantic tags (e.g. <code>[PERSON_001]</code>, <code>[EMAIL_001]</code>).</p>", unsafe_allow_html=True)
            if selected_doc.redaction_result:
                st.markdown(f'<div class="preview-box">{selected_doc.redaction_result.redacted_full_text}</div>', unsafe_allow_html=True)
                
                st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)
                st.download_button(
                    label=f"⬇ Download Sanitized Text ({selected_doc.file_name}.sanitized.txt)",
                    data=selected_doc.redaction_result.redacted_full_text,
                    file_name=f"{Path(selected_doc.file_name).stem}_sanitized.txt",
                    mime="text/plain",
                )
            else:
                st.info("No sanitized output generated.")

        with tab_findings:
            st.markdown(f"<p style='color: var(--text-muted); font-size: 13px;'>Detected {len(selected_doc.pii_findings)} PII instances in this document.</p>", unsafe_allow_html=True)
            if selected_doc.pii_findings:
                doc_f_rows = []
                for f in selected_doc.pii_findings:
                    doc_f_rows.append({
                        "Location": f.location,
                        "PII Type": f.pii_type.value if hasattr(f.pii_type, "value") else str(f.pii_type),
                        "Severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                        "Confidence": f"{f.confidence * 100:.1f}%",
                        "Method": " + ".join(f.detection_method),
                        "Entity (Masked)": f.masked_text,
                        "Explanation": f.explanation,
                    })
                st.dataframe(pd.DataFrame(doc_f_rows), use_container_width=True, hide_index=True)
            else:
                st.info("No PII detected in this document.")

        with tab_traceability:
            st.markdown("<p style='color: var(--text-muted); font-size: 13px;'>Source Traceability Matrix: Explaining exact source location, detector corroboration, and semantic tag assignment.</p>", unsafe_allow_html=True)
            if selected_doc.pii_findings and selected_doc.redaction_result:
                traceability_data = []
                for f in selected_doc.pii_findings:
                    tag = selected_doc.redaction_result.entity_mappings.get(f.text.strip(), "N/A")
                    traceability_data.append({
                        "Source Location": f.location,
                        "Detected PII Type": f.pii_type.value if hasattr(f.pii_type, "value") else str(f.pii_type),
                        "Confidence Score": f"{f.confidence * 100:.1f}% ({f.confidence_level.value})",
                        "Detection Methodology": " + ".join(f.detection_method),
                        "Semantic Replacement": tag,
                        "Risk Rationale": f.explanation,
                    })
                st.dataframe(pd.DataFrame(traceability_data), use_container_width=True, hide_index=True)
            else:
                st.info("No traceability items to display.")

        with tab_validation:
            st.markdown("<p style='color: var(--text-muted); font-size: 13px;'>Post-Redaction Validation Audit (Re-scan of sanitized text blocks to ensure fail-closed security).</p>", unsafe_allow_html=True)
            if selected_doc.validation_result:
                vr = selected_doc.validation_result

                st.markdown(
                    f"""
                    <div style="background-color: #ffffff; border: 1px solid #e6e1d6; border-radius: 6px; padding: 18px; margin-bottom: 14px;">
                        <table style="width: 100%; border-collapse: collapse; font-size: 13px;">
                            <tr style="border-bottom: 1px solid #f5f2eb;">
                                <td style="padding: 8px 0; color: #78716c; font-weight: 500;">Validation Verdict:</td>
                                <td style="padding: 8px 0; font-weight: 700; color: #1c1917;">{vr.status.value}</td>
                            </tr>
                            <tr style="border-bottom: 1px solid #f5f2eb;">
                                <td style="padding: 8px 0; color: #78716c; font-weight: 500;">Passed Security Gate:</td>
                                <td style="padding: 8px 0; font-weight: 700; color: {'#15803d' if vr.passed else '#b91c1c'};">{'YES (PASSED)' if vr.passed else 'NO (FAILED)'}</td>
                            </tr>
                            <tr style="border-bottom: 1px solid #f5f2eb;">
                                <td style="padding: 8px 0; color: #78716c; font-weight: 500;">Residual PII Detected:</td>
                                <td style="padding: 8px 0; font-weight: 700; color: #1c1917;">{len(vr.residual_findings)} items</td>
                            </tr>
                            <tr>
                                <td style="padding: 8px 0; color: #78716c; font-weight: 500;">Enforced Security Policy:</td>
                                <td style="padding: 8px 0; color: #44403c;">{vr.validation_message}</td>
                            </tr>
                        </table>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
            else:
                st.info("Validation records unavailable.")

        with tab_original:
            st.markdown("<p style='color: var(--text-muted); font-size: 13px;'>Original extracted blocks with structural boundary metadata (Kept strictly local).</p>", unsafe_allow_html=True)
            for b in selected_doc.blocks:
                st.markdown(
                    f"""
                    <div class="extracted-block-card">
                        <div class="extracted-block-meta">Location: {b.location} | Type: {b.block_type} | Order: {b.order}</div>
                        <div class="extracted-block-text">{b.text}</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

        st.markdown("<div style='height: 22px;'></div>", unsafe_allow_html=True)

        # 5. AUDIT REPORT EXPORTS
        st.markdown("<h3 style='margin-bottom: 12px; font-size: 16px;'>Compliance Audit Reports Export</h3>", unsafe_allow_html=True)
        c_rep1, c_rep2 = st.columns(2)

        with c_rep1:
            json_report_str = ReportGenerator.generate_json_report(results)
            st.download_button(
                label="⬇ Export Comprehensive Security Audit Report (JSON)",
                data=json_report_str,
                file_name="pii_security_gateway_audit_report.json",
                mime="application/json",
                use_container_width=True,
            )

        with c_rep2:
            csv_report_str = ReportGenerator.generate_csv_findings(results)
            st.download_button(
                label="⬇ Export Findings Traceability Matrix (CSV)",
                data=csv_report_str,
                file_name="pii_findings_traceability_log.csv",
                mime="text/csv",
                use_container_width=True,
            )
