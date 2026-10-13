"""PII Security Gateway - Pre-LLM Security Gateway & Document Sanitization Pipeline.

Enterprise Streamlit application providing local, explainable PII detection,
consistent semantic redaction, and fail-closed post-redaction validation.
Engineered for enterprise cybersecurity teams, SOC operations, and compliance auditors.
"""
import io
import time
from pathlib import Path
from typing import List, Dict, Optional, Any

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

# Enterprise SOC Cybersecurity Theme System CSS
ENTERPRISE_SOC_CSS = """
<style>
    /* CSS Variables: Enterprise Cybersecurity Palette */
    :root {
        --navy-darkest: #0B1220;      /* Header background & dark accents */
        --navy-surface: #142033;      /* Secondary dark surface */
        --brand-blue: #2563EB;        /* Primary action sapphire */
        --brand-blue-hover: #1D4ED8;  /* Primary button hover */
        --brand-blue-subtle: #EFF6FF; /* Blue tinted accents */
        --bg-page: #F4F6FA;           /* Crisp light background */
        --bg-card: #FFFFFF;           /* Crisp card surface */
        --border-card: #E2E8F0;       /* Neutral slate border */
        --border-hover: #CBD5E1;      /* Border hover state */
        --text-primary: #172033;      /* Primary text (Slate-900) */
        --text-secondary: #64748B;    /* Secondary text (Slate-500) */
        --text-muted: #94A3B8;        /* Muted text (Slate-400) */
        
        --status-safe-bg: #F0FDF4;    /* Green-50 */
        --status-safe-border: #BBF7D0;/* Green-200 */
        --status-safe-text: #166534;  /* Green-800 */
        --status-safe-accent: #16A34A;/* Green-600 */

        --status-blocked-bg: #FEF2F2; /* Red-50 */
        --status-blocked-border: #FECACA; /* Red-200 */
        --status-blocked-text: #991B1B; /* Red-800 */
        --status-blocked-accent: #DC2626; /* Red-600 */

        --status-review-bg: #FFFBEB;  /* Amber-50 */
        --status-review-border: #FDE68A; /* Amber-200 */
        --status-review-text: #92400E; /* Amber-800 */
        --status-review-accent: #D97706; /* Amber-600 */
    }

    /* Base Application Styling */
    .stApp {
        background-color: var(--bg-page) !important;
        color: var(--text-primary) !important;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    }

    .main .block-container {
        padding-top: 1.5rem !important;
        padding-bottom: 3rem !important;
        background-color: var(--bg-page) !important;
        max-width: 1400px;
    }

    h1, h2, h3, h4, h5, h6 {
        color: var(--text-primary) !important;
        font-weight: 600 !important;
        letter-spacing: -0.3px;
    }

    /* Enterprise SOC Header */
    .enterprise-header {
        background-color: var(--navy-darkest);
        border: 1px solid #1E293B;
        border-radius: 8px;
        padding: 18px 24px;
        margin-bottom: 22px;
        display: flex;
        align-items: center;
        justify-content: space-between;
        flex-wrap: wrap;
        gap: 16px;
        box-shadow: 0 4px 6px -1px rgba(11, 18, 32, 0.12), 0 2px 4px -2px rgba(11, 18, 32, 0.08);
    }
    .header-left {
        display: flex;
        align-items: center;
        gap: 14px;
    }
    .header-brand-icon {
        font-size: 28px;
        line-height: 1;
        display: flex;
        align-items: center;
        justify-content: center;
        width: 44px;
        height: 44px;
        background: #142033;
        border: 1px solid #1E293B;
        border-radius: 8px;
    }
    .header-title {
        color: #FFFFFF !important;
        font-size: 22px;
        font-weight: 700;
        letter-spacing: -0.4px;
        line-height: 1.2;
        margin: 0;
    }
    .header-subtitle {
        color: #94A3B8;
        font-size: 13px;
        font-weight: 400;
        margin-top: 3px;
        letter-spacing: 0.1px;
    }
    .header-right {
        display: flex;
        align-items: center;
        gap: 12px;
        flex-wrap: wrap;
    }
    .status-indicator-pill {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        padding: 6px 14px;
        border-radius: 20px;
        font-size: 12px;
        font-weight: 600;
        letter-spacing: 0.3px;
        background-color: #142033;
        border: 1px solid #1E293B;
        color: #E2E8F0;
    }
    .status-indicator-pill.status-idle {
        border-color: #334155;
        color: #94A3B8;
    }
    .status-indicator-pill.status-staged {
        border-color: #2563EB;
        color: #93C5FD;
        background-color: rgba(37, 99, 235, 0.18);
    }
    .status-indicator-pill.status-sanitized {
        border-color: #16A34A;
        color: #86EFAC;
        background-color: rgba(22, 163, 74, 0.18);
    }
    .status-indicator-pill.status-review {
        border-color: #D97706;
        color: #FDE68A;
        background-color: rgba(217, 119, 6, 0.18);
    }
    .status-indicator-pill.status-blocked {
        border-color: #DC2626;
        color: #FCA5A5;
        background-color: rgba(220, 38, 38, 0.18);
    }
    .status-dot {
        width: 8px;
        height: 8px;
        border-radius: 50%;
        display: inline-block;
    }
    .dot-idle { background-color: #94A3B8; }
    .dot-staged { background-color: #3B82F6; box-shadow: 0 0 6px rgba(59, 130, 246, 0.6); }
    .dot-sanitized { background-color: #22C55E; box-shadow: 0 0 6px rgba(34, 197, 94, 0.6); }
    .dot-review { background-color: #F59E0B; box-shadow: 0 0 6px rgba(245, 158, 11, 0.6); }
    .dot-blocked { background-color: #EF4444; box-shadow: 0 0 6px rgba(239, 68, 68, 0.6); }

    /* Compact Enterprise Metric Cards */
    .metric-card-soc {
        background-color: var(--bg-card);
        border: 1px solid var(--border-card);
        border-radius: 8px;
        padding: 16px 20px;
        box-shadow: 0 1px 3px 0 rgba(11, 18, 32, 0.04);
        height: 100%;
        display: flex;
        flex-direction: column;
        justify-content: space-between;
        transition: border-color 0.15s ease, box-shadow 0.15s ease;
    }
    .metric-card-soc:hover {
        border-color: var(--border-hover);
        box-shadow: 0 2px 5px 0 rgba(11, 18, 32, 0.06);
    }
    .metric-top-row {
        display: flex;
        align-items: center;
        justify-content: space-between;
        margin-bottom: 8px;
    }
    .metric-card-label {
        font-size: 11px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.6px;
        color: var(--text-secondary);
    }
    .metric-card-icon {
        font-size: 15px;
        color: var(--text-muted);
    }
    .metric-card-value {
        font-size: 30px;
        font-weight: 700;
        line-height: 1.1;
        color: var(--text-primary);
        margin-bottom: 6px;
    }
    .metric-card-subtext {
        font-size: 12px;
        color: var(--text-muted);
        font-weight: 500;
    }
    .val-blue { color: var(--brand-blue); }
    .val-green { color: var(--status-safe-accent); }
    .val-red { color: var(--status-blocked-accent); }
    .val-amber { color: var(--status-review-accent); }

    /* Active Artifact Card */
    .artifact-active-card {
        background-color: var(--bg-card);
        border: 1px solid var(--border-card);
        border-left: 4px solid var(--brand-blue);
        border-radius: 6px;
        padding: 12px 18px;
        margin-top: 10px;
        margin-bottom: 16px;
        display: flex;
        align-items: center;
        justify-content: space-between;
        flex-wrap: wrap;
        gap: 12px;
        box-shadow: 0 1px 2px rgba(11, 18, 32, 0.03);
    }
    .artifact-active-left {
        display: flex;
        align-items: center;
        gap: 12px;
    }
    .artifact-ext-badge {
        background-color: var(--brand-blue-subtle);
        color: var(--brand-blue);
        border: 1px solid #BFDBFE;
        font-size: 11px;
        font-weight: 700;
        text-transform: uppercase;
        padding: 4px 8px;
        border-radius: 4px;
        letter-spacing: 0.5px;
    }
    .artifact-meta-title {
        font-size: 13.5px;
        font-weight: 600;
        color: var(--text-primary);
    }
    .artifact-meta-details {
        font-size: 12px;
        color: var(--text-secondary);
        margin-top: 2px;
    }

    /* Pipeline 4-Stage Stepper */
    .pipeline-stepper-box {
        background-color: var(--bg-card);
        border: 1px solid var(--border-card);
        border-radius: 8px;
        padding: 18px 22px;
        margin-bottom: 20px;
        box-shadow: 0 1px 3px 0 rgba(11, 18, 32, 0.03);
    }
    .stepper-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        margin-bottom: 14px;
        border-bottom: 1px solid #F1F5F9;
        padding-bottom: 10px;
    }
    .stepper-title {
        font-size: 13px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.6px;
        color: var(--text-primary);
    }
    .stepper-meta {
        font-size: 12px;
        color: var(--text-secondary);
        font-weight: 500;
    }
    .pipeline-step-grid {
        display: grid;
        grid-template-columns: repeat(4, 1fr);
        gap: 12px;
    }
    @media (max-width: 900px) {
        .pipeline-step-grid {
            grid-template-columns: 1fr 1fr;
        }
    }
    .stage-item {
        background-color: #F8FAFC;
        border: 1px solid var(--border-card);
        border-radius: 6px;
        padding: 12px 14px;
        text-align: left;
    }
    .stage-item.stage-passed {
        background-color: #F0FDF4;
        border-color: #BBF7D0;
    }
    .stage-item.stage-failed {
        background-color: #FEF2F2;
        border-color: #FECACA;
    }
    .stage-item.stage-review {
        background-color: #FFFBEB;
        border-color: #FDE68A;
    }
    .stage-num {
        font-size: 11px;
        font-weight: 700;
        color: var(--brand-blue);
        text-transform: uppercase;
        letter-spacing: 0.5px;
        margin-bottom: 4px;
    }
    .stage-passed .stage-num { color: var(--status-safe-accent); }
    .stage-failed .stage-num { color: var(--status-blocked-accent); }
    .stage-review .stage-num { color: var(--status-review-accent); }
    .stage-name {
        font-size: 13px;
        font-weight: 600;
        color: var(--text-primary);
        margin-bottom: 2px;
    }
    .stage-detail {
        font-size: 11.5px;
        color: var(--text-secondary);
    }

    /* Security Gate Verdict Banners */
    .verdict-banner {
        border-radius: 8px;
        padding: 16px 20px;
        margin-bottom: 22px;
        display: flex;
        align-items: flex-start;
        gap: 14px;
    }
    .verdict-banner.verdict-sanitized {
        background-color: var(--status-safe-bg);
        border: 1px solid var(--status-safe-border);
    }
    .verdict-banner.verdict-sanitized .verdict-title {
        color: var(--status-safe-text);
        font-size: 15px;
        font-weight: 700;
        margin-bottom: 4px;
    }
    .verdict-banner.verdict-sanitized .verdict-desc {
        color: #166534;
        font-size: 13px;
        line-height: 1.5;
    }

    .verdict-banner.verdict-blocked {
        background-color: var(--status-blocked-bg);
        border: 1px solid var(--status-blocked-border);
    }
    .verdict-banner.verdict-blocked .verdict-title {
        color: var(--status-blocked-text);
        font-size: 15px;
        font-weight: 700;
        margin-bottom: 4px;
    }
    .verdict-banner.verdict-blocked .verdict-desc {
        color: #991B1B;
        font-size: 13px;
        line-height: 1.5;
    }

    .verdict-banner.verdict-review {
        background-color: var(--status-review-bg);
        border: 1px solid var(--status-review-border);
    }
    .verdict-banner.verdict-review .verdict-title {
        color: var(--status-review-text);
        font-size: 15px;
        font-weight: 700;
        margin-bottom: 4px;
    }
    .verdict-banner.verdict-review .verdict-desc {
        color: #92400E;
        font-size: 13px;
        line-height: 1.5;
    }

    .verdict-icon {
        font-size: 20px;
        line-height: 1.2;
    }

    /* Monospaced Document Preview Box */
    .preview-box {
        background-color: #FFFFFF;
        border: 1px solid var(--border-card);
        border-radius: 6px;
        padding: 18px;
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
        font-size: 13px;
        line-height: 1.6;
        color: #1E293B;
        white-space: pre-wrap;
        max-height: 460px;
        overflow-y: auto;
        box-shadow: inset 0 1px 2px rgba(11, 18, 32, 0.02);
    }

    /* Structured Block Cards */
    .extracted-block-card {
        background-color: var(--bg-card);
        border: 1px solid var(--border-card);
        border-left: 3px solid var(--brand-blue);
        border-radius: 4px;
        padding: 12px 16px;
        margin-bottom: 10px;
        box-shadow: 0 1px 2px rgba(11, 18, 32, 0.02);
    }
    .extracted-block-meta {
        font-size: 11px;
        color: var(--text-secondary);
        font-weight: 600;
        margin-bottom: 6px;
        text-transform: uppercase;
        letter-spacing: 0.4px;
    }
    .extracted-block-text {
        font-size: 13px;
        color: var(--text-primary);
        white-space: pre-wrap;
        line-height: 1.5;
    }

    /* Primary & Action Buttons */
    div.stButton > button:first-child {
        background-color: var(--brand-blue) !important;
        color: #FFFFFF !important;
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
        color: #FFFFFF !important;
    }

    /* Secondary / Download Buttons */
    div.stDownloadButton > button {
        background-color: #FFFFFF !important;
        color: var(--text-primary) !important;
        border: 1px solid var(--border-card) !important;
        border-radius: 6px !important;
        font-weight: 600 !important;
        font-size: 13px !important;
        padding: 8px 16px !important;
        box-shadow: 0 1px 2px rgba(11, 18, 32, 0.03);
    }
    div.stDownloadButton > button:hover {
        background-color: #F8FAFC !important;
        border-color: var(--border-hover) !important;
        color: var(--brand-blue) !important;
    }

    /* File Uploader Polishing */
    [data-testid="stFileUploader"] section {
        background-color: #FFFFFF !important;
        border: 1px dashed var(--border-card) !important;
        border-radius: 8px !important;
        padding: 16px 20px !important;
    }
    [data-testid="stFileUploader"] section:hover {
        border-color: var(--brand-blue) !important;
        background-color: #FAFCFF !important;
    }

    /* Only display the latest active file chip; hide any previous file chips */
    [data-testid="stFileChips"] > div > div:not(:last-child),
    [data-testid="stFileChips"] > *:first-child > *:not(:last-child),
    div[data-testid="stFileChips"] > div > div:not(:last-child),
    [data-testid="stFileUploader"] [data-testid="stFileChip"]:not(:last-child) {
        display: none !important;
        visibility: hidden !important;
    }

    /* Enterprise Tabs */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
        border-bottom: 1px solid var(--border-card);
        padding-bottom: 4px;
    }
    .stTabs [data-baseweb="tab"] {
        padding: 8px 16px;
        font-size: 13px;
        font-weight: 500;
        color: var(--text-secondary);
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

    /* Clean Table / DataFrame Box */
    [data-testid="stDataFrame"] {
        border: 1px solid var(--border-card);
        border-radius: 6px;
        background-color: #FFFFFF;
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

    /* Chart Containers */
    .chart-container-card {
        background-color: var(--bg-card);
        border: 1px solid var(--border-card);
        border-radius: 8px;
        padding: 20px 22px;
        margin-bottom: 20px;
        box-shadow: 0 1px 3px 0 rgba(11, 18, 32, 0.03);
    }
    .chart-container-title {
        font-size: 15px;
        font-weight: 700;
        color: var(--text-primary);
        margin-bottom: 4px;
    }
    .chart-container-subtitle {
        font-size: 12.5px;
        color: var(--text-secondary);
        margin-bottom: 14px;
    }

    /* Empty State Container */
    .empty-state-box {
        background-color: var(--bg-card);
        border: 1px dashed var(--border-card);
        border-radius: 8px;
        padding: 36px 24px;
        text-align: center;
        margin-top: 10px;
        margin-bottom: 20px;
    }
    .empty-state-icon {
        font-size: 32px;
        margin-bottom: 10px;
        color: var(--text-muted);
    }
    .empty-state-title {
        font-size: 15px;
        font-weight: 600;
        color: var(--text-primary);
        margin-bottom: 6px;
    }
    .empty-state-text {
        font-size: 13px;
        color: var(--text-secondary);
        max-width: 520px;
        margin: 0 auto;
        line-height: 1.5;
    }
</style>
"""
st.markdown(ENTERPRISE_SOC_CSS, unsafe_allow_html=True)


@st.cache_resource
def get_pipeline():
    """Cache singleton pipeline instance for high performance."""
    return GatewayPipeline()


def apply_corporate_theme(fig, height: int = 340):
    """Apply consistent corporate SOC light theme to Plotly figures."""
    fig.update_layout(
        height=height,
        margin=dict(l=24, r=24, t=30, b=24),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(
            family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
            color="#172033",
            size=12,
        ),
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=-0.3,
            xanchor="center",
            x=0.5,
            font=dict(size=11, color="#64748B"),
        ),
    )
    fig.update_xaxes(
        showgrid=True,
        gridcolor="#F1F5F9",
        zerolinecolor="#E2E8F0",
        tickfont=dict(color="#64748B", size=11),
    )
    fig.update_yaxes(
        showgrid=True,
        gridcolor="#F1F5F9",
        zerolinecolor="#E2E8F0",
        tickfont=dict(color="#64748B", size=11),
    )
    return fig


def format_bytes(size: int) -> str:
    """Format byte count into human-readable representation."""
    if size < 1024:
        return f"{size} B"
    elif size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size / (1024 * 1024):.2f} MB"


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


# ==============================================================================
# VIEW ROUTING: "ARCHITECTURE & POLICY" vs "VISUALS" vs "MAIN DASHBOARD"
# ==============================================================================
if st.session_state.get("show_more", False) or st.session_state.get("active_view") == "more":
    # --------------------------------------------------------------------------
    # ARCHITECTURE & POLICY VIEW (Executive Whitepaper & Methodology)
    # --------------------------------------------------------------------------
    col_hdr_left, col_hdr_right = st.columns([6, 1])

    with col_hdr_left:
        st.markdown(
            """
            <div class="enterprise-header">
                <div class="header-left">
                    <div class="header-brand-icon">🛡️</div>
                    <div>
                        <h1 class="header-title">PII Security Gateway</h1>
                        <div class="header-subtitle">Enterprise Document Privacy & Security • Architecture & Policy Specification</div>
                    </div>
                </div>
                <div class="header-right">
                    <div class="status-indicator-pill status-idle">
                        <span class="status-dot dot-idle"></span>
                        <span>DOCUMENTATION MODE</span>
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col_hdr_right:
        st.markdown("<div style='height: 14px;'></div>", unsafe_allow_html=True)
        if st.button("← Return to Dashboard", help="Return to Main Gateway Dashboard", use_container_width=True, key="back_from_more_top"):
            st.session_state.show_more = False
            st.session_state.active_view = "dashboard"
            st.rerun()

    st.markdown(
        """
        <div style="background-color: var(--bg-card); border: 1px solid var(--border-card); border-left: 4px solid var(--brand-blue); border-radius: 8px; padding: 24px 28px; margin-bottom: 24px; box-shadow: 0 1px 3px 0 rgba(11, 18, 32, 0.04); line-height: 1.6;">
            <h3 style="margin-top: 0; font-size: 18px; color: var(--brand-blue); font-weight: 700;">
                Enterprise Security Architecture & Fail-Closed Ingestion Standard
            </h3>
            <p style="font-size: 14px; color: var(--text-secondary); margin-bottom: 16px;">
                The <b>PII Security Gateway</b> acts as an automated, zero-trust cryptographic and privacy checkpoint situated between corporate unstructured data repositories and downstream Large Language Model (LLM) inference environments.
            </p>
            <div style="background-color: #F8FAFC; border: 1px solid var(--border-card); border-radius: 6px; padding: 16px 20px; margin-bottom: 20px;">
                <b style="color: var(--text-primary); font-size: 14px;">Operational Problem Statement:</b><br>
                <span style="color: var(--text-secondary); font-size: 13.5px;">
                    When corporate users upload business artifacts (contracts, invoices, employee records, incident logs) to cloud-hosted or proprietary AI models, those artifacts frequently contain confidential Personally Identifiable Information (PII) including full names, corporate email addresses, direct dial numbers, government identifiers (SSN, Aadhaar, PAN), and employee badge codes. Transmitting raw artifacts violates international compliance mandates (GDPR Art. 25, HIPAA §164.514, EU AI Act) and introduces direct enterprise liability.
                </span>
            </div>

            <h4 style="font-size: 15px; color: var(--text-primary); margin-bottom: 12px; font-weight: 600;">
                Four-Stage Fail-Closed Security Pipeline:
            </h4>
            <ol style="color: var(--text-secondary); font-size: 13.5px; padding-left: 20px; line-height: 1.75; margin-bottom: 20px;">
                <li><b>1. Structural Document Extraction:</b> Artifacts (PDF, DOCX, PPTX, TXT) are decomposed into immutable, ordered structural blocks retaining exact coordinate and paragraph boundaries (e.g., <code>page_1_block_2</code>).</li>
                <li><b>2. Multi-Engine Corroborating Detection:</b>
                    <ul style="margin-top: 4px; margin-bottom: 4px;">
                        <li><b>Deterministic Syntactic Regex:</b> Strict RFC patterns for email, E.164 phone formats, IP addresses, credit cards, and government IDs.</li>
                        <li><b>Statistical Named Entity Recognition (NER):</b> Pre-trained transformer/heuristic NLP models validated with contextual and domain filters to detect personal names without false-positive technical term flags.</li>
                        <li><b>Context-Aware Semantic Heuristics:</b> Keyword proximity evaluation for structured fields (e.g., <code>Employee ID:</code>, <code>Contact Person:</code>).</li>
                    </ul>
                </li>
                <li><b>3. Consistent Semantic Redaction:</b> Instead of destructive blacking-out, entities receive transparent, cryptographically tracked tokens (e.g., <code>[PERSON_001]</code>, <code>[EMAIL_001]</code>). Recurrences of the same entity receive identical tokens across all pages, preserving linguistic coherence for AI reasoning without leaking private identities.</li>
                <li><b>4. Independent Post-Redaction Validation:</b> A dedicated re-scan audits the sanitized text. If even a single residual PII entity is detected, the gateway triggers a fail-closed response, marking the document <b>BLOCKED ✕</b>. Downstream transmission occurs only when zero residual PII is certified.</li>
            </ol>

            <div style="border-top: 1px solid var(--border-card); padding-top: 14px; font-size: 13px; color: var(--text-secondary);">
                🔒 <b>Local Boundary Assurance:</b> All extraction, tokenization, detection, and redaction procedures run 100% locally within host memory. No telemetry or document payload is dispatched to third-party endpoints.
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
    # VISUAL ANALYTICS VIEW (Telemetry & Pictorial Representations)
    # --------------------------------------------------------------------------
    col_hdr_left, col_hdr_right = st.columns([6, 1])

    with col_hdr_left:
        st.markdown(
            """
            <div class="enterprise-header">
                <div class="header-left">
                    <div class="header-brand-icon">🛡️</div>
                    <div>
                        <h1 class="header-title">PII Security Gateway</h1>
                        <div class="header-subtitle">Enterprise Document Privacy & Security • Threat & Telemetry Visual Analytics</div>
                    </div>
                </div>
                <div class="header-right">
                    <div class="status-indicator-pill status-sanitized">
                        <span class="status-dot dot-sanitized"></span>
                        <span>TELEMETRY ACTIVE</span>
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col_hdr_right:
        st.markdown("<div style='height: 14px;'></div>", unsafe_allow_html=True)
        if st.button("← Return to Dashboard", help="Return to Main Gateway Dashboard", use_container_width=True, key="back_from_visuals_top"):
            st.session_state.active_view = "dashboard"
            st.session_state.show_more = False
            st.rerun()

    results = st.session_state.get("analysis_results", [])

    if not results:
        st.markdown(
            """
            <div class="empty-state-box">
                <div class="empty-state-icon">📊</div>
                <div class="empty-state-title">No Active Telemetry Available</div>
                <div class="empty-state-text">
                    Visual threat graphs and detection telemetry require an inspected document artifact. Return to the main dashboard, upload a business file, and execute security inspection.
                </div>
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

        # Overview Metrics Row
        c_m1, c_m2, c_m3, c_m4 = st.columns(4)
        with c_m1:
            st.markdown(
                f"""
                <div class="metric-card-soc">
                    <div class="metric-top-row">
                        <span class="metric-card-label">Total PII Entities</span>
                        <span class="metric-card-icon">🔍</span>
                    </div>
                    <div class="metric-card-value val-blue">{summary['total_pii_detected']}</div>
                    <div class="metric-card-subtext">Identified across {len(active_doc.blocks)} blocks</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        with c_m2:
            st.markdown(
                f"""
                <div class="metric-card-soc">
                    <div class="metric-top-row">
                        <span class="metric-card-label">High-Risk Findings</span>
                        <span class="metric-card-icon">⚠️</span>
                    </div>
                    <div class="metric-card-value val-red">{summary['high_risk_findings']}</div>
                    <div class="metric-card-subtext">Critical & High risk tier</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        with c_m3:
            st.markdown(
                f"""
                <div class="metric-card-soc">
                    <div class="metric-top-row">
                        <span class="metric-card-label">PII Classifications</span>
                        <span class="metric-card-icon">📑</span>
                    </div>
                    <div class="metric-card-value">{len(summary.get('type_breakdown', {}))}</div>
                    <div class="metric-card-subtext">Distinct category types</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        with c_m4:
            st.markdown(
                f"""
                <div class="metric-card-soc">
                    <div class="metric-top-row">
                        <span class="metric-card-label">Security Gate Verdict</span>
                        <span class="metric-card-icon">🛡️</span>
                    </div>
                    <div class="metric-card-value {'val-green' if doc_stat_val == 'SANITIZED' else ('val-red' if doc_stat_val == 'BLOCKED' else 'val-amber')}">{doc_stat_val}</div>
                    <div class="metric-card-subtext">Post-redaction gate decision</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        st.markdown("<div style='height: 20px;'></div>", unsafe_allow_html=True)

        type_data = summary.get("type_breakdown", {})
        sev_data = summary.get("severity_breakdown", {})
        
        method_counter: Dict[str, int] = {}
        confidence_counter = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in active_doc.pii_findings:
            m_label = " + ".join(f.detection_method) if f.detection_method else "Pattern Match"
            method_counter[m_label] = method_counter.get(m_label, 0) + 1
            conf_str = f.confidence_level.value if hasattr(f.confidence_level, "value") else str(f.confidence_level)
            confidence_counter[conf_str] = confidence_counter.get(conf_str, 0) + 1

        # Charts Row 1: Categories & Severities
        col_c1, col_c2 = st.columns(2)
        with col_c1:
            st.markdown(
                """
                <div class="chart-container-card">
                    <div class="chart-container-title">PII Classification Distribution</div>
                    <div class="chart-container-subtitle">Entity frequency across detected privacy categories.</div>
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
                    "CREDIT_CARD": "Credit Card",
                    "IP_ADDRESS": "IP Address",
                    "OTHER_PII": "Other PII",
                }
                cat_names = [category_labels_map.get(k, k.replace("_", " ").title()) for k in type_data.keys()]
                cat_counts = list(type_data.values())
                df_cat = pd.DataFrame({"Category": cat_names, "Count": cat_counts}).sort_values(by="Count", ascending=True)

                fig_cat = go.Figure(
                    go.Bar(
                        x=df_cat["Count"],
                        y=df_cat["Category"],
                        orientation="h",
                        marker=dict(color="#2563EB", line=dict(color="#1D4ED8", width=1)),
                        text=df_cat["Count"],
                        textposition="outside",
                        cliponaxis=False,
                    )
                )
                fig_cat = apply_corporate_theme(fig_cat, height=300)
                fig_cat.update_layout(xaxis_title="Entity Count", yaxis_title=None)
                st.plotly_chart(fig_cat, use_container_width=True)
            else:
                st.info("No PII entities detected.")
            st.markdown("</div>", unsafe_allow_html=True)

        with col_c2:
            st.markdown(
                """
                <div class="chart-container-card">
                    <div class="chart-container-title">Risk Severity Breakdown</div>
                    <div class="chart-container-subtitle">Threat classification proportions across findings.</div>
                """,
                unsafe_allow_html=True,
            )
            color_map = {
                "CRITICAL": "#DC2626",
                "HIGH": "#EF4444",
                "MEDIUM": "#F59E0B",
                "LOW": "#10B981",
            }
            sev_labels = []
            sev_counts = []
            sev_colors = []
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
                fig_sev = apply_corporate_theme(fig_sev, height=300)
                fig_sev.update_layout(
                    annotations=[
                        dict(
                            text=f"<b>{summary['total_pii_detected']}</b><br><span style='font-size:11px;color:#64748B;'>Entities</span>",
                            x=0.5,
                            y=0.5,
                            font_size=15,
                            showarrow=False,
                        )
                    ],
                    showlegend=True,
                )
                st.plotly_chart(fig_sev, use_container_width=True)
            else:
                st.success("Zero risk detected. Artifact is completely sanitized.")
            st.markdown("</div>", unsafe_allow_html=True)

        # Charts Row 2: Method Attribution & Confidence Distribution
        col_c3, col_c4 = st.columns(2)
        with col_c3:
            st.markdown(
                """
                <div class="chart-container-card">
                    <div class="chart-container-title">Multi-Engine Attribution</div>
                    <div class="chart-container-subtitle">Corroborating detection engines behind flagged entities.</div>
                """,
                unsafe_allow_html=True,
            )
            if method_counter:
                df_method = pd.DataFrame(
                    list(method_counter.items()),
                    columns=["Engine", "Count"]
                ).sort_values(by="Count", ascending=False)

                fig_method = go.Figure(
                    go.Bar(
                        x=df_method["Engine"],
                        y=df_method["Count"],
                        marker=dict(color=["#0284C7", "#6366F1", "#8B5CF6", "#0D9488"][:len(df_method)]),
                        text=df_method["Count"],
                        textposition="outside",
                    )
                )
                fig_method = apply_corporate_theme(fig_method, height=300)
                fig_method.update_layout(xaxis_title=None, yaxis_title="Detections Flagged")
                st.plotly_chart(fig_method, use_container_width=True)
            else:
                st.info("No detection engines triggered.")
            st.markdown("</div>", unsafe_allow_html=True)

        with col_c4:
            st.markdown(
                """
                <div class="chart-container-card">
                    <div class="chart-container-title">Detection Confidence Distribution</div>
                    <div class="chart-container-subtitle">Certainty levels calculated by syntactic and NLP models.</div>
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
                    marker=dict(color=["#16A34A", "#F59E0B", "#EF4444"]),
                    text=conf_vals,
                    textposition="outside",
                )
            )
            fig_conf = apply_corporate_theme(fig_conf, height=300)
            fig_conf.update_layout(xaxis_title=None, yaxis_title="Findings Count")
            st.plotly_chart(fig_conf, use_container_width=True)
            st.markdown("</div>", unsafe_allow_html=True)

        st.markdown("<div style='height: 18px;'></div>", unsafe_allow_html=True)
        if st.button("← Back to Main Dashboard", type="primary", key="back_from_visuals_bottom"):
            st.session_state.active_view = "dashboard"
            st.session_state.show_more = False
            st.rerun()

else:
    # --------------------------------------------------------------------------
    # MAIN DASHBOARD VIEW
    # --------------------------------------------------------------------------
    results = st.session_state.get("analysis_results", [])
    has_results = bool(results)
    active_sample = st.session_state.get("active_sample_file")

    # Determine Header Live Pipeline Status
    if has_results:
        active_doc = results[0]
        stat_val = active_doc.security_status.value if hasattr(active_doc.security_status, "value") else str(active_doc.security_status)
        if stat_val == "SANITIZED":
            status_class = "status-sanitized"
            dot_class = "dot-sanitized"
            status_text = "● GATEWAY: SANITIZED (SAFE)"
        elif stat_val == "BLOCKED":
            status_class = "status-blocked"
            dot_class = "dot-blocked"
            status_text = "● GATEWAY: BLOCKED (FAIL-CLOSED)"
        else:
            status_class = "status-review"
            dot_class = "dot-review"
            status_text = "● GATEWAY: REVIEW REQUIRED"
    elif active_sample or st.session_state.get("last_active_file_signature"):
        status_class = "status-staged"
        dot_class = "dot-staged"
        status_text = "● ARTIFACT STAGED (READY)"
    else:
        status_class = "status-idle"
        dot_class = "dot-idle"
        status_text = "● GATEWAY ACTIVE | STANDBY"

    # 1. ENTERPRISE HEADER
    col_hdr_main, col_hdr_actions = st.columns([5, 2])

    with col_hdr_main:
        st.markdown(
            f"""
            <div class="enterprise-header">
                <div class="header-left">
                    <div class="header-brand-icon">🛡️</div>
                    <div>
                        <h1 class="header-title">PII Security Gateway</h1>
                        <div class="header-subtitle">Enterprise Document Privacy & Security</div>
                    </div>
                </div>
                <div class="header-right">
                    <div class="status-indicator-pill {status_class}">
                        <span class="status-dot {dot_class}"></span>
                        <span>{status_text}</span>
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col_hdr_actions:
        st.markdown("<div style='height: 18px;'></div>", unsafe_allow_html=True)
        col_btn_vis, col_btn_doc = st.columns(2)
        with col_btn_vis:
            if has_results:
                if st.button("📊 Visuals", help="Open visual threat graphs and telemetry analytics", use_container_width=True):
                    st.session_state.active_view = "visuals"
                    st.session_state.show_more = False
                    st.rerun()
            else:
                st.button("📊 Visuals", disabled=True, help="Analyze an artifact to view telemetry graphs", use_container_width=True)
        with col_btn_doc:
            if st.button("📖 Architecture", help="View security gateway whitepaper and policy specification", use_container_width=True):
                st.session_state.active_view = "more"
                st.session_state.show_more = True
                st.rerun()

    # 2. OVERVIEW SECTION (4 Metrics Calculated from Actual Data)
    if has_results:
        summary_metrics = ReportGenerator.get_summary_metrics(results)
        val_docs = summary_metrics["total_documents"]
        val_pii = summary_metrics["total_pii_detected"]
        val_high = summary_metrics["high_risk_findings"]
        val_blocked_review = summary_metrics["files_blocked"] + summary_metrics["files_review_required"]
    else:
        val_docs = 0
        val_pii = 0
        val_high = 0
        val_blocked_review = 0

    st.markdown("<h3 style='margin-top: 4px; margin-bottom: 12px; font-size: 15px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; color: var(--text-secondary);'>Security Gateway Overview</h3>", unsafe_allow_html=True)
    c_ov1, c_ov2, c_ov3, c_ov4 = st.columns(4)

    with c_ov1:
        st.markdown(
            f"""
            <div class="metric-card-soc">
                <div class="metric-top-row">
                    <span class="metric-card-label">Documents Processed</span>
                    <span class="metric-card-icon">📄</span>
                </div>
                <div class="metric-card-value">{val_docs}</div>
                <div class="metric-card-subtext">Active inspection scope</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with c_ov2:
        st.markdown(
            f"""
            <div class="metric-card-soc">
                <div class="metric-top-row">
                    <span class="metric-card-label">Total PII Findings</span>
                    <span class="metric-card-icon">🔍</span>
                </div>
                <div class="metric-card-value {'val-blue' if val_pii > 0 else ''}">{val_pii}</div>
                <div class="metric-card-subtext">Detected private entities</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with c_ov3:
        st.markdown(
            f"""
            <div class="metric-card-soc">
                <div class="metric-top-row">
                    <span class="metric-card-label">High-Severity Findings</span>
                    <span class="metric-card-icon">⚠️</span>
                </div>
                <div class="metric-card-value {'val-red' if val_high > 0 else ''}">{val_high}</div>
                <div class="metric-card-subtext">Critical & High risk tier</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with c_ov4:
        st.markdown(
            f"""
            <div class="metric-card-soc">
                <div class="metric-top-row">
                    <span class="metric-card-label">Documents Blocked / Review</span>
                    <span class="metric-card-icon">🛡️</span>
                </div>
                <div class="metric-card-value {'val-amber' if val_blocked_review > 0 else 'val-green'}">{val_blocked_review}</div>
                <div class="metric-card-subtext">Fail-closed gate triggers</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown("<div style='height: 22px;'></div>", unsafe_allow_html=True)

    # 3. DOCUMENT PROCESSING SECTION
    st.markdown("<h3 style='margin-bottom: 12px; font-size: 15px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; color: var(--text-secondary);'>Document Ingestion & Security Inspection</h3>", unsafe_allow_html=True)

    col_upload_left, col_upload_right = st.columns([3, 1])

    with col_upload_left:
        uploaded_files = st.file_uploader(
            "Upload Business Document (Supported formats: PDF, DOCX, PPTX, TXT)",
            type=["pdf", "docx", "pptx", "txt"],
            accept_multiple_files=True,
            key="evidence_uploader",
            help="Upload an evidence document for local pre-LLM PII detection and semantic sanitization.",
        )

    # Active file state handling (latest uploaded or sample)
    active_file = None
    if uploaded_files:
        active_file = uploaded_files[-1]
        active_signature = f"{active_file.name}_{active_file.size}"

        # Clear previous analysis when a new document is introduced
        if st.session_state.get("last_active_file_signature") != active_signature:
            st.session_state.analysis_results = []
            st.session_state.last_active_file_signature = active_signature
            st.session_state.active_sample_file = None
    else:
        if not st.session_state.get("active_sample_file"):
            if st.session_state.get("last_active_file_signature") is not None:
                st.session_state.analysis_results = []
                st.session_state.last_active_file_signature = None

    with col_upload_right:
        st.markdown("<div style='height: 28px;'></div>", unsafe_allow_html=True)
        analyze_btn = st.button("⚡ Execute Security Inspection", type="primary", use_container_width=True)
        load_samples = st.button("📁 Load Sample Artifact", help="Load synthetic multi-page Executive Briefing PDF", use_container_width=True)

        if load_samples:
            sample_dir = Path(__file__).resolve().parent / "sample_documents"
            sample_file = sample_dir / "Executive_Briefing.pdf"
            if sample_file.exists():
                st.session_state.active_sample_file = (sample_file.name, sample_file.read_bytes())
                st.session_state.last_active_file_signature = f"sample_{sample_file.name}"
                st.session_state.analysis_results = []
                st.rerun()

    # Active Artifact Metadata Card
    current_active_meta = None
    if active_file is not None:
        current_active_meta = {
            "name": active_file.name,
            "ext": Path(active_file.name).suffix.replace(".", "").upper() or "FILE",
            "size": format_bytes(active_file.size),
            "source": "Uploaded Artifact",
        }
    elif st.session_state.get("active_sample_file") is not None:
        s_name, s_bytes = st.session_state.active_sample_file
        current_active_meta = {
            "name": s_name,
            "ext": Path(s_name).suffix.replace(".", "").upper() or "FILE",
            "size": format_bytes(len(s_bytes)),
            "source": "Sample Artifact",
        }

    if current_active_meta:
        inspection_state_badge = '<span style="color: #64748B; font-weight: 600;">Awaiting Inspection</span>'
        if has_results:
            res_doc = results[0]
            doc_status_str = res_doc.security_status.value if hasattr(res_doc.security_status, "value") else str(res_doc.security_status)
            if doc_status_str == "SANITIZED":
                inspection_state_badge = '<span style="color: #16A34A; font-weight: 700;">✓ Inspection Complete: Sanitized</span>'
            elif doc_status_str == "BLOCKED":
                inspection_state_badge = '<span style="color: #DC2626; font-weight: 700;">✕ Inspection Complete: Blocked</span>'
            else:
                inspection_state_badge = '<span style="color: #D97706; font-weight: 700;">⚠ Inspection Complete: Review Required</span>'

        st.markdown(
            f"""
            <div class="artifact-active-card">
                <div class="artifact-active-left">
                    <span class="artifact-ext-badge">{current_active_meta['ext']}</span>
                    <div>
                        <div class="artifact-meta-title">{current_active_meta['name']}</div>
                        <div class="artifact-meta-details">{current_active_meta['source']} • {current_active_meta['size']}</div>
                    </div>
                </div>
                <div>
                    <span style="font-size: 12.5px; background-color: #F8FAFC; border: 1px solid #E2E8F0; padding: 4px 10px; border-radius: 4px;">
                        Status: {inspection_state_badge}
                    </span>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # 4. PIPELINE EXECUTION
    if analyze_btn:
        file_to_process = None
        if active_file is not None:
            file_to_process = (active_file.name, active_file.getvalue())
        elif st.session_state.get("active_sample_file") is not None:
            file_to_process = st.session_state.active_sample_file

        if not file_to_process:
            st.warning("Please upload a document or load a sample artifact before executing security inspection.")
        else:
            fname, fbytes = file_to_process
            progress_bar = st.progress(0, text=f"Inspecting {fname}...")
            status_box = st.empty()

            status_box.markdown(
                f"""
                <div style='background: #FFFFFF; border: 1px solid #E2E8F0; padding: 12px 16px; border-radius: 6px; font-size: 13px; color: #172033; margin-bottom: 12px;'>
                    <b>Inspecting {fname}:</b> 
                    <span style='color: #2563EB; font-weight: 600;'>1. Extract</span> → 
                    <span style='color: #2563EB; font-weight: 600;'>2. Detect PII</span> → 
                    <span style='color: #2563EB; font-weight: 600;'>3. Semantic Redaction</span> → 
                    <span style='color: #2563EB; font-weight: 600;'>4. Post-Redaction Validation</span>
                </div>
                """,
                unsafe_allow_html=True,
            )

            pipeline = get_pipeline()
            res = pipeline.process_document(file_bytes=fbytes, file_name=fname)
            progress_bar.progress(100, text="Security pipeline inspection complete.")
            time.sleep(0.1)
            status_box.empty()
            progress_bar.empty()
            st.session_state.analysis_results = [res]
            st.rerun()

    # 5. SECURITY ANALYSIS RESULTS & DEEP-DIVE
    if has_results:
        st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)

        if len(results) == 1:
            selected_doc = results[0]
        else:
            doc_options = [f"{r.file_name} ({r.security_status.value if hasattr(r.security_status, 'value') else r.security_status})" for r in results]
            selected_doc_idx = st.selectbox(
                "Select Artifact for Detailed Security Inspection:",
                range(len(doc_options)),
                format_func=lambda i: doc_options[i]
            )
            selected_doc = results[selected_doc_idx]

        doc_stat_val = selected_doc.security_status.value if hasattr(selected_doc.security_status, "value") else str(selected_doc.security_status)
        vr = selected_doc.validation_result
        replacements_count = selected_doc.redaction_result.replacements_count if selected_doc.redaction_result else 0
        residual_count = len(vr.residual_findings) if vr else 0

        # Stage Stepper Evaluation
        val_stage_class = "stage-passed" if (vr and vr.passed) else ("stage-failed" if (vr and not vr.passed) else "stage-item")
        val_stage_status = "✓ PASSED (0 Residual)" if (vr and vr.passed) else (f"✕ FAILED ({residual_count} Residual)" if vr else "Pending")

        # 4-STAGE PIPELINE STEPPER
        st.markdown(
            f"""
            <div class="pipeline-stepper-box">
                <div class="stepper-header">
                    <span class="stepper-title">Security Inspection Pipeline Execution</span>
                    <span class="stepper-meta">Artifact: <b>{selected_doc.file_name}</b> ({len(selected_doc.blocks)} blocks extracted)</span>
                </div>
                <div class="pipeline-step-grid">
                    <div class="stage-item stage-passed">
                        <div class="stage-num">Stage 01</div>
                        <div class="stage-name">Document Extraction</div>
                        <div class="stage-detail">{len(selected_doc.blocks)} structural blocks extracted</div>
                    </div>
                    <div class="stage-item stage-passed">
                        <div class="stage-num">Stage 02</div>
                        <div class="stage-name">Multi-Engine Detection</div>
                        <div class="stage-detail">{len(selected_doc.pii_findings)} PII instances flagged</div>
                    </div>
                    <div class="stage-item stage-passed">
                        <div class="stage-num">Stage 03</div>
                        <div class="stage-name">Semantic Redaction</div>
                        <div class="stage-detail">{replacements_count} entity tokens mapped</div>
                    </div>
                    <div class="stage-item {val_stage_class}">
                        <div class="stage-num">Stage 04</div>
                        <div class="stage-name">Post-Redaction Validation</div>
                        <div class="stage-detail">{val_stage_status}</div>
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # SECURITY GATE VERDICT BANNER
        if doc_stat_val == SecurityStatus.SANITIZED.value:
            st.markdown(
                """
                <div class="verdict-banner verdict-sanitized">
                    <div class="verdict-icon">✓</div>
                    <div>
                        <div class="verdict-title">SECURITY GATE VERDICT: SANITIZED (APPROVED FOR DOWNSTREAM AI)</div>
                        <div class="verdict-desc">Post-redaction validation verified zero residual PII. Content is sanitized and certified safe for downstream LLM context submission.</div>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        elif doc_stat_val == SecurityStatus.BLOCKED.value:
            st.markdown(
                """
                <div class="verdict-banner verdict-blocked">
                    <div class="verdict-icon">✕</div>
                    <div>
                        <div class="verdict-title">SECURITY GATE VERDICT: BLOCKED (FAIL-CLOSED ENFORCEMENT)</div>
                        <div class="verdict-desc">Fail-closed security triggered. Residual PII or critical policy violation detected. Document is blocked from AI consumption.</div>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        else:
            st.markdown(
                """
                <div class="verdict-banner verdict-review">
                    <div class="verdict-icon">⚠</div>
                    <div>
                        <div class="verdict-title">SECURITY GATE VERDICT: REVIEW REQUIRED</div>
                        <div class="verdict-desc">Document contains low-confidence signals or unverified scanned pages requiring compliance analyst clearance before release.</div>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        # 6. PII FINDINGS TABLE (With Severity/Type Filters and Masking Toggle)
        st.markdown("<h3 style='margin-bottom: 8px; font-size: 15px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; color: var(--text-secondary);'>PII Findings Log</h3>", unsafe_allow_html=True)

        col_f_sev, col_f_type, col_f_unmask = st.columns([1.5, 1.5, 2])

        with col_f_sev:
            sev_filter = st.selectbox(
                "Filter by Severity:",
                ["All Severities", "CRITICAL", "HIGH", "MEDIUM", "LOW"],
                key="filter_sev"
            )

        with col_f_type:
            all_types = sorted(list({f.pii_type.value if hasattr(f.pii_type, "value") else str(f.pii_type) for f in selected_doc.pii_findings}))
            type_filter = st.selectbox(
                "Filter by PII Type:",
                ["All Types"] + all_types,
                key="filter_type"
            )

        with col_f_unmask:
            st.markdown("<div style='height: 28px;'></div>", unsafe_allow_html=True)
            show_raw = st.checkbox("Analyst Audit: Reveal Unmasked Original Values", value=False, help="Unmasks original sensitive entity values strictly for compliance review.")

        # Build Filtered Findings Rows
        filtered_findings = []
        for f in selected_doc.pii_findings:
            f_sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            f_type = f.pii_type.value if hasattr(f.pii_type, "value") else str(f.pii_type)

            if sev_filter != "All Severities" and f_sev != sev_filter:
                continue
            if type_filter != "All Types" and f_type != type_filter:
                continue

            display_entity = f.text if show_raw else f.masked_text
            filtered_findings.append({
                "Severity": f_sev,
                "PII Type": f_type,
                "Confidence": f"{f.confidence * 100:.1f}%",
                "Detection Method": " + ".join(f.detection_method),
                "Document Location": f.location,
                "Masked or Reviewed Entity": display_entity,
            })

        if filtered_findings:
            df_findings = pd.DataFrame(filtered_findings)
            st.dataframe(df_findings, use_container_width=True, hide_index=True)
            st.markdown(f"<div style='font-size: 12px; color: var(--text-secondary); margin-top: 4px;'>Displaying <b>{len(filtered_findings)}</b> of <b>{len(selected_doc.pii_findings)}</b> total findings.</div>", unsafe_allow_html=True)
        else:
            if selected_doc.pii_findings:
                st.info("No PII findings match the selected severity and type filter criteria.")
            else:
                st.success("Zero PII findings detected in this artifact.")

        st.markdown("<div style='height: 22px;'></div>", unsafe_allow_html=True)

        # 7. REDACTION & VALIDATION DEEP-DIVE TABS
        st.markdown("<h3 style='margin-bottom: 12px; font-size: 15px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; color: var(--text-secondary);'>Security Inspection Deep-Dive</h3>", unsafe_allow_html=True)

        tab_sanitized, tab_findings, tab_traceability, tab_validation, tab_original = st.tabs([
            "📄 Sanitized Output",
            "🔍 PII Findings & Mappings",
            "🧭 Source Traceability",
            "🛡️ Validation & Security Audit",
            "📑 Original Extracted Blocks",
        ])

        with tab_sanitized:
            st.markdown("<p style='color: var(--text-secondary); font-size: 13px; margin-bottom: 10px;'>Sanitized document content utilizing consistent semantic placeholders (e.g. <code>[PERSON_001]</code>, <code>[EMAIL_001]</code>) to maintain LLM context integrity.</p>", unsafe_allow_html=True)
            if selected_doc.redaction_result and selected_doc.redaction_result.redacted_full_text:
                st.markdown(f'<div class="preview-box">{selected_doc.redaction_result.redacted_full_text}</div>', unsafe_allow_html=True)

                st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)
                st.download_button(
                    label=f"⬇ Download Sanitized Document ({Path(selected_doc.file_name).stem}_sanitized.txt)",
                    data=selected_doc.redaction_result.redacted_full_text,
                    file_name=f"{Path(selected_doc.file_name).stem}_sanitized.txt",
                    mime="text/plain",
                )
            else:
                st.info("No sanitized output generated.")

        with tab_findings:
            st.markdown(f"<p style='color: var(--text-secondary); font-size: 13px; margin-bottom: 10px;'>Detailed breakdown of all {len(selected_doc.pii_findings)} detected PII instances and associated security justifications.</p>", unsafe_allow_html=True)
            if selected_doc.pii_findings:
                doc_findings_detailed = []
                for f in selected_doc.pii_findings:
                    doc_findings_detailed.append({
                        "Location": f.location,
                        "PII Type": f.pii_type.value if hasattr(f.pii_type, "value") else str(f.pii_type),
                        "Severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                        "Confidence": f"{f.confidence * 100:.1f}%",
                        "Method": " + ".join(f.detection_method),
                        "Entity (Masked)": f.masked_text,
                        "Security Explanation": f.explanation,
                    })
                st.dataframe(pd.DataFrame(doc_findings_detailed), use_container_width=True, hide_index=True)
            else:
                st.info("No PII detected in this document.")

        with tab_traceability:
            st.markdown("<p style='color: var(--text-secondary); font-size: 13px; margin-bottom: 10px;'>Source Traceability Matrix: Mapping exact structural locations, corroborating detectors, and cryptographic semantic tokens.</p>", unsafe_allow_html=True)
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
                st.info("No traceability records available.")

        with tab_validation:
            st.markdown("<p style='color: var(--text-secondary); font-size: 13px; margin-bottom: 10px;'>Post-Redaction Validation Audit: Independent secondary scan of sanitized text ensuring fail-closed enforcement.</p>", unsafe_allow_html=True)
            if vr:
                res_color = "#16A34A" if vr.passed else "#DC2626"
                st.markdown(
                    f"""
                    <div style="background-color: #FFFFFF; border: 1px solid #E2E8F0; border-radius: 6px; padding: 18px; margin-bottom: 14px;">
                        <table style="width: 100%; border-collapse: collapse; font-size: 13px;">
                            <tr style="border-bottom: 1px solid #F1F5F9;">
                                <td style="padding: 8px 0; color: #64748B; font-weight: 500;">Validation Gate Status:</td>
                                <td style="padding: 8px 0; font-weight: 700; color: {res_color};">{'PASSED (APPROVED)' if vr.passed else 'FAILED (BLOCKED)'}</td>
                            </tr>
                            <tr style="border-bottom: 1px solid #F1F5F9;">
                                <td style="padding: 8px 0; color: #64748B; font-weight: 500;">Residual PII Count:</td>
                                <td style="padding: 8px 0; font-weight: 700; color: #172033;">{len(vr.residual_findings)} items</td>
                            </tr>
                            <tr style="border-bottom: 1px solid #F1F5F9;">
                                <td style="padding: 8px 0; color: #64748B; font-weight: 500;">Fail-Closed Policy Outcome:</td>
                                <td style="padding: 8px 0; font-weight: 700; color: #172033;">{vr.status.value}</td>
                            </tr>
                            <tr>
                                <td style="padding: 8px 0; color: #64748B; font-weight: 500;">Enforced Security Rule:</td>
                                <td style="padding: 8px 0; color: #172033;">{vr.validation_message}</td>
                            </tr>
                        </table>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

                if vr.residual_findings:
                    st.error("Residual sensitive findings detected in sanitized text:")
                    residual_rows = []
                    for rf in vr.residual_findings:
                        residual_rows.append({
                            "Location": rf.location,
                            "Type": rf.pii_type.value if hasattr(rf.pii_type, "value") else str(rf.pii_type),
                            "Severity": rf.severity.value if hasattr(rf.severity, "value") else str(rf.severity),
                            "Residual Text": rf.text,
                        })
                    st.dataframe(pd.DataFrame(residual_rows), use_container_width=True, hide_index=True)
            else:
                st.info("Validation audit records unavailable.")

        with tab_original:
            st.markdown("<p style='color: var(--text-secondary); font-size: 13px; margin-bottom: 10px;'>Original extracted blocks with structural boundary metadata (Preserved strictly in local memory boundary).</p>", unsafe_allow_html=True)
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

        # 8. COMPLIANCE AUDIT EXPORTS
        st.markdown("<h3 style='margin-bottom: 12px; font-size: 15px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; color: var(--text-secondary);'>Compliance Audit Reports Export</h3>", unsafe_allow_html=True)
        col_exp1, col_exp2 = st.columns(2)

        with col_exp1:
            json_report_str = ReportGenerator.generate_json_report(results)
            st.download_button(
                label="⬇ Export Comprehensive Security Audit Report (JSON)",
                data=json_report_str,
                file_name="pii_security_gateway_audit_report.json",
                mime="application/json",
                use_container_width=True,
            )

        with col_exp2:
            csv_report_str = ReportGenerator.generate_csv_findings(results)
            st.download_button(
                label="⬇ Export Findings Traceability Matrix (CSV)",
                data=csv_report_str,
                file_name="pii_findings_traceability_log.csv",
                mime="text/csv",
                use_container_width=True,
            )

    else:
        # Professional Empty State
        st.markdown(
            """
            <div class="empty-state-box">
                <div class="empty-state-icon">🛡️</div>
                <div class="empty-state-title">Ready for Pre-LLM Security Inspection</div>
                <div class="empty-state-text">
                    Upload a business evidence document (PDF, Word, PowerPoint, or Text) or click <b>Load Sample Artifact</b> to inspect Personally Identifiable Information, perform consistent semantic redaction, and verify fail-closed compliance.
                </div>
                <div style="margin-top: 16px; font-size: 12px; color: #94A3B8;">
                    🔒 All extraction, detection, and validation processes execute strictly inside local memory.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
