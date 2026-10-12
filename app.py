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

from models.schemas import (
    DocumentAnalysisResult,
    SecurityStatus,
    Severity,
    ConfidenceLevel,
    PIIType,
)
from pipeline import GatewayPipeline
from reporting.report_generator import ReportGenerator
from reporting.metrics import calculate_structure_retention

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
</style>
"""
st.markdown(CORPORATE_LIGHT_CSS, unsafe_allow_html=True)


@st.cache_resource
def get_pipeline():
    """Cache singleton pipeline instance for high performance."""
    return GatewayPipeline()


# Session State Initialization
if "analysis_results" not in st.session_state:
    st.session_state.analysis_results = []
if "show_original" not in st.session_state:
    st.session_state.show_original = False
if "show_more" not in st.session_state:
    st.session_state.show_more = False
if "uploader_key" not in st.session_state:
    st.session_state.uploader_key = 0
if "last_file_signature" not in st.session_state:
    st.session_state.last_file_signature = None
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
# VIEW ROUTING: "MORE" VIEW vs "MAIN DASHBOARD" VIEW
# ==============================================================================
if st.session_state.get("show_more", False):
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
        if st.button("← Back", help="Return to Main Dashboard", use_container_width=True):
            st.session_state.show_more = False
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

    if st.button("← Back to Main Dashboard", type="primary"):
        st.session_state.show_more = False
        st.rerun()

else:
    # --------------------------------------------------------------------------
    # MAIN DASHBOARD VIEW
    # --------------------------------------------------------------------------
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

    with col_more:
        st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)
        if st.button("More", help="Click to understand how PII Security Gateway works in simple everyday words", use_container_width=True):
            st.session_state.show_more = True
            st.rerun()

    # ==============================================================================
    # FILE UPLOAD & ACTIONS SECTION
    # ==============================================================================
    col_upload, col_actions = st.columns([3, 1])

    with col_upload:
        uploaded_file = st.file_uploader(
            "Upload Business Evidence Document (Supported formats: PDF, DOCX, PPTX, TXT)",
            type=["pdf", "docx", "pptx", "txt"],
            accept_multiple_files=False,
            key=f"uploader_{st.session_state.uploader_key}",
            help="Upload a single evidence artifact for pre-LLM PII sanitization inspection.",
        )

    # Automatic State Synchronization:
    # If a new file is uploaded or if the file was removed via the ✖ button,
    # immediately clear out any lingering data from the previous file.
    current_signature = None
    if uploaded_file is not None:
        current_signature = f"{uploaded_file.name}_{uploaded_file.size}"
        if st.session_state.last_file_signature != current_signature:
            st.session_state.analysis_results = []
            st.session_state.last_file_signature = current_signature
            st.session_state.active_sample_file = None
    else:
        if st.session_state.active_sample_file is None:
            if st.session_state.last_file_signature is not None:
                st.session_state.analysis_results = []
                st.session_state.last_file_signature = None

    with col_actions:
        st.markdown("<div style='height: 28px;'></div>", unsafe_allow_html=True)
        analyze_btn = st.button("⚡ Analyze Document", type="primary", use_container_width=True)

        has_active_doc = (
            uploaded_file is not None
            or st.session_state.active_sample_file is not None
            or len(st.session_state.analysis_results) > 0
        )

        if has_active_doc:
            if st.button("🔄 Upload Another File", help="Remove current document and wipe old results to upload a new file", use_container_width=True):
                st.session_state.uploader_key += 1
                st.session_state.analysis_results = []
                st.session_state.last_file_signature = None
                st.session_state.active_sample_file = None
                st.rerun()
        else:
            load_samples = st.button("📁 Load Sample Document", help="Load pre-built synthetic test document", use_container_width=True)
            if load_samples:
                sample_dir = Path(__file__).resolve().parent / "sample_documents"
                sample_file = sample_dir / "Executive_Briefing.pdf"
                if sample_file.exists():
                    st.session_state.active_sample_file = (sample_file.name, sample_file.read_bytes())
                    st.session_state.last_file_signature = f"sample_{sample_file.name}"
                    st.session_state.analysis_results = []
                    st.info(f"Loaded sample evidence: '{sample_file.name}'. Click 'Analyze Document' to inspect.")

    # Show active sample notice if active and no upload
    if st.session_state.active_sample_file is not None and uploaded_file is None:
        s_name, s_bytes = st.session_state.active_sample_file
        st.markdown(
            f"""
            <div style="background-color: var(--bg-card); border: 1px solid var(--border-color); border-radius: 6px; padding: 8px 14px; margin-top: 6px; font-size: 13px; color: var(--text-secondary);">
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

        if uploaded_file is not None:
            file_to_process = (uploaded_file.name, uploaded_file.getvalue())
        elif st.session_state.active_sample_file is not None:
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
        st.markdown("<h3 style='margin-top: 14px; margin-bottom: 14px; font-size: 18px;'>Security Gate Overview</h3>", unsafe_allow_html=True)
        c1, c2, c3, c4, c5 = st.columns(5)

        with c1:
            st.markdown(
                f"""
                <div class="metric-card-clean">
                    <div class="metric-title">Documents Analyzed</div>
                    <div class="metric-number">{summary['total_documents']}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        with c2:
            st.markdown(
                f"""
                <div class="metric-card-clean">
                    <div class="metric-title">PII Entities Detected</div>
                    <div class="metric-number metric-number-blue">{summary['total_pii_detected']}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        with c3:
            st.markdown(
                f"""
                <div class="metric-card-clean">
                    <div class="metric-title">High-Risk Findings</div>
                    <div class="metric-number metric-number-red">{summary['high_risk_findings']}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        with c4:
            st.markdown(
                f"""
                <div class="metric-card-clean">
                    <div class="metric-title">Files Sanitized (Safe)</div>
                    <div class="metric-number metric-number-green">{summary['files_sanitized']}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        with c5:
            blocked_total = summary['files_blocked'] + summary['files_review_required']
            st.markdown(
                f"""
                <div class="metric-card-clean">
                    <div class="metric-title">Files Blocked / Review</div>
                    <div class="metric-number metric-number-amber">{blocked_total}</div>
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
                    "Document": f.file_name,
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
                        "Artifact": selected_doc.file_name,
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
                
                orig_blocks = selected_doc.blocks
                red_blocks = selected_doc.redaction_result.redacted_blocks if selected_doc.redaction_result else []
                retention_pct = calculate_structure_retention(orig_blocks, red_blocks)

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
                            <tr style="border-bottom: 1px solid #f5f2eb;">
                                <td style="padding: 8px 0; color: #78716c; font-weight: 500;">Structural Block Retention:</td>
                                <td style="padding: 8px 0; font-weight: 700; color: #2563eb;">{retention_pct}% (Original structure boundaries maintained)</td>
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
