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

# Professional Corporate Light Theme System CSS
CORPORATE_LIGHT_CSS = """
<style>
    /* Global Typography & Palette */
    :root {
        --bg-page: #f8fafc;
        --bg-card: #ffffff;
        --bg-subtle: #f1f5f9;
        --border-color: #e2e8f0;
        --border-focus: #cbd5e1;
        --text-primary: #0f172a;
        --text-secondary: #475569;
        --text-muted: #64748b;
        --brand-blue: #0284c7;
        --brand-blue-hover: #0369a1;
        --brand-blue-subtle: #e0f2fe;
        --status-safe-bg: #ecfdf5;
        --status-safe-border: #a7f3d0;
        --status-safe-text: #065f46;
        --status-safe-accent: #059669;
        --status-blocked-bg: #fef2f2;
        --status-blocked-border: #fecaca;
        --status-blocked-text: #991b1b;
        --status-blocked-accent: #dc2626;
        --status-review-bg: #fffbeb;
        --status-review-border: #fde68a;
        --status-review-text: #92400e;
        --status-review-accent: #d97706;
    }

    /* Force Light Theme Base */
    .stApp {
        background-color: var(--bg-page) !important;
        color: var(--text-primary) !important;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
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
        box-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.04);
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
    .header-subtitle {
        font-size: 14px;
        color: var(--text-secondary);
        margin-bottom: 12px;
    }
    .header-security-badge {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        padding: 4px 10px;
        background-color: var(--brand-blue-subtle);
        border: 1px solid #bae6fd;
        border-radius: 4px;
        font-size: 11px;
        font-weight: 600;
        color: var(--brand-blue-hover);
        letter-spacing: 0.5px;
        text-transform: uppercase;
    }
    .header-principle {
        font-size: 12px;
        color: var(--brand-blue);
        font-weight: 600;
        display: flex;
        align-items: center;
        gap: 6px;
    }

    /* Clean Metric Cards */
    .metric-card-clean {
        background-color: var(--bg-card);
        border: 1px solid var(--border-color);
        border-radius: 8px;
        padding: 18px 20px;
        box-shadow: 0 1px 2px 0 rgba(0, 0, 0, 0.03);
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
        color: #047857;
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
        color: #b91c1c;
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
        color: #b45309;
        font-size: 13px;
        line-height: 1.4;
    }

    /* Document Content Previews */
    .preview-box {
        background-color: var(--bg-card);
        border: 1px solid var(--border-color);
        border-radius: 6px;
        padding: 18px;
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
        font-size: 13px;
        line-height: 1.6;
        color: #1e293b;
        white-space: pre-wrap;
        max-height: 440px;
        overflow-y: auto;
        box-shadow: inset 0 1px 2px rgba(0, 0, 0, 0.02);
    }

    /* Structured Block Cards */
    .extracted-block-card {
        background-color: var(--bg-card);
        border: 1px solid var(--border-color);
        border-left: 3px solid var(--brand-blue);
        border-radius: 4px;
        padding: 12px 16px;
        margin-bottom: 10px;
        box-shadow: 0 1px 2px rgba(0, 0, 0, 0.02);
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

    /* Empty State Container */
    .empty-state-box {
        background-color: var(--bg-card);
        border: 1px dashed var(--border-focus);
        border-radius: 8px;
        padding: 48px 24px;
        text-align: center;
        margin-top: 16px;
    }
    .empty-state-icon {
        font-size: 36px;
        margin-bottom: 14px;
    }
    .empty-state-heading {
        font-size: 17px;
        font-weight: 600;
        color: var(--text-primary);
        margin-bottom: 8px;
    }
    .empty-state-text {
        font-size: 13px;
        color: var(--text-muted);
        max-width: 580px;
        margin: 0 auto 16px auto;
        line-height: 1.5;
    }
    .empty-state-footer {
        font-size: 11px;
        color: #94a3b8;
        font-weight: 500;
    }

    /* Button Styling */
    div.stButton > button:first-child {
        background-color: var(--brand-blue) !important;
        color: #ffffff !important;
        font-weight: 600 !important;
        border: 1px solid transparent !important;
        border-radius: 6px !important;
        padding: 8px 18px !important;
        font-size: 13px !important;
        transition: background-color 0.15s ease-in-out;
        box-shadow: 0 1px 2px rgba(2, 132, 199, 0.2);
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
        box-shadow: 0 1px 2px rgba(0, 0, 0, 0.03);
    }
    div.stDownloadButton > button:hover {
        background-color: var(--bg-subtle) !important;
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

    /* More Explanation Card */
    .more-explanation-card {
        background-color: var(--bg-card);
        border: 1px solid var(--border-color);
        border-left: 4px solid var(--brand-blue);
        border-radius: 8px;
        padding: 22px 26px;
        margin-bottom: 22px;
        box-shadow: 0 2px 6px 0 rgba(0, 0, 0, 0.04);
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


def format_bytes(size: int) -> str:
    """Format byte count into human-readable representation."""
    if size < 1024:
        return f"{size} B"
    elif size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size / (1024 * 1024):.2f} MB"


# ==============================================================================
# CORPORATE HEADER
# ==============================================================================
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
        st.session_state.show_more = not st.session_state.show_more

if st.session_state.show_more:
    st.markdown(
        """
        <div class="more-explanation-card">
            <h3 style="margin-top: 0; font-size: 18px; color: #0284c7; font-weight: 700;">
                💡 How Does This Project Work? (In Simple Words)
            </h3>
            <p style="font-size: 14px; color: #334155; margin-bottom: 12px;">
                Think of the <b>PII Security Gateway</b> as an <b>intelligent privacy checkpoint</b> for your documents before you share them with an AI (such as ChatGPT, Claude, or internal language models).
            </p>
            <div style="background-color: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 12px 16px; margin-bottom: 16px;">
                <b style="color: #0f172a; font-size: 13.5px;">⚠️ The Real Problem:</b><br>
                <span style="color: #475569; font-size: 13px;">
                    When you upload business files (contracts, invoices, employee records, support tickets) to an AI tool, those files often contain private data: real names, personal emails, phone numbers, employee badge IDs, credit cards, or government IDs. Sending that raw data outside your company risks data leaks and breaks strict privacy laws (like GDPR, HIPAA, or CCPA).
                </span>
            </div>
            <h4 style="font-size: 14.5px; color: #0f172a; margin-bottom: 8px; font-weight: 600;">
                How The Gateway Protects Your Data in 4 Simple Steps:
            </h4>
            <ol style="color: #334155; font-size: 13.5px; padding-left: 20px; line-height: 1.7; margin-bottom: 14px;">
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
            <div style="border-top: 1px solid #e2e8f0; padding-top: 10px; font-size: 12.5px; color: #64748b;">
                🔒 <b>100% Local & Safe:</b> Everything runs locally on your machine. Zero data is sent to external servers or third-party AI companies.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


# ==============================================================================
# FILE UPLOAD & ACTIONS SECTION
# ==============================================================================
col_upload, col_actions = st.columns([3, 1])

with col_upload:
    uploaded_files = st.file_uploader(
        "Upload Business Evidence Documents (Supported formats: PDF, DOCX, PPTX, TXT)",
        type=["pdf", "docx", "pptx", "txt"],
        accept_multiple_files=True,
        help="Upload single or multiple evidence artifacts for pre-LLM PII sanitization inspection.",
    )

with col_actions:
    st.markdown("<div style='height: 28px;'></div>", unsafe_allow_html=True)
    load_samples = st.button("📁 Load Sample Evidence", help="Load pre-built synthetic test documents", use_container_width=True)
    analyze_btn = st.button("⚡ Analyze Documents", type="primary", use_container_width=True)

# Handle Sample Document Pre-loading
sample_dir = Path(__file__).resolve().parent / "sample_documents"
sample_files_data = []

if load_samples and sample_dir.exists():
    for sample_file in sample_dir.iterdir():
        if sample_file.suffix.lower() in [".pdf", ".docx", ".pptx", ".txt"]:
            sample_files_data.append((sample_file.name, sample_file.read_bytes()))
    st.info(f"Loaded {len(sample_files_data)} sample evidence artifacts. Click 'Analyze Documents' to execute the security gate.")


# ==============================================================================
# PIPELINE EXECUTION
# ==============================================================================
if analyze_btn:
    pipeline = get_pipeline()
    files_to_process = []

    if uploaded_files:
        for f in uploaded_files:
            files_to_process.append((f.name, f.getvalue()))
    elif sample_files_data:
        files_to_process = sample_files_data
    elif sample_dir.exists():
        # Fallback to sample directory if analyze was clicked with no upload
        for sample_file in sample_dir.iterdir():
            if sample_file.suffix.lower() in [".pdf", ".docx", ".pptx", ".txt"]:
                files_to_process.append((sample_file.name, sample_file.read_bytes()))

    if not files_to_process:
        st.warning("Please upload one or more documents or load sample evidence before analyzing.")
    else:
        results: List[DocumentAnalysisResult] = []
        progress_bar = st.progress(0, text="Initializing Pre-LLM Security Gateway pipeline...")
        status_box = st.empty()

        for idx, (fname, fbytes) in enumerate(files_to_process):
            progress_pct = int((idx / len(files_to_process)) * 100)
            progress_bar.progress(progress_pct, text=f"Processing {fname} ({idx + 1}/{len(files_to_process)})...")

            # Sequential pipeline steps with live status
            status_box.markdown(
                f"""
                <div style='background: #ffffff; border: 1px solid #e2e8f0; padding: 12px 16px; border-radius: 6px; font-size: 13px; color: #475569; margin-bottom: 12px;'>
                    Inspecting <b>{fname}</b>: 
                    <span style='color: #0284c7; font-weight: 600;'>Extract</span> → 
                    <span style='color: #0284c7; font-weight: 600;'>Detect</span> → 
                    <span style='color: #0284c7; font-weight: 600;'>Redact</span> → 
                    <span style='color: #0284c7; font-weight: 600;'>Re-scan</span> → 
                    <span style='color: #0284c7; font-weight: 600;'>Validate</span>
                </div>
                """,
                unsafe_allow_html=True,
            )

            res = pipeline.process_document(file_bytes=fbytes, file_name=fname)
            results.append(res)
            time.sleep(0.1)

        progress_bar.progress(100, text="Pipeline processing complete.")
        status_box.empty()
        progress_bar.empty()
        st.session_state.analysis_results = results
        st.success(f"Security gate analysis complete for {len(results)} document(s).")


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
    st.markdown("<h3 style='margin-bottom: 8px; font-size: 16px;'>PII Findings & Action Log</h3>", unsafe_allow_html=True)

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
                "Action Taken": f.action,
            })

    if all_findings_rows:
        df_all_findings = pd.DataFrame(all_findings_rows)
        st.dataframe(df_all_findings, use_container_width=True, hide_index=True)
    else:
        st.info("Zero PII findings across analyzed documents.")

    st.markdown("<div style='height: 22px;'></div>", unsafe_allow_html=True)

    # 4. DOCUMENT DETAIL DEEP-DIVE
    st.markdown("<h3 style='margin-bottom: 12px; font-size: 16px;'>Document Deep-Dive & Source Traceability</h3>", unsafe_allow_html=True)
    
    doc_options = [f"{r.file_name} ({r.security_status.value if hasattr(r.security_status, 'value') else r.security_status})" for r in results]
    selected_doc_idx = st.selectbox(
        "Select Document Artifact for Structural Traceability Inspection:",
        range(len(doc_options)),
        format_func=lambda i: doc_options[i]
    )
    selected_doc = results[selected_doc_idx]

    # Security Status Indicator Banner
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

    # Document Detail Tabs
    tab_sanitized, tab_findings, tab_traceability, tab_validation, tab_original = st.tabs([
        "📄 Sanitized Output",
        "🔍 PII Findings & Mappings",
        "🧭 Source Traceability",
        "🛡️ Validation & Security",
        "📑 Original Extracted Blocks",
    ])

    with tab_sanitized:
        st.markdown("<p style='color: #64748b; font-size: 13px;'>Sanitized content using consistent transparent semantic tags (e.g. <code>[PERSON_001]</code>, <code>[EMAIL_001]</code>).</p>", unsafe_allow_html=True)
        if selected_doc.redaction_result:
            st.markdown(f'<div class="preview-box">{selected_doc.redaction_result.redacted_full_text}</div>', unsafe_allow_html=True)
            
            # Download Sanitized Content Button
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
        st.markdown(f"<p style='color: #64748b; font-size: 13px;'>Detected {len(selected_doc.pii_findings)} PII instances in this document.</p>", unsafe_allow_html=True)
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
                    "Action": f.action,
                    "Explanation": f.explanation,
                })
            st.dataframe(pd.DataFrame(doc_f_rows), use_container_width=True, hide_index=True)
        else:
            st.info("No PII detected in this document.")

    with tab_traceability:
        st.markdown("<p style='color: #64748b; font-size: 13px;'>Source Traceability Matrix: Explaining exact source location, detector corroboration, and semantic tag assignment.</p>", unsafe_allow_html=True)
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
        st.markdown("<p style='color: #64748b; font-size: 13px;'>Post-Redaction Validation Audit (Re-scan of sanitized text blocks to ensure fail-closed security).</p>", unsafe_allow_html=True)
        if selected_doc.validation_result:
            vr = selected_doc.validation_result
            
            orig_blocks = selected_doc.blocks
            red_blocks = selected_doc.redaction_result.redacted_blocks if selected_doc.redaction_result else []
            retention_pct = calculate_structure_retention(orig_blocks, red_blocks)

            st.markdown(
                f"""
                <div style="background-color: #ffffff; border: 1px solid #e2e8f0; border-radius: 6px; padding: 18px; margin-bottom: 14px;">
                    <table style="width: 100%; border-collapse: collapse; font-size: 13px;">
                        <tr style="border-bottom: 1px solid #f1f5f9;">
                            <td style="padding: 8px 0; color: #64748b; font-weight: 500;">Validation Verdict:</td>
                            <td style="padding: 8px 0; font-weight: 700; color: #0f172a;">{vr.status.value}</td>
                        </tr>
                        <tr style="border-bottom: 1px solid #f1f5f9;">
                            <td style="padding: 8px 0; color: #64748b; font-weight: 500;">Passed Security Gate:</td>
                            <td style="padding: 8px 0; font-weight: 700; color: {'#059669' if vr.passed else '#dc2626'};">{'YES (PASSED)' if vr.passed else 'NO (FAILED)'}</td>
                        </tr>
                        <tr style="border-bottom: 1px solid #f1f5f9;">
                            <td style="padding: 8px 0; color: #64748b; font-weight: 500;">Residual PII Detected:</td>
                            <td style="padding: 8px 0; font-weight: 700; color: #0f172a;">{len(vr.residual_findings)} items</td>
                        </tr>
                        <tr style="border-bottom: 1px solid #f1f5f9;">
                            <td style="padding: 8px 0; color: #64748b; font-weight: 500;">Structural Block Retention:</td>
                            <td style="padding: 8px 0; font-weight: 700; color: #0284c7;">{retention_pct}% (Original structure boundaries maintained)</td>
                        </tr>
                        <tr>
                            <td style="padding: 8px 0; color: #64748b; font-weight: 500;">Enforced Security Policy:</td>
                            <td style="padding: 8px 0; color: #334155;">{vr.validation_message}</td>
                        </tr>
                    </table>
                </div>
                """,
                unsafe_allow_html=True,
            )
        else:
            st.info("Validation records unavailable.")

    with tab_original:
        st.markdown("<p style='color: #64748b; font-size: 13px;'>Original extracted blocks with structural boundary metadata (Kept strictly local).</p>", unsafe_allow_html=True)
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
