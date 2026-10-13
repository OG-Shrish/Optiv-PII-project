"""PII Security Gateway - Pre-LLM Privacy & Document Sanitization Pipeline.

Academic & Enterprise Capstone Edition.
Provides deterministic, explainable, and fail-closed privacy controls
for unstructured enterprise documents prior to LLM context ingestion.
"""
import io
import time
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Any

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
from utils.helpers import calculate_file_hash

# ------------------------------------------------------------------------------
# 1. PAGE CONFIGURATION & CAPSTONE DESIGN SYSTEM
# ------------------------------------------------------------------------------
st.set_page_config(
    page_title="PII Security Gateway | Pre-LLM Privacy Gate",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

CAPSTONE_SOC_CSS = """
<style>
    /* Design Tokens: Enterprise SOC & Capstone Standard */
    :root {
        --navy-shell: #0B1220;
        --navy-surface: #142033;
        --navy-border: #1E293B;
        --slate-900: #0F172A;
        --slate-800: #1E293B;
        --slate-700: #334155;
        --slate-600: #475569;
        --slate-500: #64748B;
        --slate-400: #94A3B8;
        --slate-200: #E2E8F0;
        --slate-100: #F1F5F9;
        --slate-50: #F8FAFC;
        
        --brand-blue: #2563EB;
        --brand-blue-hover: #1D4ED8;
        --brand-blue-subtle: #EFF6FF;

        --state-safe-bg: #F0FDF4;
        --state-safe-border: #BBF7D0;
        --state-safe-text: #166534;
        --state-safe-accent: #16A34A;

        --state-blocked-bg: #FEF2F2;
        --state-blocked-border: #FECACA;
        --state-blocked-text: #991B1B;
        --state-blocked-accent: #DC2626;

        --state-review-bg: #FFFBEB;
        --state-review-border: #FDE68A;
        --state-review-text: #92400E;
        --state-review-accent: #D97706;
    }

    /* Base Architecture & Typography */
    .stApp {
        background-color: #F4F6FA !important;
        color: var(--slate-900) !important;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    }

    .main .block-container {
        padding-top: 1.25rem !important;
        padding-bottom: 2.5rem !important;
        max-width: 1440px;
    }

    /* Headings hierarchy */
    h1, h2, h3, h4 {
        color: var(--slate-900) !important;
        font-weight: 600 !important;
        letter-spacing: -0.02em;
    }

    /* Primary Capstone Header Shell */
    .capstone-header {
        background-color: var(--navy-shell);
        border: 1px solid var(--navy-border);
        border-radius: 8px;
        padding: 16px 22px;
        margin-bottom: 18px;
        display: flex;
        align-items: center;
        justify-content: space-between;
        flex-wrap: wrap;
        gap: 16px;
        box-shadow: 0 4px 6px -1px rgba(11, 18, 32, 0.15), 0 2px 4px -2px rgba(11, 18, 32, 0.1);
    }
    .header-brand-block {
        display: flex;
        align-items: center;
        gap: 14px;
    }
    .header-icon-badge {
        width: 42px;
        height: 42px;
        background-color: var(--navy-surface);
        border: 1px solid var(--navy-border);
        border-radius: 6px;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 22px;
        line-height: 1;
    }
    .product-title-row {
        display: flex;
        align-items: center;
        gap: 10px;
    }
    .product-title {
        color: #FFFFFF !important;
        font-size: 20px;
        font-weight: 700;
        letter-spacing: -0.02em;
        margin: 0;
        line-height: 1.2;
    }
    .edition-badge {
        background-color: rgba(37, 99, 235, 0.2);
        color: #93C5FD;
        border: 1px solid rgba(147, 197, 253, 0.3);
        font-size: 10px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        padding: 2px 7px;
        border-radius: 4px;
    }
    .product-subtitle {
        color: var(--slate-400);
        font-size: 12.5px;
        font-weight: 400;
        margin-top: 3px;
    }
    .header-meta-group {
        display: flex;
        align-items: center;
        gap: 16px;
        flex-wrap: wrap;
    }
    .meta-tag-item {
        display: flex;
        flex-direction: column;
        align-items: flex-end;
    }
    .meta-tag-lbl {
        font-size: 9.5px;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        color: var(--slate-500);
        font-weight: 600;
    }
    .meta-tag-val {
        font-size: 12px;
        color: #E2E8F0;
        font-weight: 600;
        font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    }
    .status-pill {
        display: inline-flex;
        align-items: center;
        gap: 7px;
        padding: 5px 12px;
        border-radius: 20px;
        font-size: 11.5px;
        font-weight: 600;
        letter-spacing: 0.02em;
    }
    .status-pill-idle {
        background-color: var(--navy-surface);
        border: 1px solid var(--navy-border);
        color: var(--slate-400);
    }
    .status-pill-ready {
        background-color: rgba(37, 99, 235, 0.15);
        border: 1px solid rgba(59, 130, 246, 0.4);
        color: #93C5FD;
    }
    .status-pill-sanitized {
        background-color: rgba(22, 163, 74, 0.15);
        border: 1px solid rgba(34, 197, 94, 0.4);
        color: #86EFAC;
    }
    .status-pill-blocked {
        background-color: rgba(220, 38, 38, 0.15);
        border: 1px solid rgba(239, 68, 68, 0.4);
        color: #FCA5A5;
    }
    .status-pill-review {
        background-color: rgba(217, 119, 6, 0.15);
        border: 1px solid rgba(245, 158, 11, 0.4);
        color: #FDE68A;
    }
    .status-dot-indicator {
        width: 7px;
        height: 7px;
        border-radius: 50%;
        display: inline-block;
    }
    .dot-idle { background-color: var(--slate-500); }
    .dot-ready { background-color: #3B82F6; box-shadow: 0 0 5px #3B82F6; }
    .dot-sanitized { background-color: #22C55E; box-shadow: 0 0 5px #22C55E; }
    .dot-blocked { background-color: #EF4444; box-shadow: 0 0 5px #EF4444; }
    .dot-review { background-color: #F59E0B; box-shadow: 0 0 5px #F59E0B; }

    /* Surface Cards & Containers */
    .soc-surface-card {
        background-color: #FFFFFF;
        border: 1px solid var(--slate-200);
        border-radius: 8px;
        padding: 18px 20px;
        margin-bottom: 16px;
        box-shadow: 0 1px 3px 0 rgba(15, 23, 42, 0.03);
    }
    .soc-section-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        margin-bottom: 12px;
        padding-bottom: 8px;
        border-bottom: 1px solid var(--slate-100);
    }
    .soc-section-title {
        font-size: 13px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        color: var(--slate-700);
        margin: 0;
    }
    .soc-section-desc {
        font-size: 11.5px;
        color: var(--slate-500);
        margin: 0;
    }

    /* Staged Artifact Dossier Card */
    .staged-dossier-card {
        background-color: #FFFFFF;
        border: 1px solid var(--slate-200);
        border-left: 4px solid var(--brand-blue);
        border-radius: 6px;
        padding: 14px 18px;
        margin-top: 10px;
        margin-bottom: 14px;
        display: flex;
        align-items: center;
        justify-content: space-between;
        flex-wrap: wrap;
        gap: 12px;
    }
    .dossier-left {
        display: flex;
        align-items: center;
        gap: 12px;
    }
    .dossier-format-tag {
        background-color: var(--brand-blue-subtle);
        color: var(--brand-blue);
        border: 1px solid #BFDBFE;
        font-size: 11px;
        font-weight: 700;
        padding: 4px 8px;
        border-radius: 4px;
        letter-spacing: 0.05em;
    }
    .dossier-filename {
        font-size: 14px;
        font-weight: 600;
        color: var(--slate-900);
    }
    .dossier-metadata {
        font-size: 12px;
        color: var(--slate-500);
        margin-top: 2px;
        font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    }

    /* 4-Stage Pipeline Tracker */
    .pipeline-grid {
        display: grid;
        grid-template-columns: repeat(4, 1fr);
        gap: 10px;
        margin-bottom: 16px;
    }
    @media (max-width: 900px) {
        .pipeline-grid {
            grid-template-columns: 1fr 1fr;
        }
    }
    .pipeline-stage-cell {
        background-color: #FFFFFF;
        border: 1px solid var(--slate-200);
        border-radius: 6px;
        padding: 12px 14px;
        text-align: left;
        position: relative;
    }
    .stage-complete {
        border-color: #BBF7D0;
        background-color: #F8FCF9;
    }
    .stage-failed {
        border-color: #FECACA;
        background-color: #FDF8F8;
    }
    .stage-review {
        border-color: #FDE68A;
        background-color: #FCFAF5;
    }
    .stage-step-tag {
        font-size: 10px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.06em;
        color: var(--brand-blue);
        margin-bottom: 4px;
    }
    .stage-complete .stage-step-tag { color: var(--state-safe-accent); }
    .stage-failed .stage-step-tag { color: var(--state-blocked-accent); }
    .stage-review .stage-step-tag { color: var(--state-review-accent); }
    .stage-title {
        font-size: 12.5px;
        font-weight: 600;
        color: var(--slate-900);
        margin-bottom: 2px;
    }
    .stage-annotation {
        font-size: 11px;
        color: var(--slate-500);
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
    }

    /* Executive Security Gate Verdict Banner */
    .verdict-banner-container {
        border-radius: 8px;
        padding: 16px 20px;
        margin-bottom: 18px;
        display: flex;
        align-items: flex-start;
        justify-content: space-between;
        flex-wrap: wrap;
        gap: 14px;
    }
    .verdict-sanitized {
        background-color: var(--state-safe-bg);
        border: 1px solid var(--state-safe-border);
    }
    .verdict-blocked {
        background-color: var(--state-blocked-bg);
        border: 1px solid var(--state-blocked-border);
    }
    .verdict-review {
        background-color: var(--state-review-bg);
        border: 1px solid var(--state-review-border);
    }
    .verdict-main {
        display: flex;
        align-items: flex-start;
        gap: 12px;
        max-width: 820px;
    }
    .verdict-symbol {
        font-size: 22px;
        line-height: 1.1;
    }
    .verdict-headline {
        font-size: 15px;
        font-weight: 700;
        margin-bottom: 4px;
    }
    .verdict-sanitized .verdict-headline { color: var(--state-safe-text); }
    .verdict-blocked .verdict-headline { color: var(--state-blocked-text); }
    .verdict-review .verdict-headline { color: var(--state-review-text); }
    .verdict-explanation {
        font-size: 13px;
        line-height: 1.45;
        color: var(--slate-700);
    }
    .verdict-metrics-strip {
        display: flex;
        align-items: center;
        gap: 14px;
        flex-wrap: wrap;
    }
    .verdict-metric-box {
        background-color: #FFFFFF;
        border: 1px solid rgba(15, 23, 42, 0.08);
        border-radius: 6px;
        padding: 6px 12px;
        text-align: center;
        min-width: 80px;
    }
    .v-met-lbl {
        font-size: 10px;
        font-weight: 700;
        text-transform: uppercase;
        color: var(--slate-500);
    }
    .v-met-val {
        font-size: 16px;
        font-weight: 700;
        color: var(--slate-900);
    }

    /* Monospaced Document Preview */
    .sanitized-preview-container {
        background-color: #FFFFFF;
        border: 1px solid var(--slate-200);
        border-radius: 6px;
        padding: 16px;
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
        font-size: 12.5px;
        line-height: 1.65;
        color: #1E293B;
        white-space: pre-wrap;
        max-height: 480px;
        overflow-y: auto;
        box-shadow: inset 0 1px 2px rgba(15, 23, 42, 0.02);
    }

    /* Extracted Block Cards */
    .source-block-card {
        background-color: #FFFFFF;
        border: 1px solid var(--slate-200);
        border-left: 3px solid var(--slate-400);
        border-radius: 4px;
        padding: 10px 14px;
        margin-bottom: 8px;
    }
    .block-card-meta {
        font-size: 11px;
        font-weight: 600;
        color: var(--slate-500);
        margin-bottom: 5px;
        font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    }
    .block-card-text {
        font-size: 12.5px;
        color: var(--slate-800);
        white-space: pre-wrap;
        line-height: 1.5;
    }

    /* Button Polish */
    div.stButton > button:first-child {
        background-color: var(--brand-blue) !important;
        color: #FFFFFF !important;
        font-weight: 600 !important;
        border: 1px solid transparent !important;
        border-radius: 6px !important;
        padding: 7px 16px !important;
        font-size: 13px !important;
        transition: all 0.15s ease-in-out;
    }
    div.stButton > button:first-child:hover {
        background-color: var(--brand-blue-hover) !important;
    }

    div.stDownloadButton > button {
        background-color: #FFFFFF !important;
        color: var(--slate-800) !important;
        border: 1px solid var(--slate-200) !important;
        border-radius: 6px !important;
        font-weight: 600 !important;
        font-size: 12.5px !important;
        padding: 7px 14px !important;
    }
    div.stDownloadButton > button:hover {
        background-color: var(--slate-50) !important;
        border-color: var(--slate-300) !important;
        color: var(--brand-blue) !important;
    }

    /* Streamlit Tabs */
    .stTabs [data-baseweb="tab-list"] {
        gap: 6px;
        border-bottom: 1px solid var(--slate-200);
        padding-bottom: 2px;
    }
    .stTabs [data-baseweb="tab"] {
        padding: 8px 16px;
        font-size: 13px;
        font-weight: 600;
        color: var(--slate-500);
        border-radius: 4px 4px 0 0;
    }
    .stTabs [aria-selected="true"] {
        color: var(--brand-blue) !important;
        border-bottom: 2px solid var(--brand-blue) !important;
    }

    /* File Uploader */
    [data-testid="stFileUploader"] section {
        background-color: #FFFFFF !important;
        border: 1px dashed var(--slate-300) !important;
        border-radius: 6px !important;
        padding: 14px 18px !important;
    }
    [data-testid="stFileUploader"] section:hover {
        border-color: var(--brand-blue) !important;
    }

    /* Hide unnecessary Streamlit widgets */
    [data-testid="stFileChips"] > div > div:not(:last-child),
    [data-testid="stFileChips"] > *:first-child > *:not(:last-child),
    div[data-testid="stFileChips"] > div > div:not(:last-child),
    [data-testid="stFileUploader"] [data-testid="stFileChip"]:not(:last-child),
    [data-testid="stElementToolbar"],
    [data-testid="stDataFrameToolbar"],
    .stDataFrameToolbar,
    [data-testid="StyledFullScreenButton"],
    button[title="View fullscreen"],
    button[title="Download as CSV"],
    button[title="Search"],
    [data-testid="stHeaderActionElements"],
    a.header-anchor,
    .header-anchor {
        display: none !important;
        visibility: hidden !important;
    }

    /* Clean Empty State Display */
    .capstone-empty-box {
        background-color: #FFFFFF;
        border: 1px dashed var(--slate-200);
        border-radius: 8px;
        padding: 32px 20px;
        text-align: center;
        margin-top: 10px;
        margin-bottom: 16px;
    }
    .empty-icon {
        font-size: 28px;
        color: var(--slate-400);
        margin-bottom: 8px;
    }
    .empty-title {
        font-size: 14px;
        font-weight: 600;
        color: var(--slate-800);
        margin-bottom: 4px;
    }
    .empty-sub {
        font-size: 12.5px;
        color: var(--slate-500);
        max-width: 500px;
        margin: 0 auto;
        line-height: 1.5;
    }
</style>
"""
st.markdown(CAPSTONE_SOC_CSS, unsafe_allow_html=True)


# ------------------------------------------------------------------------------
# 2. PIPELINE & HELPER INITIALIZATION
# ------------------------------------------------------------------------------
@st.cache_resource
def get_pipeline() -> GatewayPipeline:
    """Initialize singleton GatewayPipeline instance."""
    return GatewayPipeline()


def format_bytes(size: int) -> str:
    """Format bytes into readable representation."""
    if size < 1024:
        return f"{size} B"
    elif size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size / (1024 * 1024):.2f} MB"


# Session State Management
if "analysis_results" not in st.session_state:
    st.session_state.analysis_results = []
if "active_view" not in st.session_state:
    st.session_state.active_view = "inspection"
if "last_active_file_signature" not in st.session_state:
    st.session_state.last_active_file_signature = None
if "active_sample_file" not in st.session_state:
    st.session_state.active_sample_file = None


# ------------------------------------------------------------------------------
# 3. HEADER RENDERING
# ------------------------------------------------------------------------------
def render_header(status_label: str, status_class: str, dot_class: str):
    """Render compact, technical application shell header."""
    col_hdr, col_nav = st.columns([5, 2])

    with col_hdr:
        st.markdown(
            f"""
            <header class="capstone-header">
                <div class="header-brand-block">
                    <div class="header-icon-badge">🛡️</div>
                    <div>
                        <div class="product-title-row">
                            <h1 class="product-title">PII SECURITY GATEWAY</h1>
                            <span class="edition-badge">CAPSTONE EDITION • v2.4</span>
                        </div>
                        <div class="product-subtitle">
                            Zero-Trust Pre-LLM Document Privacy, Semantic Redaction & Fail-Closed Validation Engine
                        </div>
                    </div>
                </div>
                <div class="header-meta-group">
                    <div class="meta-tag-item">
                        <span class="meta-tag-lbl">ISOLATION</span>
                        <span class="meta-tag-val">LOCAL RAM</span>
                    </div>
                    <div class="meta-tag-item">
                        <span class="meta-tag-lbl">DETECTION ENGINE</span>
                        <span class="meta-tag-val">NER+REGEX+RULES</span>
                    </div>
                    <div class="status-pill {status_class}">
                        <span class="status-dot-indicator {dot_class}"></span>
                        <span>{status_label}</span>
                    </div>
                </div>
            </header>
            """,
            unsafe_allow_html=True,
        )

    with col_nav:
        st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)
        c_v1, c_v2 = st.columns(2)
        with c_v1:
            if st.button("🔬 Gateway", use_container_width=True, help="Switch to Document Inspection Workspace"):
                st.session_state.active_view = "inspection"
                st.rerun()
        with c_v2:
            if st.button("📐 Architecture", use_container_width=True, help="Switch to Technical & Security Architecture Guide"):
                st.session_state.active_view = "architecture"
                st.rerun()


# ------------------------------------------------------------------------------
# 4. VIEW ROUTING: ARCHITECTURE vs INSPECTION WORKSPACE
# ------------------------------------------------------------------------------
if st.session_state.get("active_view") == "architecture":
    # --------------------------------------------------------------------------
    # ARCHITECTURE & SECURITY SPECIFICATION VIEW
    # --------------------------------------------------------------------------
    render_header("SPECIFICATION MODE", "status-pill-idle", "dot-idle")

    st.markdown(
        """
        <div class="soc-surface-card" style="border-left: 4px solid var(--brand-blue); line-height: 1.6;">
            <div class="soc-section-header">
                <div>
                    <h3 class="soc-section-title" style="color: var(--brand-blue);">Pre-LLM Privacy Gateway Architecture & Formal Specification</h3>
                    <p class="soc-section-desc">Zero-Trust Local Ingestion Pipeline • Academic Capstone Engineering Standard</p>
                </div>
            </div>

            <h4 style="font-size: 14.5px; color: var(--slate-900); margin-top: 14px; margin-bottom: 8px;">1. Problem Formulation & Security Threat Model</h4>
            <p style="font-size: 13px; color: var(--slate-600); margin-bottom: 12px;">
                Modern enterprise environments frequently integrate Large Language Models (LLMs) to summarize contracts, analyze incident reports, and query internal knowledge bases. However, unstructured corporate artifacts routinely contain Personally Identifiable Information (PII) including full names, corporate email addresses, direct dial numbers, government IDs (SSN, PAN, Aadhaar), and payment credentials. Transmitting unredacted text to public or vendor-hosted LLM endpoints introduces catastrophic privacy violations under GDPR (Art. 25 & 32), HIPAA (§164.514 Safe Harbor), and the EU AI Act.
            </p>

            <h4 style="font-size: 14.5px; color: var(--slate-900); margin-top: 16px; margin-bottom: 8px;">2. Four-Stage Deterministic Security Pipeline</h4>
            <div style="background-color: var(--slate-50); border: 1px solid var(--slate-200); border-radius: 6px; padding: 14px 16px; margin-bottom: 14px;">
                <ol style="margin: 0; padding-left: 20px; font-size: 13px; color: var(--slate-700); line-height: 1.7;">
                    <li><b>Stage 1 — Structural Decomposition & Ingestion:</b> Multi-format parsing (PDF via PyPDF/pdfplumber, Word DOCX via python-docx, PPTX via python-pptx, and plain text) splits artifacts into ordered, boundary-preserving structural blocks (<code>page_1_block_2</code>).</li>
                    <li><b>Stage 2 — Corroborating Tri-Engine Detection:</b>
                        <ul style="margin: 4px 0;">
                            <li><i>Deterministic Syntactic Matcher:</i> High-precision RFC-compliant regular expressions for emails, E.164 phone formats, credit cards (Luhn-verified), IP addresses, and government IDs.</li>
                            <li><i>Statistical Named Entity Recognition (NER):</i> Transformer/heuristic spaCy NLP models specialized for personal name extraction, fortified with domain validation filters to eliminate technical and mathematical false positives.</li>
                            <li><i>Context-Proximity Rules:</i> Heuristic lexical proximity evaluation for structured fields (e.g., <code>Employee ID:</code>, <code>Contact:</code>).</li>
                        </ul>
                    </li>
                    <li><b>Stage 3 — Consistent Semantic Redaction:</b> Instead of destructive masking (e.g. <code>[REDACTED]</code>) which destroys linguistic context, the gateway generates deterministic surrogate keys (e.g. <code>[PERSON_001]</code>, <code>[EMAIL_001]</code>). Recurrences of the same identity receive identical surrogate tokens across pages and slides, preserving conversational co-reference resolution for AI reasoning.</li>
                    <li><b>Stage 4 — Independent Fail-Closed Post-Validation:</b> A secondary, independent scan is executed across the sanitized text blocks. If even a single residual PII entity is identified, the gateway immediately fails closed (status: <b>BLOCKED</b>). Downstream transmission is permitted strictly when zero residual PII is certified.</li>
                </ol>
            </div>

            <h4 style="font-size: 14.5px; color: var(--slate-900); margin-top: 16px; margin-bottom: 8px;">3. Cryptographic & Privacy Guarantees</h4>
            <table style="width: 100%; border-collapse: collapse; font-size: 12.5px; margin-bottom: 14px;">
                <tr style="border-bottom: 1px solid var(--slate-200); background-color: var(--slate-100);">
                    <th style="padding: 8px 10px; text-align: left; color: var(--slate-700);">Security Requirement</th>
                    <th style="padding: 8px 10px; text-align: left; color: var(--slate-700);">Implementation Mechanism</th>
                    <th style="padding: 8px 10px; text-align: left; color: var(--slate-700);">Verification Standard</th>
                </tr>
                <tr style="border-bottom: 1px solid var(--slate-200);">
                    <td style="padding: 8px 10px; font-weight: 600;">Host Boundary Isolation</td>
                    <td style="padding: 8px 10px; color: var(--slate-600);">100% In-Memory Processing (No Cloud Egress)</td>
                    <td style="padding: 8px 10px; color: var(--state-safe-text); font-weight: 600;">Zero External API Network Calls</td>
                </tr>
                <tr style="border-bottom: 1px solid var(--slate-200);">
                    <td style="padding: 8px 10px; font-weight: 600;">Fail-Closed Enforcement</td>
                    <td style="padding: 8px 10px; color: var(--slate-600);">Empty file, corrupt blocks, or validation leaks halt release</td>
                    <td style="padding: 8px 10px; color: var(--state-safe-text); font-weight: 600;">Status = BLOCKED on Any Leak</td>
                </tr>
                <tr style="border-bottom: 1px solid var(--slate-200);">
                    <td style="padding: 8px 10px; font-weight: 600;">Co-Reference Integrity</td>
                    <td style="padding: 8px 10px; color: var(--slate-600);">Deterministic Entity-to-Surrogate Token Registry</td>
                    <td style="padding: 8px 10px; color: var(--state-safe-text); font-weight: 600;">Identical Tag Across Document Blocks</td>
                </tr>
                <tr>
                    <td style="padding: 8px 10px; font-weight: 600;">Source Traceability</td>
                    <td style="padding: 8px 10px; color: var(--slate-600);">Explicit structural coordinates per detected entity</td>
                    <td style="padding: 8px 10px; color: var(--state-safe-text); font-weight: 600;">Forensic Audit Traceability Matrix</td>
                </tr>
            </table>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if st.button("← Return to Gateway Workspace", type="primary"):
        st.session_state.active_view = "inspection"
        st.rerun()

else:
    # --------------------------------------------------------------------------
    # MAIN GATEWAY INSPECTION WORKSPACE
    # --------------------------------------------------------------------------
    results: List[DocumentAnalysisResult] = st.session_state.get("analysis_results", [])
    has_results = bool(results)
    active_sample = st.session_state.get("active_sample_file")

    # Determine Header Live State
    if has_results:
        active_doc = results[0]
        stat_val = active_doc.security_status.value if hasattr(active_doc.security_status, "value") else str(active_doc.security_status)
        if stat_val == "SANITIZED":
            hdr_status_lbl, hdr_status_cls, hdr_dot_cls = "GATEWAY: SANITIZED (PASS)", "status-pill-sanitized", "dot-sanitized"
        elif stat_val == "BLOCKED":
            hdr_status_lbl, hdr_status_cls, hdr_dot_cls = "GATEWAY: BLOCKED (FAIL-CLOSED)", "status-pill-blocked", "dot-blocked"
        else:
            hdr_status_lbl, hdr_status_cls, hdr_dot_cls = "GATEWAY: REVIEW REQUIRED", "status-pill-review", "dot-review"
    elif active_sample or st.session_state.get("last_active_file_signature"):
        hdr_status_lbl, hdr_status_cls, hdr_dot_cls = "ARTIFACT STAGED (READY)", "status-pill-ready", "dot-ready"
    else:
        hdr_status_lbl, hdr_status_cls, hdr_dot_cls = "STANDBY • READY FOR INGESTION", "status-pill-idle", "dot-idle"

    render_header(hdr_status_lbl, hdr_status_cls, hdr_dot_cls)

    # ==========================================================================
    # WORKSPACE PARTITION: 1. INGESTION & STAGING CONSOLE
    # ==========================================================================
    st.markdown(
        """
        <div class="soc-section-header">
            <div>
                <h3 class="soc-section-title">1. Artifact Ingestion & Staging</h3>
                <p class="soc-section-desc">Select or upload business evidence artifact for local pre-LLM security inspection</p>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    col_ingest_main, col_ingest_side = st.columns([3, 1])

    with col_ingest_main:
        uploaded_files = st.file_uploader(
            "Upload Document Artifact (Supported: PDF, DOCX, PPTX, TXT)",
            type=["pdf", "docx", "pptx", "txt"],
            accept_multiple_files=True,
            key="evidence_uploader",
            label_visibility="collapsed",
            help="Files are processed exclusively in host RAM. No data is stored externally.",
        )

    # Active file state management
    active_file = None
    if uploaded_files:
        active_file = uploaded_files[-1]
        active_sig = f"{active_file.name}_{active_file.size}"
        if st.session_state.get("last_active_file_signature") != active_sig:
            st.session_state.analysis_results = []
            st.session_state.last_active_file_signature = active_sig
            st.session_state.active_sample_file = None
    else:
        if not st.session_state.get("active_sample_file"):
            if st.session_state.get("last_active_file_signature") is not None:
                st.session_state.analysis_results = []
                st.session_state.last_active_file_signature = None

    with col_ingest_side:
        sample_options = {
            "Executive Briefing (PDF)": "Executive_Briefing.pdf",
            "Financial Org Pack (PPTX)": "Cadence_Financial_Group_Org_Pack.pptx",
            "HR Incident Report (DOCX)": "HR_Incident_Report.docx",
            "Customer Support Log (TXT)": "Customer_Support_Evidence.txt",
        }
        selected_sample_label = st.selectbox(
            "Load Benchmark Test Artifact:",
            options=list(sample_options.keys()),
            key="sample_selector"
        )
        if st.button("📁 Stage Sample Artifact", use_container_width=True, help="Load pre-built test document from sample corpus"):
            sample_dir = Path(__file__).resolve().parent / "sample_documents"
            sample_file_path = sample_dir / sample_options[selected_sample_label]
            if sample_file_path.exists():
                st.session_state.active_sample_file = (sample_file_path.name, sample_file_path.read_bytes())
                st.session_state.last_active_file_signature = f"sample_{sample_file_path.name}"
                st.session_state.analysis_results = []
                st.rerun()

    # Active Staged Artifact Card
    staged_payload: Optional[Tuple[str, bytes]] = None
    staged_meta: Optional[Dict[str, str]] = None

    if active_file is not None:
        staged_payload = (active_file.name, active_file.getvalue())
        staged_meta = {
            "name": active_file.name,
            "ext": Path(active_file.name).suffix.replace(".", "").upper() or "FILE",
            "size": format_bytes(active_file.size),
            "source": "Uploaded Artifact",
            "hash": calculate_file_hash(active_file.getvalue()),
        }
    elif st.session_state.get("active_sample_file") is not None:
        s_name, s_bytes = st.session_state.active_sample_file
        staged_payload = (s_name, s_bytes)
        staged_meta = {
            "name": s_name,
            "ext": Path(s_name).suffix.replace(".", "").upper() or "FILE",
            "size": format_bytes(len(s_bytes)),
            "source": "Benchmark Sample Corpus",
            "hash": calculate_file_hash(s_bytes),
        }

    if staged_meta:
        col_dossier, col_cta = st.columns([4, 1.5])
        with col_dossier:
            st.markdown(
                f"""
                <div class="staged-dossier-card">
                    <div class="dossier-left">
                        <span class="dossier-format-tag">{staged_meta['ext']}</span>
                        <div>
                            <div class="dossier-filename">{staged_meta['name']}</div>
                            <div class="dossier-metadata">
                                Source: {staged_meta['source']} • Size: {staged_meta['size']} • SHA-256: <code>{staged_meta['hash']}</code>
                            </div>
                        </div>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        with col_cta:
            st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)
            run_inspection_btn = st.button("⚡ Run Security Pipeline", type="primary", use_container_width=True)

        if run_inspection_btn and staged_payload:
            fname, fbytes = staged_payload
            prog_bar = st.progress(0, text=f"Initializing security pipeline on {fname}...")
            
            pipeline = get_pipeline()
            prog_bar.progress(30, text="1/4 Decomposing structural document blocks...")
            time.sleep(0.05)
            prog_bar.progress(60, text="2/4 Executing hybrid multi-engine PII discovery...")
            time.sleep(0.05)
            prog_bar.progress(85, text="3/4 Applying consistent semantic redaction...")
            
            res = pipeline.process_document(file_bytes=fbytes, file_name=fname)
            prog_bar.progress(100, text="4/4 Post-redaction fail-closed validation verified.")
            time.sleep(0.05)
            prog_bar.empty()
            
            st.session_state.analysis_results = [res]
            st.rerun()

    else:
        st.markdown(
            """
            <div class="capstone-empty-box">
                <div class="empty-icon">📂</div>
                <div class="empty-title">No Artifact Staged for Security Inspection</div>
                <div class="empty-sub">
                    Upload a business document (PDF, Word DOCX, Slides PPTX, or Log TXT) or select a benchmark sample artifact to begin the 4-stage Zero-Trust verification process.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # ==========================================================================
    # WORKSPACE PARTITION: 2. SECURITY PIPELINE STAGES & VERDICT
    # ==========================================================================
    if has_results:
        selected_doc = results[0]
        vr = selected_doc.validation_result
        doc_stat_val = selected_doc.security_status.value if hasattr(selected_doc.security_status, "value") else str(selected_doc.security_status)
        replacements_count = selected_doc.redaction_result.replacements_count if selected_doc.redaction_result else 0
        residual_count = len(vr.residual_findings) if vr else 0

        st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)
        st.markdown(
            """
            <div class="soc-section-header">
                <div>
                    <h3 class="soc-section-title">2. Pipeline Execution & Gate Verdict</h3>
                    <p class="soc-section-desc">Deterministic 4-stage pipeline outputs and authoritative post-validation security decision</p>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # 4-Stage Technical Progression Grid
        stage4_cls = "stage-complete" if (vr and vr.passed) else ("stage-failed" if (vr and not vr.passed) else "pipeline-stage-cell")
        stage4_desc = "0 Residual PII (Passed)" if (vr and vr.passed) else (f"{residual_count} Leaks Detected (Failed)" if vr else "Pending")

        st.markdown(
            f"""
            <div class="pipeline-grid">
                <div class="pipeline-stage-cell stage-complete">
                    <div class="stage-step-tag">Stage 01 • Extraction</div>
                    <div class="stage-title">Structural Parsing</div>
                    <div class="stage-annotation">{len(selected_doc.blocks)} blocks preserved</div>
                </div>
                <div class="pipeline-stage-cell stage-complete">
                    <div class="stage-step-tag">Stage 02 • Detection</div>
                    <div class="stage-title">Tri-Engine Discovery</div>
                    <div class="stage-annotation">{len(selected_doc.pii_findings)} entities flagged</div>
                </div>
                <div class="pipeline-stage-cell stage-complete">
                    <div class="stage-step-tag">Stage 03 • Redaction</div>
                    <div class="stage-title">Semantic Replacement</div>
                    <div class="stage-annotation">{replacements_count} surrogate keys assigned</div>
                </div>
                <div class="pipeline-stage-cell {stage4_cls}">
                    <div class="stage-step-tag">Stage 04 • Validation</div>
                    <div class="stage-title">Post-Scan Gate</div>
                    <div class="stage-annotation">{stage4_desc}</div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # Executive Security Gate Verdict Banner
        high_risk_count = sum(1 for f in selected_doc.pii_findings if (f.severity.value if hasattr(f.severity, "value") else str(f.severity)) in ("CRITICAL", "HIGH"))

        if doc_stat_val == SecurityStatus.SANITIZED.value:
            st.markdown(
                f"""
                <div class="verdict-banner-container verdict-sanitized">
                    <div class="verdict-main">
                        <div class="verdict-symbol">✓</div>
                        <div>
                            <div class="verdict-headline">SECURITY VERDICT: SANITIZED — APPROVED FOR DOWNSTREAM LLM INGESTION</div>
                            <div class="verdict-explanation">
                                Post-redaction secondary validation verified zero residual PII entities across all {len(selected_doc.blocks)} extracted blocks. Semantic surrogate keys maintain linguistic co-reference resolution for downstream AI reasoning while certifying complete privacy.
                            </div>
                        </div>
                    </div>
                    <div class="verdict-metrics-strip">
                        <div class="verdict-metric-box">
                            <div class="v-met-lbl">Latency</div>
                            <div class="v-met-val">{selected_doc.processing_time_ms:.1f}ms</div>
                        </div>
                        <div class="verdict-metric-box">
                            <div class="v-met-lbl">PII Found</div>
                            <div class="v-met-val">{len(selected_doc.pii_findings)}</div>
                        </div>
                        <div class="verdict-metric-box">
                            <div class="v-met-lbl">High-Risk</div>
                            <div class="v-met-val">{high_risk_count}</div>
                        </div>
                        <div class="verdict-metric-box">
                            <div class="v-met-lbl">Residual</div>
                            <div class="v-met-val" style="color: var(--state-safe-text);">0</div>
                        </div>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        elif doc_stat_val == SecurityStatus.BLOCKED.value:
            st.markdown(
                f"""
                <div class="verdict-banner-container verdict-blocked">
                    <div class="verdict-main">
                        <div class="verdict-symbol">✕</div>
                        <div>
                            <div class="verdict-headline">SECURITY VERDICT: BLOCKED — FAIL-CLOSED ENFORCEMENT TRIGGERED</div>
                            <div class="verdict-explanation">
                                Post-redaction re-scan detected residual PII entities or extraction anomaly. Downstream transmission to LLMs is halted immediately to prevent sensitive corporate data leakage.
                            </div>
                        </div>
                    </div>
                    <div class="verdict-metrics-strip">
                        <div class="verdict-metric-box">
                            <div class="v-met-lbl">Latency</div>
                            <div class="v-met-val">{selected_doc.processing_time_ms:.1f}ms</div>
                        </div>
                        <div class="verdict-metric-box">
                            <div class="v-met-lbl">PII Found</div>
                            <div class="v-met-val">{len(selected_doc.pii_findings)}</div>
                        </div>
                        <div class="verdict-metric-box">
                            <div class="v-met-lbl">Residual</div>
                            <div class="v-met-val" style="color: var(--state-blocked-text);">{residual_count}</div>
                        </div>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        else:
            st.markdown(
                f"""
                <div class="verdict-banner-container verdict-review">
                    <div class="verdict-main">
                        <div class="verdict-symbol">⚠</div>
                        <div>
                            <div class="verdict-headline">SECURITY VERDICT: REVIEW REQUIRED — MANUAL CLEARANCE MANDATED</div>
                            <div class="verdict-explanation">
                                Document contains low-confidence detections or unscanned embedded elements requiring compliance analyst verification prior to release.
                            </div>
                        </div>
                    </div>
                    <div class="verdict-metrics-strip">
                        <div class="verdict-metric-box">
                            <div class="v-met-lbl">Latency</div>
                            <div class="v-met-val">{selected_doc.processing_time_ms:.1f}ms</div>
                        </div>
                        <div class="verdict-metric-box">
                            <div class="v-met-lbl">PII Found</div>
                            <div class="v-met-val">{len(selected_doc.pii_findings)}</div>
                        </div>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        # ======================================================================
        # WORKSPACE PARTITION: 3. INVESTIGATION CONSOLE & ANALYSIS TABS
        # ======================================================================
        st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)
        st.markdown(
            """
            <div class="soc-section-header">
                <div>
                    <h3 class="soc-section-title">3. Security Operations & Investigation Console</h3>
                    <p class="soc-section-desc">Detailed entity audit, sanitized artifact view, validation proof, and source traceability</p>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        tab_findings, tab_sanitized, tab_validation, tab_traceability, tab_blocks, tab_exports = st.tabs([
            "🔍 PII Findings Log",
            "📄 Sanitized Artifact & Surrogate Keys",
            "🛡️ Post-Redaction Validation Audit",
            "🧭 Structural Traceability Matrix",
            "📑 Raw Extracted Blocks",
            "📋 Compliance Export (JSON/CSV)",
        ])

        # TAB 1: PII FINDINGS LOG & TRIAGE
        with tab_findings:
            col_filter_sev, col_filter_cat, col_unmask = st.columns([1.5, 1.5, 2])
            with col_filter_sev:
                sev_choice = st.selectbox(
                    "Filter Severity:",
                    ["All Severities", "CRITICAL", "HIGH", "MEDIUM", "LOW"],
                    key="soc_sev_filter"
                )
            with col_filter_cat:
                all_cats = sorted(list({f.pii_type.value if hasattr(f.pii_type, "value") else str(f.pii_type) for f in selected_doc.pii_findings}))
                cat_choice = st.selectbox(
                    "Filter Classification:",
                    ["All Classifications"] + all_cats,
                    key="soc_cat_filter"
                )
            with col_unmask:
                st.markdown("<div style='height: 28px;'></div>", unsafe_allow_html=True)
                reveal_raw = st.checkbox(
                    "Analyst Clearance: Reveal Unmasked Values",
                    value=False,
                    help="Controlled access for authorized SOC analysts to inspect plaintext values."
                )

            filtered_rows = []
            for f in selected_doc.pii_findings:
                f_sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
                f_type = f.pii_type.value if hasattr(f.pii_type, "value") else str(f.pii_type)

                if sev_choice != "All Severities" and f_sev != sev_choice:
                    continue
                if cat_choice != "All Classifications" and f_type != cat_choice:
                    continue

                display_val = f.text if reveal_raw else f.masked_text
                filtered_rows.append({
                    "Severity": f_sev,
                    "Classification": f_type,
                    "Confidence": f"{f.confidence * 100:.1f}% ({f.confidence_level.value})",
                    "Method": " + ".join(f.detection_method),
                    "Location": f.location,
                    "Entity Representation": display_val,
                    "Risk Rationale": f.explanation,
                })

            if filtered_rows:
                st.dataframe(pd.DataFrame(filtered_rows), use_container_width=True, hide_index=True)
                st.markdown(f"<div style='font-size: 11.5px; color: var(--slate-500); margin-top: 4px;'>Displaying <b>{len(filtered_rows)}</b> of <b>{len(selected_doc.pii_findings)}</b> verified findings.</div>", unsafe_allow_html=True)
            else:
                if selected_doc.pii_findings:
                    st.info("No findings match the selected filter criteria.")
                else:
                    st.success("Zero PII entities detected across this document.")

        # TAB 2: SANITIZED ARTIFACT & SURROGATE KEYS
        with tab_sanitized:
            if selected_doc.redaction_result and selected_doc.redaction_result.redacted_full_text:
                col_text_prev, col_dict_prev = st.columns([3, 2])

                with col_text_prev:
                    st.markdown("<div style='font-size: 12px; font-weight: 600; color: var(--slate-700); margin-bottom: 6px;'>Sanitized Full-Text Output (Semantic Surrogate Tokens Preserved):</div>", unsafe_allow_html=True)
                    st.markdown(f'<div class="sanitized-preview-container">{selected_doc.redaction_result.redacted_full_text}</div>', unsafe_allow_html=True)

                    st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)
                    if doc_stat_val == SecurityStatus.SANITIZED.value:
                        st.download_button(
                            label=f"⬇ Download Sanitized Document ({Path(selected_doc.file_name).stem}_sanitized.txt)",
                            data=selected_doc.redaction_result.redacted_full_text,
                            file_name=f"{Path(selected_doc.file_name).stem}_sanitized.txt",
                            mime="text/plain",
                        )
                    else:
                        st.warning("⚠️ Sanitized artifact download is locked because post-redaction validation did not certify clean status.")

                with col_dict_prev:
                    st.markdown("<div style='font-size: 12px; font-weight: 600; color: var(--slate-700); margin-bottom: 6px;'>Deterministic Surrogate Key Mapping Registry:</div>", unsafe_allow_html=True)
                    mapping_entries = []
                    for raw_key, tag in selected_doc.redaction_result.entity_mappings.items():
                        mapping_entries.append({
                            "Surrogate Key": tag,
                            "Masked Entity": raw_key if reveal_raw else f"•••••••• ({len(raw_key)} chars)",
                            "Co-Reference Standard": "Deterministic 1:1 Tag",
                        })
                    if mapping_entries:
                        st.dataframe(pd.DataFrame(mapping_entries), use_container_width=True, hide_index=True)
                        st.markdown("<div style='font-size: 11px; color: var(--slate-500); margin-top: 4px;'>Recurring mentions of the same identity map to identical surrogate tokens across pages.</div>", unsafe_allow_html=True)
                    else:
                        st.info("No surrogate keys generated.")
            else:
                st.info("No redaction outputs available.")

        # TAB 3: POST-REDACTION VALIDATION AUDIT
        with tab_validation:
            if vr:
                stat_badge_color = "var(--state-safe-text)" if vr.passed else "var(--state-blocked-text)"
                st.markdown(
                    f"""
                    <div class="soc-surface-card" style="padding: 16px;">
                        <table style="width: 100%; border-collapse: collapse; font-size: 13px;">
                            <tr style="border-bottom: 1px solid var(--slate-200);">
                                <td style="padding: 8px 0; color: var(--slate-600); font-weight: 600;">Secondary Validation Gate:</td>
                                <td style="padding: 8px 0; font-weight: 700; color: {stat_badge_color};">{'PASSED (ZERO RESIDUAL PII)' if vr.passed else 'FAILED (RESIDUAL DETECTIONS FOUND)'}</td>
                            </tr>
                            <tr style="border-bottom: 1px solid var(--slate-200);">
                                <td style="padding: 8px 0; color: var(--slate-600); font-weight: 600;">Residual PII Count:</td>
                                <td style="padding: 8px 0; font-weight: 700; color: var(--slate-900);">{len(vr.residual_findings)} entities</td>
                            </tr>
                            <tr style="border-bottom: 1px solid var(--slate-200);">
                                <td style="padding: 8px 0; color: var(--slate-600); font-weight: 600;">Fail-Closed Security Verdict:</td>
                                <td style="padding: 8px 0; font-weight: 700; color: var(--slate-900);">{vr.status.value}</td>
                            </tr>
                            <tr>
                                <td style="padding: 8px 0; color: var(--slate-600); font-weight: 600;">Enforced Security Rule:</td>
                                <td style="padding: 8px 0; color: var(--slate-700);">{vr.validation_message}</td>
                            </tr>
                        </table>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

                if vr.residual_findings:
                    st.error(f"✕ Quarantine Alert: {len(vr.residual_findings)} residual PII entities detected during secondary audit:")
                    residual_rows = []
                    for rf in vr.residual_findings:
                        residual_rows.append({
                            "Location": rf.location,
                            "Classification": rf.pii_type.value if hasattr(rf.pii_type, "value") else str(rf.pii_type),
                            "Residual Plaintext": rf.text,
                            "Confidence": f"{rf.confidence * 100:.1f}%",
                        })
                    st.dataframe(pd.DataFrame(residual_rows), use_container_width=True, hide_index=True)
                else:
                    st.success("✓ Secondary re-scan certified 0 residual PII leaks. All original structural boundaries maintained.")
            else:
                st.info("Validation audit logs unavailable.")

        # TAB 4: STRUCTURAL TRACEABILITY MATRIX
        with tab_traceability:
            if selected_doc.pii_findings and selected_doc.redaction_result:
                traceability_rows = []
                for f in selected_doc.pii_findings:
                    assigned_tag = selected_doc.redaction_result.entity_mappings.get(f.text.strip(), "N/A")
                    traceability_rows.append({
                        "Source Location": f.location,
                        "PII Classification": f.pii_type.value if hasattr(f.pii_type, "value") else str(f.pii_type),
                        "Confidence Score": f"{f.confidence * 100:.1f}% ({f.confidence_level.value})",
                        "Corroborating Engine": " + ".join(f.detection_method),
                        "Surrogate Token Assigned": assigned_tag,
                        "Risk Justification": f.explanation,
                    })
                st.dataframe(pd.DataFrame(traceability_rows), use_container_width=True, hide_index=True)
            else:
                st.info("Traceability matrix records unavailable.")

        # TAB 5: RAW EXTRACTED BLOCKS
        with tab_blocks:
            st.markdown(f"<div style='font-size: 12px; color: var(--slate-500); margin-bottom: 10px;'>Preserved structural blocks for <b>{selected_doc.file_name}</b> (Retained in local memory):</div>", unsafe_allow_html=True)
            for b in selected_doc.blocks:
                st.markdown(
                    f"""
                    <div class="source-block-card">
                        <div class="block-card-meta">Coordinate: {b.location} | Type: {b.block_type} | Index: {b.order}</div>
                        <div class="block-card-text">{b.text}</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

        # TAB 6: COMPLIANCE EXPORTS
        with tab_exports:
            st.markdown("<div style='font-size: 13px; font-weight: 600; color: var(--slate-700); margin-bottom: 8px;'>Export SIEM-Ready Audit Telemetry & Forensic Traceability Matrix:</div>", unsafe_allow_html=True)
            c_exp1, c_exp2 = st.columns(2)
            with c_exp1:
                json_data = ReportGenerator.generate_json_report(results)
                st.download_button(
                    label="⬇ Export Security Audit Dossier (JSON)",
                    data=json_data,
                    file_name="pii_security_gateway_audit_dossier.json",
                    mime="application/json",
                    use_container_width=True,
                )
            with c_exp2:
                csv_data = ReportGenerator.generate_csv_findings(results)
                st.download_button(
                    label="⬇ Export Findings Traceability Matrix (CSV)",
                    data=csv_data,
                    file_name="pii_findings_traceability_matrix.csv",
                    mime="text/csv",
                    use_container_width=True,
                )
