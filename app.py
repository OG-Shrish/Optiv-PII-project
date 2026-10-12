"""PII Security Gateway - Pre-LLM Security Gateway & Document Sanitization Pipeline.

Streamlit Application providing local, explainable PII detection, consistent semantic
redaction, and fail-closed post-redaction validation.
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

# Professional Corporate Security Theme CSS
CUSTOM_CSS = """
<style>
    /* Dark Navy & Slate Security Palette */
    :root {
        --bg-main: #0b132b;
        --card-bg: #1c2541;
        --card-border: #2e3a59;
        --text-primary: #f8fafc;
        --text-secondary: #94a3b8;
        --accent-blue: #38bdf8;
        --status-safe-bg: #064e3b;
        --status-safe-text: #34d399;
        --status-safe-border: #059669;
        --status-blocked-bg: #7f1d1d;
        --status-blocked-text: #f87171;
        --status-blocked-border: #dc2626;
        --status-review-bg: #78350f;
        --status-review-text: #fbbf24;
        --status-review-border: #d97706;
    }

    .stApp {
        background-color: #0d1527;
        color: #f1f5f9;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    }

    /* Header styling */
    .header-container {
        background: linear-gradient(135deg, #0b132b 0%, #1c2541 100%);
        border: 1px solid #2e3a59;
        border-radius: 8px;
        padding: 24px 30px;
        margin-bottom: 24px;
    }
    .header-title {
        font-size: 26px;
        font-weight: 700;
        color: #ffffff;
        letter-spacing: -0.5px;
        margin-bottom: 6px;
        display: flex;
        align-items: center;
        gap: 12px;
    }
    .header-subtitle {
        font-size: 14px;
        color: #94a3b8;
        margin-bottom: 12px;
    }
    .security-badge {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        padding: 4px 10px;
        background-color: #1e293b;
        border: 1px solid #334155;
        border-radius: 4px;
        font-size: 11px;
        font-weight: 600;
        color: #38bdf8;
        letter-spacing: 0.5px;
        text-transform: uppercase;
    }

    /* Metric Cards */
    .metric-card {
        background-color: #162035;
        border: 1px solid #28354f;
        border-radius: 8px;
        padding: 18px 20px;
        text-align: left;
    }
    .metric-label {
        font-size: 12px;
        text-transform: uppercase;
        letter-spacing: 0.8px;
        color: #94a3b8;
        margin-bottom: 8px;
        font-weight: 600;
    }
    .metric-value {
        font-size: 28px;
        font-weight: 700;
        color: #ffffff;
        line-height: 1.2;
    }

    /* Status Pills */
    .status-pill {
        display: inline-block;
        padding: 4px 12px;
        border-radius: 4px;
        font-weight: 700;
        font-size: 12px;
        letter-spacing: 0.5px;
    }
    .status-sanitized {
        background-color: #064e3b;
        color: #34d399;
        border: 1px solid #059669;
    }
    .status-blocked {
        background-color: #7f1d1d;
        color: #f87171;
        border: 1px solid #dc2626;
    }
    .status-review {
        background-color: #78350f;
        color: #fbbf24;
        border: 1px solid #d97706;
    }

    /* Content Boxes */
    .content-box {
        background-color: #121b2d;
        border: 1px solid #23304a;
        border-radius: 6px;
        padding: 16px;
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
        font-size: 13px;
        line-height: 1.6;
        color: #cbd5e1;
        white-space: pre-wrap;
        max-height: 420px;
        overflow-y: auto;
    }

    /* Severity badges */
    .badge-critical {
        background-color: #450a0a;
        color: #fca5a5;
        border: 1px solid #991b1b;
        padding: 2px 6px;
        border-radius: 3px;
        font-size: 11px;
        font-weight: 700;
    }
    .badge-high {
        background-color: #431407;
        color: #fdba74;
        border: 1px solid #9a3412;
        padding: 2px 6px;
        border-radius: 3px;
        font-size: 11px;
        font-weight: 700;
    }
    .badge-medium {
        background-color: #3b2d07;
        color: #fde047;
        border: 1px solid #854d0e;
        padding: 2px 6px;
        border-radius: 3px;
        font-size: 11px;
        font-weight: 700;
    }
    .badge-low {
        background-color: #0f2744;
        color: #93c5fd;
        border: 1px solid #1e3a8a;
        padding: 2px 6px;
        border-radius: 3px;
        font-size: 11px;
        font-weight: 700;
    }

    /* Button adjustments */
    .stButton > button {
        background-color: #0284c7;
        color: #ffffff;
        font-weight: 600;
        border: none;
        border-radius: 6px;
        padding: 8px 20px;
        transition: background-color 0.2s;
    }
    .stButton > button:hover {
        background-color: #0369a1;
        color: #ffffff;
    }
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)


@st.cache_resource
def get_pipeline():
    """Cache singleton pipeline instance for high performance."""
    return GatewayPipeline()


# Session State Initialization
if "analysis_results" not in st.session_state:
    st.session_state.analysis_results = []
if "show_original" not in st.session_state:
    st.session_state.show_original = False


def format_bytes(size: int) -> str:
    """Format byte count into human-readable representation."""
    if size < 1024:
        return f"{size} B"
    elif size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size / (1024 * 1024):.2f} MB"


# ==============================================================================
# HEADER
# ==============================================================================
st.markdown(
    """
    <div class="header-container">
        <div class="header-title">
            <span>🛡️ PII Security Gateway</span>
            <span class="security-badge">● Local Processing — Zero External AI Call</span>
        </div>
        <div class="header-subtitle">
            Pre-LLM Security Gateway & Document Sanitization Pipeline • Detect • Classify • Redact • Validate
        </div>
        <div style="font-size: 12px; color: #38bdf8; font-weight: 600;">
            Security Principle: "NO PII → SAFE FOR DOWNSTREAM AI"
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
        "Upload Business Evidence Documents (Supported: PDF, DOCX, PPTX, TXT)",
        type=["pdf", "docx", "pptx", "txt"],
        accept_multiple_files=True,
        help="Upload single or multiple evidence artifacts for pre-LLM PII sanitization inspection.",
    )

with col_actions:
    st.markdown("<div style='height: 28px;'></div>", unsafe_allow_html=True)
    load_samples = st.button("📁 Load Sample Evidence", help="Load pre-built synthetic test documents")
    analyze_btn = st.button("⚡ Analyze Documents", type="primary", use_container_width=True)

# Handle Sample Document Pre-loading
sample_dir = Path(__file__).resolve().parent / "sample_documents"
sample_files_data = []

if load_samples and sample_dir.exists():
    for sample_file in sample_dir.iterdir():
        if sample_file.suffix.lower() in [".pdf", ".docx", ".pptx", ".txt"]:
            sample_files_data.append((sample_file.name, sample_file.read_bytes()))
    st.info(f"Loaded {len(sample_files_data)} sample evidence artifacts. Click 'Analyze Documents' below.")


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
                <div style='background: #162035; padding: 12px; border-radius: 6px; font-size: 13px; color: #94a3b8;'>
                    Pipeline for <b>{fname}</b>: 
                    <span style='color: #38bdf8;'>Extract</span> → 
                    <span style='color: #38bdf8;'>Detect</span> → 
                    <span style='color: #38bdf8;'>Redact</span> → 
                    <span style='color: #38bdf8;'>Re-scan</span> → 
                    <span style='color: #38bdf8;'>Validate</span>
                </div>
                """,
                unsafe_allow_html=True,
            )

            res = pipeline.process_document(file_bytes=fbytes, file_name=fname)
            results.append(res)
            time.sleep(0.1)  # Minimal pause for smooth UI state update

        progress_bar.progress(100, text="Pipeline processing complete.")
        status_box.empty()
        progress_bar.empty()
        st.session_state.analysis_results = results
        st.success(f"Analysis complete for {len(results)} document(s).")


# ==============================================================================
# DASHBOARD DISPLAY
# ==============================================================================
results = st.session_state.analysis_results

if results:
    summary = ReportGenerator.get_summary_metrics(results)

    # 1. SUMMARY METRIC CARDS
    st.markdown("<h4 style='color: #f8fafc; margin-top: 10px; margin-bottom: 16px;'>Security Gate Overview</h4>", unsafe_allow_html=True)
    c1, c2, c3, c4, c5 = st.columns(5)

    with c1:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-label">Documents Analyzed</div>
                <div class="metric-value">{summary['total_documents']}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with c2:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-label">PII Detected</div>
                <div class="metric-value" style="color: #38bdf8;">{summary['total_pii_detected']}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with c3:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-label">High-Risk Findings</div>
                <div class="metric-value" style="color: #f87171;">{summary['high_risk_findings']}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with c4:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-label">Sanitized (Safe)</div>
                <div class="metric-value" style="color: #34d399;">{summary['files_sanitized']}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with c5:
        blocked_total = summary['files_blocked'] + summary['files_review_required']
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-label">Blocked / Review</div>
                <div class="metric-value" style="color: #fbbf24;">{blocked_total}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown("<div style='height: 20px;'></div>", unsafe_allow_html=True)

    # 2. PII BREAKDOWN & SEVERITY METRICS
    st.markdown("<h4 style='color: #f8fafc; margin-bottom: 14px;'>PII Distribution by Category & Severity</h4>", unsafe_allow_html=True)
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
                columns=["Severity", "Count"]
            ).sort_values(by="Count", ascending=False)
            st.dataframe(df_sev, use_container_width=True, hide_index=True)
        else:
            st.info("No severity metrics available.")

    st.markdown("<div style='height: 20px;'></div>", unsafe_allow_html=True)

    # 3. GLOBAL FINDINGS TABLE
    st.markdown("<h4 style='color: #f8fafc; margin-bottom: 8px;'>PII Findings & Action Log</h4>", unsafe_allow_html=True)

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

    st.markdown("<div style='height: 24px;'></div>", unsafe_allow_html=True)

    # 4. DOCUMENT DETAIL DEEP-DIVE
    st.markdown("<h4 style='color: #f8fafc; margin-bottom: 12px;'>Document Deep-Dive & Source Traceability</h4>", unsafe_allow_html=True)
    
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
            <div style="background-color: #064e3b; border: 1px solid #059669; border-radius: 6px; padding: 14px 18px; margin-bottom: 18px;">
                <b style="color: #34d399; font-size: 15px;">✓ STATUS: SANITIZED (SAFE FOR DOWNSTREAM AI)</b><br>
                <span style="color: #a7f3d0; font-size: 13px;">Validation verified zero residual PII. Content is sanitized and certified safe for LLM context submission.</span>
            </div>
            """,
            unsafe_allow_html=True,
        )
    elif doc_stat_val == SecurityStatus.BLOCKED.value:
        st.markdown(
            f"""
            <div style="background-color: #7f1d1d; border: 1px solid #dc2626; border-radius: 6px; padding: 14px 18px; margin-bottom: 18px;">
                <b style="color: #f87171; font-size: 15px;">✕ STATUS: BLOCKED (UNSAFE FOR LLM SUBMISSION)</b><br>
                <span style="color: #fecaca; font-size: 13px;">Fail-closed security triggered. Residual PII or critical policy violation detected. Submission blocked.</span>
            </div>
            """,
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            f"""
            <div style="background-color: #78350f; border: 1px solid #d97706; border-radius: 6px; padding: 14px 18px; margin-bottom: 18px;">
                <b style="color: #fbbf24; font-size: 15px;">⚠ STATUS: REVIEW REQUIRED</b><br>
                <span style="color: #fde68a; font-size: 13px;">Document contains low-confidence signals or unverified scanned pages requiring analyst clearance.</span>
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
        st.markdown("<p style='color: #94a3b8; font-size: 13px;'>Sanitized content using consistent transparent semantic tags (e.g. <code>[PERSON_001]</code>, <code>[EMAIL_001]</code>).</p>", unsafe_allow_html=True)
        if selected_doc.redaction_result:
            st.markdown(f'<div class="content-box">{selected_doc.redaction_result.redacted_full_text}</div>', unsafe_allow_html=True)
            
            # Download Sanitized Content Button
            st.download_button(
                label=f"⬇ Download Sanitized Text ({selected_doc.file_name}.sanitized.txt)",
                data=selected_doc.redaction_result.redacted_full_text,
                file_name=f"{Path(selected_doc.file_name).stem}_sanitized.txt",
                mime="text/plain",
            )
        else:
            st.info("No sanitized output generated.")

    with tab_findings:
        st.markdown(f"<p style='color: #94a3b8; font-size: 13px;'>Detected {len(selected_doc.pii_findings)} PII instances in this document.</p>", unsafe_allow_html=True)
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
        st.markdown("<p style='color: #94a3b8; font-size: 13px;'>Source Traceability Matrix: Explaining exact source location, detector corroboration, and semantic tag assignment.</p>", unsafe_allow_html=True)
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
        st.markdown("<p style='color: #94a3b8; font-size: 13px;'>Post-Redaction Validation Audit (Re-scan of sanitized text blocks to ensure fail-closed security).</p>", unsafe_allow_html=True)
        if selected_doc.validation_result:
            vr = selected_doc.validation_result
            st.write(f"**Validation Verdict:** {vr.status.value}")
            st.write(f"**Passed Security Gate:** {'YES' if vr.passed else 'NO'}")
            st.write(f"**Residual PII Detected:** {len(vr.residual_findings)} items")
            st.write(f"**Policy Message:** {vr.validation_message}")

            # Structure retention score
            orig_blocks = selected_doc.blocks
            red_blocks = selected_doc.redaction_result.redacted_blocks if selected_doc.redaction_result else []
            retention_pct = calculate_structure_retention(orig_blocks, red_blocks)
            st.write(f"**Structural Block Retention:** {retention_pct}% (Original structure boundaries maintained)")
        else:
            st.info("Validation records unavailable.")

    with tab_original:
        st.markdown("<p style='color: #94a3b8; font-size: 13px;'>Original extracted blocks with structural boundary metadata (Kept strictly local).</p>", unsafe_allow_html=True)
        for b in selected_doc.blocks:
            st.markdown(
                f"""
                <div style="background: #162035; border-left: 3px solid #38bdf8; padding: 8px 12px; margin-bottom: 8px; border-radius: 4px;">
                    <div style="font-size: 11px; color: #94a3b8; margin-bottom: 4px;"><b>Location:</b> {b.location} | <b>Type:</b> {b.block_type} | <b>Order:</b> {b.order}</div>
                    <div style="font-size: 13px; color: #f1f5f9; white-space: pre-wrap;">{b.text}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

    st.markdown("<div style='height: 24px;'></div>", unsafe_allow_html=True)

    # 5. AUDIT REPORT EXPORTS
    st.markdown("<h4 style='color: #f8fafc; margin-bottom: 12px;'>Compliance Audit Reports Export</h4>", unsafe_allow_html=True)
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

else:
    # Initial clean landing message
    st.markdown(
        """
        <div style="background-color: #162035; border: 1px dashed #28354f; border-radius: 8px; padding: 40px; text-align: center; margin-top: 20px;">
            <div style="font-size: 36px; margin-bottom: 12px;">🛡️</div>
            <div style="font-size: 18px; font-weight: 600; color: #ffffff; margin-bottom: 8px;">Pre-LLM Security Inspection Ready</div>
            <div style="font-size: 14px; color: #94a3b8; max-width: 600px; margin: 0 auto 20px auto;">
                Upload business evidence documents (PDF, DOCX, PPTX, TXT) or click <b>Load Sample Evidence</b> above to test the hybrid PII detection, consistent semantic redaction, and fail-closed validation pipeline.
            </div>
            <div style="font-size: 12px; color: #64748b;">
                Local computation • Zero telemetry • No external LLM calls • Fail-closed architecture
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
