"""PII Security Gateway - Pre-LLM Privacy & Document Sanitization Pipeline.

Enterprise Capstone Edition.
Vibrant white-background SaaS design system inspired by modern Figma security products.
Provides deterministic, explainable, and fail-closed privacy controls
for unstructured business documents prior to LLM context ingestion.
"""
import io
import time
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Any

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
from utils.helpers import calculate_file_hash

# ------------------------------------------------------------------------------
# ------------------------------------------------------------------------------
# 1. PAGE CONFIGURATION & DYNAMIC DESIGN SYSTEM (LIGHT & VIBRANT NIGHT MODES)
# ------------------------------------------------------------------------------
st.set_page_config(
    page_title="PII Security Gateway | Enterprise Privacy Gate",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

if "theme_mode" not in st.session_state:
    st.session_state.theme_mode = "light"


def get_vibrant_css(is_dark: bool) -> str:
    """Generate dynamic CSS tokens and styles for Light SaaS Mode and Vibrant Night SOC Mode."""
    if is_dark:
        # Vibrant Night Theme Tokens
        theme_vars = """
        --bg-app: #0B1220;
        --bg-surface: #111C30;
        --bg-card: #14223C;
        --border-subtle: #1E3156;
        --border-hover: #334B7D;
        --shadow-card: 0 4px 16px rgba(0, 0, 0, 0.35);
        --shadow-card-hover: 0 8px 24px rgba(0, 0, 0, 0.45), 0 0 14px rgba(99, 102, 241, 0.3);

        --text-headline: #F8FAFC;
        --text-body: #E2E8F0;
        --text-secondary: #94A3B8;
        --text-muted: #64748B;

        /* Vibrant Brand Palette */
        --brand-blue: #3B82F6;
        --brand-indigo: #6366F1;
        --brand-violet: #A855F7;
        --brand-teal: #14B8A6;
        --brand-cyan: #06B6D4;

        /* High-contrast vibrant security state tokens */
        --safe-green: #10B981;
        --safe-bg: rgba(16, 185, 129, 0.14);
        --safe-border: rgba(16, 185, 129, 0.45);
        --safe-text: #34D399;

        --blocked-red: #F43F5E;
        --blocked-bg: rgba(244, 63, 94, 0.16);
        --blocked-border: rgba(244, 63, 94, 0.45);
        --blocked-text: #FB7185;

        --review-amber: #F59E0B;
        --review-bg: rgba(245, 158, 11, 0.16);
        --review-border: rgba(245, 158, 11, 0.45);
        --review-text: #FBBF24;

        --staged-bg: rgba(59, 130, 246, 0.15);
        --staged-border: rgba(59, 130, 246, 0.45);
        --staged-text: #60A5FA;

        --preview-bg: #070D18;
        --preview-border: #1E3156;

        --btn-sec-bg: #172642;
        --btn-sec-text: #F8FAFC;
        --btn-sec-border: #2A4068;
        --btn-sec-hover-bg: #1E3358;
        --btn-sec-hover-border: #6366F1;
        --btn-sec-hover-text: #818CF8;

        --uploader-bg: #14223C;
        --uploader-border: #2E456E;
        --uploader-hover-bg: #192A4A;

        --step-extract-bg: rgba(99, 102, 241, 0.1);
        --step-extract-border: rgba(99, 102, 241, 0.45);
        --step-detect-bg: rgba(168, 85, 247, 0.1);
        --step-detect-border: rgba(168, 85, 247, 0.45);
        --step-risk-bg: rgba(249, 115, 22, 0.1);
        --step-risk-border: rgba(249, 115, 22, 0.45);
        --step-redact-bg: rgba(59, 130, 246, 0.1);
        --step-redact-border: rgba(59, 130, 246, 0.45);
        --step-pass-bg: rgba(16, 185, 129, 0.12);
        --step-pass-border: rgba(16, 185, 129, 0.45);
        --step-fail-bg: rgba(244, 63, 94, 0.14);
        --step-fail-border: rgba(244, 63, 94, 0.45);

        --stripe-glow-indigo: 0 -2px 10px rgba(99, 102, 241, 0.5);
        --stripe-glow-violet: 0 -2px 10px rgba(168, 85, 247, 0.5);
        --stripe-glow-rose: 0 -2px 10px rgba(244, 63, 94, 0.5);
        --stripe-glow-emerald: 0 -2px 10px rgba(16, 185, 129, 0.5);
        --stripe-glow-amber: 0 -2px 10px rgba(245, 158, 11, 0.5);

        --badge-brand-bg: linear-gradient(135deg, rgba(99, 102, 241, 0.2) 0%, rgba(139, 92, 246, 0.2) 100%);
        --badge-brand-border: rgba(99, 102, 241, 0.45);
        --badge-brand-text: #A5B4FC;
        """
    else:
        # Vibrant Light Theme Tokens
        theme_vars = """
        --bg-app: #FFFFFF;
        --bg-surface: #F8FAFC;
        --bg-card: #FFFFFF;
        --border-subtle: #E2E8F0;
        --border-hover: #CBD5E1;
        --shadow-card: 0 1px 3px rgba(15, 23, 42, 0.05), 0 1px 2px rgba(15, 23, 42, 0.03);
        --shadow-card-hover: 0 6px 16px -2px rgba(15, 23, 42, 0.08);

        --text-headline: #0F172A;
        --text-body: #1E293B;
        --text-secondary: #475569;
        --text-muted: #64748B;

        /* Vibrant Brand Palette */
        --brand-blue: #2563EB;
        --brand-indigo: #4F46E5;
        --brand-violet: #7C3AED;
        --brand-teal: #0D9488;
        --brand-cyan: #06B6D4;

        /* Security State Tones */
        --safe-green: #10B981;
        --safe-bg: #ECFDF5;
        --safe-border: #A7F3D0;
        --safe-text: #065F46;

        --blocked-red: #EF4444;
        --blocked-bg: #FEF2F2;
        --blocked-border: #FECACA;
        --blocked-text: #991B1B;

        --review-amber: #F59E0B;
        --review-bg: #FFFBEB;
        --review-border: #FDE68A;
        --review-text: #92400E;

        --staged-bg: #EFF6FF;
        --staged-border: #BFDBFE;
        --staged-text: #1E40AF;

        --preview-bg: #FFFFFF;
        --preview-border: #E2E8F0;

        --btn-sec-bg: #FFFFFF;
        --btn-sec-text: #0F172A;
        --btn-sec-border: #E2E8F0;
        --btn-sec-hover-bg: #F8FAFC;
        --btn-sec-hover-border: #C7D2FE;
        --btn-sec-hover-text: #4F46E5;

        --uploader-bg: #FFFFFF;
        --uploader-border: #CBD5E1;
        --uploader-hover-bg: #FAFAFE;

        --step-extract-bg: #FAFAFF;
        --step-extract-border: #C7D2FE;
        --step-detect-bg: #FAF5FF;
        --step-detect-border: #DDD6FE;
        --step-risk-bg: #FFFDF9;
        --step-risk-border: #FED7AA;
        --step-redact-bg: #F8FAFF;
        --step-redact-border: #BFDBFE;
        --step-pass-bg: #F8FCF9;
        --step-pass-border: #A7F3D0;
        --step-fail-bg: #FEF2F2;
        --step-fail-border: #FECACA;

        --stripe-glow-indigo: none;
        --stripe-glow-violet: none;
        --stripe-glow-rose: none;
        --stripe-glow-emerald: none;
        --stripe-glow-amber: none;

        --badge-brand-bg: linear-gradient(135deg, #EFF6FF 0%, #EEF2FF 100%);
        --badge-brand-border: #C7D2FE;
        --badge-brand-text: #4F46E5;
        """

    return f"""
<style>
    :root {{
        {theme_vars}
    }}

    /* Base Styling */
    .stApp {{
        background-color: var(--bg-app) !important;
        color: var(--text-body) !important;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    }}

    .main .block-container {{
        padding-top: 1.25rem !important;
        padding-bottom: 2.5rem !important;
        max-width: 1440px;
    }}

    h1, h2, h3, h4, h5, h6 {{
        color: var(--text-headline) !important;
        font-weight: 700 !important;
        letter-spacing: -0.025em;
    }}

    /* Vibrant SaaS / SOC Header */
    .saas-header-card {{
        background-color: var(--bg-card);
        border: 1px solid var(--border-subtle);
        border-radius: 12px;
        padding: 16px 22px;
        margin-bottom: 20px;
        display: flex;
        align-items: center;
        justify-content: space-between;
        flex-wrap: wrap;
        gap: 16px;
        box-shadow: var(--shadow-card);
    }}
    .saas-brand-group {{
        display: flex;
        align-items: center;
        gap: 14px;
    }}
    .saas-brand-icon {{
        width: 44px;
        height: 44px;
        background: linear-gradient(135deg, var(--brand-blue) 0%, var(--brand-indigo) 50%, var(--brand-violet) 100%);
        border-radius: 10px;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 22px;
        color: #FFFFFF;
        box-shadow: 0 4px 14px rgba(99, 102, 241, 0.35);
    }}
    .saas-brand-title {{
        font-size: 20px;
        font-weight: 800;
        color: var(--text-headline);
        letter-spacing: -0.03em;
        line-height: 1.2;
        margin: 0;
        display: flex;
        align-items: center;
        gap: 8px;
        flex-wrap: wrap;
    }}
    .saas-brand-badge {{
        background: var(--badge-brand-bg);
        color: var(--badge-brand-text);
        border: 1px solid var(--badge-brand-border);
        font-size: 10.5px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.06em;
        padding: 2px 8px;
        border-radius: 20px;
    }}
    .saas-theme-badge {{
        font-size: 10px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.06em;
        padding: 2px 8px;
        border-radius: 20px;
    }}
    .saas-theme-badge-light {{
        background: #F1F5F9;
        color: #475569;
        border: 1px solid #CBD5E1;
    }}
    .saas-theme-badge-dark {{
        background: rgba(99, 102, 241, 0.2);
        color: #A5B4FC;
        border: 1px solid rgba(99, 102, 241, 0.5);
        box-shadow: 0 0 10px rgba(99, 102, 241, 0.3);
    }}
    .saas-brand-sub {{
        font-size: 12.5px;
        color: var(--text-muted);
        margin-top: 2px;
    }}
    .saas-status-pill {{
        display: inline-flex;
        align-items: center;
        gap: 7px;
        padding: 5px 13px;
        border-radius: 20px;
        font-size: 12px;
        font-weight: 600;
        letter-spacing: 0.02em;
    }}
    .pill-sanitized {{
        background-color: var(--safe-bg);
        border: 1px solid var(--safe-border);
        color: var(--safe-text);
    }}
    .pill-blocked {{
        background-color: var(--blocked-bg);
        border: 1px solid var(--blocked-border);
        color: var(--blocked-text);
    }}
    .pill-review {{
        background-color: var(--review-bg);
        border: 1px solid var(--review-border);
        color: var(--review-text);
    }}
    .pill-staged {{
        background-color: var(--staged-bg);
        border: 1px solid var(--staged-border);
        color: var(--staged-text);
    }}
    .pill-standby {{
        background-color: var(--bg-surface);
        border: 1px solid var(--border-subtle);
        color: var(--text-muted);
    }}
    .status-dot {{
        width: 7px;
        height: 7px;
        border-radius: 50%;
        display: inline-block;
    }}
    .dot-sanitized {{ background-color: var(--safe-green); box-shadow: 0 0 8px var(--safe-green); }}
    .dot-blocked {{ background-color: var(--blocked-red); box-shadow: 0 0 8px var(--blocked-red); }}
    .dot-review {{ background-color: var(--review-amber); box-shadow: 0 0 8px var(--review-amber); }}
    .dot-staged {{ background-color: var(--brand-blue); box-shadow: 0 0 8px var(--brand-blue); }}
    .dot-standby {{ background-color: var(--text-muted); }}

    /* 5 Vibrant Metric Cards */
    .metric-card-vibrant {{
        background-color: var(--bg-card);
        border: 1px solid var(--border-subtle);
        border-radius: 10px;
        padding: 16px 18px;
        height: 100%;
        display: flex;
        flex-direction: column;
        justify-content: space-between;
        position: relative;
        overflow: hidden;
        transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1);
        box-shadow: var(--shadow-card);
    }}
    .metric-card-vibrant:hover {{
        transform: translateY(-2px);
        box-shadow: var(--shadow-card-hover);
        border-color: var(--border-hover);
    }}
    .metric-stripe-indigo {{ border-top: 3px solid var(--brand-indigo); box-shadow: var(--stripe-glow-indigo); }}
    .metric-stripe-violet {{ border-top: 3px solid var(--brand-violet); box-shadow: var(--stripe-glow-violet); }}
    .metric-stripe-rose {{ border-top: 3px solid var(--blocked-red); box-shadow: var(--stripe-glow-rose); }}
    .metric-stripe-emerald {{ border-top: 3px solid var(--safe-green); box-shadow: var(--stripe-glow-emerald); }}
    .metric-stripe-amber {{ border-top: 3px solid var(--review-amber); box-shadow: var(--stripe-glow-amber); }}

    .metric-header-row {{
        display: flex;
        align-items: center;
        justify-content: space-between;
        margin-bottom: 6px;
    }}
    .metric-label-txt {{
        font-size: 11px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.06em;
    }}
    .metric-label-indigo {{ color: var(--brand-indigo); }}
    .metric-label-violet {{ color: var(--brand-violet); }}
    .metric-label-rose {{ color: var(--blocked-red); }}
    .metric-label-emerald {{ color: var(--safe-green); }}
    .metric-label-amber {{ color: var(--review-amber); }}

    .metric-icon-box {{
        font-size: 15px;
    }}
    .metric-main-val {{
        font-size: 30px;
        font-weight: 800;
        line-height: 1.1;
        color: var(--text-headline);
        margin-bottom: 4px;
        letter-spacing: -0.02em;
    }}
    .metric-sub-txt {{
        font-size: 11.5px;
        color: var(--text-muted);
        font-weight: 500;
    }}

    /* Section Headers */
    .section-title-wrap {{
        display: flex;
        align-items: center;
        justify-content: space-between;
        margin-bottom: 12px;
        padding-bottom: 8px;
        border-bottom: 1px solid var(--border-subtle);
    }}
    .section-title-text {{
        font-size: 13.5px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        color: var(--text-secondary);
        margin: 0;
    }}
    .section-desc-text {{
        font-size: 12px;
        color: var(--text-muted);
        margin: 0;
    }}

    /* Active Staged Artifact Card */
    .staged-artifact-card {{
        background-color: var(--bg-card);
        border: 1px solid var(--border-subtle);
        border-left: 4px solid var(--brand-indigo);
        border-radius: 8px;
        padding: 14px 18px;
        margin-top: 10px;
        margin-bottom: 14px;
        display: flex;
        align-items: center;
        justify-content: space-between;
        flex-wrap: wrap;
        gap: 12px;
        box-shadow: var(--shadow-card);
    }}
    .staged-left-info {{
        display: flex;
        align-items: center;
        gap: 12px;
    }}
    .staged-badge-format {{
        background: var(--badge-brand-bg);
        color: var(--badge-brand-text);
        border: 1px solid var(--badge-brand-border);
        font-size: 11px;
        font-weight: 800;
        padding: 4px 8px;
        border-radius: 6px;
        letter-spacing: 0.05em;
    }}
    .staged-name-text {{
        font-size: 14px;
        font-weight: 700;
        color: var(--text-headline);
    }}
    .staged-meta-text {{
        font-size: 12px;
        color: var(--text-muted);
        margin-top: 2px;
        font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    }}

    /* 5-Stage Visual Progression Stepper */
    .stepper-5stage-grid {{
        display: grid;
        grid-template-columns: repeat(5, 1fr);
        gap: 10px;
        margin-bottom: 16px;
    }}
    @media (max-width: 1024px) {{
        .stepper-5stage-grid {{
            grid-template-columns: repeat(3, 1fr);
        }}
    }}
    .step-box-cell {{
        background-color: var(--bg-card);
        border: 1px solid var(--border-subtle);
        border-radius: 8px;
        padding: 12px 14px;
        text-align: left;
        transition: all 0.2s ease;
    }}
    .step-box-cell:hover {{
        border-color: var(--border-hover);
        box-shadow: var(--shadow-card);
    }}
    .step-cell-extract {{
        background-color: var(--step-extract-bg) !important;
        border-color: var(--step-extract-border) !important;
    }}
    .step-cell-detect {{
        background-color: var(--step-detect-bg) !important;
        border-color: var(--step-detect-border) !important;
    }}
    .step-cell-risk {{
        background-color: var(--step-risk-bg) !important;
        border-color: var(--step-risk-border) !important;
    }}
    .step-cell-redact {{
        background-color: var(--step-redact-bg) !important;
        border-color: var(--step-redact-border) !important;
    }}
    .step-cell-pass {{
        background-color: var(--step-pass-bg) !important;
        border-color: var(--step-pass-border) !important;
    }}
    .step-cell-fail {{
        background-color: var(--step-fail-bg) !important;
        border-color: var(--step-fail-border) !important;
    }}
    .step-tag-text {{
        font-size: 10px;
        font-weight: 800;
        text-transform: uppercase;
        letter-spacing: 0.07em;
        margin-bottom: 4px;
    }}
    .step-done-tag {{ color: var(--safe-green); }}
    .step-title-text {{
        font-size: 12.5px;
        font-weight: 700;
        color: var(--text-headline);
        margin-bottom: 2px;
    }}
    .step-sub-text {{
        font-size: 11px;
        color: var(--text-muted);
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
    }}

    /* Executive Security Gate Verdict Banner */
    .verdict-banner-card {{
        border-radius: 10px;
        padding: 18px 22px;
        margin-bottom: 20px;
        display: flex;
        align-items: flex-start;
        justify-content: space-between;
        flex-wrap: wrap;
        gap: 16px;
        box-shadow: var(--shadow-card);
    }}
    .verdict-bg-sanitized {{
        background-color: var(--safe-bg);
        border: 1px solid var(--safe-border);
    }}
    .verdict-bg-blocked {{
        background-color: var(--blocked-bg);
        border: 1px solid var(--blocked-border);
    }}
    .verdict-bg-review {{
        background-color: var(--review-bg);
        border: 1px solid var(--review-border);
    }}
    .verdict-primary-col {{
        display: flex;
        align-items: flex-start;
        gap: 14px;
        max-width: 820px;
    }}
    .verdict-icon-symbol {{
        font-size: 24px;
        line-height: 1.1;
    }}
    .verdict-title-headline {{
        font-size: 15.5px;
        font-weight: 800;
        margin-bottom: 4px;
        letter-spacing: -0.01em;
    }}
    .verdict-bg-sanitized .verdict-title-headline {{ color: var(--safe-text); }}
    .verdict-bg-blocked .verdict-title-headline {{ color: var(--blocked-text); }}
    .verdict-bg-review .verdict-title-headline {{ color: var(--review-text); }}
    .verdict-body-desc {{
        font-size: 13px;
        line-height: 1.5;
        color: var(--text-secondary);
    }}
    .verdict-telemetry-strip {{
        display: flex;
        align-items: center;
        gap: 10px;
        flex-wrap: wrap;
    }}
    .verdict-metric-pill {{
        background-color: var(--bg-surface);
        border: 1px solid var(--border-subtle);
        border-radius: 8px;
        padding: 6px 12px;
        text-align: center;
        min-width: 84px;
        box-shadow: var(--shadow-card);
    }}
    .v-pill-lbl {{
        font-size: 9.5px;
        font-weight: 700;
        text-transform: uppercase;
        color: var(--text-muted);
        letter-spacing: 0.05em;
    }}
    .v-pill-num {{
        font-size: 15px;
        font-weight: 800;
        color: var(--text-headline);
    }}

    /* Monospaced Document Preview */
    .preview-doc-box {{
        background-color: var(--preview-bg);
        border: 1px solid var(--preview-border);
        border-radius: 8px;
        padding: 16px 18px;
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
        font-size: 12.5px;
        line-height: 1.7;
        color: var(--text-body);
        white-space: pre-wrap;
        max-height: 480px;
        overflow-y: auto;
        box-shadow: inset 0 1px 3px rgba(0, 0, 0, 0.15);
    }}

    /* Card helpers for architecture, telemetry, validation, risk, and raw blocks */
    .architecture-doc-card {{
        background-color: var(--bg-card);
        border: 1px solid var(--border-subtle);
        border-left: 4px solid var(--brand-indigo);
        border-radius: 10px;
        padding: 22px 26px;
        margin-bottom: 20px;
        box-shadow: var(--shadow-card);
        line-height: 1.65;
    }}
    .architecture-callout-box {{
        background-color: var(--bg-surface);
        border: 1px solid var(--border-subtle);
        border-radius: 8px;
        padding: 14px 18px;
        margin-bottom: 16px;
        font-size: 13px;
        color: var(--text-secondary);
    }}
    .telemetry-chart-card {{
        background-color: var(--bg-card);
        border: 1px solid var(--border-subtle);
        border-radius: 10px;
        padding: 18px 20px;
        box-shadow: var(--shadow-card);
    }}
    .risk-metric-box {{
        background-color: var(--bg-surface);
        border: 1px solid var(--border-subtle);
        border-radius: 8px;
        padding: 12px 14px;
        text-align: center;
    }}
    .validation-audit-card {{
        background-color: var(--bg-card);
        border: 1px solid var(--border-subtle);
        border-radius: 8px;
        padding: 16px 20px;
        margin-bottom: 14px;
    }}
    .raw-block-card {{
        background-color: var(--bg-card);
        border: 1px solid var(--border-subtle);
        border-left: 3px solid var(--brand-indigo);
        border-radius: 4px;
        padding: 10px 14px;
        margin-bottom: 8px;
    }}

    /* Buttons: Primary Vibrant Action */
    div.stButton > button[kind="primary"],
    div.stButton > button[data-testid="baseButton-primary"],
    button[kind="primary"] {{
        background: linear-gradient(135deg, var(--brand-blue) 0%, var(--brand-indigo) 50%, var(--brand-violet) 100%) !important;
        color: #FFFFFF !important;
        font-weight: 700 !important;
        border: none !important;
        border-radius: 8px !important;
        padding: 8px 18px !important;
        font-size: 13px !important;
        transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1) !important;
        box-shadow: 0 4px 16px rgba(99, 102, 241, 0.35) !important;
    }}
    div.stButton > button[kind="primary"]:hover,
    button[kind="primary"]:hover {{
        transform: translateY(-1px) !important;
        box-shadow: 0 6px 20px rgba(99, 102, 241, 0.55) !important;
    }}

    /* Secondary / Navigation Buttons */
    div.stButton > button:not([kind="primary"]):not([data-testid="baseButton-primary"]) {{
        background-color: var(--btn-sec-bg) !important;
        color: var(--btn-sec-text) !important;
        border: 1px solid var(--btn-sec-border) !important;
        border-radius: 8px !important;
        font-weight: 600 !important;
        font-size: 12.5px !important;
        padding: 7px 14px !important;
        transition: all 0.2s ease !important;
        box-shadow: var(--shadow-card) !important;
    }}
    div.stButton > button:not([kind="primary"]):not([data-testid="baseButton-primary"]):hover {{
        background-color: var(--btn-sec-hover-bg) !important;
        border-color: var(--btn-sec-hover-border) !important;
        color: var(--btn-sec-hover-text) !important;
        transform: translateY(-1px) !important;
    }}

    /* Secondary / Download Buttons */
    div.stDownloadButton > button {{
        background-color: var(--btn-sec-bg) !important;
        color: var(--btn-sec-text) !important;
        border: 1px solid var(--btn-sec-border) !important;
        border-radius: 8px !important;
        font-weight: 600 !important;
        font-size: 12.5px !important;
        padding: 7px 16px !important;
        box-shadow: var(--shadow-card) !important;
    }}
    div.stDownloadButton > button:hover {{
        background-color: var(--btn-sec-hover-bg) !important;
        border-color: var(--btn-sec-hover-border) !important;
        color: var(--btn-sec-hover-text) !important;
        transform: translateY(-1px) !important;
    }}

    /* Streamlit Tabs Polish */
    .stTabs [data-baseweb="tab-list"] {{
        gap: 6px;
        border-bottom: 1px solid var(--border-subtle);
        padding-bottom: 2px;
    }}
    .stTabs [data-baseweb="tab"] {{
        padding: 8px 16px;
        font-size: 13px;
        font-weight: 600;
        color: var(--text-secondary);
        border-radius: 6px 6px 0 0;
    }}
    .stTabs [aria-selected="true"] {{
        color: var(--brand-indigo) !important;
        border-bottom: 2px solid var(--brand-indigo) !important;
    }}

    /* File Uploader Polishing */
    [data-testid="stFileUploader"] section {{
        background-color: var(--uploader-bg) !important;
        border: 1px dashed var(--uploader-border) !important;
        border-radius: 8px !important;
        padding: 16px 20px !important;
        transition: border-color 0.2s ease;
    }}
    [data-testid="stFileUploader"] section:hover {{
        border-color: var(--brand-indigo) !important;
        background-color: var(--uploader-hover-bg) !important;
    }}
    [data-testid="stFileUploader"] section div,
    [data-testid="stFileUploader"] section span,
    [data-testid="stFileUploader"] section small {{
        color: var(--text-secondary) !important;
    }}

    /* Dark Mode Selectbox, Inputs & Checkboxes */
    div[data-baseweb="select"] > div {{
        background-color: var(--bg-card) !important;
        border-color: var(--border-subtle) !important;
        color: var(--text-headline) !important;
    }}
    div[data-baseweb="popover"] > div,
    div[data-baseweb="popover"] ul {{
        background-color: var(--bg-card) !important;
        border-color: var(--border-subtle) !important;
        color: var(--text-headline) !important;
    }}
    div[data-baseweb="popover"] li {{
        background-color: var(--bg-card) !important;
        color: var(--text-body) !important;
    }}
    div[data-baseweb="popover"] li:hover {{
        background-color: var(--bg-surface) !important;
        color: var(--brand-indigo) !important;
    }}
    div[data-baseweb="select"] span {{
        color: var(--text-headline) !important;
    }}
    div[data-baseweb="select"] svg {{
        fill: var(--text-secondary) !important;
    }}
    .stCheckbox label span {{
        color: var(--text-body) !important;
    }}
    code {{
        background-color: rgba(99, 102, 241, 0.15) !important;
        color: var(--brand-indigo) !important;
        border-radius: 4px;
        padding: 2px 5px;
    }}

    /* Streamlit DataFrame Container */
    div[data-testid="stDataFrame"] {{
        border: 1px solid var(--border-subtle) !important;
        border-radius: 8px !important;
        overflow: hidden;
    }}

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
    .header-anchor {{
        display: none !important;
        visibility: hidden !important;
    }}

    /* Empty State Box */
    .saas-empty-container {{
        background-color: var(--bg-card);
        border: 1px dashed var(--border-subtle);
        border-radius: 10px;
        padding: 36px 24px;
        text-align: center;
        margin-top: 10px;
        margin-bottom: 18px;
        box-shadow: var(--shadow-card);
    }}
    .empty-symbol {{
        font-size: 32px;
        color: var(--brand-indigo);
        margin-bottom: 10px;
    }}
    .empty-lead {{
        font-size: 15px;
        font-weight: 700;
        color: var(--text-headline);
        margin-bottom: 4px;
    }}
    .empty-detail {{
        font-size: 13px;
        color: var(--text-muted);
        max-width: 520px;
        margin: 0 auto;
        line-height: 1.5;
    }}
</style>
"""


is_dark = st.session_state.theme_mode == "dark"
st.markdown(get_vibrant_css(is_dark), unsafe_allow_html=True)



# ------------------------------------------------------------------------------
# 2. APPLICATION INITIALIZATION & HELPERS
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


def apply_vibrant_theme(fig, height: int = 320):
    """Apply consistent vibrant SaaS / SOC theme to Plotly figures."""
    is_dark = st.session_state.get("theme_mode", "light") == "dark"
    paper_bg = "#14223C" if is_dark else "#FFFFFF"
    plot_bg = "#14223C" if is_dark else "#FFFFFF"
    font_color = "#F8FAFC" if is_dark else "#0F172A"
    grid_color = "#1E3156" if is_dark else "#F1F5F9"
    zeroline_color = "#2E456E" if is_dark else "#E2E8F0"
    tick_color = "#94A3B8" if is_dark else "#475569"

    fig.update_layout(
        height=height,
        margin=dict(l=24, r=24, t=28, b=24),
        paper_bgcolor=paper_bg,
        plot_bgcolor=plot_bg,
        font=dict(
            family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
            color=font_color,
            size=12,
        ),
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=-0.3,
            xanchor="center",
            x=0.5,
            font=dict(size=11, color=tick_color),
        ),
    )
    fig.update_xaxes(
        showgrid=True,
        gridcolor=grid_color,
        zerolinecolor=zeroline_color,
        tickfont=dict(color=tick_color, size=11),
    )
    fig.update_yaxes(
        showgrid=True,
        gridcolor=grid_color,
        zerolinecolor=zeroline_color,
        tickfont=dict(color=tick_color, size=11),
    )
    return fig


# Session State Management
if "analysis_results" not in st.session_state:
    st.session_state.analysis_results = []
if "active_view" not in st.session_state:
    st.session_state.active_view = "workspace"
if "last_active_file_signature" not in st.session_state:
    st.session_state.last_active_file_signature = None
if "active_sample_file" not in st.session_state:
    st.session_state.active_sample_file = None


# ------------------------------------------------------------------------------
# 3. HEADER RENDERING
# ------------------------------------------------------------------------------
def render_header(status_label: str, status_class: str, dot_class: str):
    """Render compact, vibrant header with live status pill and theme toggle."""
    is_dark = st.session_state.get("theme_mode", "light") == "dark"
    theme_badge_text = "🌙 NIGHT MODE" if is_dark else "☀️ LIGHT MODE"
    theme_badge_cls = "saas-theme-badge-dark" if is_dark else "saas-theme-badge-light"

    col_hdr, col_nav = st.columns([4.2, 2.8])

    with col_hdr:
        st.markdown(
            f"""
            <div class="saas-header-card">
                <div class="saas-brand-group">
                    <div class="saas-brand-icon">🛡️</div>
                    <div>
                        <div class="saas-brand-title">
                            PII Security Gateway
                            <span class="saas-brand-badge">Enterprise Edition</span>
                            <span class="saas-theme-badge {theme_badge_cls}">{theme_badge_text}</span>
                        </div>
                        <div class="saas-brand-sub">
                            Pre-LLM Document Privacy, Semantic Redaction & Fail-Closed Gate
                        </div>
                    </div>
                </div>
                <div>
                    <span class="saas-status-pill {status_class}">
                        <span class="status-dot {dot_class}"></span>
                        <span>{status_label}</span>
                    </span>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col_nav:
        st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)
        c_n1, c_n2, c_n3, c_n4 = st.columns([1, 1.1, 1.25, 1.05])
        with c_n1:
            if st.button("🔬 Gateway", use_container_width=True, help="Document Inspection Workspace"):
                st.session_state.active_view = "workspace"
                st.rerun()
        with c_n2:
            has_res = bool(st.session_state.get("analysis_results"))
            if st.button("📊 Telemetry", use_container_width=True, disabled=not has_res, help="View pictorial risk telemetry"):
                st.session_state.active_view = "telemetry"
                st.rerun()
        with c_n3:
            if st.button("📐 Architecture", use_container_width=True, help="Technical Specification & Policy Guide"):
                st.session_state.active_view = "architecture"
                st.rerun()
        with c_n4:
            theme_btn_label = "☀️ Light" if is_dark else "🌙 Night"
            theme_btn_help = "Switch to Light Mode" if is_dark else "Switch to Vibrant Night Mode"
            if st.button(theme_btn_label, use_container_width=True, help=theme_btn_help):
                st.session_state.theme_mode = "light" if is_dark else "dark"
                st.rerun()


# ------------------------------------------------------------------------------
# 4. VIEW ROUTING: ARCHITECTURE vs TELEMETRY vs MAIN WORKSPACE
# ------------------------------------------------------------------------------
results: List[DocumentAnalysisResult] = st.session_state.get("analysis_results", [])
has_results = bool(results)

if st.session_state.get("active_view") == "architecture":
    # --------------------------------------------------------------------------
    # ARCHITECTURE & SPECIFICATION VIEW
    # --------------------------------------------------------------------------
    render_header("SPECIFICATION MODE", "pill-standby", "dot-standby")

    st.markdown(
        """
        <div class="architecture-doc-card">
            <h3 style="margin-top: 0; font-size: 18px; color: var(--brand-indigo); font-weight: 800;">
                Zero-Trust Pre-LLM Security Architecture & Policy Specification
            </h3>
            <p style="font-size: 13.5px; color: var(--text-secondary); margin-bottom: 14px;">
                The <b>PII Security Gateway</b> serves as an automated local cryptographic and privacy checkpoint situated between corporate unstructured document repositories and downstream Large Language Model (LLM) inference environments.
            </p>

            <h4 style="font-size: 14.5px; color: var(--text-headline); margin-top: 16px; margin-bottom: 8px;">1. Operational Threat Model</h4>
            <div class="architecture-callout-box">
                When employees upload business files (contracts, invoices, employee records, support tickets, incident reports) to LLMs, those files routinely contain confidential Personally Identifiable Information (PII) including full names, email addresses, phone numbers, employee badge IDs, credit cards, and government IDs. Transmitting unredacted documents breaches GDPR (Art. 25 & 32), HIPAA (§164.514), and the EU AI Act.
            </div>

            <h4 style="font-size: 14.5px; color: var(--text-headline); margin-top: 16px; margin-bottom: 8px;">2. Five-Stage Fail-Closed Pipeline</h4>
            <ol style="color: var(--text-secondary); font-size: 13px; padding-left: 20px; line-height: 1.75; margin-bottom: 16px;">
                <li><b>Stage 1 — Document Extraction:</b> Structural decomposition into immutable, ordered blocks (<code>page_1_block_2</code>) preserving layout boundaries across PDF, DOCX, PPTX, and TXT formats.</li>
                <li><b>Stage 2 — Multi-Engine Detection:</b> Corroborating hybrid scanner combining deterministic RFC-compliant regex, statistical spaCy NLP entity recognition with false-positive filtering, and proximity context rules.</li>
                <li><b>Stage 3 — Intelligent Risk Assessment:</b> Evaluates distinct entity volume, multi-attribute correlation hazard, and credential sensitivity to calculate an explainable Risk Score (0–100) and Risk Tier (LOW, MODERATE, HIGH, CRITICAL).</li>
                <li><b>Stage 4 — Consistent Semantic Redaction:</b> Generates deterministic surrogate keys (e.g. <code>[PERSON_001]</code>, <code>[EMAIL_001]</code>) rather than destructive blacking out, preserving co-reference resolution for AI reasoning.</li>
                <li><b>Stage 5 — Independent Secondary Validation:</b> An automated re-scan audits the sanitized text. If even a single residual PII entity is detected, the gateway fails closed (<b>BLOCKED ✕</b>). Downstream transmission is permitted strictly when zero residual PII is certified.</li>
            </ol>

            <div style="border-top: 1px solid var(--border-subtle); padding-top: 12px; font-size: 12.5px; color: var(--text-muted);">
                🔒 <b>Local Isolation Guarantee:</b> All parsing, extraction, tokenization, detection, and redaction procedures execute 100% locally within host memory. Zero document payload or telemetry is dispatched to external endpoints.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if st.button("← Return to Gateway Workspace", type="primary"):
        st.session_state.active_view = "workspace"
        st.rerun()

elif st.session_state.get("active_view") == "telemetry" and has_results:
    # --------------------------------------------------------------------------
    # VISUAL TELEMETRY VIEW
    # --------------------------------------------------------------------------
    render_header("TELEMETRY ACTIVE", "pill-sanitized", "dot-sanitized")

    active_doc = results[0]
    summary = ReportGenerator.get_summary_metrics(results)
    type_data = summary.get("type_breakdown", {})
    sev_data = summary.get("severity_breakdown", {})

    st.markdown("<div style='height: 6px;'></div>", unsafe_allow_html=True)
    c_t1, c_t2 = st.columns(2)

    col_t_is_dark = st.session_state.get("theme_mode", "light") == "dark"
    with c_t1:
        st.markdown(
            """
            <div class="telemetry-chart-card">
                <div style="font-size:14px; font-weight:700; color:var(--text-headline); margin-bottom:2px;">PII Classification Distribution</div>
                <div style="font-size:12px; color:var(--text-muted); margin-bottom:12px;">Entity frequency across detected privacy categories.</div>
            """,
            unsafe_allow_html=True,
        )
        if type_data:
            df_cat = pd.DataFrame(list(type_data.items()), columns=["Category", "Count"]).sort_values(by="Count", ascending=True)
            bar_color = "#6366F1" if col_t_is_dark else "#4F46E5"
            bar_line = "#818CF8" if col_t_is_dark else "#3730A3"
            fig_cat = go.Figure(
                go.Bar(
                    x=df_cat["Count"],
                    y=df_cat["Category"],
                    orientation="h",
                    marker=dict(color=bar_color, line=dict(color=bar_line, width=1.5)),
                    text=df_cat["Count"],
                    textposition="outside",
                    textfont=dict(color="#F8FAFC" if col_t_is_dark else "#0F172A"),
                )
            )
            fig_cat = apply_vibrant_theme(fig_cat, height=280)
            fig_cat.update_layout(xaxis_title="Entity Count", yaxis_title=None)
            st.plotly_chart(fig_cat, use_container_width=True)
        else:
            st.info("Zero PII detected.")
        st.markdown("</div>", unsafe_allow_html=True)

    with c_t2:
        st.markdown(
            """
            <div class="telemetry-chart-card">
                <div style="font-size:14px; font-weight:700; color:var(--text-headline); margin-bottom:2px;">Risk Severity Breakdown</div>
                <div style="font-size:12px; color:var(--text-muted); margin-bottom:12px;">Distribution across finding severity tiers.</div>
            """,
            unsafe_allow_html=True,
        )
        color_map = {
            "CRITICAL": "#F43F5E" if col_t_is_dark else "#DC2626",
            "HIGH": "#FB7185" if col_t_is_dark else "#EF4444",
            "MEDIUM": "#F59E0B" if col_t_is_dark else "#F59E0B",
            "LOW": "#10B981" if col_t_is_dark else "#10B981",
        }
        sev_labels, sev_counts, sev_colors = [], [], []
        for sk in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            if sk in sev_data and sev_data[sk] > 0:
                sev_labels.append(sk)
                sev_counts.append(sev_data[sk])
                sev_colors.append(color_map[sk])

        if sev_counts:
            fig_sev = go.Figure(
                data=[
                    go.Pie(
                        labels=sev_labels,
                        values=sev_counts,
                        hole=0.6,
                        marker=dict(colors=sev_colors),
                        textinfo="label+percent",
                    )
                ]
            )
            fig_sev = apply_vibrant_theme(fig_sev, height=280)
            fig_sev.update_layout(showlegend=True)
            st.plotly_chart(fig_sev, use_container_width=True)
        else:
            st.success("Zero risk findings.")
        st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("<div style='height: 14px;'></div>", unsafe_allow_html=True)
    if st.button("← Return to Gateway Workspace", type="primary"):
        st.session_state.active_view = "workspace"
        st.rerun()

else:
    # --------------------------------------------------------------------------
    # MAIN GATEWAY WORKSPACE
    # --------------------------------------------------------------------------
    active_sample = st.session_state.get("active_sample_file")

    # Determine Header Live State
    if has_results:
        active_doc = results[0]
        stat_val = active_doc.security_status.value if hasattr(active_doc.security_status, "value") else str(active_doc.security_status)
        if stat_val == "SANITIZED":
            hdr_lbl, hdr_cls, dot_cls = "GATEWAY: SANITIZED (PASS)", "pill-sanitized", "dot-sanitized"
        elif stat_val == "BLOCKED":
            hdr_lbl, hdr_cls, dot_cls = "GATEWAY: BLOCKED (FAIL-CLOSED)", "pill-blocked", "dot-blocked"
        else:
            hdr_lbl, hdr_cls, dot_cls = "GATEWAY: REVIEW REQUIRED", "pill-review", "dot-review"
    elif active_sample or st.session_state.get("last_active_file_signature"):
        hdr_lbl, hdr_cls, dot_cls = "ARTIFACT STAGED (READY)", "pill-staged", "dot-staged"
    else:
        hdr_lbl, hdr_cls, dot_cls = "STANDBY • READY FOR INGESTION", "pill-standby", "dot-standby"

    render_header(hdr_lbl, hdr_cls, dot_cls)

    # ==========================================================================
    # 1. FIVE VIBRANT METRIC CARDS (Calculated from Real Data)
    # ==========================================================================
    if has_results:
        summary_metrics = ReportGenerator.get_summary_metrics(results)
        m_docs = summary_metrics["total_documents"]
        m_pii = summary_metrics["total_pii_detected"]
        m_high = summary_metrics["high_risk_findings"]
        m_low = summary_metrics["low_risk_documents"]
        m_blocked_rev = summary_metrics["review_or_blocked"]
    else:
        m_docs = 0
        m_pii = 0
        m_high = 0
        m_low = 0
        m_blocked_rev = 0

    is_dark_ws = st.session_state.get("theme_mode", "light") == "dark"
    pii_val_color = "#C084FC" if is_dark_ws else "#7C3AED"
    high_val_color = ("#FB7185" if is_dark_ws else "#EF4444") if m_high > 0 else "var(--text-headline)"
    low_val_color = "#34D399" if is_dark_ws else "#059669"
    blocked_val_color = (("#FBBF24" if is_dark_ws else "#D97706") if m_blocked_rev > 0 else ("#34D399" if is_dark_ws else "#059669"))

    c_m1, c_m2, c_m3, c_m4, c_m5 = st.columns(5)

    with c_m1:
        st.markdown(
            f"""
            <div class="metric-card-vibrant metric-stripe-indigo">
                <div class="metric-header-row">
                    <span class="metric-label-txt metric-label-indigo">Documents Processed</span>
                    <span class="metric-icon-box">📄</span>
                </div>
                <div class="metric-main-val">{m_docs}</div>
                <div class="metric-sub-txt">Active inspection scope</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with c_m2:
        st.markdown(
            f"""
            <div class="metric-card-vibrant metric-stripe-violet">
                <div class="metric-header-row">
                    <span class="metric-label-txt metric-label-violet">Total Detected PII</span>
                    <span class="metric-icon-box">🔍</span>
                </div>
                <div class="metric-main-val" style="color: {pii_val_color};">{m_pii}</div>
                <div class="metric-sub-txt">Flagged private entities</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with c_m3:
        st.markdown(
            f"""
            <div class="metric-card-vibrant metric-stripe-rose">
                <div class="metric-header-row">
                    <span class="metric-label-txt metric-label-rose">High-Risk Findings</span>
                    <span class="metric-icon-box">⚠️</span>
                </div>
                <div class="metric-main-val" style="color: {high_val_color};">{m_high}</div>
                <div class="metric-sub-txt">Critical & High risk findings</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with c_m4:
        st.markdown(
            f"""
            <div class="metric-card-vibrant metric-stripe-emerald">
                <div class="metric-header-row">
                    <span class="metric-label-txt metric-label-emerald">Low-Risk Documents</span>
                    <span class="metric-icon-box">🛡️</span>
                </div>
                <div class="metric-main-val" style="color: {low_val_color};">{m_low}</div>
                <div class="metric-sub-txt">Safe / low exposure profile</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with c_m5:
        st.markdown(
            f"""
            <div class="metric-card-vibrant metric-stripe-amber">
                <div class="metric-header-row">
                    <span class="metric-label-txt metric-label-amber">Review or Blocked</span>
                    <span class="metric-icon-box">🛑</span>
                </div>
                <div class="metric-main-val" style="color: {blocked_val_color};">{m_blocked_rev}</div>
                <div class="metric-sub-txt">Gate holds & policy rejections</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown("<div style='height: 22px;'></div>", unsafe_allow_html=True)

    # ==========================================================================
    # 2. DOCUMENT INGESTION & STAGING WORKSPACE
    # ==========================================================================
    st.markdown(
        """
        <div class="section-title-wrap">
            <div>
                <h3 class="section-title-text">Document Ingestion & Staging</h3>
                <p class="section-desc-text">Upload business evidence artifact for pre-LLM PII detection and semantic sanitization</p>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    col_up_main, col_up_sample = st.columns([3, 1])

    with col_up_main:
        uploaded_files = st.file_uploader(
            "Upload Document Artifact (Supported: PDF, DOCX, PPTX, TXT)",
            type=["pdf", "docx", "pptx", "txt"],
            accept_multiple_files=True,
            key="saas_uploader",
            label_visibility="collapsed",
            help="Files are processed exclusively in host RAM. No data is stored externally.",
        )

    # Active file state handling
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

    with col_up_sample:
        sample_options = {
            "Executive Briefing (PDF)": "Executive_Briefing.pdf",
            "Financial Org Pack (PPTX)": "Cadence_Financial_Group_Org_Pack.pptx",
            "HR Incident Report (DOCX)": "HR_Incident_Report.docx",
            "Customer Support Log (TXT)": "Customer_Support_Evidence.txt",
        }
        selected_sample_label = st.selectbox(
            "Benchmark Sample Corpus:",
            options=list(sample_options.keys()),
            key="saas_sample_select"
        )
        if st.button("📁 Stage Benchmark Artifact", use_container_width=True, help="Load test document from pre-built sample corpus"):
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
        col_staged_left, col_staged_cta = st.columns([4, 1.6])
        with col_staged_left:
            st.markdown(
                f"""
                <div class="staged-artifact-card">
                    <div class="staged-left-info">
                        <span class="staged-badge-format">{staged_meta['ext']}</span>
                        <div>
                            <div class="staged-name-text">{staged_meta['name']}</div>
                            <div class="staged-meta-text">
                                Source: {staged_meta['source']} • Size: {staged_meta['size']} • SHA-256: <code>{staged_meta['hash']}</code>
                            </div>
                        </div>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        with col_staged_cta:
            st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)
            run_inspection_btn = st.button("⚡ Execute Security Pipeline", type="primary", use_container_width=True)

        if run_inspection_btn and staged_payload:
            fname, fbytes = staged_payload
            prog_bar = st.progress(0, text=f"Initializing security pipeline for {fname}...")
            
            pipeline = get_pipeline()
            prog_bar.progress(20, text="1/5 Extracting structural document blocks...")
            time.sleep(0.04)
            prog_bar.progress(45, text="2/5 Executing hybrid tri-engine PII discovery...")
            time.sleep(0.04)
            prog_bar.progress(65, text="3/5 Computing multi-factor risk assessment...")
            time.sleep(0.04)
            prog_bar.progress(85, text="4/5 Applying consistent semantic surrogate redaction...")
            
            res = pipeline.process_document(file_bytes=fbytes, file_name=fname)
            prog_bar.progress(100, text="5/5 Post-redaction secondary validation verified.")
            time.sleep(0.04)
            prog_bar.empty()
            
            st.session_state.analysis_results = [res]
            st.rerun()

    else:
        st.markdown(
            """
            <div class="saas-empty-container">
                <div class="empty-symbol">📂</div>
                <div class="empty-lead">Ready for Document Security Ingestion</div>
                <div class="empty-detail">
                    Upload a business document (PDF, Word DOCX, Presentation PPTX, or Log TXT) or select a benchmark sample artifact to trigger the 5-stage Zero-Trust verification process.
                </div>
                <div style="margin-top: 12px; font-size: 11.5px; color: #94A3B8;">
                    🔒 All processing is executed locally in volatile RAM. No data egress to cloud LLMs or third parties.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # ==========================================================================
    # 3. FIVE-STAGE PIPELINE PROGRESSION & VERDICT
    # ==========================================================================
    if has_results:
        selected_doc = results[0]
        vr = selected_doc.validation_result
        doc_stat_val = selected_doc.security_status.value if hasattr(selected_doc.security_status, "value") else str(selected_doc.security_status)
        replacements_count = selected_doc.redaction_result.replacements_count if selected_doc.redaction_result else 0
        residual_count = len(vr.residual_findings) if vr else 0
        risk_data = selected_doc.risk_assessment or {}
        risk_tier = risk_data.get("risk_tier", "LOW")
        risk_score = risk_data.get("risk_score", 0)

        st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)
        st.markdown(
            """
            <div class="section-title-wrap">
                <div>
                    <h3 class="section-title-text">Pipeline Progression & Security Gate Decision</h3>
                    <p class="section-desc-text">Sequential 5-stage verification outputs and authoritative security clearance</p>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # 5-Stage Stepper Grid
        s5_cls = "step-cell-pass" if (vr and vr.passed) else ("step-cell-fail" if vr else "")
        s5_tag = "Stage 05 • Validation"
        s5_status = "0 Residual (Passed)" if (vr and vr.passed) else (f"{residual_count} Leaks (Failed)" if vr else "Pending")
        s5_tag_color = "var(--safe-green)" if (vr and vr.passed) else "var(--blocked-red)"

        st.markdown(
            f"""
            <div class="stepper-5stage-grid">
                <div class="step-box-cell step-cell-extract">
                    <div class="step-tag-text step-done-tag">Stage 01 • Extraction</div>
                    <div class="step-title-text">Structural Parsing</div>
                    <div class="step-sub-text">{len(selected_doc.blocks)} blocks preserved</div>
                </div>
                <div class="step-box-cell step-cell-detect">
                    <div class="step-tag-text" style="color: var(--brand-violet);">Stage 02 • Detection</div>
                    <div class="step-title-text">Tri-Engine Discovery</div>
                    <div class="step-sub-text">{len(selected_doc.pii_findings)} entities flagged</div>
                </div>
                <div class="step-box-cell step-cell-risk">
                    <div class="step-tag-text" style="color: var(--review-amber);">Stage 03 • Risk Assessment</div>
                    <div class="step-title-text">Risk Tier: {risk_tier}</div>
                    <div class="step-sub-text">Calculated Score: {risk_score}/100</div>
                </div>
                <div class="step-box-cell step-cell-redact">
                    <div class="step-tag-text" style="color: var(--brand-blue);">Stage 04 • Redaction</div>
                    <div class="step-title-text">Semantic Replacement</div>
                    <div class="step-sub-text">{replacements_count} surrogate keys</div>
                </div>
                <div class="step-box-cell {s5_cls}">
                    <div class="step-tag-text" style="color: {s5_tag_color};">{s5_tag}</div>
                    <div class="step-title-text">Secondary Gate</div>
                    <div class="step-sub-text">{s5_status}</div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # Executive Gate Verdict Banner
        high_risk_count = sum(1 for f in selected_doc.pii_findings if (f.severity.value if hasattr(f.severity, "value") else str(f.severity)) in ("CRITICAL", "HIGH"))

        if doc_stat_val == SecurityStatus.SANITIZED.value:
            st.markdown(
                f"""
                <div class="verdict-banner-card verdict-bg-sanitized">
                    <div class="verdict-primary-col">
                        <div class="verdict-icon-symbol" style="color: var(--safe-green);">✓</div>
                        <div>
                            <div class="verdict-title-headline">SECURITY VERDICT: SANITIZED — APPROVED FOR DOWNSTREAM LLM INGESTION</div>
                            <div class="verdict-body-desc">
                                Post-redaction validation verified zero residual PII entities across all {len(selected_doc.blocks)} extracted blocks. Semantic surrogate keys maintain linguistic co-reference resolution for downstream AI reasoning while guaranteeing complete privacy.
                            </div>
                        </div>
                    </div>
                    <div class="verdict-telemetry-strip">
                        <div class="verdict-metric-pill">
                            <div class="v-pill-lbl">Latency</div>
                            <div class="v-pill-num">{selected_doc.processing_time_ms:.1f}ms</div>
                        </div>
                        <div class="verdict-metric-pill">
                            <div class="v-pill-lbl">PII Found</div>
                            <div class="v-pill-num">{len(selected_doc.pii_findings)}</div>
                        </div>
                        <div class="verdict-metric-pill">
                            <div class="v-pill-lbl">Risk Tier</div>
                            <div class="v-pill-num" style="color: var(--safe-green);">{risk_tier}</div>
                        </div>
                        <div class="verdict-metric-pill">
                            <div class="v-pill-lbl">Residual</div>
                            <div class="v-pill-num" style="color: var(--safe-green);">0</div>
                        </div>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        elif doc_stat_val == SecurityStatus.BLOCKED.value:
            st.markdown(
                f"""
                <div class="verdict-banner-card verdict-bg-blocked">
                    <div class="verdict-primary-col">
                        <div class="verdict-icon-symbol" style="color: var(--blocked-red);">✕</div>
                        <div>
                            <div class="verdict-title-headline">SECURITY VERDICT: BLOCKED — FAIL-CLOSED ENFORCEMENT TRIGGERED</div>
                            <div class="verdict-body-desc">
                                Post-redaction re-scan detected residual PII entities or extraction anomaly. Downstream transmission to LLMs is halted immediately to prevent sensitive corporate data leakage.
                            </div>
                        </div>
                    </div>
                    <div class="verdict-telemetry-strip">
                        <div class="verdict-metric-pill">
                            <div class="v-pill-lbl">Latency</div>
                            <div class="v-pill-num">{selected_doc.processing_time_ms:.1f}ms</div>
                        </div>
                        <div class="verdict-metric-pill">
                            <div class="v-pill-lbl">PII Found</div>
                            <div class="v-pill-num">{len(selected_doc.pii_findings)}</div>
                        </div>
                        <div class="verdict-metric-pill">
                            <div class="v-pill-lbl">Risk Tier</div>
                            <div class="v-pill-num" style="color: var(--blocked-red);">{risk_tier}</div>
                        </div>
                        <div class="verdict-metric-pill">
                            <div class="v-pill-lbl">Residual</div>
                            <div class="v-pill-num" style="color: var(--blocked-red);">{residual_count}</div>
                        </div>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        else:
            st.markdown(
                f"""
                <div class="verdict-banner-card verdict-bg-review">
                    <div class="verdict-primary-col">
                        <div class="verdict-icon-symbol" style="color: var(--review-amber);">⚠</div>
                        <div>
                            <div class="verdict-title-headline">SECURITY VERDICT: REVIEW REQUIRED — MANUAL CLEARANCE MANDATED</div>
                            <div class="verdict-body-desc">
                                Document contains low-confidence detections or unscanned embedded elements requiring compliance analyst verification prior to release.
                            </div>
                        </div>
                    </div>
                    <div class="verdict-telemetry-strip">
                        <div class="verdict-metric-pill">
                            <div class="v-pill-lbl">Latency</div>
                            <div class="v-pill-num">{selected_doc.processing_time_ms:.1f}ms</div>
                        </div>
                        <div class="verdict-metric-pill">
                            <div class="v-pill-lbl">PII Found</div>
                            <div class="v-pill-num">{len(selected_doc.pii_findings)}</div>
                        </div>
                        <div class="verdict-metric-pill">
                            <div class="v-pill-lbl">Risk Tier</div>
                            <div class="v-pill-num" style="color: var(--review-amber);">{risk_tier}</div>
                        </div>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        # ======================================================================
        # 4. TABBED INVESTIGATION & TRIAGE CONSOLE
        # ======================================================================
        st.markdown("<div style='height: 8px;'></div>", unsafe_allow_html=True)
        st.markdown(
            """
            <div class="section-title-wrap">
                <div>
                    <h3 class="section-title-text">Security Operations & Analysis Console</h3>
                    <p class="section-desc-text">Detailed entity triage, intelligent risk assessment, sanitized artifact preview, and traceability matrix</p>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        tab_findings, tab_risk, tab_sanitized, tab_validation, tab_traceability, tab_blocks, tab_exports = st.tabs([
            "🔍 PII Findings Log",
            "⚖️ Intelligent Risk Assessment",
            "📄 Sanitized Output & Surrogate Registry",
            "🛡️ Post-Redaction Validation Audit",
            "🧭 Structural Traceability Matrix",
            "📑 Raw Extracted Blocks",
            "📋 Compliance Export (JSON/CSV)",
        ])

        # TAB 1: PII FINDINGS LOG & TRIAGE
        with tab_findings:
            col_f_sev, col_f_cat, col_unmask = st.columns([1.5, 1.5, 2])
            with col_f_sev:
                sev_choice = st.selectbox(
                    "Filter Severity:",
                    ["All Severities", "CRITICAL", "HIGH", "MEDIUM", "LOW"],
                    key="vibrant_sev_filter"
                )
            with col_f_cat:
                all_cats = sorted(list({f.pii_type.value if hasattr(f.pii_type, "value") else str(f.pii_type) for f in selected_doc.pii_findings}))
                cat_choice = st.selectbox(
                    "Filter Classification:",
                    ["All Classifications"] + all_cats,
                    key="vibrant_cat_filter"
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
                st.markdown(f"<div style='font-size: 11.5px; color: var(--text-muted); margin-top: 4px;'>Displaying <b>{len(filtered_rows)}</b> of <b>{len(selected_doc.pii_findings)}</b> verified findings.</div>", unsafe_allow_html=True)
            else:
                if selected_doc.pii_findings:
                    st.info("No findings match the selected filter criteria.")
                else:
                    st.success("Zero PII entities detected across this document.")

        # TAB 2: INTELLIGENT RISK ASSESSMENT
        with tab_risk:
            st.markdown("<div style='font-size: 13.5px; font-weight: 700; color: var(--text-headline); margin-bottom: 8px;'>Explainable Document Privacy Risk Breakdown:</div>", unsafe_allow_html=True)
            
            risk_tier_color = "var(--blocked-red)" if risk_tier in ('CRITICAL', 'HIGH') else ("var(--review-amber)" if risk_tier == 'MODERATE' else "var(--safe-green)")
            c_rk1, c_rk2, c_rk3, c_rk4 = st.columns(4)
            with c_rk1:
                st.markdown(
                    f"""
                    <div class="risk-metric-box">
                        <div style="font-size:11px; font-weight:700; color:var(--text-muted); text-transform:uppercase;">Overall Risk Tier</div>
                        <div style="font-size:22px; font-weight:800; color:{risk_tier_color}; margin-top:2px;">{risk_tier}</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
            with c_rk2:
                st.markdown(
                    f"""
                    <div class="risk-metric-box">
                        <div style="font-size:11px; font-weight:700; color:var(--text-muted); text-transform:uppercase;">Calculated Score</div>
                        <div style="font-size:22px; font-weight:800; color:var(--brand-indigo); margin-top:2px;">{risk_score} / 100</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
            with c_rk3:
                st.markdown(
                    f"""
                    <div class="risk-metric-box">
                        <div style="font-size:11px; font-weight:700; color:var(--text-muted); text-transform:uppercase;">Distinct Entities</div>
                        <div style="font-size:22px; font-weight:800; color:var(--text-headline); margin-top:2px;">{risk_data.get('distinct_entities_count', 0)}</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
            with c_rk4:
                st.markdown(
                    f"""
                    <div class="risk-metric-box">
                        <div style="font-size:11px; font-weight:700; color:var(--text-muted); text-transform:uppercase;">Regulated Credentials</div>
                        <div style="font-size:22px; font-weight:800; color:{'var(--blocked-red)' if risk_data.get('critical_identifiers_present') else 'var(--safe-green)'}; margin-top:2px;">{'YES' if risk_data.get('critical_identifiers_present') else 'NO'}</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

            st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)
            st.markdown("<div style='font-size: 12.5px; font-weight: 700; color: var(--text-headline);'>Risk Factors & Justification:</div>", unsafe_allow_html=True)
            for factor in risk_data.get("risk_factors", []):
                st.markdown(f"- **Evidence**: {factor}")

            st.markdown("<div style='height: 8px;'></div>", unsafe_allow_html=True)
            st.markdown(f"**Policy Recommendation**: {risk_data.get('recommendation', 'N/A')}")

        # TAB 3: SANITIZED ARTIFACT & SURROGATE KEYS
        with tab_sanitized:
            if selected_doc.redaction_result and selected_doc.redaction_result.redacted_full_text:
                col_prev_txt, col_prev_dict = st.columns([3, 2])

                with col_prev_txt:
                    st.markdown("<div style='font-size: 12.5px; font-weight: 700; color: var(--text-headline); margin-bottom: 6px;'>Sanitized Document Content (Semantic Surrogate Tokens Preserved):</div>", unsafe_allow_html=True)
                    st.markdown(f'<div class="preview-doc-box">{selected_doc.redaction_result.redacted_full_text}</div>', unsafe_allow_html=True)

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

                with col_prev_dict:
                    st.markdown("<div style='font-size: 12.5px; font-weight: 700; color: var(--text-headline); margin-bottom: 6px;'>Deterministic Surrogate Key Mapping Registry:</div>", unsafe_allow_html=True)
                    mapping_entries = []
                    for raw_key, tag in selected_doc.redaction_result.entity_mappings.items():
                        mapping_entries.append({
                            "Surrogate Key": tag,
                            "Masked Entity": raw_key if reveal_raw else f"•••••••• ({len(raw_key)} chars)",
                            "Co-Reference Standard": "Deterministic 1:1 Tag",
                        })
                    if mapping_entries:
                        st.dataframe(pd.DataFrame(mapping_entries), use_container_width=True, hide_index=True)
                        st.markdown("<div style='font-size: 11px; color: var(--text-muted); margin-top: 4px;'>Recurring mentions of the same identity map to identical surrogate tokens across pages.</div>", unsafe_allow_html=True)
                    else:
                        st.info("No surrogate keys generated.")
            else:
                st.info("No redaction outputs available.")

        # TAB 4: POST-REDACTION VALIDATION AUDIT
        with tab_validation:
            if vr:
                stat_badge_color = "var(--safe-green)" if vr.passed else "var(--blocked-red)"
                st.markdown(
                    f"""
                    <div class="validation-audit-card">
                        <table style="width: 100%; border-collapse: collapse; font-size: 13px;">
                            <tr style="border-bottom: 1px solid var(--border-subtle);">
                                <td style="padding: 8px 0; color: var(--text-muted); font-weight: 600;">Secondary Validation Gate:</td>
                                <td style="padding: 8px 0; font-weight: 700; color: {stat_badge_color};">{'PASSED (ZERO RESIDUAL PII)' if vr.passed else 'FAILED (RESIDUAL DETECTIONS FOUND)'}</td>
                            </tr>
                            <tr style="border-bottom: 1px solid var(--border-subtle);">
                                <td style="padding: 8px 0; color: var(--text-muted); font-weight: 600;">Residual PII Count:</td>
                                <td style="padding: 8px 0; font-weight: 700; color: var(--text-headline);">{len(vr.residual_findings)} entities</td>
                            </tr>
                            <tr style="border-bottom: 1px solid var(--border-subtle);">
                                <td style="padding: 8px 0; color: var(--text-muted); font-weight: 600;">Fail-Closed Security Verdict:</td>
                                <td style="padding: 8px 0; font-weight: 700; color: var(--text-headline);">{vr.status.value}</td>
                            </tr>
                            <tr>
                                <td style="padding: 8px 0; color: var(--text-muted); font-weight: 600;">Enforced Security Rule:</td>
                                <td style="padding: 8px 0; color: var(--text-secondary);">{vr.validation_message}</td>
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

        # TAB 5: STRUCTURAL TRACEABILITY MATRIX
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

        # TAB 6: RAW EXTRACTED BLOCKS
        with tab_blocks:
            st.markdown(f"<div style='font-size: 12px; color: var(--text-muted); margin-bottom: 10px;'>Preserved structural blocks for <b>{selected_doc.file_name}</b> (Retained in volatile local memory):</div>", unsafe_allow_html=True)
            for b in selected_doc.blocks:
                st.markdown(
                    f"""
                    <div class="raw-block-card">
                        <div style="font-size:11px; font-weight:600; color:var(--text-muted); margin-bottom:4px; font-family:ui-monospace, SFMono-Regular, Menlo, monospace;">Coordinate: {b.location} | Type: {b.block_type} | Index: {b.order}</div>
                        <div style="font-size:12.5px; color:var(--text-body); white-space:pre-wrap; line-height:1.5;">{b.text}</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

        # TAB 7: COMPLIANCE EXPORTS
        with tab_exports:
            st.markdown("<div style='font-size: 13px; font-weight: 700; color: var(--text-headline); margin-bottom: 8px;'>Export SIEM-Ready Audit Telemetry & Forensic Traceability Matrix:</div>", unsafe_allow_html=True)
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
