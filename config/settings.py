"""Configuration settings for PII Security Gateway."""
from pathlib import Path
from typing import Dict, Any

# Base Directories
BASE_DIR = Path(__file__).resolve().parent.parent
UPLOAD_DIR = BASE_DIR / "uploads"
OUTPUT_DIR = BASE_DIR / "outputs"

UPLOAD_DIR.mkdir(exist_ok=True)
OUTPUT_DIR.mkdir(exist_ok=True)

# Supported File Types
SUPPORTED_EXTENSIONS = {".pdf", ".docx", ".pptx", ".txt"}

# Security Status Constants
STATUS_SANITIZED = "SANITIZED"
STATUS_BLOCKED = "BLOCKED"
STATUS_REVIEW_REQUIRED = "REVIEW REQUIRED"
STATUS_PROCESSING_ERROR = "PROCESSING ERROR"

# Confidence Thresholds
CONFIDENCE_HIGH = 0.90
CONFIDENCE_MEDIUM = 0.70

# Minimum OCR Character Count threshold for Scanned Page Detection
OCR_MIN_CHAR_COUNT = 15

# Default Internal Severity Mapping
DEFAULT_SEVERITY_MAPPING: Dict[str, str] = {
    "GOVERNMENT_ID": "CRITICAL",
    "CREDIT_CARD": "CRITICAL",
    "EMPLOYEE_ID": "HIGH",
    "EMAIL": "HIGH",
    "PHONE": "HIGH",
    "PERSON": "HIGH",
    "ADDRESS": "MEDIUM",
    "DATE_OF_BIRTH": "MEDIUM",
    "IP_ADDRESS": "LOW",
    "OTHER_PII": "LOW",
}

# Regex Patterns Configuration
REGEX_PATTERNS = {
    "EMAIL": r"\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\b",
    "PHONE_INTL": r"(?:\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}\b",
    "PHONE_DOMESTIC_IN": r"\b[6-9]\d{9}\b",
    "PHONE_US": r"\b\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
    "IP_ADDRESS": r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
    "CREDIT_CARD": r"\b(?:\d{4}[-\s]?){3}\d{4}\b|\b\d{15,16}\b",
    "EMPLOYEE_ID": r"\b(?:EMP|E|STAFF|ID)[-_]?[0-9]{4,8}\b",
    "GOVERNMENT_ID_GENERIC": r"\b(?:GVT|GOV|ID|PASSPORT|SSN)[-_]?[0-9A-Z]{5,10}\b",
    "GOVERNMENT_ID_SSN": r"\b\d{3}-\d{2}-\d{4}\b",
    "GOVERNMENT_ID_AADHAAR": r"\b\d{4}\s?\d{4}\s?\d{4}\b",
}
