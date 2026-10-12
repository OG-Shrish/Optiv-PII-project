"""Common data schemas for PII Security Gateway.

Defines normalized data structures for document blocks, findings, redactions,
validation results, and analysis summaries.
"""
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any


class PIIType(str, Enum):
    """Supported Personally Identifiable Information classifications."""
    PERSON = "PERSON"
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    EMPLOYEE_ID = "EMPLOYEE_ID"
    GOVERNMENT_ID = "GOVERNMENT_ID"
    ADDRESS = "ADDRESS"
    DATE_OF_BIRTH = "DATE_OF_BIRTH"
    CREDIT_CARD = "CREDIT_CARD"
    IP_ADDRESS = "IP_ADDRESS"
    OTHER_PII = "OTHER_PII"


class Severity(str, Enum):
    """Internal application risk classification severity."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class ConfidenceLevel(str, Enum):
    """Categorized confidence levels."""
    HIGH = "HIGH"        # >= 0.90
    MEDIUM = "MEDIUM"    # 0.70 - 0.89
    LOW = "LOW"          # < 0.70


class SecurityStatus(str, Enum):
    """Document security outcome status."""
    SANITIZED = "SANITIZED"
    BLOCKED = "BLOCKED"
    REVIEW_REQUIRED = "REVIEW REQUIRED"
    PROCESSING_ERROR = "PROCESSING ERROR"


@dataclass
class DocumentBlock:
    """Normalized document content block retaining structure and source location."""
    document_id: str
    file_name: str
    file_type: str
    location: str          # e.g., 'page_1', 'slide_2_text', 'paragraph_5', 'table_1_row_2'
    block_type: str        # e.g., 'page', 'paragraph', 'heading', 'table_cell', 'slide_text'
    text: str
    order: int
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "document_id": self.document_id,
            "file_name": self.file_name,
            "file_type": self.file_type,
            "location": self.location,
            "block_type": self.block_type,
            "text": self.text,
            "order": self.order,
            "metadata": self.metadata,
        }


@dataclass
class PIIFinding:
    """Detailed record of detected Personally Identifiable Information."""
    finding_id: str
    document_id: str
    file_name: str
    location: str
    block_order: int
    start: int
    end: int
    text: str
    pii_type: PIIType
    confidence: float
    confidence_level: ConfidenceLevel
    detection_method: List[str]
    severity: Severity
    explanation: str = ""
    masked_text: str = ""
    action: str = "REDACTED"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "document_id": self.document_id,
            "file_name": self.file_name,
            "location": self.location,
            "block_order": self.block_order,
            "start": self.start,
            "end": self.end,
            "text": self.text,
            "pii_type": self.pii_type.value if isinstance(self.pii_type, PIIType) else str(self.pii_type),
            "confidence": round(self.confidence, 4),
            "confidence_level": self.confidence_level.value if isinstance(self.confidence_level, ConfidenceLevel) else str(self.confidence_level),
            "detection_method": self.detection_method,
            "severity": self.severity.value if isinstance(self.severity, Severity) else str(self.severity),
            "explanation": self.explanation,
            "masked_text": self.masked_text,
            "action": self.action,
        }


@dataclass
class RedactionResult:
    """Outcome of redaction transformation with semantic placeholders."""
    document_id: str
    file_name: str
    redacted_blocks: List[DocumentBlock]
    redacted_full_text: str
    entity_mappings: Dict[str, str]  # Internal mapping e.g., {"john.smith@example.com": "[EMAIL_001]"}
    replacements_count: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "document_id": self.document_id,
            "file_name": self.file_name,
            "replacements_count": self.replacements_count,
            "redacted_full_text": self.redacted_full_text,
        }


@dataclass
class ValidationResult:
    """Outcome of re-scanning sanitized content (post-redaction validation)."""
    document_id: str
    is_safe: bool
    status: SecurityStatus
    residual_findings: List[PIIFinding]
    validation_message: str
    passed: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "document_id": self.document_id,
            "is_safe": self.is_safe,
            "status": self.status.value if isinstance(self.status, SecurityStatus) else str(self.status),
            "residual_findings_count": len(self.residual_findings),
            "residual_findings": [f.to_dict() for f in self.residual_findings],
            "validation_message": self.validation_message,
            "passed": self.passed,
        }


@dataclass
class DocumentAnalysisResult:
    """Comprehensive analysis outcome for a single document artifact."""
    document_id: str
    file_name: str
    file_type: str
    file_size_bytes: int
    extraction_status: str
    blocks: List[DocumentBlock]
    total_characters: int
    pii_findings: List[PIIFinding]
    redaction_result: Optional[RedactionResult] = None
    validation_result: Optional[ValidationResult] = None
    security_status: SecurityStatus = SecurityStatus.BLOCKED
    requires_ocr: bool = False
    error_message: Optional[str] = None
    processing_time_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "document_id": self.document_id,
            "file_name": self.file_name,
            "file_type": self.file_type,
            "file_size_bytes": self.file_size_bytes,
            "extraction_status": self.extraction_status,
            "blocks_count": len(self.blocks),
            "total_characters": self.total_characters,
            "pii_findings_count": len(self.pii_findings),
            "pii_findings": [f.to_dict() for f in self.pii_findings],
            "redaction_result": self.redaction_result.to_dict() if self.redaction_result else None,
            "validation_result": self.validation_result.to_dict() if self.validation_result else None,
            "security_status": self.security_status.value if isinstance(self.security_status, SecurityStatus) else str(self.security_status),
            "requires_ocr": self.requires_ocr,
            "error_message": self.error_message,
            "processing_time_ms": round(self.processing_time_ms, 2),
        }
