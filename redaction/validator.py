"""Post-redaction validation engine implementing fail-closed security re-scanning."""
import logging
from typing import List

from models.schemas import (
    DocumentBlock,
    PIIFinding,
    ValidationResult,
    SecurityStatus,
    Severity,
    ConfidenceLevel,
)
from detection.pii_engine import PIIEngine

logger = logging.getLogger(__name__)


class PostRedactionValidator:
    """Validates sanitized content by executing a secondary security scan."""

    def __init__(self, pii_engine: PIIEngine):
        self.pii_engine = pii_engine

    def validate(
        self,
        redacted_blocks: List[DocumentBlock],
        document_id: str
    ) -> ValidationResult:
        """Re-scan sanitized blocks to verify complete elimination of detectable PII."""
        # 1. Run full hybrid detection engine again on the sanitized blocks
        residual_findings = self.pii_engine.detect_blocks(redacted_blocks)

        # 2. Filter out non-actionable or low confidence false-positives if any
        # Any residual PII with confidence >= 0.70 or severity in [CRITICAL, HIGH] causes immediate BLOCK
        actionable_residuals = [
            f for f in residual_findings
            if f.confidence >= 0.70 or f.severity in (Severity.CRITICAL, Severity.HIGH)
        ]

        if actionable_residuals:
            # Residual PII detected: FAIL-CLOSED
            logger.warning(
                f"Document {document_id} failed post-redaction validation: {len(actionable_residuals)} residual findings."
            )
            msg = (
                f"BLOCKED — Residual PII detected after redaction ({len(actionable_residuals)} items remaining). "
                "Document fails validation and is unsafe for downstream AI processing."
            )
            return ValidationResult(
                document_id=document_id,
                is_safe=False,
                status=SecurityStatus.BLOCKED,
                residual_findings=actionable_residuals,
                validation_message=msg,
                passed=False,
            )

        if residual_findings:
            # Low confidence residual notes: requires analyst review
            msg = (
                f"REVIEW REQUIRED — Minor low-confidence signals ({len(residual_findings)} items) detected during re-scan. "
                "Document requires manual analyst clearance before downstream AI submission."
            )
            return ValidationResult(
                document_id=document_id,
                is_safe=False,
                status=SecurityStatus.REVIEW_REQUIRED,
                residual_findings=residual_findings,
                validation_message=msg,
                passed=False,
            )

        # 3. Clean clearance: SANITIZED
        msg = "SANITIZED — Zero detectable PII remains after re-scan. Verified safe for downstream AI processing."
        return ValidationResult(
            document_id=document_id,
            is_safe=True,
            status=SecurityStatus.SANITIZED,
            residual_findings=[],
            validation_message=msg,
            passed=True,
        )
