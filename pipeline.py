"""End-to-end security pipeline coordinator for PII Security Gateway.

Implements the strict fail-closed pipeline:
UPLOAD -> CLASSIFY -> EXTRACT -> PRESERVE STRUCTURE -> DETECT -> CLASSIFY
-> CALCULATE CONFIDENCE -> DISPLAY EXPOSURE -> REDACT -> RE-SCAN -> VALIDATE
-> SAFE / BLOCKED -> SANITIZED OUTPUT
"""
import time
import logging
from pathlib import Path
from typing import List, Optional

from models.schemas import (
    DocumentAnalysisResult,
    SecurityStatus,
    RedactionResult,
    ValidationResult,
)
from extractors import extract_document
from detection.pii_engine import PIIEngine
from redaction.redactor import PIIRedactor
from redaction.validator import PostRedactionValidator
from utils.helpers import calculate_file_hash

logger = logging.getLogger(__name__)


class GatewayPipeline:
    """Coordinates the end-to-end pre-LLM security gateway workflow."""

    def __init__(self, spacy_model: str = "en_core_web_sm"):
        self.pii_engine = PIIEngine(spacy_model=spacy_model)
        self.redactor = PIIRedactor()
        self.validator = PostRedactionValidator(pii_engine=self.pii_engine)

    def process_document(
        self,
        file_bytes: bytes,
        file_name: str,
        document_id: Optional[str] = None
    ) -> DocumentAnalysisResult:
        """Execute the full gateway pipeline on a document artifact."""
        start_time = time.time()
        file_ext = Path(file_name).suffix.lower()
        file_size = len(file_bytes)

        if not document_id:
            document_id = f"doc_{calculate_file_hash(file_bytes)}"

        # Fail-closed check: Empty file
        if file_size == 0:
            return DocumentAnalysisResult(
                document_id=document_id,
                file_name=file_name,
                file_type=file_ext.lstrip("."),
                file_size_bytes=0,
                extraction_status="FAILED_EMPTY_FILE",
                blocks=[],
                total_characters=0,
                pii_findings=[],
                security_status=SecurityStatus.BLOCKED,
                error_message="Uploaded document is empty (0 bytes). Pipeline failed closed.",
                processing_time_ms=(time.time() - start_time) * 1000,
            )

        # 1. Extraction with structure preservation
        try:
            blocks, requires_ocr, extraction_status = extract_document(
                file_bytes=file_bytes,
                file_name=file_name,
                document_id=document_id
            )
        except Exception as extract_err:
            logger.error(f"Extraction error for {file_name}: {extract_err}")
            # Fail closed on extraction error
            return DocumentAnalysisResult(
                document_id=document_id,
                file_name=file_name,
                file_type=file_ext.lstrip("."),
                file_size_bytes=file_size,
                extraction_status=f"EXTRACTION_FAILED: {extract_err}",
                blocks=[],
                total_characters=0,
                pii_findings=[],
                security_status=SecurityStatus.BLOCKED,
                error_message=f"Extraction failure: {extract_err}. Document blocked.",
                processing_time_ms=(time.time() - start_time) * 1000,
            )

        total_chars = sum(len(b.text) for b in blocks)

        # Fail closed check: No usable text extracted
        if total_chars == 0:
            return DocumentAnalysisResult(
                document_id=document_id,
                file_name=file_name,
                file_type=file_ext.lstrip("."),
                file_size_bytes=file_size,
                extraction_status="NO_TEXT_FOUND",
                blocks=blocks,
                total_characters=0,
                pii_findings=[],
                security_status=SecurityStatus.BLOCKED,
                requires_ocr=requires_ocr,
                error_message="No extractable text found in document. Document blocked.",
                processing_time_ms=(time.time() - start_time) * 1000,
            )

        # 2. Hybrid PII Detection
        try:
            findings = self.pii_engine.detect_blocks(blocks)
        except Exception as det_err:
            logger.error(f"Detection error for {file_name}: {det_err}")
            # Fail closed on detection failure
            return DocumentAnalysisResult(
                document_id=document_id,
                file_name=file_name,
                file_type=file_ext.lstrip("."),
                file_size_bytes=file_size,
                extraction_status=extraction_status,
                blocks=blocks,
                total_characters=total_chars,
                pii_findings=[],
                security_status=SecurityStatus.BLOCKED,
                requires_ocr=requires_ocr,
                error_message=f"PII detection engine error: {det_err}. Document blocked.",
                processing_time_ms=(time.time() - start_time) * 1000,
            )

        # 3. Redaction using Consistent Semantic Placeholders
        try:
            redaction_res = self.redactor.redact_document(
                blocks=blocks,
                findings=findings,
                document_id=document_id,
                file_name=file_name,
            )
        except Exception as red_err:
            logger.error(f"Redaction error for {file_name}: {red_err}")
            return DocumentAnalysisResult(
                document_id=document_id,
                file_name=file_name,
                file_type=file_ext.lstrip("."),
                file_size_bytes=file_size,
                extraction_status=extraction_status,
                blocks=blocks,
                total_characters=total_chars,
                pii_findings=findings,
                security_status=SecurityStatus.BLOCKED,
                requires_ocr=requires_ocr,
                error_message=f"Redaction failure: {red_err}. Document blocked.",
                processing_time_ms=(time.time() - start_time) * 1000,
            )

        # 4. Post-Redaction Validation (Re-scanning sanitized blocks)
        try:
            validation_res = self.validator.validate(
                redacted_blocks=redaction_res.redacted_blocks,
                document_id=document_id,
            )
        except Exception as val_err:
            logger.error(f"Validation error for {file_name}: {val_err}")
            return DocumentAnalysisResult(
                document_id=document_id,
                file_name=file_name,
                file_type=file_ext.lstrip("."),
                file_size_bytes=file_size,
                extraction_status=extraction_status,
                blocks=blocks,
                total_characters=total_chars,
                pii_findings=findings,
                redaction_result=redaction_res,
                security_status=SecurityStatus.BLOCKED,
                requires_ocr=requires_ocr,
                error_message=f"Validation failure: {val_err}. Document blocked.",
                processing_time_ms=(time.time() - start_time) * 1000,
            )

        # 5. Final Security Status Decision
        # If page requires OCR and text is unreadable, warn or block if not confident
        final_status = validation_res.status
        if requires_ocr and not any("ocr" in b.location for b in blocks):
            # Scanned page where OCR was unavailable -> Mark REVIEW REQUIRED
            final_status = SecurityStatus.REVIEW_REQUIRED

        elapsed_ms = (time.time() - start_time) * 1000

        return DocumentAnalysisResult(
            document_id=document_id,
            file_name=file_name,
            file_type=file_ext.lstrip("."),
            file_size_bytes=file_size,
            extraction_status=extraction_status,
            blocks=blocks,
            total_characters=total_chars,
            pii_findings=findings,
            redaction_result=redaction_res,
            validation_result=validation_res,
            security_status=final_status,
            requires_ocr=requires_ocr,
            processing_time_ms=elapsed_ms,
        )
