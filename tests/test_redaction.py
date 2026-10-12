"""Tests for semantic redaction, placeholder consistency, and mapping registry."""
from redaction.redactor import PIIRedactor
from models.schemas import DocumentBlock, PIIFinding, PIIType, Severity, ConfidenceLevel


def test_consistent_placeholder_mapping():
    """Verify that multiple occurrences of the same entity receive the same placeholder."""
    redactor = PIIRedactor()
    
    # Document with John Smith in block 0 and block 1, and Jane Doe in block 1
    block0 = DocumentBlock(
        document_id="d1",
        file_name="test.txt",
        file_type="txt",
        location="p1",
        block_type="paragraph",
        text="Lead investigator is John Smith.",
        order=0
    )
    block1 = DocumentBlock(
        document_id="d1",
        file_name="test.txt",
        file_type="txt",
        location="p2",
        block_type="paragraph",
        text="Report submitted by John Smith and reviewed by Jane Doe.",
        order=1
    )

    findings = [
        PIIFinding(
            finding_id="f1",
            document_id="d1",
            file_name="test.txt",
            location="p1",
            block_order=0,
            start=20,
            end=30,
            text="John Smith",
            pii_type=PIIType.PERSON,
            confidence=0.95,
            confidence_level=ConfidenceLevel.HIGH,
            detection_method=["NER"],
            severity=Severity.HIGH,
        ),
        PIIFinding(
            finding_id="f2",
            document_id="d1",
            file_name="test.txt",
            location="p2",
            block_order=1,
            start=20,
            end=30,
            text="John Smith",
            pii_type=PIIType.PERSON,
            confidence=0.95,
            confidence_level=ConfidenceLevel.HIGH,
            detection_method=["NER"],
            severity=Severity.HIGH,
        ),
        PIIFinding(
            finding_id="f3",
            document_id="d1",
            file_name="test.txt",
            location="p2",
            block_order=1,
            start=47,
            end=55,
            text="Jane Doe",
            pii_type=PIIType.PERSON,
            confidence=0.95,
            confidence_level=ConfidenceLevel.HIGH,
            detection_method=["NER"],
            severity=Severity.HIGH,
        ),
    ]

    result = redactor.redact_document([block0, block1], findings, "d1", "test.txt")

    assert result.replacements_count == 3
    # Both John Smith occurrences must be [PERSON_001]
    assert "[PERSON_001]" in result.redacted_blocks[0].text
    assert "[PERSON_001]" in result.redacted_blocks[1].text
    # Jane Doe must be [PERSON_002]
    assert "[PERSON_002]" in result.redacted_blocks[1].text
    # Neither original name should remain in the redacted text
    assert "John Smith" not in result.redacted_full_text
    assert "Jane Doe" not in result.redacted_full_text


def test_multiple_pii_types_redaction():
    """Verify semantic tag naming for different PII categories."""
    redactor = PIIRedactor()
    text = "User Alice at alice@domain.com with phone 212-555-1234."
    block = DocumentBlock(
        document_id="d2",
        file_name="test.txt",
        file_type="txt",
        location="p1",
        block_type="paragraph",
        text=text,
        order=0
    )

    findings = [
        PIIFinding(
            finding_id="f1",
            document_id="d2",
            file_name="test.txt",
            location="p1",
            block_order=0,
            start=5,
            end=10,
            text="Alice",
            pii_type=PIIType.PERSON,
            confidence=0.90,
            confidence_level=ConfidenceLevel.HIGH,
            detection_method=["NER"],
            severity=Severity.HIGH,
        ),
        PIIFinding(
            finding_id="f2",
            document_id="d2",
            file_name="test.txt",
            location="p1",
            block_order=0,
            start=14,
            end=30,
            text="alice@domain.com",
            pii_type=PIIType.EMAIL,
            confidence=0.98,
            confidence_level=ConfidenceLevel.HIGH,
            detection_method=["REGEX"],
            severity=Severity.HIGH,
        ),
        PIIFinding(
            finding_id="f3",
            document_id="d2",
            file_name="test.txt",
            location="p1",
            block_order=0,
            start=42,
            end=54,
            text="212-555-1234",
            pii_type=PIIType.PHONE,
            confidence=0.92,
            confidence_level=ConfidenceLevel.HIGH,
            detection_method=["REGEX"],
            severity=Severity.HIGH,
        ),
    ]

    result = redactor.redact_document([block], findings, "d2", "test.txt")
    redacted_text = result.redacted_blocks[0].text

    assert "[PERSON_001]" in redacted_text
    assert "[EMAIL_001]" in redacted_text
    assert "[PHONE_001]" in redacted_text
    assert "alice@domain.com" not in redacted_text
    assert "212-555-1234" not in redacted_text
