"""Regex-based PII detector for high-confidence pattern matching."""
import re
from typing import List, Dict, Any

from models.schemas import PIIFinding, PIIType, Severity, ConfidenceLevel
from utils.helpers import validate_luhn, is_valid_ipv4, mask_sensitive_value


# Precompiled regex patterns for performance
# Boundary-enforced email regex ending with valid 2+ character TLD
EMAIL_REGEX = re.compile(
    r"\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*\.[a-zA-Z]{2,}\b"
)

# Phone patterns:
# 1. International with country code e.g. +1 212 555 1234, +91 9876543210, +1-800-555-0199
# 2. US standard: (212) 555-1234 or 212-555-1234
# 3. 10-digit mobile starting with 6, 7, 8, 9 (e.g. India mobile)
PHONE_INTL_REGEX = re.compile(
    r"(?<!\w)\+\d{1,3}[\s.-]?(?:\(?\d{2,4}\)?[\s.-]?)?\d{3,4}[\s.-]?\d{4}(?!\w)"
)
PHONE_IN_MOBILE_REGEX = re.compile(r"(?<!\w)(?:(?:\+91[\s.-]?)?[6-9]\d{9})(?!\w)")
PHONE_US_REGEX = re.compile(r"(?<!\w)(?:\(\d{3}\)\s?|\d{3}[-.\s])\d{3}[-.\s]\d{4}(?!\w)")

# Credit card: 13-19 digits, possibly hyphen or space separated
CREDIT_CARD_REGEX = re.compile(
    r"(?<!\w)(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11}|(?:\d{4}[-\s]){3}\d{4})(?!\w)"
)

# IPv4: 4 octets
IPV4_REGEX = re.compile(
    r"(?<!\w)(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?!\w)"
)

# Employee ID patterns (EMP12345, E10234, EMP-99214, STAFF-1234)
EMPLOYEE_ID_REGEX = re.compile(
    r"(?<!\w)(?:EMP[-_]?[0-9]{4,8}|E[0-9]{5,7}|STAFF[-_]?[0-9]{4,6})(?!\w)",
    re.IGNORECASE
)

# Government IDs (SSN, GVT-*, Aadhaar, etc.)
SSN_REGEX = re.compile(r"(?<!\w)\b\d{3}-\d{2}-\d{4}\b(?!\w)")
GOVT_GENERIC_REGEX = re.compile(r"(?<!\w)\b(?:GVT|GOV|ID|PASSPORT)[-_][0-9A-Z]{5,10}\b(?!\w)", re.IGNORECASE)
AADHAAR_REGEX = re.compile(r"(?<!\w)\b[2-9]\d{3}\s\d{4}\s\d{4}\b(?!\s\d{4})(?!\w)")


class RegexDetector:
    """Detects PII entities based on deterministic regex pattern rules."""

    def detect(
        self,
        text: str,
        document_id: str,
        file_name: str,
        location: str,
        block_order: int
    ) -> List[PIIFinding]:
        findings: List[PIIFinding] = []
        if not text or not text.strip():
            return findings

        # Check if text is just a placeholder like [PERSON_001]
        # Ignore already redacted tokens to prevent false alarms on re-scan
        placeholder_pattern = re.compile(r"\[(PERSON|EMAIL|PHONE|EMPLOYEE_ID|GOVERNMENT_ID|ADDRESS|DATE_OF_BIRTH|CREDIT_CARD|IP_ADDRESS|OTHER_PII)_\d+\]")

        # 1. Emails
        for match in EMAIL_REGEX.finditer(text):
            val = match.group(0)
            if placeholder_pattern.match(val):
                continue
            findings.append(
                PIIFinding(
                    finding_id=f"rgx_email_{block_order}_{match.start()}",
                    document_id=document_id,
                    file_name=file_name,
                    location=location,
                    block_order=block_order,
                    start=match.start(),
                    end=match.end(),
                    text=val,
                    pii_type=PIIType.EMAIL,
                    confidence=0.96,
                    confidence_level=ConfidenceLevel.HIGH,
                    detection_method=["REGEX"],
                    severity=Severity.HIGH,
                    explanation="Standard RFC-compliant email address structure identified.",
                    masked_text=mask_sensitive_value(val, "EMAIL"),
                )
            )

        # 2. Credit Cards - Strictly require Luhn checksum validity
        for match in CREDIT_CARD_REGEX.finditer(text):
            val = match.group(0)
            if placeholder_pattern.match(val):
                continue
            digits = re.sub(r"\D", "", val)
            if not validate_luhn(digits):
                continue
            findings.append(
                PIIFinding(
                    finding_id=f"rgx_cc_{block_order}_{match.start()}",
                    document_id=document_id,
                    file_name=file_name,
                    location=location,
                    block_order=block_order,
                    start=match.start(),
                    end=match.end(),
                    text=val,
                    pii_type=PIIType.CREDIT_CARD,
                    confidence=0.98,
                    confidence_level=ConfidenceLevel.HIGH,
                    detection_method=["REGEX"],
                    severity=Severity.CRITICAL,
                    explanation="Payment card number format (Luhn checksum verified).",
                    masked_text=mask_sensitive_value(val, "CREDIT_CARD"),
                )
            )

        # 3. IPv4 Addresses
        for match in IPV4_REGEX.finditer(text):
            val = match.group(0)
            if placeholder_pattern.match(val):
                continue
            if is_valid_ipv4(val):
                findings.append(
                    PIIFinding(
                        finding_id=f"rgx_ip_{block_order}_{match.start()}",
                        document_id=document_id,
                        file_name=file_name,
                        location=location,
                        block_order=block_order,
                        start=match.start(),
                        end=match.end(),
                        text=val,
                        pii_type=PIIType.IP_ADDRESS,
                        confidence=0.95,
                        confidence_level=ConfidenceLevel.HIGH,
                        detection_method=["REGEX"],
                        severity=Severity.LOW,
                        explanation="Valid IPv4 network address identified.",
                        masked_text=mask_sensitive_value(val, "IP_ADDRESS"),
                    )
                )

        # 4. Employee IDs
        for match in EMPLOYEE_ID_REGEX.finditer(text):
            val = match.group(0)
            if placeholder_pattern.match(val):
                continue
            findings.append(
                PIIFinding(
                    finding_id=f"rgx_empid_{block_order}_{match.start()}",
                    document_id=document_id,
                    file_name=file_name,
                    location=location,
                    block_order=block_order,
                    start=match.start(),
                    end=match.end(),
                    text=val,
                    pii_type=PIIType.EMPLOYEE_ID,
                    confidence=0.92,
                    confidence_level=ConfidenceLevel.HIGH,
                    detection_method=["REGEX"],
                    severity=Severity.HIGH,
                    explanation="Internal corporate employee identifier format.",
                    masked_text=mask_sensitive_value(val, "EMPLOYEE_ID"),
                )
            )

        # 5. Government IDs
        # SSN
        for match in SSN_REGEX.finditer(text):
            val = match.group(0)
            if placeholder_pattern.match(val):
                continue
            findings.append(
                PIIFinding(
                    finding_id=f"rgx_ssn_{block_order}_{match.start()}",
                    document_id=document_id,
                    file_name=file_name,
                    location=location,
                    block_order=block_order,
                    start=match.start(),
                    end=match.end(),
                    text=val,
                    pii_type=PIIType.GOVERNMENT_ID,
                    confidence=0.98,
                    confidence_level=ConfidenceLevel.HIGH,
                    detection_method=["REGEX"],
                    severity=Severity.CRITICAL,
                    explanation="US Social Security Number (SSN) format.",
                    masked_text=mask_sensitive_value(val, "GOVERNMENT_ID"),
                )
            )

        # Generic Govt ID
        for match in GOVT_GENERIC_REGEX.finditer(text):
            val = match.group(0)
            if placeholder_pattern.match(val):
                continue
            findings.append(
                PIIFinding(
                    finding_id=f"rgx_gov_{block_order}_{match.start()}",
                    document_id=document_id,
                    file_name=file_name,
                    location=location,
                    block_order=block_order,
                    start=match.start(),
                    end=match.end(),
                    text=val,
                    pii_type=PIIType.GOVERNMENT_ID,
                    confidence=0.95,
                    confidence_level=ConfidenceLevel.HIGH,
                    detection_method=["REGEX"],
                    severity=Severity.CRITICAL,
                    explanation="Government-issued identity token format.",
                    masked_text=mask_sensitive_value(val, "GOVERNMENT_ID"),
                )
            )

        # Aadhaar
        for match in AADHAAR_REGEX.finditer(text):
            val = match.group(0)
            if placeholder_pattern.match(val):
                continue
            if any(f.start <= match.start() and f.end >= match.end() for f in findings if f.pii_type == PIIType.CREDIT_CARD):
                continue
            findings.append(
                PIIFinding(
                    finding_id=f"rgx_aadhaar_{block_order}_{match.start()}",
                    document_id=document_id,
                    file_name=file_name,
                    location=location,
                    block_order=block_order,
                    start=match.start(),
                    end=match.end(),
                    text=val,
                    pii_type=PIIType.GOVERNMENT_ID,
                    confidence=0.95,
                    confidence_level=ConfidenceLevel.HIGH,
                    detection_method=["REGEX"],
                    severity=Severity.CRITICAL,
                    explanation="12-digit national identity format.",
                    masked_text=mask_sensitive_value(val, "GOVERNMENT_ID"),
                )
            )

        # 6. Phone Numbers
        # Combine phone detectors while avoiding overlaps
        phone_matches = []
        for rgx in [PHONE_IN_MOBILE_REGEX, PHONE_US_REGEX, PHONE_INTL_REGEX]:
            for match in rgx.finditer(text):
                val = match.group(0).strip()
                if placeholder_pattern.match(val):
                    continue
                # Sanity filter: phone must have at least 7 digits and not look like an IP or date
                digits = re.sub(r"\D", "", val)
                if len(digits) < 7 or len(digits) > 15:
                    continue
                # Disallow dummy/all-same digits (e.g. 9999999999) or financial numbers with 5+ consecutive zeroes (e.g. 8000000000)
                if len(set(digits)) <= 2 or re.search(r"0{5,}", digits):
                    continue
                # Check if immediately preceded by currency symbol/keyword in text
                preceding_slice = text[max(0, match.start() - 6):match.start()].lower()
                if re.search(r"[\$€£¥₹]|(?:inr|usd|eur|gbp|rs\.?)\s*$", preceding_slice):
                    continue
                # Skip if already detected as IP or Credit Card
                if any(f.start <= match.start() and f.end >= match.end() for f in findings if f.pii_type in [PIIType.IP_ADDRESS, PIIType.CREDIT_CARD]):
                    continue
                phone_matches.append((match.start(), match.end(), val))

        # Deduplicate internal phone spans
        for start, end, val in phone_matches:
            # Check overlap with existing phone findings
            if not any(f.start <= start and f.end >= end for f in findings if f.pii_type == PIIType.PHONE):
                findings.append(
                    PIIFinding(
                        finding_id=f"rgx_phone_{block_order}_{start}",
                        document_id=document_id,
                        file_name=file_name,
                        location=location,
                        block_order=block_order,
                        start=start,
                        end=end,
                        text=val,
                        pii_type=PIIType.PHONE,
                        confidence=0.92,
                        confidence_level=ConfidenceLevel.HIGH,
                        detection_method=["REGEX"],
                        severity=Severity.HIGH,
                        explanation="Telephone numbering plan pattern.",
                        masked_text=mask_sensitive_value(val, "PHONE"),
                    )
                )

        return findings
