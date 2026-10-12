"""Utility helper functions for PII Security Gateway."""
import hashlib
import re
from typing import Optional


def calculate_file_hash(content: bytes) -> str:
    """Calculate SHA-256 hash of file content for unique document tracking."""
    return hashlib.sha256(content).hexdigest()[:16]


def validate_luhn(card_number: str) -> bool:
    """Validate credit card number using Luhn algorithm."""
    digits_only = re.sub(r"\D", "", card_number)
    if not (13 <= len(digits_only) <= 19):
        return False
    
    total = 0
    reverse_digits = digits_only[::-1]
    for idx, char in enumerate(reverse_digits):
        d = int(char)
        if idx % 2 == 1:
            d = d * 2
            if d > 9:
                d = d - 9
        total += d
    return total % 10 == 0


def is_valid_ipv4(ip_str: str) -> bool:
    """Verify that an IPv4 address string contains 4 valid octets (0-255)."""
    parts = ip_str.strip().split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit():
            return False
        num = int(part)
        if num < 0 or num > 255:
            return False
        # Disallow leading zeros for multi-digit octets (standard IP syntax)
        if len(part) > 1 and part.startswith("0"):
            return False
    return True


def mask_sensitive_value(text: str, pii_type: str = "OTHER_PII") -> str:
    """Mask a sensitive PII value for safe analyst presentation without exposing raw data."""
    if not text:
        return "[REDACTED]"
    
    val = text.strip()
    
    if pii_type == "EMAIL":
        parts = val.split("@")
        if len(parts) == 2:
            name, domain = parts
            masked_name = name[0] + "***" if len(name) > 1 else "*"
            return f"{masked_name}@{domain}"
        return "[MASKED_EMAIL]"
    
    if pii_type == "PHONE":
        digits = re.sub(r"\D", "", val)
        if len(digits) >= 4:
            return f"***-***-{digits[-4:]}"
        return "***-***-****"
    
    if pii_type == "CREDIT_CARD":
        digits = re.sub(r"\D", "", val)
        if len(digits) >= 4:
            return f"****-****-****-{digits[-4:]}"
        return "****-****-****-****"
    
    if pii_type == "EMPLOYEE_ID":
        if len(val) > 4:
            return f"{val[:3]}***{val[-2:]}"
        return "EMP-****"
        
    if pii_type == "GOVERNMENT_ID":
        if len(val) > 4:
            return f"{val[:3]}****{val[-2:]}"
        return "****-****"
        
    if pii_type == "IP_ADDRESS":
        parts = val.split(".")
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.*.*"
        return "*.*.*.*"
        
    if pii_type == "PERSON":
        words = val.split()
        masked_words = [f"{w[0]}***" if len(w) > 1 else "*" for w in words]
        return " ".join(masked_words)
        
    if len(val) > 4:
        return f"{val[:2]}***{val[-2:]}"
    return "***"
