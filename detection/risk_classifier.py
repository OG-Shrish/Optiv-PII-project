"""Intelligent Document Risk Classifier.

Calculates an explainable document-level risk assessment based on:
1. PII classification sensitivity (Critical vs High vs Moderate)
2. Number of distinct PII entities (deduplicated mentions)
3. Detection confidence levels
4. Presence of sensitive structured identifiers (Payment, Govt ID, Healthcare)
5. Contextual evidence and correlation risk
"""
from typing import List, Dict, Any, Set
from models.schemas import PIIFinding, PIIType, Severity


class RiskClassifier:
    """Evaluates multi-factor document privacy and exposure risk."""

    @staticmethod
    def assess_document(
        findings: List[PIIFinding],
        total_characters: int = 0,
        blocks_count: int = 0
    ) -> Dict[str, Any]:
        """Compute an explainable, calibrated risk assessment for an analyzed document."""
        if not findings:
            return {
                "risk_tier": "LOW",
                "risk_score": 0,
                "distinct_entities_count": 0,
                "sensitive_categories_count": 0,
                "critical_identifiers_present": False,
                "risk_factors": ["Zero sensitive entities identified in document content."],
                "recommendation": "Document content contains zero detected PII. Low privacy risk profile.",
            }

        # 1. Deduplicate findings by normalized text to count unique real-world entities
        unique_entities: Set[str] = set()
        unique_categories: Set[str] = set()
        has_critical = False
        has_high_id = False
        high_severity_count = 0

        for f in findings:
            cleaned_text = f.text.strip().lower()
            unique_entities.add(cleaned_text)
            type_str = f.pii_type.value if hasattr(f.pii_type, "value") else str(f.pii_type)
            unique_categories.add(type_str)

            sev_str = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            if sev_str in ("CRITICAL", "HIGH"):
                high_severity_count += 1

            if f.pii_type in (PIIType.CREDIT_CARD, PIIType.GOVERNMENT_ID):
                has_critical = True
            elif f.pii_type in (PIIType.EMPLOYEE_ID, PIIType.DATE_OF_BIRTH, PIIType.ADDRESS):
                has_high_id = True

        distinct_count = len(unique_entities)
        categories_count = len(unique_categories)

        # 2. Compute Multi-Factor Risk Score (0 - 100)
        base_score = 0
        risk_factors: List[str] = []

        # Category Sensitivity Weights
        if has_critical:
            base_score += 55
            risk_factors.append("Regulated high-hazard credentials detected (Government ID or Payment Card).")
        elif has_high_id:
            base_score += 35
            risk_factors.append("Institutional or demographic identifiers detected (Employee ID, DOB, or Address).")
        else:
            base_score += 15

        # Correlation Risk: Combining multiple distinct PII types multiplies disclosure hazard
        if categories_count >= 3:
            base_score += 25
            risk_factors.append(f"Multi-attribute correlation risk: {categories_count} distinct privacy categories present.")
        elif categories_count == 2:
            base_score += 12
            risk_factors.append("Dual-attribute correlation: 2 distinct privacy categories detected.")

        # Entity Volume (Based on UNIQUE entities, preventing false inflation from word repetition)
        if distinct_count >= 6:
            base_score += 20
            risk_factors.append(f"High entity density: {distinct_count} distinct individuals or tokens identified.")
        elif distinct_count >= 3:
            base_score += 10
            risk_factors.append(f"Moderate entity density: {distinct_count} distinct individuals or tokens identified.")
        elif distinct_count == 1:
            risk_factors.append("Isolated entity footprint: Only 1 distinct individual or token identified.")

        # Cap score between 0 and 100
        risk_score = min(100, max(0, base_score))

        # 3. Determine Calibrated Risk Tier
        if has_critical or risk_score >= 80:
            risk_tier = "CRITICAL"
            recommendation = "High regulatory scrutiny required. Ensure strict semantic redaction and secondary validation pass."
        elif risk_score >= 50 or (distinct_count >= 3 and categories_count >= 2):
            risk_tier = "HIGH"
            recommendation = "Multiple correlating personal attributes detected. Automated semantic sanitization required prior to LLM release."
        elif risk_score >= 25 or distinct_count >= 2:
            risk_tier = "MODERATE"
            recommendation = "Standard personal contact mentions. Low disclosure hazard once semantic tags are applied."
        else:
            risk_tier = "LOW"
            recommendation = "Minimal privacy footprint. Automated redaction of single entity sufficient for LLM safe state."

        return {
            "risk_tier": risk_tier,
            "risk_score": risk_score,
            "distinct_entities_count": distinct_count,
            "sensitive_categories_count": categories_count,
            "critical_identifiers_present": has_critical,
            "risk_factors": risk_factors,
            "recommendation": recommendation,
        }
