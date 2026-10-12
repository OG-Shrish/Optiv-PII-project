"""Named Entity Recognition (NER) PII detector using spaCy."""
import logging
import re
from typing import List, Optional

from models.schemas import PIIFinding, PIIType, Severity, ConfidenceLevel
from utils.helpers import mask_sensitive_value

logger = logging.getLogger(__name__)

# Pattern to avoid classifying placeholders as NER entities
PLACEHOLDER_REGEX = re.compile(
    r"^\[(PERSON|EMAIL|PHONE|EMPLOYEE_ID|GOVERNMENT_ID|ADDRESS|DATE_OF_BIRTH|CREDIT_CARD|IP_ADDRESS|OTHER_PII)_\d+\]$"
)

# Common non-person titles or words that small NER models occasionally misclassify as PERSON
NON_PERSON_WORDS = {
    "monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday",
    "january", "february", "march", "april", "may", "june", "july", "august",
    "september", "october", "november", "december", "confidential", "internal",
    "restricted", "public", "draft", "version", "summary", "overview", "introduction"
}


class NERDetector:
    """Detects Named Entities using spaCy's English model with safety fallbacks."""

    def __init__(self, model_name: str = "en_core_web_sm"):
        self.model_name = model_name
        self.nlp = None
        self.is_available = False
        self._load_model()

    def _load_model(self):
        try:
            import spacy
            self.nlp = spacy.load(self.model_name)
            self.is_available = True
            logger.info(f"Loaded spaCy NER model: {self.model_name}")
        except Exception as e:
            self.is_available = False
            logger.warning(
                f"spaCy model '{self.model_name}' unavailable ({e}). Continuing with regex/context detectors."
            )

    def detect(
        self,
        text: str,
        document_id: str,
        file_name: str,
        location: str,
        block_order: int
    ) -> List[PIIFinding]:
        findings: List[PIIFinding] = []
        if not self.is_available or not self.nlp or not text or not text.strip():
            return findings

        try:
            doc = self.nlp(text)
        except Exception as e:
            logger.warning(f"Error executing spaCy NER: {e}")
            return findings

        for ent in doc.ents:
            ent_text = ent.text.strip()
            if not ent_text or PLACEHOLDER_REGEX.match(ent_text):
                continue

            # PERSON classification
            if ent.label_ == "PERSON":
                # Filter out single words that are obviously days, months, or generic labels
                if ent_text.lower() in NON_PERSON_WORDS or len(ent_text) < 2:
                    continue
                # Filter out pure numbers or symbols
                if re.match(r"^[\d\W]+$", ent_text):
                    continue

                findings.append(
                    PIIFinding(
                        finding_id=f"ner_person_{block_order}_{ent.start_char}",
                        document_id=document_id,
                        file_name=file_name,
                        location=location,
                        block_order=block_order,
                        start=ent.start_char,
                        end=ent.end_char,
                        text=ent_text,
                        pii_type=PIIType.PERSON,
                        confidence=0.88,
                        confidence_level=ConfidenceLevel.MEDIUM,
                        detection_method=["NER"],
                        severity=Severity.HIGH,
                        explanation=f"spaCy NER identified entity with label '{ent.label_}'.",
                        masked_text=mask_sensitive_value(ent_text, "PERSON"),
                    )
                )

            # GPE / LOC (Geographical entity / Location)
            # Only classify if adjacent to residential or personal address cues
            elif ent.label_ in ("GPE", "LOC"):
                start_context = max(0, ent.start_char - 35)
                context_window = text[start_context:ent.start_char].lower()
                address_cues = ["residence", "home", "address", "lives at", "located at", "street"]
                if any(cue in context_window for cue in address_cues):
                    findings.append(
                        PIIFinding(
                            finding_id=f"ner_loc_{block_order}_{ent.start_char}",
                            document_id=document_id,
                            file_name=file_name,
                            location=location,
                            block_order=block_order,
                            start=ent.start_char,
                            end=ent.end_char,
                            text=ent_text,
                            pii_type=PIIType.ADDRESS,
                            confidence=0.78,
                            confidence_level=ConfidenceLevel.MEDIUM,
                            detection_method=["NER"],
                            severity=Severity.MEDIUM,
                            explanation="Location entity in residential address context.",
                            masked_text=mask_sensitive_value(ent_text, "ADDRESS"),
                        )
                    )

            # DATE
            # Only classify if preceded by birth or personal cues
            elif ent.label_ == "DATE":
                start_context = max(0, ent.start_char - 30)
                context_window = text[start_context:ent.start_char].lower()
                dob_cues = ["birth", "born", "dob", "date of birth"]
                if any(cue in context_window for cue in dob_cues):
                    findings.append(
                        PIIFinding(
                            finding_id=f"ner_dob_{block_order}_{ent.start_char}",
                            document_id=document_id,
                            file_name=file_name,
                            location=location,
                            block_order=block_order,
                            start=ent.start_char,
                            end=ent.end_char,
                            text=ent_text,
                            pii_type=PIIType.DATE_OF_BIRTH,
                            confidence=0.89,
                            confidence_level=ConfidenceLevel.MEDIUM,
                            detection_method=["NER"],
                            severity=Severity.MEDIUM,
                            explanation="Date entity identified with preceding birth context.",
                            masked_text=mask_sensitive_value(ent_text, "DATE_OF_BIRTH"),
                        )
                    )

        return findings
