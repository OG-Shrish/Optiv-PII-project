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

# Comprehensive non-person words, document labels, travel/airline terms, and measurements
# that small NER models occasionally misclassify as PERSON
NON_PERSON_WORDS = {
    # Determiners, modifiers, structural words
    "other", "another", "all", "any", "each", "every", "some", "few", "more", "less",
    "many", "much", "add", "addon", "add-on", "add-ons", "addons", "additional", "added",
    "extra", "new", "old", "first", "last", "next", "previous", "prior", "total", "subtotal",
    "net", "gross", "grand", "standard", "basic", "special", "general", "main", "sub",
    # Document structure & labels
    "table", "row", "column", "col", "page", "slide", "section", "header", "footer",
    "paragraph", "item", "items", "list", "status", "type", "category", "class",
    "description", "details", "detail", "summary", "overview", "introduction",
    "conclusion", "note", "notes", "notice", "remark", "remarks", "policy", "terms",
    "condition", "conditions", "rule", "rules", "information", "info", "guidelines",
    # Travel, airline, transit & ticket terms
    "passport", "visa", "cabin", "baggage", "luggage", "seat", "seats", "ticket", "tickets",
    "boarding", "flight", "flights", "gate", "gates", "terminal", "airport", "airports",
    "airline", "airlines", "airways", "aircraft", "plane", "carrier", "fare", "pnr",
    "booking", "checkin", "check-in", "security", "customs", "immigration", "transit",
    "layover", "stopover", "origin", "destination", "arrival", "arrivals", "departure",
    "departures", "route", "sector", "economy", "business", "premium", "meal", "meals",
    "beverage", "beverages", "snack", "snacks", "service", "services", "amenity", "amenities",
    "infant", "child", "adult", "passenger", "traveler", "traveller", "guest", "pass",
    # Financial and commerce words
    "price", "prices", "cost", "costs", "amount", "fee", "fees", "charge", "charges",
    "tax", "taxes", "gst", "vat", "cgst", "sgst", "igst", "discount", "coupon", "voucher",
    "payment", "paid", "due", "balance", "invoice", "receipt", "bill", "billing", "currency",
    "usd", "inr", "eur", "gbp",
    # Units of measurement
    "kg", "kgs", "kilo", "kilos", "kilogram", "kilograms", "g", "gm", "gms", "gram", "grams",
    "lb", "lbs", "pound", "pounds", "oz", "ounce", "ounces", "l", "ltr", "liter", "liters",
    "ml", "km", "m", "cm", "mm", "in", "ft",
    # Temporal & calendar terms
    "monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday",
    "january", "february", "march", "april", "may", "june", "july", "august",
    "september", "october", "november", "december", "today", "yesterday", "tomorrow",
    "date", "time", "day", "days", "month", "months", "year", "years", "hour", "hours",
    "minute", "minutes", "min", "mins", "sec", "secs",
    # General corporate / system
    "confidential", "internal", "restricted", "public", "draft", "version", "ver",
    "code", "ref", "reference", "id", "identifier", "number", "no", "male", "female",
    "executive", "briefing"
}


def is_valid_person_entity(ent_text: str) -> bool:
    """Validate that an NER candidate entity represents a genuine person name."""
    cleaned = ent_text.strip()
    if len(cleaned) < 2 or len(cleaned) > 60:
        return False
    # Person names never contain numbers (e.g. '7 Kg', 'Gate 4')
    if re.search(r"\d", cleaned):
        return False
    # Reject entity if it contains disallowed symbols
    if re.search(r"[/\\@#\$%\^\*\+=\<\>~\|_]", cleaned):
        return False
    # Genuine person names in any language contain at least one vowel
    if not re.search(r"[aeiouyAEIOUY]", cleaned):
        return False
    words = re.findall(r"[A-Za-z]+", cleaned)
    if not words:
        return False
    # If ANY word in the candidate is a known non-person word, reject immediately
    if any(w.lower() in NON_PERSON_WORDS for w in words):
        return False
    # If the combined normalized phrase is in the blocklist
    if cleaned.lower().replace(" ", "").replace("-", "") in NON_PERSON_WORDS:
        return False
    # Single word names must be at least 3 letters and titlecased
    if len(words) == 1 and (len(words[0]) < 3 or not words[0].istitle()):
        return False
    return True


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
                if not is_valid_person_entity(ent_text):
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
