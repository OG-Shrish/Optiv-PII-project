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
    "hand", "checked", "excess", "allowance", "dimension", "dimensions", "weight",
    "counter", "kiosk", "zone", "bay", "carousel", "hall", "lounge",
    # Airline brands and carriers
    "akasa", "air", "indigo", "spicejet", "vistara", "airindia", "emirates", "qatar", "lufthansa",
    # ID document types and regulatory keywords
    "identification", "identity", "photo", "proof", "valid", "validity", "mandatory", "required",
    "requirement", "requirements", "instruction", "instructions", "guideline", "guidelines",
    "aadhaar", "pan", "voter", "driving", "license", "licence",
    # Financial and commerce words
    "price", "prices", "cost", "costs", "amount", "fee", "fees", "charge", "charges",
    "tax", "taxes", "gst", "vat", "cgst", "sgst", "igst", "discount", "coupon", "voucher",
    "payment", "paid", "due", "balance", "invoice", "receipt", "bill", "billing", "currency",
    "usd", "inr", "eur", "gbp",
    # Units of measurement
    "kg", "kgs", "kilo", "kilos", "kilogram", "kilograms", "g", "gm", "gms", "gram", "grams",
    "lb", "lbs", "pound", "pounds", "oz", "ounce", "ounces", "l", "ltr", "liter", "liters",
    "ml", "km", "m", "cm", "mm", "in", "ft",
    # Corporate departments, teams, operations & roles
    "customer", "support", "technical", "sales", "marketing", "finance", "accounting", "legal",
    "compliance", "audit", "operations", "administration", "human", "resources", "department",
    "dept", "division", "branch", "group", "team", "desk", "helpdesk", "reception", "center",
    "centre", "office", "hq", "headquarters", "agency", "unit", "management", "staff", "crew",
    "officer", "agent", "rep", "representative", "specialist", "coordinator", "supervisor",
    "full", "part", "shift", "associate", "analyst", "lead", "leader", "member",
    # Status, state, booleans & null markers
    "active", "inactive", "pending", "confirmed", "approved", "rejected", "declined", "completed",
    "submitted", "final", "open", "closed", "available", "unavailable", "mandatory", "optional",
    "applicable", "routine", "urgent", "true", "false", "yes", "no", "none", "null", "nil",
    "na", "nan", "unknown", "empty", "blank", "missing",
    # Temporal & calendar terms
    "monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday",
    "january", "february", "march", "april", "may", "june", "july", "august",
    "september", "october", "november", "december", "today", "yesterday", "tomorrow",
    "date", "time", "day", "days", "month", "months", "year", "years", "hour", "hours",
    "minute", "minutes", "min", "mins", "sec", "secs",
    # General corporate / system
    "confidential", "internal", "restricted", "public", "draft", "version", "ver",
    "code", "ref", "reference", "id", "identifier", "number", "no", "male", "female",
    "executive", "briefing",
    # Contact and communication labels
    "email", "mail", "e-mail", "emails", "mailbox", "cell", "phone", "telephone", "tel", "mobile",
    "fax", "contact", "contacts", "communication", "calling",
    # Location, address & geography labels
    "location", "locations", "address", "addresses", "city", "state", "country", "pincode", "pin",
    "zipcode", "zip", "postal", "residence", "native", "nationality", "region", "zone",
    # Web, social & digital profile labels
    "website", "web", "url", "link", "linkedin", "github", "portfolio", "blog", "twitter",
    "profile", "profiles", "bio", "biography",
    # Resume, CV, and document section headings
    "resume", "resumes", "cv", "curriculum", "vitae", "summary", "objective", "experience",
    "experiences", "education", "educational", "academics", "academic", "skills", "skill",
    "expertise", "competencies", "competency", "projects", "project", "certifications",
    "certification", "certified", "licenses", "license", "achievements", "achievement",
    "awards", "award", "honors", "honor", "publications", "publication", "patents", "patent",
    "references", "reference", "referees", "referee", "professional", "background",
    "qualifications", "qualification", "history", "employment", "work", "working", "job",
    "jobs", "career", "careers", "activities", "activity", "interests", "interest",
    "hobbies", "hobby", "languages", "language", "declaration", "declarations",
    # Corporate hierarchy & executive title acronyms
    "dgm", "gm", "agm", "vp", "avp", "svp", "evp", "ceo", "cto", "cfo", "coo", "cio", "ciso",
    "cmo", "cro", "hr", "mgr", "director", "president"
}

# Corporate & organizational suffixes to distinguish organizations from person names
ORG_SUFFIX_WORDS = {
    "inc", "incorporated", "corp", "corporation", "llc", "llp", "ltd", "limited",
    "pvt", "private", "gmbh", "co", "company", "enterprises", "holdings",
    "technologies", "solutions", "systems", "services", "software", "bank",
    "air", "airlines", "airways", "hospital", "college", "university", "school",
    "institute", "foundation", "group", "industries", "motors", "labs", "laboratory"
}

# Known nationalities, demonyms, religions, and political affiliations (true NORP entities)
# spaCy's statistical model often misclassifies non-Western names ending in '-ish' (e.g. Shrish, Ashish, Girish, Satish)
# as NORP instead of PERSON. We use this dictionary to disambiguate true NORP words from genuine personal names.
KNOWN_NORP_WORDS = {
    # Genuine nationalities, demonyms & cultural groups
    "american", "americans", "british", "english", "canadian", "canadians", "australian", "australians",
    "indian", "indians", "chinese", "japanese", "russian", "russians", "french", "german", "germans",
    "italian", "italians", "spanish", "mexican", "mexicans", "brazilian", "brazilians", "korean", "koreans",
    "irish", "scottish", "welsh", "dutch", "swiss", "swedish", "norwegian", "danish", "finnish", "polish",
    "turkish", "greek", "greeks", "egyptian", "egyptians", "nigerian", "nigerians", "kenyan", "kenyans",
    "south african", "african", "africans", "asian", "asians", "european", "europeans", "hispanic", "hispanics",
    "latino", "latinos", "arab", "arabs", "israeli", "israelis", "palestinian", "palestinians",
    "pakistani", "pakistanis", "bangladeshi", "bangladeshis", "sri lankan", "nepali", "nepalese",
    "tibetan", "persian", "persians", "iranian", "iranians", "iraqi", "iraqis", "afghan", "afghans",
    "syrian", "syrians", "lebanese", "jordanian", "saudi", "saudis", "emirati", "emiratis", "qatari",
    "kuwaiti", "omani", "yemeni", "filipino", "filipinos", "vietnamese", "thai", "indonesian", "indonesians",
    "malaysian", "malaysians", "singaporean", "singaporeans", "taiwanese", "ukrainian", "ukrainians",
    "belarusian", "czech", "czechs", "slovak", "slovaks", "hungarian", "hungarians", "romanian", "romanians",
    "bulgarian", "bulgarians", "serbian", "serbians", "croatian", "croatians", "bosnian", "bosnians",
    "slovenian", "slovenians", "albanian", "albanians", "macedonian", "macedonians", "austrian", "austrians",
    "belgian", "belgians", "portuguese", "argentinian", "argentinians", "argentine", "colombian", "colombians",
    "peruvian", "peruvians", "chilean", "chileans", "venezuelan", "venezuelans", "amish", "kurdish", "flemish",
    # Religions and religious adherents
    "christian", "christians", "christianity", "muslim", "muslims", "islamic", "hindu", "hindus", "hinduism",
    "jewish", "jews", "judaism", "buddhist", "buddhists", "buddhism", "sikh", "sikhs", "sikhism",
    "catholic", "catholics", "catholicism", "protestant", "protestants", "orthodox",
    # Political affiliations
    "democrat", "democrats", "democratic", "republican", "republicans", "conservative", "conservatives",
    "labour", "socialist", "socialists", "communist", "communists", "liberal", "liberals", "marxist"
}


def is_valid_person_entity(ent_text: str) -> bool:
    """Validate that an NER candidate entity represents a genuine person name."""
    cleaned = ent_text.strip()
    if len(cleaned) < 2 or len(cleaned) > 60:
        return False
    # Person names never span multiple lines
    if "\n" in cleaned or "\r" in cleaned:
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
    # If any word in the candidate is an organization suffix, reject
    if any(w.lower() in ORG_SUFFIX_WORDS for w in words):
        return False
    # If the combined normalized phrase is in the blocklist
    if cleaned.lower().replace(" ", "").replace("-", "") in NON_PERSON_WORDS:
        return False
    # Single word names must be at least 3 letters and titlecased
    if len(words) == 1 and (len(words[0]) < 3 or not words[0].istitle()):
        return False
    return True


def is_standalone_name_line(line: str) -> bool:
    """Validate whether a dedicated standalone line represents a personal candidate name."""
    cleaned = line.strip()
    if "\n" in cleaned or "\r" in cleaned:
        return False
    words = re.findall(r"[A-Za-z]+", cleaned)
    if not (2 <= len(words) <= 4):
        return False
    # Each word must be either titlecased, an uppercase initial, or all uppercase (for ALL CAPS names)
    is_title = all(w.istitle() or (len(w) == 1 and w.isupper()) for w in words)
    is_all_caps = all(w.isupper() and len(w) >= 2 for w in words)
    if not (is_title or is_all_caps):
        return False
    if any(w.lower() in ORG_SUFFIX_WORDS for w in words):
        return False
    if any(w.lower() in NON_PERSON_WORDS for w in words):
        return False
    return is_valid_person_entity(cleaned)


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
            ent_raw = ent.text
            ent_text = ent_raw.strip()
            if not ent_text or PLACEHOLDER_REGEX.match(ent_text):
                continue

            leading_ws = len(ent_raw) - len(ent_raw.lstrip())
            start_char = ent.start_char + leading_ws
            end_char = start_char + len(ent_text)

            # PERSON classification (including Indian/non-Western names misclassified as NORP)
            is_person_label = ent.label_ == "PERSON"
            is_misclassified_norp = ent.label_ == "NORP" and ent_text.lower() not in KNOWN_NORP_WORDS
            if is_person_label or is_misclassified_norp:
                if not is_valid_person_entity(ent_text):
                    continue

                findings.append(
                    PIIFinding(
                        finding_id=f"ner_person_{block_order}_{start_char}",
                        document_id=document_id,
                        file_name=file_name,
                        location=location,
                        block_order=block_order,
                        start=start_char,
                        end=end_char,
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
                start_context = max(0, start_char - 35)
                context_window = text[start_context:start_char].lower()
                address_cues = ["residence", "home", "address", "lives at", "located at", "street"]
                if any(cue in context_window for cue in address_cues):
                    findings.append(
                        PIIFinding(
                            finding_id=f"ner_loc_{block_order}_{start_char}",
                            document_id=document_id,
                            file_name=file_name,
                            location=location,
                            block_order=block_order,
                            start=start_char,
                            end=end_char,
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
                start_context = max(0, start_char - 30)
                context_window = text[start_context:start_char].lower()
                dob_cues = ["birth", "born", "dob", "date of birth"]
                if any(cue in context_window for cue in dob_cues):
                    findings.append(
                        PIIFinding(
                            finding_id=f"ner_dob_{block_order}_{start_char}",
                            document_id=document_id,
                            file_name=file_name,
                            location=location,
                            block_order=block_order,
                            start=start_char,
                            end=end_char,
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

        # Dedicated standalone candidate / personal name lines (e.g. 'Vikas Laxman Ahankari')
        name_line_pattern = re.compile(
            r"(?m)^[ \t]*((?:[A-Z][a-z]+|[A-Z]{2,})(?:\s+(?:[A-Z](?:\.|\b|[a-z]+)|[A-Z]{2,})){1,3})[ \t\r]*$"
        )
        for match in name_line_pattern.finditer(text):
            candidate = match.group(1).strip()
            if is_standalone_name_line(candidate):
                start_c = match.start(1)
                end_c = match.end(1)
                # Avoid duplicate if a PERSON finding already covers this exact span or a superset
                if not any(f.start <= start_c and f.end >= end_c for f in findings if f.pii_type == PIIType.PERSON):
                    findings.append(
                        PIIFinding(
                            finding_id=f"ner_name_line_{block_order}_{start_c}",
                            document_id=document_id,
                            file_name=file_name,
                            location=location,
                            block_order=block_order,
                            start=start_c,
                            end=end_c,
                            text=candidate,
                            pii_type=PIIType.PERSON,
                            confidence=0.94,
                            confidence_level=ConfidenceLevel.HIGH,
                            detection_method=["NER"],
                            severity=Severity.HIGH,
                            explanation="Personal candidate name identified on dedicated header line.",
                            masked_text=mask_sensitive_value(candidate, "PERSON"),
                        )
                    )

        return findings
