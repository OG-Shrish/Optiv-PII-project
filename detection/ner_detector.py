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

# Characters permitted in personal names (letters, spaces, periods, apostrophes, hyphens)
NAME_ALLOWED_CHARS = re.compile(r"^[A-Za-z\s.'’\-]+$")

# Cultural / nobiliary particles allowed internally in multi-word personal names
NAME_PARTICLES = {
    "van", "von", "de", "del", "della", "di", "da", "la", "le", "du", "des",
    "bin", "ibn", "al", "el", "ben", "bar", "san", "santa"
}

# Strictly non-person words: ANY occurrence in a candidate entity immediately disqualifies it.
STRICT_NON_PERSON_WORDS = {
    # Technical, computer science, graph theory, algorithm & mathematical concepts
    "network", "networks", "antiparallel", "residual", "residuals", "algorithm", "algorithms",
    "subgraph", "subgraphs", "vertex", "vertices", "node", "nodes", "graph", "graphs",
    "bipartite", "acyclic", "asymptotic", "polynomial", "exponential", "logarithmic",
    "combinatorial", "stochastic", "deterministic", "heuristic", "heuristics",
    "recursion", "recursive", "iterative", "iteration", "matrix", "matrices", "vector", "vectors",
    "tensor", "tensors", "database", "databases", "bandwidth", "latency", "throughput",
    "encryption", "decryption", "ciphertext", "plaintext", "cryptography", "compiler", "compilers",
    "bytecode", "middleware", "microservice", "microservices", "pipeline", "pipelines",
    "topology", "topological", "eigenvalue", "eigenvalues", "eigenvector", "eigenvectors",
    "convex", "concave", "simplex", "concurrency", "deadlock", "semaphore", "mutex",
    "checksum", "payload", "packets", "packet", "theorem", "theorems", "lemma", "lemmas",
    "corollary", "corollaries", "axiom", "axioms", "hypothesis", "hypotheses",
    "proposition", "propositions", "equation", "equations", "formula", "formulas", "formulae",
    "function", "functions", "variable", "variables", "parameter", "parameters",
    "architecture", "architectures", "framework", "frameworks", "interface", "interfaces",
    "configuration", "configurations", "implementation", "implementations", "documentation",
    "specification", "specifications", "bibliography", "appendix", "appendices", "abstract", "abstracts",
    "minimum", "maximum", "optimal", "suboptimal", "augmenting", "capacity", "capacities",
    "adjacency", "directed", "undirected", "weighted", "unweighted", "flow", "flows", "cut", "cuts",
    "tree", "trees", "heap", "heaps", "queue", "queues", "stack", "stacks", "array", "arrays",
    "hash", "hashing", "linear", "nonlinear", "gradient", "descent", "entropy", "variance",
    "regression", "classification", "clustering", "inference", "neural", "convolution",
    "transformer", "attention", "embedding", "embeddings", "binary", "ternary", "boolean",
    "integer", "float", "double", "scalar", "tuple", "pointer", "buffer", "cache", "protocol", "protocols",
    "routing", "router", "subnet", "firewall", "schema", "schemas", "query", "queries",
    "index", "indices", "dataset", "datasets", "benchmark", "benchmarks", "metric", "metrics",
    "precision", "recall", "accuracy", "runtime", "thread", "threads", "algebra",
    # Determiners, modifiers, structural words
    "other", "another", "all", "any", "each", "every", "some", "few", "more", "less",
    "many", "much", "add", "addon", "add-on", "add-ons", "addons", "additional", "added",
    "extra", "new", "old", "first", "last", "next", "previous", "prior", "total", "subtotal",
    "net", "standard", "basic", "special", "general", "main", "sub",
    # Document structure & labels
    "table", "row", "column", "col", "slide", "section", "header", "footer",
    "paragraph", "item", "items", "list", "status", "type", "category",
    "description", "details", "detail", "summary", "overview", "introduction",
    "conclusion", "note", "notes", "notice", "remark", "remarks", "policy", "terms",
    "condition", "conditions", "rule", "rules", "information", "info", "guidelines",
    "report", "reports",
    # Travel, airline, transit & ticket terms
    "passport", "visa", "cabin", "baggage", "luggage", "seat", "seats", "ticket", "tickets",
    "boarding", "flight", "flights", "terminal", "airport", "airports",
    "airline", "airlines", "airways", "aircraft", "plane", "carrier", "fare", "pnr",
    "booking", "checkin", "check-in", "security", "customs", "immigration", "transit",
    "layover", "stopover", "origin", "destination", "arrival", "arrivals", "departure",
    "departures", "route", "sector", "economy", "business", "premium", "meal", "meals",
    "beverage", "beverages", "snack", "snacks", "service", "services", "amenity", "amenities",
    "infant", "child", "adult", "passenger", "traveler", "traveller", "guest", "pass",
    "hand", "checked", "excess", "allowance", "dimension", "dimensions", "weight",
    "counter", "kiosk", "zone", "bay", "carousel", "lounge",
    # Airline brands and carriers
    "akasa", "air", "indigo", "spicejet", "vistara", "airindia", "emirates", "qatar", "lufthansa",
    # ID document types and regulatory keywords
    "identification", "identity", "photo", "proof", "valid", "validity", "mandatory", "required",
    "requirement", "requirements", "instruction", "instructions", "guideline",
    "aadhaar", "pan", "voter", "driving", "license", "licence",
    # Units of measurement
    "kg", "kgs", "kilo", "kilos", "kilogram", "kilograms", "lb", "lbs", "pound", "pounds",
    "oz", "ounce", "ounces", "ltr", "liter", "liters", "ml", "km", "cm", "mm",
    # Corporate departments, teams, operations & roles
    "customer", "support", "technical", "sales", "marketing", "finance", "accounting", "legal",
    "compliance", "audit", "operations", "administration", "human", "resources", "department",
    "dept", "division", "branch", "group", "team", "desk", "helpdesk", "reception", "center",
    "centre", "office", "hq", "headquarters", "agency", "unit", "management", "staff", "crew",
    "officer", "rep", "representative", "specialist", "coordinator", "supervisor",
    "associate", "analyst",
    # Status, state, booleans & null markers
    "active", "inactive", "pending", "confirmed", "approved", "rejected", "declined", "completed",
    "submitted", "final", "open", "closed", "available", "unavailable", "optional",
    "applicable", "routine", "urgent", "true", "false", "yes", "no", "none", "null", "nil",
    "na", "nan", "unknown", "empty", "blank", "missing", "full", "part", "shift",
    # Temporal & calendar terms (unambiguous)
    "monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday",
    "january", "february", "march", "april", "june", "july", "august",
    "september", "october", "november", "december", "today", "yesterday", "tomorrow",
    "time", "date",
    # General corporate / system
    "confidential", "internal", "restricted", "public", "draft", "version", "ver",
    "code", "ref", "reference", "identifier", "male", "female", "executive", "briefing",
    "class", "lead", "leader", "member",
    # Contact and communication labels
    "email", "mail", "e-mail", "emails", "mailbox", "cell", "telephone", "tel", "mobile",
    "fax", "communication", "calling",
    # Location, address & geography labels
    "locations", "addresses", "pincode", "zipcode", "residence", "native", "nationality",
    # Web, social & digital profile labels
    "website", "web", "url", "link", "linkedin", "github", "portfolio", "blog", "twitter",
    "profile", "profiles",
    # Resume, CV, and document section headings
    "resume", "resumes", "cv", "curriculum", "vitae", "objective", "experience",
    "experiences", "academics", "competencies", "competency",
    "certifications", "certification", "certified", "licenses", "achievements", "achievement",
    "awards", "honors", "publications", "publication", "patents", "patent",
    "references", "referees", "referee", "background", "qualifications", "qualification",
    "employment", "activities", "activity", "interests", "interest", "hobbies", "hobby",
    "declaration", "declarations", "professional", "education", "educational",
    "skills", "skill", "projects", "project", "work", "job", "career", "careers",
    # Corporate hierarchy & executive title acronyms
    "dgm", "gm", "agm", "vp", "avp", "svp", "evp", "ceo", "cto", "cfo", "coo", "cio", "ciso",
    "cmo", "cro", "hr", "mgr",
    # Examination, question paper, academic & coursework vocabulary
    "question", "questions", "answer", "answers", "problem", "problems", "solution", "solutions",
    "exercise", "exercises", "assignment", "assignments", "homework", "exam", "exams", "examination",
    "quiz", "quizzes", "test", "tests", "paper", "papers", "marks", "points", "score", "scores",
    "part", "parts", "module", "modules", "unit", "units", "chapter", "chapters", "topic", "topics",
    "lesson", "lessons", "syllabus", "curriculum", "semester", "semesters", "course", "courses",
    "midterm", "final", "finals", "compulsory", "attempt", "derive", "evaluate", "calculate",
    "determine", "compute", "prove", "explain", "describe", "discuss", "define", "illustrate",
    "verify", "compare", "distinguish", "differentiate", "agenda", "bullet", "bullets",
    "figure", "figures", "diagram", "diagrams", "illustration", "illustrations"
}

# Common English words/labels that are non-person when appearing alone as a single word or label,
# but which CAN form valid multi-word personal names (e.g., 'Larry Page', 'Bill Gates', 'Brian May').
SINGLE_WORD_NON_PERSON_WORDS = {
    "page", "gate", "gates", "hall", "price", "may", "rose", "bell", "ford", "cook",
    "baker", "miller", "taylor", "brown", "white", "green", "wood", "stone", "hill",
    "king", "young", "ward", "miles", "dean", "day", "month", "year",
    "hour", "minute", "sec", "city", "state", "country", "pin", "zip", "id", "no",
    "contact", "phone", "address", "location"
}

# Plural nouns or technical head nouns that, when ending a multi-word phrase, indicate a technical concept.
TECHNICAL_HEAD_NOUNS = {
    "edges", "nodes", "graphs", "trees", "paths", "cuts", "flows", "networks",
    "components", "matrices", "vertices", "algorithms", "equations", "functions",
    "variables", "constraints", "subgraphs", "layers", "models", "methods",
    "circuits", "signals", "packets", "protocols", "parameters", "structures",
    "operations", "systems", "tables", "queues", "stacks", "arrays", "sets",
    "subsets", "clusters", "distributions", "heuristics", "iterations", "processes",
    "threads", "caches", "buffers", "properties", "papers", "questions", "answers",
    "problems", "solutions", "exercises", "assignments", "modules", "units", "chapters"
}

# Corporate & organizational suffixes to distinguish organizations from person names
ORG_SUFFIX_WORDS = {
    "inc", "incorporated", "corp", "corporation", "llc", "llp", "ltd", "limited",
    "pvt", "private", "gmbh", "co", "company", "enterprises", "holdings",
    "technologies", "solutions", "systems", "services", "software", "bank",
    "air", "airlines", "airways", "hospital", "college", "university", "school",
    "institute", "foundation", "group", "industries", "motors", "labs", "laboratory"
}

# Union set preserved for backward compatibility
NON_PERSON_WORDS = STRICT_NON_PERSON_WORDS | SINGLE_WORD_NON_PERSON_WORDS

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
    # Must only contain characters allowed in personal names (rejects math/code expressions like f(u), O(n), etc.)
    if not NAME_ALLOWED_CHARS.match(cleaned):
        return False
    # Genuine person names in any language contain at least one vowel
    if not re.search(r"[aeiouyAEIOUY]", cleaned):
        return False

    words = re.findall(r"[A-Za-z]+", cleaned)
    if not words or len(words) > 5:
        return False

    # Check against strictly non-person words
    if any(w.lower() in STRICT_NON_PERSON_WORDS for w in words):
        return False
    # Check against organization suffixes
    if any(w.lower() in ORG_SUFFIX_WORDS for w in words):
        return False

    # Single-word name validation
    if len(words) == 1:
        w = words[0]
        if len(w) < 3:
            return False
        if not (w.istitle() or (w.isupper() and len(w) >= 3)):
            return False
        if w.lower() in SINGLE_WORD_NON_PERSON_WORDS:
            return False
        return True

    # Multi-word name validation
    # Cannot consist solely of single-letter tokens (e.g. 'U V')
    if all(len(w) == 1 for w in words):
        return False

    # First and last words must start with an uppercase letter
    if not (words[0][0].isupper() and words[-1][0].isupper()):
        return False

    # Check each word casing (must be Titlecase, initial, or valid particle)
    is_all_caps = all(w.isupper() for w in words)
    if not is_all_caps:
        for idx, w in enumerate(words):
            if idx == 0 or idx == len(words) - 1:
                if not (w.istitle() or (len(w) == 1 and w.isupper())):
                    return False
            else:
                if w.lower() in NAME_PARTICLES:
                    continue
                if not (w.istitle() or (len(w) == 1 and w.isupper())):
                    return False

    # Check if phrase ends with a technical head noun (e.g. 'Antiparallel Edges', 'Augmenting Paths', 'Question Paper')
    if words[-1].lower() in TECHNICAL_HEAD_NOUNS:
        return False

    # Roman numerals in 2-word phrase (e.g. 'Part I', 'Section II', 'Unit IV') indicate outline structure
    if len(words) <= 2 and re.match(r"^(?:I|II|III|IV|V|VI|VII|VIII|IX|X|XI|XII)$", words[-1], re.IGNORECASE):
        return False

    # Reject if combined string is in strict dictionary
    if cleaned.lower().replace(" ", "").replace("-", "") in STRICT_NON_PERSON_WORDS:
        return False

    return True


def has_personal_document_context(text: str) -> bool:
    """Check if the text block contains contextual evidence of personal/contact/resume information."""
    if not text:
        return False
    # 1. Contact indicators (email address, phone numbers, contact label prefixes)
    if re.search(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", text):
        return True
    if re.search(r"(?i)\b(?:email|cell|mobile|phone|telephone|contact|tel|pincode|zipcode|location|address)\s*[:=-]", text):
        return True
    if re.search(r"(?i)\b(?:linkedin\.com|github\.com)\b", text):
        return True

    # 2. Resume / Candidate / Profile headings or structural markers
    if re.search(r"(?i)\b(?:curriculum\s+vitae|resume|professional\s+profile|career\s+objective|work\s+experience|educational\s+background|academic\s+qualifications)\b", text):
        return True
    if re.search(r"(?i)\b(?:candidate|applicant|passenger|employee|patient|client|attendee|traveler|traveller)\s*[:=-]", text):
        return True

    # 3. Professional designation / job title cues
    if re.search(r"(?i)\b(?:dgm|agm|gm|vp|avp|svp|director|manager|engineer|developer|consultant|analyst|architect|specialist|officer|executive)\b", text):
        return True

    return False


def is_standalone_name_line(line: str) -> bool:
    """Validate whether a dedicated standalone line represents a personal candidate name."""
    cleaned = line.strip()
    if "\n" in cleaned or "\r" in cleaned:
        return False
    words = re.findall(r"[A-Za-z]+", cleaned)
    if not (2 <= len(words) <= 4):
        return False
    # Line must satisfy all personal entity validation rules
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
                        confidence=0.85,
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

        # Standalone candidate / personal name lines (e.g. 'Vikas Laxman Ahankari')
        # Only activated when the surrounding block provides supporting personal/contact/resume context
        if has_personal_document_context(text):
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
                                confidence=0.88,
                                confidence_level=ConfidenceLevel.MEDIUM,
                                detection_method=["NER"],
                                severity=Severity.HIGH,
                                explanation="Personal candidate name identified on header line with supporting contextual cues.",
                                masked_text=mask_sensitive_value(candidate, "PERSON"),
                            )
                        )

        return findings
