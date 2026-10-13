"""Tests for hybrid PII detection (Regex, NER, Context Rules, and Overlap Merging)."""
from detection.regex_detector import RegexDetector
from detection.ner_detector import NERDetector
from detection.context_rules import ContextDetector
from detection.pii_engine import PIIEngine
from models.schemas import PIIType, DocumentBlock, Severity


def test_email_detection():
    detector = RegexDetector()
    text = "Please reach out to john.smith@company.com or security-team@example.org for inquiries."
    findings = detector.detect(text, "d1", "test.txt", "p1", 0)

    emails = [f.text for f in findings if f.pii_type == PIIType.EMAIL]
    assert "john.smith@company.com" in emails
    assert "security-team@example.org" in emails
    assert all(f.confidence >= 0.90 for f in findings)
    assert all(f.severity == Severity.HIGH for f in findings)


def test_phone_detection():
    detector = RegexDetector()
    text = "Call us at +1 212 555 1234 or +91 9876543210 or (212) 555-1234."
    findings = detector.detect(text, "d1", "test.txt", "p1", 0)

    phones = [f.text for f in findings if f.pii_type == PIIType.PHONE]
    assert len(phones) >= 2


def test_employee_id_detection():
    detector = RegexDetector()
    text = "Staff badges: EMP10293, E10234, and EMP-99214."
    findings = detector.detect(text, "d1", "test.txt", "p1", 0)

    emp_ids = [f.text for f in findings if f.pii_type == PIIType.EMPLOYEE_ID]
    assert "EMP10293" in emp_ids
    assert "EMP-99214" in emp_ids


def test_credit_card_and_ip_detection():
    detector = RegexDetector()
    # 4111... is a standard Visa test number satisfying Luhn
    text = "Payment details: 4111 1111 1111 1111. Server IP: 192.168.1.10."
    findings = detector.detect(text, "d1", "test.txt", "p1", 0)

    types = [f.pii_type for f in findings]
    assert PIIType.CREDIT_CARD in types
    assert PIIType.IP_ADDRESS in types


def test_government_id_detection():
    detector = RegexDetector()
    text = "Evidence contains SSN: 123-45-6789 and Govt ID: GVT-982341."
    findings = detector.detect(text, "d1", "test.txt", "p1", 0)

    gov_findings = [f for f in findings if f.pii_type == PIIType.GOVERNMENT_ID]
    assert len(gov_findings) >= 2
    assert any("123-45-6789" in f.text for f in gov_findings)
    assert any(f.severity == Severity.CRITICAL for f in gov_findings)


def test_person_detection_ner():
    ner = NERDetector()
    if not ner.is_available:
        return
    text = "Dr. Alice Henderson and Robert Langdon attended the executive briefing."
    findings = ner.detect(text, "d1", "test.txt", "p1", 0)

    persons = [f.text for f in findings if f.pii_type == PIIType.PERSON]
    assert any("Alice Henderson" in p or "Robert Langdon" in p for p in persons)


def test_context_rules_detection():
    ctx = ContextDetector()
    text = "Employee ID: 48392\nDate of Birth: 12/04/1998\nContact: Sarah Connor"
    findings = ctx.detect(text, "d1", "test.txt", "p1", 0)

    types = {f.pii_type for f in findings}
    assert PIIType.EMPLOYEE_ID in types
    assert PIIType.DATE_OF_BIRTH in types
    assert PIIType.PERSON in types


def test_duplicate_finding_merging():
    """Verify overlapping findings from multiple detectors are merged into a single higher-confidence finding."""
    engine = PIIEngine()
    # In this block, "Contact: John Smith" will trigger ContextDetector and NERDetector
    block = DocumentBlock(
        document_id="d1",
        file_name="test.txt",
        file_type="txt",
        location="p1",
        block_type="paragraph",
        text="Contact: John Smith\nEmail: john.smith@company.com",
        order=0
    )
    findings = engine.detect_in_block(block)

    # Check John Smith findings
    john_findings = [f for f in findings if "John Smith" in f.text]
    # Merged into exactly 1 finding
    assert len(john_findings) == 1
    # Methods should include NER and/or CONTEXT
    assert len(john_findings[0].detection_method) >= 1
    # Confidence should be high
    assert john_findings[0].confidence >= 0.85


def test_non_pii_numbers_not_flagged():
    """Ensure normal business metrics and dates are not falsely classified as PII."""
    engine = PIIEngine()
    normal_text = "Fiscal Year 2026 report. Total revenue was 1500000 USD across 45 departments with 98% uptime."
    findings = engine.detect_raw_text(normal_text)

    # Should not flag 2026, 1500000, 45, or 98 as phone or SSN or credit card
    flagged_texts = [f.text for f in findings]
    assert "2026" not in flagged_texts
    assert "1500000" not in flagged_texts
    assert "45" not in flagged_texts


def test_travel_document_non_person_not_flagged():
    """Ensure airline ticket terms, travel documents, baggage weights, and table labels are not falsely flagged as PERSON."""
    ner = NERDetector()
    if not ner.is_available:
        return
    text = "Passenger: Jay Prakash. Details: Passport and Visa required. Cabin baggage: 7 Kg. Ancillary: Other Add."
    findings = ner.detect(text, "d1", "ticket.txt", "p1", 0)

    person_names = [f.text for f in findings if f.pii_type == PIIType.PERSON]
    assert "Jay Prakash" in person_names
    assert "Passport" not in person_names
    assert "Visa" not in person_names
    assert "Cabin" not in person_names
    assert "7 Kg" not in person_names
    assert "Other Add" not in person_names


def test_context_false_positives_eliminated():
    """Ensure context keyword labels followed by English status words are not falsely flagged as PII."""
    context_detector = ContextDetector()
    text = (
        "Document guidelines:\n"
        "Passport: Required\n"
        "Employee: Full Time\n"
        "Contact: Customer Support\n"
        "Lead Investigator: John Smith\n"
        "Employee ID: EMP-10293\n"
        "Passport No: A1234567\n"
    )
    findings = context_detector.detect(text, "d1", "guide.txt", "p1", 0)

    finding_map = {f.text: f.pii_type for f in findings}
    assert "Required" not in finding_map
    assert "Full Time" not in finding_map
    assert "Customer Support" not in finding_map
    assert "John Smith" in finding_map
    assert finding_map["John Smith"] == PIIType.PERSON
    assert "EMP-10293" in finding_map
    assert finding_map["EMP-10293"] == PIIType.EMPLOYEE_ID
    assert "A1234567" in finding_map
    assert finding_map["A1234567"] == PIIType.GOVERNMENT_ID


def test_regex_false_positives_eliminated():
    """Ensure non-Luhn card numbers, financial totals, and sentence-ending email periods are handled cleanly."""
    rgx = RegexDetector()
    text = (
        "Tracking block: 1234-5678-9012-3456.\n"
        "Please email support@example.com.\n"
        "Total revenue: $8000000000 and cost INR 9876543210.\n"
        "Valid payment card: 4111 1111 1111 1111.\n"
        "Call us at +91 9876543210.\n"
    )
    findings = rgx.detect(text, "d1", "test.txt", "p1", 0)

    finding_texts = [f.text for f in findings]
    # Non-Luhn card must not be flagged
    assert "1234-5678-9012-3456" not in finding_texts
    # Email must not capture the sentence period
    assert "support@example.com" in finding_texts
    assert "support@example.com." not in finding_texts
    # Financial sums must not be flagged as phone numbers
    assert "8000000000" not in finding_texts
    # Valid credit card and genuine phone must be detected
    assert any("4111" in t for t in finding_texts)
    assert any("9876543210" in t for t in finding_texts)


def test_indian_names_and_single_names_detected():
    """Ensure Indian names like Shrish and single names in ticket headers are accurately detected."""
    engine = PIIEngine()
    text = "Boarding pass for Passenger: Shrish. Also traveling with Ashish."
    findings = engine.detect_raw_text(text)

    names = [f.text for f in findings if f.pii_type == PIIType.PERSON]
    assert "Shrish" in names
    assert "Ashish" in names


def test_resume_candidate_name_and_contact_labels():
    """Ensure dedicated resume candidate name lines are detected and contact labels are preserved."""
    engine = PIIEngine()
    resume_text = (
        "Vikas Laxman Ahankari\n"
        "DGM Sales and Marketing\n\n"
        "Email: vikas.ahankari@rediffmail.com   Cell: +91 9876543210 Location: PUNE\n\n"
        "Professional Profile\n"
    )
    findings = engine.detect_raw_text(resume_text)

    finding_map = {f.text: f.pii_type for f in findings}

    # Full candidate name must be detected as PERSON
    assert "Vikas Laxman Ahankari" in finding_map
    assert finding_map["Vikas Laxman Ahankari"] == PIIType.PERSON

    # Labels and job titles must NEVER be classified as PII
    assert "Email" not in finding_map
    assert "Cell" not in finding_map
    assert "Location" not in finding_map
    assert "DGM Sales and Marketing" not in finding_map
    assert "Professional Profile" not in finding_map

    # Actual contact information must be detected
    assert "vikas.ahankari@rediffmail.com" in finding_map
    assert finding_map["vikas.ahankari@rediffmail.com"] == PIIType.EMAIL
    assert "+91 9876543210" in finding_map
    assert finding_map["+91 9876543210"] == PIIType.PHONE


def test_technical_terms_not_flagged_as_person():
    """Ensure algorithm names, graph theory concepts, and CS terminology are not flagged as PERSON."""
    engine = PIIEngine()
    technical_samples = [
        "Flow Network",
        "Antiparallel Edges",
        "Residual Network",
        "Minimum Cut",
        "Maximum Flow",
        "Augmenting Paths",
        "Residual Capacity",
        "Breadth-First Search",
        "Adjacency Matrix",
        "Spanning Tree",
        "Greedy Algorithm",
    ]
    for term in technical_samples:
        findings = engine.detect_raw_text(term)
        person_findings = [f.text for f in findings if f.pii_type == PIIType.PERSON]
        assert len(person_findings) == 0, f"Technical term {term!r} was falsely classified as PERSON: {person_findings}"


def test_mathematical_expressions_not_flagged_as_person():
    """Ensure mathematical expressions and function notations are not classified as PERSON."""
    engine = PIIEngine()
    math_samples = [
        "f(u)",
        "c(u)",
        "f(u, v)",
        "c(u, v) - f(u, v)",
        "G = (V, E)",
        "O(V E^2)",
        "f(u) <= c(u)",
        "Capacity constraint: f(u, v) <= c(u, v) for all edges (u, v).",
    ]
    for expr in math_samples:
        findings = engine.detect_raw_text(expr)
        person_findings = [f.text for f in findings if f.pii_type == PIIType.PERSON]
        assert len(person_findings) == 0, f"Math expression {expr!r} was falsely classified as PERSON: {person_findings}"


def test_technical_headings_and_names_in_realistic_document_context():
    """Ensure technical headings and terms in mixed documents are ignored while genuine names are detected."""
    engine = PIIEngine()
    mixed_doc = (
        "Flow Network Analysis\n\n"
        "Section 1.2: Antiparallel Edges\n"
        "We construct the Residual Network and find the Minimum Cut.\n"
        "Formula: f(u, v) <= c(u, v) and f(u) = 0.\n\n"
        "Lead Researcher: Dr. Alice Henderson\n"
        "Email: alice.henderson@research-lab.org\n"
        "Contact Person: Robert Langdon\n"
        "Candidate Name: Vikas Laxman Ahankari\n"
        "Applicant: Pooja Sharma\n"
    )
    findings = engine.detect_raw_text(mixed_doc)
    person_names = {f.text for f in findings if f.pii_type == PIIType.PERSON}

    # Genuine people must be detected
    assert "Alice Henderson" in person_names
    assert "Robert Langdon" in person_names
    assert "Vikas Laxman Ahankari" in person_names
    assert "Pooja Sharma" in person_names

    # Technical terms and math must NOT be classified as PERSON
    assert "Flow Network" not in person_names
    assert "Flow Network Analysis" not in person_names
    assert "Antiparallel Edges" not in person_names
    assert "Residual Network" not in person_names
    assert "Minimum Cut" not in person_names
    assert not any("f(u" in n for n in person_names)
    assert not any("c(u" in n for n in person_names)


def test_names_with_common_word_surnames_preserved():
    """Ensure legitimate multi-word names containing words that are also common nouns are detected."""
    ner = NERDetector()
    if not ner.is_available:
        return
    text = "We consulted Larry Page, Bill Gates, Vincent Price, and Brian May regarding the initiative."
    findings = ner.detect(text, "d1", "test.txt", "p1", 0)
    person_names = [f.text for f in findings if f.pii_type == PIIType.PERSON]

    assert any("Larry Page" in n for n in person_names)
    assert any("Bill Gates" in n for n in person_names)
    assert any("Vincent Price" in n for n in person_names)
    assert any("Brian May" in n for n in person_names)

