"""Document Extractors Package for PII Security Gateway.

Normalizes PDF, DOCX, PPTX, and TXT files into standard DocumentBlock structures
while strictly preserving structure and source location.
"""
from pathlib import Path
from typing import List, Tuple

from models.schemas import DocumentBlock
from extractors.pdf_extractor import extract_pdf
from extractors.docx_extractor import extract_docx
from extractors.pptx_extractor import extract_pptx
from extractors.txt_extractor import extract_txt


def extract_document(
    file_bytes: bytes,
    file_name: str,
    document_id: str
) -> Tuple[List[DocumentBlock], bool, str]:
    """Dispatch document extraction based on file extension.

    Returns:
        Tuple of (blocks, requires_ocr, extraction_status)
    """
    ext = Path(file_name).suffix.lower()

    if ext == ".pdf":
        blocks, requires_ocr = extract_pdf(file_bytes, file_name, document_id)
        return blocks, requires_ocr, "SUCCESS"
    elif ext == ".docx":
        blocks, requires_ocr = extract_docx(file_bytes, file_name, document_id)
        return blocks, requires_ocr, "SUCCESS"
    elif ext == ".pptx":
        blocks, requires_ocr = extract_pptx(file_bytes, file_name, document_id)
        return blocks, requires_ocr, "SUCCESS"
    elif ext == ".txt":
        blocks, requires_ocr = extract_txt(file_bytes, file_name, document_id)
        return blocks, requires_ocr, "SUCCESS"
    else:
        raise ValueError(f"Unsupported file format '{ext}'. Supported formats: PDF, DOCX, PPTX, TXT")


__all__ = [
    "extract_document",
    "extract_pdf",
    "extract_docx",
    "extract_pptx",
    "extract_txt",
]
