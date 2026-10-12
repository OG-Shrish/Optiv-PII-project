"""Plain text document extractor preserving paragraph structure and line boundaries."""
import logging
from typing import List, Tuple

from models.schemas import DocumentBlock

logger = logging.getLogger(__name__)


def extract_txt(
    file_bytes: bytes,
    file_name: str,
    document_id: str
) -> Tuple[List[DocumentBlock], bool]:
    """Extract structured document blocks from plain text.

    Returns:
        Tuple of (blocks, requires_ocr=False)
    """
    blocks: List[DocumentBlock] = []
    
    # Try decoding with utf-8 first, fallback to latin-1
    try:
        text_content = file_bytes.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text_content = file_bytes.decode("latin-1")
        except Exception as e:
            logger.error(f"Failed to decode text file {file_name}: {e}")
            raise ValueError(f"Unable to decode text file: {e}")

    # Split by paragraphs (double newlines) or non-empty lines
    paragraphs = [p.strip() for p in text_content.split("\n\n") if p.strip()]
    if not paragraphs:
        # Fall back to single lines if no double newlines
        paragraphs = [line.strip() for line in text_content.splitlines() if line.strip()]

    for idx, p in enumerate(paragraphs):
        blocks.append(
            DocumentBlock(
                document_id=document_id,
                file_name=file_name,
                file_type="txt",
                location=f"paragraph_{idx + 1}",
                block_type="paragraph",
                text=p,
                order=idx,
                metadata={"paragraph_index": idx + 1}
            )
        )

    return blocks, False
