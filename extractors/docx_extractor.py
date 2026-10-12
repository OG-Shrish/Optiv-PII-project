"""DOCX Document Extractor using python-docx preserving headings, paragraphs, and tables."""
import io
import logging
from typing import List, Tuple
import docx

from models.schemas import DocumentBlock

logger = logging.getLogger(__name__)


def extract_docx(
    file_bytes: bytes,
    file_name: str,
    document_id: str
) -> Tuple[List[DocumentBlock], bool]:
    """Extract structured document blocks from a DOCX file.

    Returns:
        Tuple of (blocks, requires_ocr=False)
    """
    blocks: List[DocumentBlock] = []
    order_counter = 0

    try:
        doc = docx.Document(io.BytesIO(file_bytes))
    except Exception as e:
        logger.error(f"Failed to open DOCX stream for {file_name}: {e}")
        raise ValueError(f"Corrupted or invalid DOCX file: {e}")

    # Process paragraphs and headings
    for p_idx, paragraph in enumerate(doc.paragraphs):
        text = paragraph.text.strip()
        if not text:
            continue
        
        style_name = paragraph.style.name.lower() if paragraph.style and paragraph.style.name else ""
        block_type = "heading" if "heading" in style_name or "title" in style_name else "paragraph"
        location = f"heading_{p_idx + 1}" if block_type == "heading" else f"paragraph_{p_idx + 1}"

        blocks.append(
            DocumentBlock(
                document_id=document_id,
                file_name=file_name,
                file_type="docx",
                location=location,
                block_type=block_type,
                text=text,
                order=order_counter,
                metadata={"index": p_idx, "style": style_name}
            )
        )
        order_counter += 1

    # Process tables
    for t_idx, table in enumerate(doc.tables):
        for r_idx, row in enumerate(table.rows):
            cell_texts = []
            for c_idx, cell in enumerate(row.cells):
                cell_val = cell.text.strip()
                if cell_val:
                    cell_texts.append(cell_val)
                    # Also keep granular cell block if table has detailed info
            
            row_combined = " | ".join(cell_texts).strip()
            if row_combined:
                blocks.append(
                    DocumentBlock(
                        document_id=document_id,
                        file_name=file_name,
                        file_type="docx",
                        location=f"table_{t_idx + 1}_row_{r_idx + 1}",
                        block_type="table_row",
                        text=row_combined,
                        order=order_counter,
                        metadata={"table_index": t_idx + 1, "row_index": r_idx + 1}
                    )
                )
                order_counter += 1

    return blocks, False
