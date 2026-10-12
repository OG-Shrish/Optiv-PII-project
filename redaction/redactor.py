"""Redaction engine for consistent semantic placeholder substitution."""
import logging
from typing import List, Dict, Tuple
from collections import defaultdict

from models.schemas import (
    DocumentBlock,
    PIIFinding,
    RedactionResult,
    PIIType,
)

logger = logging.getLogger(__name__)


class PIIRedactor:
    """Performs consistent semantic redaction across document blocks."""

    def redact_document(
        self,
        blocks: List[DocumentBlock],
        findings: List[PIIFinding],
        document_id: str,
        file_name: str
    ) -> RedactionResult:
        """Redact detected PII entities across all blocks using consistent semantic tags."""
        # 1. Build document-level consistent mapping for entities
        # Map: (pii_type, normalized_value) -> placeholder (e.g. "[PERSON_001]")
        type_counters: Dict[str, int] = defaultdict(int)
        entity_registry: Dict[Tuple[str, str], str] = {}
        # Also maintain raw value -> placeholder for internal report
        raw_mappings: Dict[str, str] = {}

        for f in findings:
            type_key = f.pii_type.value if isinstance(f.pii_type, PIIType) else str(f.pii_type)
            norm_val = f.text.strip().lower()
            dict_key = (type_key, norm_val)

            if dict_key not in entity_registry:
                type_counters[type_key] += 1
                seq_id = f"{type_counters[type_key]:03d}"
                placeholder = f"[{type_key}_{seq_id}]"
                entity_registry[dict_key] = placeholder
                raw_mappings[f.text.strip()] = placeholder

        # Group findings by block_order
        findings_by_block: Dict[int, List[PIIFinding]] = defaultdict(list)
        for f in findings:
            findings_by_block[f.block_order].append(f)

        redacted_blocks: List[DocumentBlock] = []
        total_replacements = 0

        # 2. Apply redaction per block
        for block in blocks:
            block_findings = findings_by_block.get(block.order, [])
            
            if not block_findings:
                # No findings in this block, preserve original text
                redacted_blocks.append(
                    DocumentBlock(
                        document_id=block.document_id,
                        file_name=block.file_name,
                        file_type=block.file_type,
                        location=block.location,
                        block_type=block.block_type,
                        text=block.text,
                        order=block.order,
                        metadata=block.metadata.copy(),
                    )
                )
                continue

            # Sort findings in reverse start offset so replacements don't offset subsequent indices
            sorted_block_findings = sorted(block_findings, key=lambda f: f.start, reverse=True)
            text_chars = list(block.text)

            for f in sorted_block_findings:
                type_key = f.pii_type.value if isinstance(f.pii_type, PIIType) else str(f.pii_type)
                norm_val = f.text.strip().lower()
                placeholder = entity_registry.get((type_key, norm_val), f"[{type_key}_REDACTED]")

                # Guard against index out of range
                s = max(0, f.start)
                e = min(len(text_chars), f.end)
                if s < e:
                    text_chars[s:e] = list(placeholder)
                    total_replacements += 1

            new_text = "".join(text_chars)
            redacted_blocks.append(
                DocumentBlock(
                    document_id=block.document_id,
                    file_name=block.file_name,
                    file_type=block.file_type,
                    location=block.location,
                    block_type=block.block_type,
                    text=new_text,
                    order=block.order,
                    metadata=block.metadata.copy(),
                )
            )

        # 3. Assemble full sanitized text retaining structure
        sanitized_parts: List[str] = []
        current_loc_prefix = ""

        for b in redacted_blocks:
            # Add structural separator for readability if location changes
            loc_root = b.location.split("_")[0] if "_" in b.location else b.location
            if loc_root != current_loc_prefix and b.file_type in ("pdf", "pptx"):
                sanitized_parts.append(f"\n--- [{b.location.upper()}] ---")
                current_loc_prefix = loc_root
            sanitized_parts.append(b.text)

        redacted_full_text = "\n\n".join(sanitized_parts).strip()

        return RedactionResult(
            document_id=document_id,
            file_name=file_name,
            redacted_blocks=redacted_blocks,
            redacted_full_text=redacted_full_text,
            entity_mappings=raw_mappings,
            replacements_count=total_replacements,
        )
