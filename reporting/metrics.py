"""Metrics evaluation module for PII detection precision, recall, and structure retention."""
from dataclasses import dataclass
from typing import List, Dict, Optional, Set, Tuple

from models.schemas import DocumentBlock, PIIFinding


@dataclass
class GroundTruthAnnotation:
    """Expected ground truth PII annotation for benchmarking."""
    location: str
    text: str
    pii_type: str


@dataclass
class EvaluationMetrics:
    """Benchmark performance metrics based on verified ground truth."""
    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float
    recall: float
    f1_score: float
    residual_pii_count: int
    structure_retention_score: float
    is_ground_truth_available: bool
    status_message: str


def calculate_structure_retention(
    original_blocks: List[DocumentBlock],
    redacted_blocks: List[DocumentBlock]
) -> float:
    """Calculate structural block retention percentage.

    Verifies that page, slide, paragraph, and table boundaries are preserved
    throughout extraction and redaction pipelines.
    """
    if not original_blocks:
        return 0.0
    
    # Check that block count and location keys match 1:1
    orig_locations = [b.location for b in original_blocks]
    redacted_locations = [b.location for b in redacted_blocks]
    
    matches = sum(1 for o, r in zip(orig_locations, redacted_locations) if o == r)
    retention_ratio = matches / len(orig_blocks) if (orig_blocks := orig_locations) else 0.0
    return round(retention_ratio * 100.0, 2)


def evaluate_detection_metrics(
    detected_findings: List[PIIFinding],
    ground_truth: Optional[List[GroundTruthAnnotation]] = None,
    residual_findings: Optional[List[PIIFinding]] = None,
    structure_retention: float = 100.0
) -> EvaluationMetrics:
    """Evaluate detection metrics against explicit ground-truth annotations.

    If ground-truth is not provided, returns explicit 'unavailable' indicator
    rather than simulated numbers.
    """
    residual_count = len(residual_findings) if residual_findings else 0

    if ground_truth is None or len(ground_truth) == 0:
        return EvaluationMetrics(
            true_positives=0,
            false_positives=0,
            false_negatives=0,
            precision=0.0,
            recall=0.0,
            f1_score=0.0,
            residual_pii_count=residual_count,
            structure_retention_score=structure_retention,
            is_ground_truth_available=False,
            status_message="Metrics unavailable — ground truth not provided.",
        )

    # Match detected findings to ground truth
    # Criteria: location matches and text normalized matches
    gt_matched: Set[int] = set()
    tp = 0
    fp = 0

    for df in detected_findings:
        matched = False
        norm_det_text = df.text.strip().lower()
        for idx, gt in enumerate(ground_truth):
            if idx in gt_matched:
                continue
            norm_gt_text = gt.text.strip().lower()
            if (df.location == gt.location or not gt.location) and (
                norm_det_text == norm_gt_text or norm_det_text in norm_gt_text or norm_gt_text in norm_det_text
            ):
                gt_matched.add(idx)
                matched = True
                tp += 1
                break
        if not matched:
            fp += 1

    fn = len(ground_truth) - len(gt_matched)

    precision = round(tp / (tp + fp), 4) if (tp + fp) > 0 else 0.0
    recall = round(tp / (tp + fn), 4) if (tp + fn) > 0 else 0.0
    f1 = round(2 * (precision * recall) / (precision + recall), 4) if (precision + recall) > 0 else 0.0

    return EvaluationMetrics(
        true_positives=tp,
        false_positives=fp,
        false_negatives=fn,
        precision=precision,
        recall=recall,
        f1_score=f1,
        residual_pii_count=residual_count,
        structure_retention_score=structure_retention,
        is_ground_truth_available=True,
        status_message=f"Ground truth evaluation: F1 = {f1 * 100:.1f}%, Precision = {precision * 100:.1f}%, Recall = {recall * 100:.1f}%.",
    )
