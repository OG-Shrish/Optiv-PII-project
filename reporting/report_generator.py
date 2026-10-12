"""Analysis report generator producing JSON and CSV audit artifacts."""
import csv
import io
import json
from datetime import datetime
from typing import List, Dict, Any
from collections import Counter

from models.schemas import DocumentAnalysisResult, SecurityStatus, Severity


class ReportGenerator:
    """Generates structured compliance and forensic audit reports."""

    @staticmethod
    def get_summary_metrics(results: List[DocumentAnalysisResult]) -> Dict[str, Any]:
        """Aggregate summary numbers across all analyzed documents."""
        total_docs = len(results)
        total_pii = sum(len(r.pii_findings) for r in results)
        
        high_risk_count = 0
        type_counter: Counter = Counter()
        severity_counter: Counter = Counter()

        for r in results:
            for f in r.pii_findings:
                sev_str = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
                type_str = f.pii_type.value if hasattr(f.pii_type, "value") else str(f.pii_type)
                
                type_counter[type_str] += 1
                severity_counter[sev_str] += 1
                if sev_str in ("CRITICAL", "HIGH"):
                    high_risk_count += 1

        sanitized_count = sum(1 for r in results if r.security_status == SecurityStatus.SANITIZED)
        blocked_count = sum(1 for r in results if r.security_status in (SecurityStatus.BLOCKED, SecurityStatus.PROCESSING_ERROR))
        review_count = sum(1 for r in results if r.security_status == SecurityStatus.REVIEW_REQUIRED)

        return {
            "total_documents": total_docs,
            "total_pii_detected": total_pii,
            "high_risk_findings": high_risk_count,
            "files_sanitized": sanitized_count,
            "files_blocked": blocked_count,
            "files_review_required": review_count,
            "type_breakdown": dict(type_counter),
            "severity_breakdown": dict(severity_counter),
        }

    @staticmethod
    def generate_json_report(results: List[DocumentAnalysisResult]) -> str:
        """Create a complete forensic audit log in formatted JSON."""
        summary = ReportGenerator.get_summary_metrics(results)
        report_data = {
            "report_timestamp": datetime.now().isoformat(),
            "pipeline": "PII Security Gateway Pre-LLM Inspection",
            "security_policy": "NO PII -> SAFE FOR DOWNSTREAM AI",
            "fail_closed_enforced": True,
            "summary": summary,
            "documents": [r.to_dict() for r in results],
        }
        return json.dumps(report_data, indent=2)

    @staticmethod
    def generate_csv_findings(results: List[DocumentAnalysisResult]) -> str:
        """Export all individual PII findings to a flat CSV table."""
        output = io.StringIO()
        writer = csv.writer(output)
        
        headers = [
            "Severity",
            "PII Type",
            "Confidence",
            "Detection Method",
            "File Name",
            "Location",
            "Masked Text",
            "Action",
            "Explanation",
            "Document Security Status",
        ]
        writer.writerow(headers)

        for doc in results:
            doc_status = doc.security_status.value if hasattr(doc.security_status, "value") else str(doc.security_status)
            for f in doc.pii_findings:
                writer.writerow([
                    f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                    f.pii_type.value if hasattr(f.pii_type, "value") else str(f.pii_type),
                    f"{f.confidence * 100:.1f}%",
                    " + ".join(f.detection_method),
                    f.file_name,
                    f.location,
                    f.masked_text,
                    f.action,
                    f.explanation,
                    doc_status,
                ])

        return output.getvalue()
