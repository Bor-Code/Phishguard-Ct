import csv
import json
from pathlib import Path
from typing import Tuple, Union
from phishguard.evaluation.models import EvaluationReport


def export_report_to_json(report: EvaluationReport, target_path: Path) -> None:
    data = {
        "generated_at": report.generated_at,
        "suspect_threshold": report.suspect_threshold,
        "overall_metrics": {
            "total_samples": report.overall_metrics.total_samples,
            "phishing_samples": report.overall_metrics.phishing_samples,
            "benign_samples": report.overall_metrics.benign_samples,
            "true_positives": report.overall_metrics.true_positives,
            "false_positives": report.overall_metrics.false_positives,
            "true_negatives": report.overall_metrics.true_negatives,
            "false_negatives": report.overall_metrics.false_negatives,
            "precision": report.overall_metrics.precision,
            "recall": report.overall_metrics.recall,
            "f1_score": report.overall_metrics.f1_score,
            "false_positive_rate": report.overall_metrics.false_positive_rate,
        },
        "brand_metrics": [
            {
                "brand": bm.brand,
                "total_samples": bm.total_samples,
                "true_positives": bm.true_positives,
                "false_negatives": bm.false_negatives,
                "recall": bm.recall,
            }
            for bm in report.brand_metrics
        ],
        "flagged_domains_count": len(report.flagged_domains),
        "flagged_domains": report.flagged_domains,
    }
    target_path.parent.mkdir(parents=True, exist_ok=True)
    target_path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def export_report_to_csv(report: EvaluationReport, target_path: Path) -> None:
    target_path.parent.mkdir(parents=True, exist_ok=True)
    with target_path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["Metric", "Value"])
        writer.writerow(["Generated At", report.generated_at])
        writer.writerow(["Suspect Threshold", report.suspect_threshold])
        writer.writerow(["Total Samples", report.overall_metrics.total_samples])
        writer.writerow(["Phishing Samples", report.overall_metrics.phishing_samples])
        writer.writerow(["Benign Samples", report.overall_metrics.benign_samples])
        writer.writerow(["True Positives", report.overall_metrics.true_positives])
        writer.writerow(["False Positives", report.overall_metrics.false_positives])
        writer.writerow(["True Negatives", report.overall_metrics.true_negatives])
        writer.writerow(["False Negatives", report.overall_metrics.false_negatives])
        writer.writerow(["Precision", f"{report.overall_metrics.precision:.4f}"])
        writer.writerow(["Recall", f"{report.overall_metrics.recall:.4f}"])
        writer.writerow(["F1 Score", f"{report.overall_metrics.f1_score:.4f}"])
        writer.writerow(["False Positive Rate", f"{report.overall_metrics.false_positive_rate:.4f}"])

        writer.writerow([])
        writer.writerow(["Brand", "Total Samples", "True Positives", "False Negatives", "Recall"])
        for bm in report.brand_metrics:
            writer.writerow([bm.brand, bm.total_samples, bm.true_positives, bm.false_negatives, f"{bm.recall:.4f}"])


def save_evaluation_report(
    report: EvaluationReport, output_dir: Union[str, Path] = "reports"
) -> Tuple[Path, Path]:
    dir_path = Path(output_dir)
    json_path = dir_path / "evaluation_report.json"
    csv_path = dir_path / "evaluation_report.csv"

    export_report_to_json(report, json_path)
    export_report_to_csv(report, csv_path)
    return json_path, csv_path
