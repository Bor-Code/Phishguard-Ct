import argparse
from pathlib import Path
from typing import List
from phishguard.evaluation.datasets import (
    load_benign_dataset,
    load_openphish_dataset,
    load_phishtank_dataset,
)
from phishguard.evaluation.models import DatasetSample
from phishguard.evaluation.pipeline import EvaluationPipeline
from phishguard.evaluation.reporter import save_evaluation_report
from phishguard.scoring import ScoringEngine
from phishguard.watchlist import BrandWatchlist


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="phishguard.evaluation.runner",
        description="Run evaluation pipeline against PhishTank and OpenPhish benchmarks",
    )
    parser.add_argument(
        "--phishtank",
        default="data/benchmarks/phishtank_sample.json",
        help="Path to PhishTank JSON dataset",
    )
    parser.add_argument(
        "--openphish",
        default="data/benchmarks/openphish_sample.txt",
        help="Path to OpenPhish URL feed dataset",
    )
    parser.add_argument(
        "--benign",
        default="data/benchmarks/benign_sample.txt",
        help="Path to Benign domains list",
    )
    parser.add_argument(
        "--output-dir",
        default="reports",
        help="Output directory for JSON and CSV evaluation reports",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.75,
        help="Scoring engine suspect threshold",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_arguments()

    samples: List[DatasetSample] = []

    phishtank_path = Path(args.phishtank)
    if phishtank_path.is_file():
        samples.extend(load_phishtank_dataset(phishtank_path))

    openphish_path = Path(args.openphish)
    if openphish_path.is_file():
        samples.extend(load_openphish_dataset(openphish_path))

    benign_path = Path(args.benign)
    if benign_path.is_file():
        samples.extend(load_benign_dataset(benign_path))

    if not samples:
        print("No evaluation samples loaded. Exiting.")
        return

    engine = ScoringEngine(suspect_threshold=args.threshold)
    watchlist = BrandWatchlist.from_defaults()
    pipeline = EvaluationPipeline(scoring_engine=engine, watchlist=watchlist)

    report = pipeline.evaluate_samples(samples)
    json_path, csv_path = save_evaluation_report(report, output_dir=args.output_dir)

    metrics = report.overall_metrics
    print("Evaluation Complete")
    print(f"Total Samples: {metrics.total_samples}")
    print(f"Phishing Samples: {metrics.phishing_samples} | Benign Samples: {metrics.benign_samples}")
    print(f"True Positives: {metrics.true_positives} | False Positives: {metrics.false_positives}")
    print(f"True Negatives: {metrics.true_negatives} | False Negatives: {metrics.false_negatives}")
    print(f"Precision: {metrics.precision:.4f}")
    print(f"Recall: {metrics.recall:.4f}")
    print(f"F1-Score: {metrics.f1_score:.4f}")
    print(f"False Positive Rate: {metrics.false_positive_rate:.4f}")
    print(f"Report Artifacts Saved: {json_path} and {csv_path}")


if __name__ == "__main__":
    main()
