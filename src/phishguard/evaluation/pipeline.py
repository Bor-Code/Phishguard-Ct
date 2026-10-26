from datetime import datetime, timezone
from typing import Dict, List, Optional
from phishguard.evaluation.metrics import calculate_metrics
from phishguard.evaluation.models import BrandMetric, DatasetSample, EvaluationReport
from phishguard.scoring import ScoringEngine
from phishguard.watchlist import BrandWatchlist


class EvaluationPipeline:
    def __init__(
        self,
        scoring_engine: Optional[ScoringEngine] = None,
        watchlist: Optional[BrandWatchlist] = None,
    ) -> None:
        self.engine = scoring_engine or ScoringEngine(suspect_threshold=0.75)
        self.watchlist = watchlist or BrandWatchlist.from_defaults()

    def evaluate_samples(self, samples: List[DatasetSample]) -> EvaluationReport:
        target_brands = self.watchlist.all_brand_names()
        true_positives = 0
        false_positives = 0
        true_negatives = 0
        false_negatives = 0

        brand_stats: Dict[str, Dict[str, int]] = {
            brand: {"tp": 0, "fn": 0, "total": 0} for brand in target_brands
        }
        flagged_list: List[Dict[str, object]] = []

        for sample in samples:
            is_legitimate = self.watchlist.is_legitimate_domain(sample.domain)
            score_result = (
                None
                if is_legitimate
                else self.engine.score_domain(sample.domain, target_brands)
            )

            is_suspect = (
                score_result is not None and score_result.is_phishing_suspect
            )

            if sample.is_phishing:
                matched_brand = score_result.target_brand if score_result else sample.target_brand
                if matched_brand and matched_brand in brand_stats:
                    brand_stats[matched_brand]["total"] += 1
                if is_suspect:
                    true_positives += 1
                    if matched_brand and matched_brand in brand_stats:
                        brand_stats[matched_brand]["tp"] += 1
                else:
                    false_negatives += 1
                    if matched_brand and matched_brand in brand_stats:
                        brand_stats[matched_brand]["fn"] += 1
            else:
                if is_suspect:
                    false_positives += 1
                else:
                    true_negatives += 1

            if is_suspect and score_result is not None:
                flagged_list.append(
                    {
                        "domain": sample.domain,
                        "source": sample.source,
                        "target_brand": score_result.target_brand,
                        "matched_term": score_result.matched_term,
                        "composite_score": score_result.composite_score,
                        "actual_is_phishing": sample.is_phishing,
                    }
                )

        overall_metrics = calculate_metrics(
            true_positives=true_positives,
            false_positives=false_positives,
            true_negatives=true_negatives,
            false_negatives=false_negatives,
        )

        brand_metrics: List[BrandMetric] = []
        for brand, counts in brand_stats.items():
            if counts["total"] > 0:
                recall = (
                    counts["tp"] / counts["total"]
                    if counts["total"] > 0
                    else 0.0
                )
                brand_metrics.append(
                    BrandMetric(
                        brand=brand,
                        total_samples=counts["total"],
                        true_positives=counts["tp"],
                        false_negatives=counts["fn"],
                        recall=round(recall, 4),
                    )
                )

        now_iso = datetime.now(timezone.utc).isoformat()
        return EvaluationReport(
            generated_at=now_iso,
            suspect_threshold=self.engine.suspect_threshold,
            overall_metrics=overall_metrics,
            brand_metrics=brand_metrics,
            flagged_domains=flagged_list,
        )
