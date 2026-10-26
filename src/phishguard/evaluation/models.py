from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass(frozen=True)
class DatasetSample:
    domain: str
    is_phishing: bool
    target_brand: Optional[str] = None
    source: str = "custom"


@dataclass(frozen=True)
class EvaluationMetrics:
    total_samples: int
    phishing_samples: int
    benign_samples: int
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    precision: float
    recall: float
    f1_score: float
    false_positive_rate: float


@dataclass(frozen=True)
class BrandMetric:
    brand: str
    total_samples: int
    true_positives: int
    false_negatives: int
    recall: float


@dataclass(frozen=True)
class EvaluationReport:
    generated_at: str
    suspect_threshold: float
    overall_metrics: EvaluationMetrics
    brand_metrics: List[BrandMetric] = field(default_factory=list)
    flagged_domains: List[Dict[str, object]] = field(default_factory=list)
