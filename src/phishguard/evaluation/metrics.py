from phishguard.evaluation.models import EvaluationMetrics


def calculate_metrics(
    true_positives: int,
    false_positives: int,
    true_negatives: int,
    false_negatives: int,
) -> EvaluationMetrics:
    total_samples = true_positives + false_positives + true_negatives + false_negatives
    phishing_samples = true_positives + false_negatives
    benign_samples = false_positives + true_negatives

    precision = (
        true_positives / (true_positives + false_positives)
        if (true_positives + false_positives) > 0
        else 0.0
    )
    recall = (
        true_positives / (true_positives + false_negatives)
        if (true_positives + false_negatives) > 0
        else 0.0
    )
    f1_score = (
        2.0 * (precision * recall) / (precision + recall)
        if (precision + recall) > 0.0
        else 0.0
    )
    fpr = (
        false_positives / (false_positives + true_negatives)
        if (false_positives + true_negatives) > 0
        else 0.0
    )

    return EvaluationMetrics(
        total_samples=total_samples,
        phishing_samples=phishing_samples,
        benign_samples=benign_samples,
        true_positives=true_positives,
        false_positives=false_positives,
        true_negatives=true_negatives,
        false_negatives=false_negatives,
        precision=round(precision, 4),
        recall=round(recall, 4),
        f1_score=round(f1_score, 4),
        false_positive_rate=round(fpr, 4),
    )
