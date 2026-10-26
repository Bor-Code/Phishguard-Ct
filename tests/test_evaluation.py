import json
from phishguard.evaluation import (
    DatasetSample,
    EvaluationPipeline,
    calculate_metrics,
    export_report_to_csv,
    export_report_to_json,
    extract_domain_from_url,
    load_benign_dataset,
    load_openphish_dataset,
    load_phishtank_dataset,
    save_evaluation_report,
)


def test_extract_domain_from_url():
    assert extract_domain_from_url("https://www.paypal.com/signin") == "www.paypal.com"
    assert extract_domain_from_url("http://paypa1-security.com/") == "paypa1-security.com"
    assert extract_domain_from_url("simple-domain.org") == "simple-domain.org"
    assert extract_domain_from_url("") is None


def test_calculate_metrics_values():
    metrics = calculate_metrics(
        true_positives=8,
        false_positives=2,
        true_negatives=18,
        false_negatives=2,
    )
    assert metrics.total_samples == 30
    assert metrics.precision == 0.8
    assert metrics.recall == 0.8
    assert metrics.f1_score == 0.8
    assert metrics.false_positive_rate == 0.1


def test_calculate_metrics_zero_division():
    metrics = calculate_metrics(0, 0, 0, 0)
    assert metrics.total_samples == 0
    assert metrics.precision == 0.0
    assert metrics.recall == 0.0
    assert metrics.f1_score == 0.0
    assert metrics.false_positive_rate == 0.0


def test_dataset_loaders():
    phishtank_raw = json.dumps([{"url": "https://paypa1.com/login", "target": "paypal"}])
    samples_pt = load_phishtank_dataset(phishtank_raw)
    assert len(samples_pt) == 1
    assert samples_pt[0].domain == "paypa1.com"
    assert samples_pt[0].target_brand == "paypal"
    assert samples_pt[0].is_phishing is True

    openphish_raw = "https://g00gle-verify.xyz/auth\nhttp://apple-id-reset.org"
    samples_op = load_openphish_dataset(openphish_raw)
    assert len(samples_op) == 2
    assert samples_op[0].domain == "g00gle-verify.xyz"
    assert samples_op[0].is_phishing is True

    benign_raw = "https://wikipedia.org/\nhttps://github.com"
    samples_benign = load_benign_dataset(benign_raw)
    assert len(samples_benign) == 2
    assert samples_benign[0].domain == "wikipedia.org"
    assert samples_benign[0].is_phishing is False


def test_evaluation_pipeline_execution():
    pipeline = EvaluationPipeline()
    samples = [
        DatasetSample("paypa1-security.com", is_phishing=True, target_brand="paypal"),
        DatasetSample("g00gle-login.xyz", is_phishing=True, target_brand="google"),
        DatasetSample("wikipedia.org", is_phishing=False),
        DatasetSample("github.com", is_phishing=False),
        DatasetSample("paypal.com", is_phishing=False),
    ]

    report = pipeline.evaluate_samples(samples)
    assert report.overall_metrics.true_positives >= 2
    assert report.overall_metrics.false_positives == 0
    assert report.overall_metrics.precision == 1.0
    assert report.overall_metrics.recall == 1.0


def test_save_evaluation_report(tmp_path):
    pipeline = EvaluationPipeline()
    samples = [
        DatasetSample("paypa1-security.com", is_phishing=True, target_brand="paypal"),
        DatasetSample("wikipedia.org", is_phishing=False),
    ]
    report = pipeline.evaluate_samples(samples)
    json_path, csv_path = save_evaluation_report(report, output_dir=tmp_path)

    assert json_path.is_file()
    assert csv_path.is_file()

    json_content = json.loads(json_path.read_text(encoding="utf-8"))
    assert "overall_metrics" in json_content
    assert json_content["overall_metrics"]["true_positives"] == 1

    csv_content = csv_path.read_text(encoding="utf-8")
    assert "Precision" in csv_content
    assert "Recall" in csv_content
    assert "True Positives" in csv_content
