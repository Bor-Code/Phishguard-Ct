import json
from pathlib import Path
from typing import List, Optional, Union
from urllib.parse import urlparse
from phishguard.evaluation.models import DatasetSample
from phishguard.ingestion.parser import clean_domain


def extract_domain_from_url(raw_input: str) -> Optional[str]:
    candidate = raw_input.strip()
    if not candidate:
        return None
    if not candidate.startswith(("http://", "https://")):
        candidate = f"http://{candidate}"
    try:
        parsed = urlparse(candidate)
        hostname = parsed.hostname
        if not hostname:
            return None
        return clean_domain(hostname)
    except Exception:
        return None


def load_phishtank_dataset(source: Union[str, Path]) -> List[DatasetSample]:
    path = Path(source) if isinstance(source, Path) or Path(source).is_file() else None
    raw_text = path.read_text(encoding="utf-8") if path else str(source)
    try:
        data = json.loads(raw_text)
    except json.JSONDecodeError:
        return []

    if not isinstance(data, list):
        return []

    samples: List[DatasetSample] = []
    seen = set()
    for item in data:
        if not isinstance(item, dict):
            continue
        url = item.get("url", "")
        domain = extract_domain_from_url(url)
        if not domain or domain in seen:
            continue
        seen.add(domain)
        target = item.get("target")
        target_brand = str(target).lower() if target else None
        samples.append(
            DatasetSample(
                domain=domain,
                is_phishing=True,
                target_brand=target_brand,
                source="phishtank",
            )
        )
    return samples


def load_openphish_dataset(source: Union[str, Path]) -> List[DatasetSample]:
    path = Path(source) if isinstance(source, Path) or Path(source).is_file() else None
    raw_text = path.read_text(encoding="utf-8") if path else str(source)

    samples: List[DatasetSample] = []
    seen = set()
    for line in raw_text.splitlines():
        line = line.strip()
        if not line:
            continue
        domain = extract_domain_from_url(line)
        if not domain or domain in seen:
            continue
        seen.add(domain)
        samples.append(
            DatasetSample(
                domain=domain,
                is_phishing=True,
                target_brand=None,
                source="openphish",
            )
        )
    return samples


def load_benign_dataset(source: Union[str, Path]) -> List[DatasetSample]:
    path = Path(source) if isinstance(source, Path) or Path(source).is_file() else None
    raw_text = path.read_text(encoding="utf-8") if path else str(source)

    samples: List[DatasetSample] = []
    seen = set()
    for line in raw_text.splitlines():
        line = line.strip()
        if not line:
            continue
        domain = extract_domain_from_url(line)
        if not domain or domain in seen:
            continue
        seen.add(domain)
        samples.append(
            DatasetSample(
                domain=domain,
                is_phishing=False,
                target_brand=None,
                source="benign",
            )
        )
    return samples
