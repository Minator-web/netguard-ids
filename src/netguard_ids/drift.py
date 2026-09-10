from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from .cross_dataset import (
    SHARED_FLOW_FEATURES,
    _cic_shared_features,
    _resolve_cic_columns,
    _resolve_cic_files,
    _unsw_shared_features,
)
from .unsw import _load_dependencies, _read_dataset


def _priority_sample_cic(
    cic_files: list[Path],
    dependencies,
    sample_rows: int,
    chunk_size: int,
    seed: int,
) -> tuple:
    rng = dependencies["np"].random.default_rng(seed)
    reservoir = None
    reservoir_keys = None
    total_rows = 0
    missing_counts = dependencies["pd"].Series(0, index=SHARED_FLOW_FEATURES, dtype="int64")
    file_stats = []

    for path in cic_files:
        columns = _resolve_cic_columns(path, dependencies)
        file_rows = 0
        reader = dependencies["pd"].read_csv(
            path,
            usecols=list(columns.values()),
            chunksize=chunk_size,
            low_memory=False,
        )
        for chunk in reader:
            features = _cic_shared_features(chunk, columns, dependencies)
            total_rows += len(features)
            file_rows += len(features)
            missing_counts += features.isna().sum()
            keys = rng.random(len(features))
            if reservoir is None:
                candidates = features.reset_index(drop=True)
                candidate_keys = keys
            else:
                candidates = dependencies["pd"].concat([reservoir, features], ignore_index=True)
                candidate_keys = dependencies["np"].concatenate([reservoir_keys, keys])
            if len(candidates) > sample_rows:
                selected = dependencies["np"].argpartition(candidate_keys, sample_rows - 1)[
                    :sample_rows
                ]
                reservoir = candidates.iloc[selected].reset_index(drop=True)
                reservoir_keys = candidate_keys[selected]
            else:
                reservoir = candidates
                reservoir_keys = candidate_keys
        file_stats.append({"file": path.name, "rows": file_rows})

    if reservoir is None or total_rows == 0:
        raise ValueError("No CIC-IDS2017 rows were loaded")
    missing_rates = (missing_counts / total_rows).to_dict()
    return reservoir, total_rows, missing_rates, file_stats


def _psi(source, target, dependencies, bins: int = 10) -> tuple[float | None, int]:
    np = dependencies["np"]
    quantiles = np.linspace(0, 1, bins + 1)
    edges = np.unique(np.quantile(source, quantiles))
    if len(edges) < 3:
        return None, max(0, len(edges) - 1)
    edges = edges.astype(float)
    edges[0] = -np.inf
    edges[-1] = np.inf
    source_counts, _ = np.histogram(source, bins=edges)
    target_counts, _ = np.histogram(target, bins=edges)
    epsilon = 1e-6
    source_share = np.maximum(source_counts / source_counts.sum(), epsilon)
    target_share = np.maximum(target_counts / target_counts.sum(), epsilon)
    value = np.sum((target_share - source_share) * np.log(target_share / source_share))
    return float(value), len(edges) - 1


def _severity(psi: float | None) -> str:
    if psi is None:
        return "undetermined"
    if psi < 0.10:
        return "low"
    if psi < 0.25:
        return "moderate"
    return "high"


def _feature_drift(
    source_frame,
    target_frame,
    source_missing_rates: dict,
    target_missing_rates: dict,
    dependencies,
) -> list[dict]:
    results = []
    for feature in SHARED_FLOW_FEATURES:
        source = source_frame[feature].dropna().to_numpy(dtype=float)
        target = target_frame[feature].dropna().to_numpy(dtype=float)
        if len(source) < 2 or len(target) < 2:
            raise ValueError(f"Not enough finite values to analyze feature: {feature}")
        psi, effective_bins = _psi(source, target, dependencies)
        ks_result = dependencies["ks_2samp"](source, target, method="asymp")
        source_q25, source_median, source_q75 = dependencies["np"].quantile(
            source, [0.25, 0.5, 0.75]
        )
        target_median = float(dependencies["np"].median(target))
        source_iqr = float(source_q75 - source_q25)
        standardized_median_shift = (
            (target_median - float(source_median)) / source_iqr if source_iqr > 0 else None
        )
        results.append(
            {
                "feature": feature,
                "psi": psi,
                "psi_effective_bins": effective_bins,
                "severity": _severity(psi),
                "ks_statistic": float(ks_result.statistic),
                "ks_pvalue": float(ks_result.pvalue),
                "source_median": float(source_median),
                "target_median": target_median,
                "source_iqr": source_iqr,
                "standardized_median_shift": standardized_median_shift,
                "source_missing_rate": float(source_missing_rates[feature]),
                "target_missing_rate": float(target_missing_rates[feature]),
            }
        )
    return sorted(
        results,
        key=lambda item: (
            item["psi"] is not None,
            item["psi"] if item["psi"] is not None else -1,
        ),
        reverse=True,
    )


def analyze_domain_shift(
    unsw_train_path: str | Path,
    cic_path: str | Path,
    metrics_path: str | Path,
    summary_path: str | Path,
    sample_rows: int = 200_000,
    chunk_size: int = 100_000,
    seed: int = 42,
) -> dict:
    if sample_rows < 100:
        raise ValueError("sample_rows must be at least 100")
    if chunk_size < 1:
        raise ValueError("chunk_size must be positive")

    dependencies = _load_dependencies()
    unsw_frame = _read_dataset(unsw_train_path, dependencies)
    source_features = _unsw_shared_features(unsw_frame, dependencies)
    source_missing_rates = source_features.isna().mean().to_dict()
    source_sample = source_features.sample(
        n=min(sample_rows, len(source_features)),
        random_state=seed,
    )
    target_sample, target_rows, target_missing_rates, file_stats = _priority_sample_cic(
        _resolve_cic_files(cic_path),
        dependencies,
        sample_rows,
        chunk_size,
        seed,
    )
    features = _feature_drift(
        source_sample,
        target_sample,
        source_missing_rates,
        target_missing_rates,
        dependencies,
    )
    severity_counts = {
        severity: sum(item["severity"] == severity for item in features)
        for severity in ["high", "moderate", "low", "undetermined"]
    }
    metrics = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "experiment": "UNSW-NB15-to-CIC-IDS2017 unlabeled feature-drift analysis",
        "source_dataset": "UNSW-NB15",
        "target_dataset": "CIC-IDS2017",
        "source_rows": len(source_features),
        "target_rows": target_rows,
        "source_sample_rows": len(source_sample),
        "target_sample_rows": len(target_sample),
        "sample_method": "seeded random-priority reservoir sample",
        "random_seed": seed,
        "target_files": file_stats,
        "severity_counts": severity_counts,
        "features": features,
        "methodology": (
            "PSI bins are defined by source deciles. KS is reported as an effect-size "
            "statistic; its p-value is not treated as practical significance."
        ),
        "limitations": [
            "PSI cutoffs are heuristic rather than universal statistical laws.",
            "KS and PSI describe marginal distributions, not multivariate interactions.",
            "Target sampling is uniform but still an estimate of the full target distribution.",
            "No CIC labels are used in this analysis.",
        ],
    }
    metrics_destination = Path(metrics_path)
    metrics_destination.parent.mkdir(parents=True, exist_ok=True)
    metrics_destination.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    _save_drift_summary(metrics, summary_path)
    return metrics


def _format_number(value: float | None) -> str:
    return "N/A" if value is None else f"{value:.4f}"


def _save_drift_summary(metrics: dict, path: str | Path) -> None:
    rows = []
    for item in metrics["features"]:
        rows.append(
            f"| {item['feature']} | {_format_number(item['psi'])} | "
            f"{item['severity']} | {item['ks_statistic']:.4f} | "
            f"{_format_number(item['standardized_median_shift'])} | "
            f"{item['source_missing_rate']:.4f} | {item['target_missing_rate']:.4f} |"
        )
    counts = metrics["severity_counts"]
    content = "\n".join(
        [
            "# UNSW-NB15 -> CIC-IDS2017 feature drift",
            "",
            f"- Source rows: {metrics['source_rows']:,}",
            f"- Target rows scanned: {metrics['target_rows']:,}",
            f"- Source sample rows: {metrics['source_sample_rows']:,}",
            f"- Target sample rows: {metrics['target_sample_rows']:,}",
            f"- High-drift features: {counts['high']}",
            f"- Moderate-drift features: {counts['moderate']}",
            f"- Low-drift features: {counts['low']}",
            "",
            "| Feature | PSI | PSI severity | KS | Median shift / source IQR | Source missing | Target missing |",
            "| --- | ---: | --- | ---: | ---: | ---: | ---: |",
            *rows,
            "",
            "PSI bins use source deciles; 0.10 and 0.25 are heuristic warning levels.",
            "KS is interpreted as an effect size because large samples make p-values tiny.",
            "No CIC labels were used.",
        ]
    )
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(content + "\n", encoding="utf-8")
