from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

from .unsw import (
    _binary_evaluation,
    _load_dependencies,
    _read_dataset,
    _select_threshold,
    _targets,
)

SHARED_FLOW_FEATURES = [
    "duration_seconds",
    "forward_packets",
    "backward_packets",
    "forward_bytes",
    "backward_bytes",
    "packets_per_second",
    "forward_bytes_per_second",
    "backward_bytes_per_second",
    "forward_iat_mean_ms",
    "backward_iat_mean_ms",
]

CIC_COLUMN_ALIASES = {
    "flow_duration": ["flow_duration"],
    "forward_packets": ["total_fwd_packets", "tot_fwd_pkts"],
    "backward_packets": ["total_backward_packets", "tot_bwd_pkts"],
    "forward_bytes": ["total_length_of_fwd_packets", "totlen_fwd_pkts"],
    "backward_bytes": ["total_length_of_bwd_packets", "totlen_bwd_pkts"],
    "forward_iat_mean": ["fwd_iat_mean"],
    "backward_iat_mean": ["bwd_iat_mean"],
    "label": ["label"],
}


def _normalize_column(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(name).strip().lower()).strip("_")


def _shared_pipeline(dependencies, seed: int):
    return dependencies["Pipeline"](
        [
            ("imputer", dependencies["SimpleImputer"](strategy="median")),
            ("scaler", dependencies["StandardScaler"]()),
            (
                "classifier",
                dependencies["SGDClassifier"](
                    loss="log_loss",
                    class_weight="balanced",
                    max_iter=2000,
                    tol=1e-4,
                    random_state=seed,
                ),
            ),
        ]
    )


def _safe_rate(numerator, duration, dependencies):
    result = numerator / duration.mask(duration <= 0)
    return result.replace(
        [dependencies["np"].inf, -dependencies["np"].inf],
        dependencies["np"].nan,
    )


def _unsw_shared_features(frame, dependencies):
    pd = dependencies["pd"]
    numeric = frame.copy()
    for column in [
        "dur",
        "spkts",
        "dpkts",
        "sbytes",
        "dbytes",
        "sinpkt",
        "dinpkt",
    ]:
        numeric[column] = pd.to_numeric(numeric[column], errors="coerce")
    duration = numeric["dur"]
    result = pd.DataFrame(
        {
            "duration_seconds": duration,
            "forward_packets": numeric["spkts"],
            "backward_packets": numeric["dpkts"],
            "forward_bytes": numeric["sbytes"],
            "backward_bytes": numeric["dbytes"],
            "packets_per_second": _safe_rate(
                numeric["spkts"] + numeric["dpkts"], duration, dependencies
            ),
            "forward_bytes_per_second": _safe_rate(numeric["sbytes"], duration, dependencies),
            "backward_bytes_per_second": _safe_rate(numeric["dbytes"], duration, dependencies),
            "forward_iat_mean_ms": numeric["sinpkt"],
            "backward_iat_mean_ms": numeric["dinpkt"],
        }
    )
    return result[SHARED_FLOW_FEATURES].replace(
        [dependencies["np"].inf, -dependencies["np"].inf],
        dependencies["np"].nan,
    )


def _resolve_cic_files(path: str | Path) -> list[Path]:
    source = Path(path)
    if source.is_file():
        return [source]
    if source.is_dir():
        files = sorted(source.rglob("*.csv"))
        if files:
            return files
        raise ValueError(f"No CSV files found in CIC directory: {source}")
    raise ValueError(f"CIC path does not exist: {source}")


def _resolve_cic_columns(path: Path, dependencies) -> dict[str, str]:
    header = dependencies["pd"].read_csv(path, nrows=0)
    normalized = {_normalize_column(column): column for column in header.columns}
    resolved = {}
    for canonical, aliases in CIC_COLUMN_ALIASES.items():
        match = next((normalized[alias] for alias in aliases if alias in normalized), None)
        if match is None:
            raise ValueError(
                f"{path.name} is not a supported CIC-IDS2017 CSV; missing column for {canonical}"
            )
        resolved[canonical] = match
    return resolved


def _cic_shared_features(frame, columns: dict[str, str], dependencies):
    pd = dependencies["pd"]
    values = {
        name: pd.to_numeric(frame[column], errors="coerce")
        for name, column in columns.items()
        if name != "label"
    }
    duration_seconds = values["flow_duration"] / 1_000_000.0
    result = pd.DataFrame(
        {
            "duration_seconds": duration_seconds,
            "forward_packets": values["forward_packets"],
            "backward_packets": values["backward_packets"],
            "forward_bytes": values["forward_bytes"],
            "backward_bytes": values["backward_bytes"],
            "packets_per_second": _safe_rate(
                values["forward_packets"] + values["backward_packets"],
                duration_seconds,
                dependencies,
            ),
            "forward_bytes_per_second": _safe_rate(
                values["forward_bytes"], duration_seconds, dependencies
            ),
            "backward_bytes_per_second": _safe_rate(
                values["backward_bytes"], duration_seconds, dependencies
            ),
            "forward_iat_mean_ms": values["forward_iat_mean"] / 1_000.0,
            "backward_iat_mean_ms": values["backward_iat_mean"] / 1_000.0,
        }
    )
    return result[SHARED_FLOW_FEATURES].replace(
        [dependencies["np"].inf, -dependencies["np"].inf],
        dependencies["np"].nan,
    )


def _evaluate_cic_files(
    pipeline,
    cic_files: list[Path],
    threshold: float,
    dependencies,
    chunk_size: int,
    max_rows: int | None,
) -> tuple[dict, list[dict]]:
    probabilities = []
    targets = []
    file_stats = []
    rows_remaining = max_rows
    attack_index = list(pipeline.named_steps["classifier"].classes_).index("attack")

    for path in cic_files:
        if rows_remaining is not None and rows_remaining <= 0:
            break
        columns = _resolve_cic_columns(path, dependencies)
        rows = 0
        benign_rows = 0
        attack_rows = 0
        reader = dependencies["pd"].read_csv(
            path,
            usecols=list(columns.values()),
            chunksize=chunk_size,
            low_memory=False,
        )
        for chunk in reader:
            if rows_remaining is not None and len(chunk) > rows_remaining:
                chunk = chunk.iloc[:rows_remaining]
            labels = chunk[columns["label"]].fillna("").astype(str).str.strip().str.upper()
            chunk_targets = dependencies["np"].where(labels.eq("BENIGN"), "normal", "attack")
            features = _cic_shared_features(chunk, columns, dependencies)
            chunk_probabilities = pipeline.predict_proba(features)[:, attack_index]
            probabilities.append(chunk_probabilities)
            targets.append(chunk_targets)
            rows += len(chunk)
            benign_rows += int((chunk_targets == "normal").sum())
            attack_rows += int((chunk_targets == "attack").sum())
            if rows_remaining is not None:
                rows_remaining -= len(chunk)
                if rows_remaining <= 0:
                    break
        file_stats.append(
            {
                "file": path.name,
                "rows": rows,
                "benign_rows": benign_rows,
                "attack_rows": attack_rows,
            }
        )

    if not probabilities:
        raise ValueError("No CIC-IDS2017 rows were loaded")
    all_probabilities = dependencies["np"].concatenate(probabilities)
    all_targets = dependencies["np"].concatenate(targets)
    if len(set(all_targets)) < 2:
        raise ValueError("CIC evaluation requires both BENIGN and attack rows")
    return (
        _binary_evaluation(all_targets, all_probabilities, threshold, dependencies),
        file_stats,
    )


def run_cross_dataset_experiment(
    unsw_train_path: str | Path,
    cic_path: str | Path,
    model_path: str | Path,
    metrics_path: str | Path,
    summary_path: str | Path,
    target_fpr: float = 0.10,
    validation_size: float = 0.20,
    seed: int = 42,
    chunk_size: int = 100_000,
    max_cic_rows: int | None = None,
) -> dict:
    if not 0 < target_fpr < 1:
        raise ValueError("target_fpr must be between 0 and 1")
    if not 0.1 <= validation_size <= 0.4:
        raise ValueError("validation_size must be between 0.1 and 0.4")
    if chunk_size < 1:
        raise ValueError("chunk_size must be positive")
    if max_cic_rows is not None and max_cic_rows < 2:
        raise ValueError("max_cic_rows must be at least 2")

    dependencies = _load_dependencies()
    unsw_frame = _read_dataset(unsw_train_path, dependencies)
    unsw_targets = _targets(unsw_frame, "binary")
    fit_frame, validation_frame, fit_targets, validation_targets = dependencies["train_test_split"](
        unsw_frame,
        unsw_targets,
        test_size=validation_size,
        random_state=seed,
        stratify=unsw_targets,
    )
    pipeline = _shared_pipeline(dependencies, seed)
    pipeline.fit(_unsw_shared_features(fit_frame, dependencies), fit_targets)
    attack_index = list(pipeline.named_steps["classifier"].classes_).index("attack")
    validation_probabilities = pipeline.predict_proba(
        _unsw_shared_features(validation_frame, dependencies)
    )[:, attack_index]
    selection = _select_threshold(
        validation_targets, validation_probabilities, target_fpr, dependencies
    )
    source_metrics = _binary_evaluation(
        validation_targets,
        validation_probabilities,
        selection["threshold"],
        dependencies,
    )
    target_metrics, file_stats = _evaluate_cic_files(
        pipeline,
        _resolve_cic_files(cic_path),
        selection["threshold"],
        dependencies,
        chunk_size,
        max_cic_rows,
    )

    metrics = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "experiment": "UNSW-NB15-to-CIC-IDS2017 binary cross-dataset evaluation",
        "source_dataset": "UNSW-NB15",
        "target_dataset": "CIC-IDS2017",
        "unsw_train_file": Path(unsw_train_path).name,
        "fit_rows": len(fit_frame),
        "source_validation_rows": len(validation_frame),
        "target_test_rows": sum(item["rows"] for item in file_stats),
        "target_files": file_stats,
        "shared_features": SHARED_FLOW_FEATURES,
        "random_seed": seed,
        "validation_size": validation_size,
        "target_validation_fpr": target_fpr,
        "selected_threshold": selection["threshold"],
        "source_validation_metrics": source_metrics,
        "target_test_metrics": target_metrics,
        "generalization_gap": {
            "macro_f1": target_metrics["macro_f1"] - source_metrics["macro_f1"],
            "balanced_accuracy": (
                target_metrics["balanced_accuracy"] - source_metrics["balanced_accuracy"]
            ),
            "false_positive_rate": (
                target_metrics["false_positive_rate"] - source_metrics["false_positive_rate"]
            ),
        },
        "methodology": (
            "The model and threshold use only UNSW-NB15 fit/validation data. "
            "CIC-IDS2017 labels are used only for final target-domain evaluation."
        ),
        "limitations": [
            "Forward/backward flow direction is treated as source/destination direction.",
            "Only ten features with defensible mappings and harmonized units are used.",
            "Dataset collection, traffic, tools, and label definitions differ.",
            "CIC-IDS2017 is an external benchmark, not current production traffic.",
        ],
    }

    model_destination = Path(model_path)
    model_destination.parent.mkdir(parents=True, exist_ok=True)
    dependencies["joblib"].dump(
        {
            "pipeline": pipeline,
            "threshold": selection["threshold"],
            "features": SHARED_FLOW_FEATURES,
            "source_dataset": "UNSW-NB15",
            "target_dataset": "CIC-IDS2017",
            "task": "binary-cross-dataset",
            "version": "0.6.0",
            "trained_at": metrics["generated_at"],
        },
        model_destination,
    )
    metrics_destination = Path(metrics_path)
    metrics_destination.parent.mkdir(parents=True, exist_ok=True)
    metrics_destination.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    _save_cross_dataset_summary(metrics, summary_path)
    return metrics


def _save_cross_dataset_summary(metrics: dict, path: str | Path) -> None:
    source = metrics["source_validation_metrics"]
    target = metrics["target_test_metrics"]
    gap = metrics["generalization_gap"]
    content = "\n".join(
        [
            "# UNSW-NB15 -> CIC-IDS2017 cross-dataset results",
            "",
            f"- Shared features: {len(metrics['shared_features'])}",
            f"- UNSW fit rows: {metrics['fit_rows']:,}",
            f"- UNSW validation rows: {metrics['source_validation_rows']:,}",
            f"- CIC target-test rows: {metrics['target_test_rows']:,}",
            f"- Selected source-validation threshold: {metrics['selected_threshold']:.6f}",
            "",
            "| Domain | Balanced accuracy | Macro F1 | FPR | FNR | ROC AUC |",
            "| --- | ---: | ---: | ---: | ---: | ---: |",
            (
                f"| UNSW validation | {source['balanced_accuracy']:.4f} | "
                f"{source['macro_f1']:.4f} | {source['false_positive_rate']:.4f} | "
                f"{source['false_negative_rate']:.4f} | {source['roc_auc']:.4f} |"
            ),
            (
                f"| CIC target test | {target['balanced_accuracy']:.4f} | "
                f"{target['macro_f1']:.4f} | {target['false_positive_rate']:.4f} | "
                f"{target['false_negative_rate']:.4f} | {target['roc_auc']:.4f} |"
            ),
            "",
            "## Generalization gap (target minus source)",
            "",
            f"- Macro F1: {gap['macro_f1']:+.4f}",
            f"- Balanced accuracy: {gap['balanced_accuracy']:+.4f}",
            f"- False-positive rate: {gap['false_positive_rate']:+.4f}",
            "",
            "The CIC labels were not used for fitting, preprocessing, or threshold selection.",
            "Poor target-domain performance is a valid result and must not be hidden.",
        ]
    )
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(content + "\n", encoding="utf-8")
