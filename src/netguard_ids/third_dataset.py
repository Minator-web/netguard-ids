from __future__ import annotations

import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path

from .cross_dataset import SHARED_FLOW_FEATURES, _safe_rate
from .unsw import _binary_evaluation, _load_dependencies

TON_COLUMN_ALIASES = {
    "duration": ["duration", "dur"],
    "source_packets": ["src_pkts", "source_packets"],
    "destination_packets": ["dst_pkts", "destination_packets"],
    "source_bytes": ["src_bytes", "source_bytes"],
    "destination_bytes": ["dst_bytes", "destination_bytes"],
    "label": ["label"],
}

TON_DIRECT_FEATURES = [
    "duration_seconds",
    "forward_packets",
    "backward_packets",
    "forward_bytes",
    "backward_bytes",
]
TON_DERIVED_FEATURES = [
    "packets_per_second",
    "forward_bytes_per_second",
    "backward_bytes_per_second",
]
TON_UNAVAILABLE_FEATURES = ["forward_iat_mean_ms", "backward_iat_mean_ms"]


def _normalize_column(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(name).strip().lower()).strip("_")


def _resolve_ton_files(path: str | Path) -> list[Path]:
    source = Path(path)
    if source.is_file():
        return [source]
    if source.is_dir():
        files = sorted(source.rglob("*.csv"))
        if files:
            return files
        raise ValueError(f"No CSV files found in ToN-IoT directory: {source}")
    raise ValueError(f"ToN-IoT path does not exist: {source}")


def _resolve_ton_columns(path: Path, dependencies) -> dict[str, str]:
    header = dependencies["pd"].read_csv(path, nrows=0)
    normalized = {_normalize_column(column): column for column in header.columns}
    resolved = {}
    for canonical, aliases in TON_COLUMN_ALIASES.items():
        match = next((normalized[alias] for alias in aliases if alias in normalized), None)
        if match is None:
            raise ValueError(
                f"{path.name} is not a supported ToN-IoT network CSV; "
                f"missing column for {canonical}"
            )
        resolved[canonical] = match
    return resolved


def _ton_shared_features(frame, columns: dict[str, str], dependencies):
    pd = dependencies["pd"]
    values = {
        name: pd.to_numeric(frame[column], errors="coerce")
        for name, column in columns.items()
        if name != "label"
    }
    duration = values["duration"]
    result = pd.DataFrame(
        {
            "duration_seconds": duration,
            "forward_packets": values["source_packets"],
            "backward_packets": values["destination_packets"],
            "forward_bytes": values["source_bytes"],
            "backward_bytes": values["destination_bytes"],
            "packets_per_second": _safe_rate(
                values["source_packets"] + values["destination_packets"],
                duration,
                dependencies,
            ),
            "forward_bytes_per_second": _safe_rate(
                values["source_bytes"], duration, dependencies
            ),
            "backward_bytes_per_second": _safe_rate(
                values["destination_bytes"], duration, dependencies
            ),
            "forward_iat_mean_ms": dependencies["np"].nan,
            "backward_iat_mean_ms": dependencies["np"].nan,
        },
        index=frame.index,
    )
    return result[SHARED_FLOW_FEATURES].replace(
        [dependencies["np"].inf, -dependencies["np"].inf],
        dependencies["np"].nan,
    )


def _load_locked_models(path: str | Path, dependencies) -> tuple[dict, dict, str]:
    artifact = dependencies["joblib"].load(path)
    pipelines = artifact.get("pipelines")
    thresholds = artifact.get("thresholds")
    selected = artifact.get("selected_on_source_validation")
    if not isinstance(pipelines, dict) or not isinstance(thresholds, dict):
        raise ValueError("Model artifact does not contain locked preprocessing pipelines")
    if selected not in pipelines or selected not in thresholds:
        raise ValueError("Model artifact does not contain a valid source-selected pipeline")
    names = ["standard"] if selected == "standard" else ["standard", selected]
    for name in names:
        if name not in pipelines or name not in thresholds:
            raise ValueError(f"Model artifact is missing required pipeline: {name}")
    return ({name: pipelines[name] for name in names}, thresholds, selected)


def evaluate_locked_on_ton(
    model_path: str | Path,
    ton_path: str | Path,
    metrics_path: str | Path,
    summary_path: str | Path,
    chunk_size: int = 100_000,
    max_rows: int | None = None,
) -> dict:
    """Evaluate the pre-registered baseline and source-selected pipeline on ToN-IoT."""
    if chunk_size < 1:
        raise ValueError("chunk_size must be positive")
    if max_rows is not None and max_rows < 2:
        raise ValueError("max_rows must be at least 2")

    dependencies = _load_dependencies()
    pipelines, thresholds, selected = _load_locked_models(model_path, dependencies)
    probabilities = {name: [] for name in pipelines}
    targets = []
    file_stats = []
    inference_seconds = {name: 0.0 for name in pipelines}
    attack_indices = {
        name: list(pipeline.named_steps["classifier"].classes_).index("attack")
        for name, pipeline in pipelines.items()
    }
    rows_remaining = max_rows

    for path in _resolve_ton_files(ton_path):
        if rows_remaining is not None and rows_remaining <= 0:
            break
        columns = _resolve_ton_columns(path, dependencies)
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
            numeric_labels = dependencies["pd"].to_numeric(
                chunk[columns["label"]], errors="coerce"
            )
            if numeric_labels.isna().any() or not set(numeric_labels.unique()).issubset({0, 1}):
                raise ValueError(f"{path.name} label must contain only binary 0/1 values")
            chunk_targets = dependencies["np"].where(
                numeric_labels.eq(0), "normal", "attack"
            )
            features = _ton_shared_features(chunk, columns, dependencies)
            for name, pipeline in pipelines.items():
                started = time.perf_counter()
                values = pipeline.predict_proba(features)[:, attack_indices[name]]
                inference_seconds[name] += time.perf_counter() - started
                probabilities[name].append(values)
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

    if not targets:
        raise ValueError("No ToN-IoT rows were loaded")
    all_targets = dependencies["np"].concatenate(targets)
    if len(set(all_targets)) < 2:
        raise ValueError("ToN-IoT evaluation requires both normal and attack rows")

    results = {}
    target_rows = len(all_targets)
    for name in pipelines:
        all_probabilities = dependencies["np"].concatenate(probabilities[name])
        results[name] = {
            "threshold": thresholds[name],
            "metrics": _binary_evaluation(
                all_targets,
                all_probabilities,
                thresholds[name],
                dependencies,
            ),
            "inference_seconds": inference_seconds[name],
            "rows_per_second": (
                target_rows / inference_seconds[name]
                if inference_seconds[name] > 0
                else None
            ),
        }

    standard = results["standard"]["metrics"]
    selected_metrics = results[selected]["metrics"]
    metrics = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "experiment": "locked third-dataset evaluation on ToN-IoT Network",
        "target_dataset": "ToN-IoT Network",
        "target_rows": target_rows,
        "target_files": file_stats,
        "locked_model_artifact": Path(model_path).name,
        "source_selected_pipeline": selected,
        "evaluated_pipelines": list(pipelines),
        "results": results,
        "selected_minus_standard": {
            "macro_f1": selected_metrics["macro_f1"] - standard["macro_f1"],
            "balanced_accuracy": (
                selected_metrics["balanced_accuracy"] - standard["balanced_accuracy"]
            ),
            "false_positive_rate": (
                selected_metrics["false_positive_rate"] - standard["false_positive_rate"]
            ),
            "false_negative_rate": (
                selected_metrics["false_negative_rate"] - standard["false_negative_rate"]
            ),
            "roc_auc": selected_metrics["roc_auc"] - standard["roc_auc"],
        },
        "direct_features": TON_DIRECT_FEATURES,
        "derived_features": TON_DERIVED_FEATURES,
        "unavailable_features_imputed_from_source": TON_UNAVAILABLE_FEATURES,
        "model_or_threshold_fitting_on_ton": False,
        "methodology": (
            "The standard baseline and source-selected pipeline are loaded unchanged "
            "from the NetGuard 0.9 artifact. No model, transformer, feature choice, or "
            "threshold is fitted or selected using ToN-IoT. Labels are used only for "
            "this final evaluation."
        ),
        "limitations": [
            "Source/destination are treated as forward/backward flow direction.",
            "ToN-IoT does not provide the two mapped IAT means; source-fitted imputers are used.",
            "Only eight of ten shared features are directly available or derivable.",
            "Dataset traffic, collection tooling, and label definitions differ.",
        ],
    }
    destination = Path(metrics_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    _save_summary(metrics, summary_path)
    return metrics


def _save_summary(metrics: dict, path: str | Path) -> None:
    rows = []
    for name in metrics["evaluated_pipelines"]:
        result = metrics["results"][name]
        values = result["metrics"]
        role = "source-selected" if name == metrics["source_selected_pipeline"] else "baseline"
        rows.append(
            f"| {name} | {role} | {result['threshold']:.6f} | "
            f"{values['balanced_accuracy']:.4f} | {values['macro_f1']:.4f} | "
            f"{values['false_positive_rate']:.4f} | "
            f"{values['false_negative_rate']:.4f} | {values['roc_auc']:.4f} |"
        )
    gap = metrics["selected_minus_standard"]
    content = "\n".join(
        [
            "# Locked third-dataset evaluation: ToN-IoT Network",
            "",
            f"- Target rows: {metrics['target_rows']:,}",
            f"- Source-selected pipeline: {metrics['source_selected_pipeline']}",
            f"- Direct features: {len(metrics['direct_features'])}",
            f"- Derived features: {len(metrics['derived_features'])}",
            (
                "- Source-imputed unavailable features: "
                f"{len(metrics['unavailable_features_imputed_from_source'])}"
            ),
            "- Model or threshold fitting on ToN-IoT: no",
            "",
            (
                "| Pipeline | Role | Threshold | Balanced accuracy | "
                "Macro F1 | FPR | FNR | ROC AUC |"
            ),
            "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |",
            *rows,
            "",
            "## Source-selected minus standard",
            "",
            f"- Macro F1: {gap['macro_f1']:+.4f}",
            f"- Balanced accuracy: {gap['balanced_accuracy']:+.4f}",
            f"- False-positive rate: {gap['false_positive_rate']:+.4f}",
            f"- False-negative rate: {gap['false_negative_rate']:+.4f}",
            f"- ROC AUC: {gap['roc_auc']:+.4f}",
            "",
            "The pipelines and thresholds were loaded unchanged from the v0.9 artifact.",
            "ToN-IoT labels were used only for this final evaluation.",
            "Two unavailable IAT features were filled by the source-fitted imputers.",
        ]
    )
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(content + "\n", encoding="utf-8")
