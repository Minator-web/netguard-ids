from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path

from .cross_dataset import (
    SHARED_FLOW_FEATURES,
    _collect_cic_probabilities,
    _resolve_cic_files,
    _unsw_shared_features,
)
from .unsw import (
    _binary_evaluation,
    _load_dependencies,
    _read_dataset,
    _select_threshold,
    _targets,
)

PREPROCESSING_NAMES = ["standard", "robust", "quantile_normal"]


def _classifier(dependencies, seed: int):
    return dependencies["SGDClassifier"](
        loss="log_loss",
        class_weight="balanced",
        max_iter=2000,
        tol=1e-4,
        random_state=seed,
    )


def _candidate_pipelines(dependencies, seed: int, fit_rows: int) -> dict:
    return {
        "standard": dependencies["Pipeline"](
            [
                ("imputer", dependencies["SimpleImputer"](strategy="median")),
                ("scaler", dependencies["StandardScaler"]()),
                ("classifier", _classifier(dependencies, seed)),
            ]
        ),
        "robust": dependencies["Pipeline"](
            [
                ("imputer", dependencies["SimpleImputer"](strategy="median")),
                (
                    "scaler",
                    dependencies["RobustScaler"](
                        quantile_range=(10.0, 90.0),
                        unit_variance=True,
                    ),
                ),
                ("classifier", _classifier(dependencies, seed)),
            ]
        ),
        "quantile_normal": dependencies["Pipeline"](
            [
                ("imputer", dependencies["SimpleImputer"](strategy="median")),
                (
                    "scaler",
                    dependencies["QuantileTransformer"](
                        n_quantiles=min(1000, fit_rows),
                        output_distribution="normal",
                        subsample=min(100_000, fit_rows),
                        random_state=seed,
                    ),
                ),
                ("classifier", _classifier(dependencies, seed)),
            ]
        ),
    }


def _validate_parameters(target_fpr, validation_size, chunk_size, max_cic_rows):
    if not 0 < target_fpr < 1:
        raise ValueError("target_fpr must be between 0 and 1")
    if not 0.1 <= validation_size <= 0.4:
        raise ValueError("validation_size must be between 0.1 and 0.4")
    if chunk_size < 1:
        raise ValueError("chunk_size must be positive")
    if max_cic_rows is not None and max_cic_rows < 2:
        raise ValueError("max_cic_rows must be at least 2")


def compare_source_only_preprocessing(
    unsw_train_path: str | Path,
    cic_path: str | Path,
    models_path: str | Path,
    metrics_path: str | Path,
    summary_path: str | Path,
    target_fpr: float = 0.10,
    validation_size: float = 0.20,
    seed: int = 42,
    chunk_size: int = 100_000,
    max_cic_rows: int | None = None,
) -> dict:
    """Select preprocessing on UNSW validation, then evaluate unchanged on CIC."""
    _validate_parameters(target_fpr, validation_size, chunk_size, max_cic_rows)
    dependencies = _load_dependencies()
    unsw_frame = _read_dataset(unsw_train_path, dependencies)
    unsw_targets = _targets(unsw_frame, "binary")
    fit_frame, validation_frame, fit_targets, validation_targets = dependencies[
        "train_test_split"
    ](
        unsw_frame,
        unsw_targets,
        test_size=validation_size,
        random_state=seed,
        stratify=unsw_targets,
    )
    fit_features = _unsw_shared_features(fit_frame, dependencies)
    validation_features = _unsw_shared_features(validation_frame, dependencies)
    pipelines = _candidate_pipelines(dependencies, seed, len(fit_frame))
    results = {}

    for name, pipeline in pipelines.items():
        started = time.perf_counter()
        pipeline.fit(fit_features, fit_targets)
        fit_seconds = time.perf_counter() - started
        attack_index = list(pipeline.named_steps["classifier"].classes_).index("attack")
        validation_probabilities = pipeline.predict_proba(validation_features)[:, attack_index]
        selection = _select_threshold(
            validation_targets,
            validation_probabilities,
            target_fpr,
            dependencies,
        )
        results[name] = {
            "fit_seconds": fit_seconds,
            "selected_threshold": selection["threshold"],
            "source_validation_metrics": _binary_evaluation(
                validation_targets,
                validation_probabilities,
                selection["threshold"],
                dependencies,
            ),
        }

    selected_name = max(
        PREPROCESSING_NAMES,
        key=lambda name: (
            results[name]["source_validation_metrics"]["macro_f1"],
            results[name]["source_validation_metrics"]["balanced_accuracy"],
            -results[name]["source_validation_metrics"]["false_positive_rate"],
        ),
    )

    target_labels, target_probabilities, file_stats, inference_seconds = (
        _collect_cic_probabilities(
            pipelines,
            _resolve_cic_files(cic_path),
            dependencies,
            chunk_size,
            max_cic_rows,
        )
    )
    target_rows = len(target_labels)
    for name, result in results.items():
        target_metrics = _binary_evaluation(
            target_labels,
            target_probabilities[name],
            result["selected_threshold"],
            dependencies,
        )
        source_metrics = result["source_validation_metrics"]
        result["target_test_metrics"] = target_metrics
        result["target_inference_seconds"] = inference_seconds[name]
        result["target_rows_per_second"] = (
            target_rows / inference_seconds[name] if inference_seconds[name] > 0 else None
        )
        result["generalization_gap"] = {
            "macro_f1": target_metrics["macro_f1"] - source_metrics["macro_f1"],
            "balanced_accuracy": (
                target_metrics["balanced_accuracy"] - source_metrics["balanced_accuracy"]
            ),
            "false_positive_rate": (
                target_metrics["false_positive_rate"]
                - source_metrics["false_positive_rate"]
            ),
        }

    metrics = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "experiment": "source-only preprocessing robustness evaluation",
        "source_dataset": "UNSW-NB15",
        "target_dataset": "CIC-IDS2017",
        "fit_rows": len(fit_frame),
        "source_validation_rows": len(validation_frame),
        "target_test_rows": target_rows,
        "target_files": file_stats,
        "shared_features": SHARED_FLOW_FEATURES,
        "preprocessing_candidates": results,
        "selected_on_source_validation": selected_name,
        "selection_locked_before_target_evaluation": True,
        "random_seed": seed,
        "validation_size": validation_size,
        "target_validation_fpr": target_fpr,
        "methodology": (
            "Candidate preprocessing and thresholds are compared using only UNSW-NB15 "
            "fit/validation data. The winner is locked before CIC files are read. CIC "
            "labels are used only for final descriptive evaluation."
        ),
        "selection_rule": (
            "Highest source-validation macro F1, then balanced accuracy, then lower FPR."
        ),
        "warning": (
            "CIC outcomes must not be used to revise the selected candidate. Any new "
            "choice requires confirmation on a third untouched dataset."
        ),
    }

    models_destination = Path(models_path)
    models_destination.parent.mkdir(parents=True, exist_ok=True)
    dependencies["joblib"].dump(
        {
            "pipelines": pipelines,
            "thresholds": {
                name: result["selected_threshold"] for name, result in results.items()
            },
            "selected_on_source_validation": selected_name,
            "features": SHARED_FLOW_FEATURES,
            "version": "0.9.0",
            "trained_at": metrics["generated_at"],
        },
        models_destination,
    )
    metrics_destination = Path(metrics_path)
    metrics_destination.parent.mkdir(parents=True, exist_ok=True)
    metrics_destination.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    _save_summary(metrics, summary_path)
    return metrics


def _save_summary(metrics: dict, path: str | Path) -> None:
    rows = []
    for name in PREPROCESSING_NAMES:
        result = metrics["preprocessing_candidates"][name]
        source = result["source_validation_metrics"]
        target = result["target_test_metrics"]
        selected = "yes" if name == metrics["selected_on_source_validation"] else "no"
        rows.append(
            f"| {name} | {selected} | {result['selected_threshold']:.6f} | "
            f"{source['macro_f1']:.4f} | {source['false_positive_rate']:.4f} | "
            f"{target['macro_f1']:.4f} | {target['false_positive_rate']:.4f} | "
            f"{target['false_negative_rate']:.4f} | {target['roc_auc']:.4f} |"
        )
    content = "\n".join(
        [
            "# Source-only preprocessing robustness",
            "",
            f"- UNSW fit rows: {metrics['fit_rows']:,}",
            f"- UNSW validation rows: {metrics['source_validation_rows']:,}",
            f"- CIC target-test rows: {metrics['target_test_rows']:,}",
            f"- Source-selected candidate: {metrics['selected_on_source_validation']}",
            "- Selection locked before target evaluation: yes",
            "",
            (
                "| Preprocessing | Source selected | Threshold | Source macro F1 | "
                "Source FPR | Target macro F1 | Target FPR | Target FNR | Target ROC AUC |"
            ),
            "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
            *rows,
            "",
            "The candidate and every threshold were selected using only UNSW data.",
            "CIC labels were used only for final descriptive evaluation.",
            "Do not revise the choice after seeing CIC results without a third untouched dataset.",
        ]
    )
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(content + "\n", encoding="utf-8")
