from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

UNSW_NUMERIC_FEATURES = [
    "dur",
    "spkts",
    "dpkts",
    "sbytes",
    "dbytes",
    "rate",
    "sttl",
    "dttl",
    "sload",
    "dload",
    "sloss",
    "dloss",
    "sinpkt",
    "dinpkt",
    "sjit",
    "djit",
    "swin",
    "dwin",
    "tcprtt",
    "synack",
    "ackdat",
    "smean",
    "dmean",
    "trans_depth",
    "response_body_len",
    "ct_srv_src",
    "ct_state_ttl",
    "ct_dst_ltm",
    "ct_src_dport_ltm",
    "ct_dst_sport_ltm",
    "ct_dst_src_ltm",
    "is_ftp_login",
    "ct_ftp_cmd",
    "ct_flw_http_mthd",
    "ct_src_ltm",
    "ct_srv_dst",
    "is_sm_ips_ports",
]
UNSW_CATEGORICAL_FEATURES = ["proto", "service", "state"]
UNSW_FEATURES = UNSW_NUMERIC_FEATURES + UNSW_CATEGORICAL_FEATURES


def _load_dependencies():
    try:
        import joblib
        import numpy as np
        import pandas as pd
        from scipy.stats import ks_2samp
        from sklearn.compose import ColumnTransformer
        from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
        from sklearn.impute import SimpleImputer
        from sklearn.linear_model import SGDClassifier
        from sklearn.metrics import (
            accuracy_score,
            balanced_accuracy_score,
            classification_report,
            confusion_matrix,
            f1_score,
            roc_auc_score,
            roc_curve,
        )
        from sklearn.model_selection import train_test_split
        from sklearn.pipeline import Pipeline
        from sklearn.preprocessing import (
            OneHotEncoder,
            QuantileTransformer,
            RobustScaler,
            StandardScaler,
        )
    except ImportError as exc:
        raise RuntimeError("UNSW support requires: pip install '.[ml]'") from exc
    return {
        "joblib": joblib,
        "np": np,
        "pd": pd,
        "ColumnTransformer": ColumnTransformer,
        "HistGradientBoostingClassifier": HistGradientBoostingClassifier,
        "RandomForestClassifier": RandomForestClassifier,
        "SimpleImputer": SimpleImputer,
        "SGDClassifier": SGDClassifier,
        "accuracy_score": accuracy_score,
        "balanced_accuracy_score": balanced_accuracy_score,
        "classification_report": classification_report,
        "confusion_matrix": confusion_matrix,
        "f1_score": f1_score,
        "roc_auc_score": roc_auc_score,
        "roc_curve": roc_curve,
        "train_test_split": train_test_split,
        "Pipeline": Pipeline,
        "OneHotEncoder": OneHotEncoder,
        "QuantileTransformer": QuantileTransformer,
        "RobustScaler": RobustScaler,
        "StandardScaler": StandardScaler,
        "ks_2samp": ks_2samp,
    }


def _read_dataset(path: str | Path, dependencies):
    frame = dependencies["pd"].read_csv(path, low_memory=False)
    frame.columns = [str(column).strip().lower() for column in frame.columns]
    required = set(UNSW_FEATURES + ["label", "attack_cat"])
    missing = sorted(required.difference(frame.columns))
    if missing:
        raise ValueError(
            f"{Path(path).name} is not a supported UNSW-NB15 split; missing: " + ", ".join(missing)
        )
    frame = frame.replace([dependencies["np"].inf, -dependencies["np"].inf], dependencies["np"].nan)
    return frame


def _targets(frame, task: str):
    if task == "binary":
        numeric = frame["label"].astype(int)
        return numeric.map({0: "normal", 1: "attack"})
    if task == "multiclass":
        categories = frame["attack_cat"].fillna("Normal").astype(str).str.strip()
        categories = categories.mask(frame["label"].astype(int).eq(0), "Normal")
        return categories.replace("", "Normal")
    raise ValueError("task must be 'binary' or 'multiclass'")


def _label_order(train_y, test_y, task: str) -> list[str]:
    available = set(train_y.unique()).union(test_y.unique())
    if task == "binary":
        return [label for label in ["normal", "attack"] if label in available]
    return sorted(available, key=lambda label: (label.lower() != "normal", label.lower()))


def _build_pipeline(dependencies, seed: int):
    numeric_pipeline = dependencies["Pipeline"](
        [
            ("imputer", dependencies["SimpleImputer"](strategy="median")),
            ("scaler", dependencies["StandardScaler"]()),
        ]
    )
    categorical_pipeline = dependencies["Pipeline"](
        [
            ("imputer", dependencies["SimpleImputer"](strategy="most_frequent")),
            ("encoder", dependencies["OneHotEncoder"](handle_unknown="ignore")),
        ]
    )
    preprocessing = dependencies["ColumnTransformer"](
        [
            ("numeric", numeric_pipeline, UNSW_NUMERIC_FEATURES),
            ("categorical", categorical_pipeline, UNSW_CATEGORICAL_FEATURES),
        ]
    )
    return dependencies["Pipeline"](
        [
            ("preprocessing", preprocessing),
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


def _top_coefficients(pipeline, labels: list[str], limit: int = 15) -> dict[str, list[dict]]:
    preprocessing = pipeline.named_steps["preprocessing"]
    classifier = pipeline.named_steps["classifier"]
    names = preprocessing.get_feature_names_out()
    coefficients = classifier.coef_
    if len(labels) == 2 and coefficients.shape[0] == 1:
        coefficient_rows = [(classifier.classes_[1], coefficients[0])]
    else:
        coefficient_rows = list(zip(classifier.classes_, coefficients))

    result = {}
    for label, values in coefficient_rows:
        indices = sorted(range(len(values)), key=lambda index: abs(values[index]), reverse=True)[
            :limit
        ]
        result[str(label)] = [
            {"feature": str(names[index]), "coefficient": float(values[index])} for index in indices
        ]
    return result


def _false_positive_rate(confusion: list[list[int]], labels: list[str]) -> float | None:
    if labels != ["normal", "attack"]:
        return None
    true_negative = confusion[0][0]
    false_positive = confusion[0][1]
    denominator = true_negative + false_positive
    return false_positive / denominator if denominator else 0.0


def _false_negative_rate(confusion: list[list[int]], labels: list[str]) -> float | None:
    if labels != ["normal", "attack"]:
        return None
    false_negative = confusion[1][0]
    true_positive = confusion[1][1]
    denominator = false_negative + true_positive
    return false_negative / denominator if denominator else 0.0


def _binary_evaluation(targets, probabilities, threshold: float, dependencies) -> dict:
    labels = ["normal", "attack"]
    predictions = dependencies["np"].where(probabilities >= threshold, "attack", "normal")
    confusion = dependencies["confusion_matrix"](targets, predictions, labels=labels).tolist()
    return {
        "threshold": float(threshold),
        "accuracy": float(dependencies["accuracy_score"](targets, predictions)),
        "balanced_accuracy": float(dependencies["balanced_accuracy_score"](targets, predictions)),
        "macro_f1": float(dependencies["f1_score"](targets, predictions, average="macro")),
        "roc_auc": float(
            dependencies["roc_auc_score"]((targets == "attack").astype(int), probabilities)
        ),
        "false_positive_rate": _false_positive_rate(confusion, labels),
        "false_negative_rate": _false_negative_rate(confusion, labels),
        "confusion_matrix": confusion,
        "classification_report": dependencies["classification_report"](
            targets, predictions, labels=labels, output_dict=True, zero_division=0
        ),
    }


def _select_threshold(targets, probabilities, target_fpr: float, dependencies) -> dict:
    binary_targets = (targets == "attack").astype(int)
    false_positive_rates, true_positive_rates, thresholds = dependencies["roc_curve"](
        binary_targets, probabilities
    )
    candidates = [
        index
        for index, (fpr, threshold) in enumerate(zip(false_positive_rates, thresholds))
        if fpr <= target_fpr and dependencies["np"].isfinite(threshold)
    ]
    if not candidates:
        raise ValueError("No finite threshold satisfies the requested validation FPR")
    selected = max(
        candidates,
        key=lambda index: (true_positive_rates[index], -false_positive_rates[index]),
    )
    return {
        "threshold": float(thresholds[selected]),
        "validation_fpr": float(false_positive_rates[selected]),
        "validation_recall": float(true_positive_rates[selected]),
    }


def train_unsw_model(
    train_path: str | Path,
    test_path: str | Path,
    model_path: str | Path,
    metrics_path: str | Path,
    summary_path: str | Path,
    task: str = "binary",
    seed: int = 42,
) -> dict:
    dependencies = _load_dependencies()
    train_frame = _read_dataset(train_path, dependencies)
    test_frame = _read_dataset(test_path, dependencies)
    train_y = _targets(train_frame, task)
    test_y = _targets(test_frame, task)
    labels = _label_order(train_y, test_y, task)

    pipeline = _build_pipeline(dependencies, seed)
    pipeline.fit(train_frame[UNSW_FEATURES], train_y)
    predictions = pipeline.predict(test_frame[UNSW_FEATURES])
    confusion = dependencies["confusion_matrix"](test_y, predictions, labels=labels).tolist()
    report = dependencies["classification_report"](
        test_y, predictions, labels=labels, output_dict=True, zero_division=0
    )
    roc_auc = None
    if task == "binary":
        attack_index = list(pipeline.named_steps["classifier"].classes_).index("attack")
        attack_probabilities = pipeline.predict_proba(test_frame[UNSW_FEATURES])[:, attack_index]
        roc_auc = float(
            dependencies["roc_auc_score"]((test_y == "attack").astype(int), attack_probabilities)
        )

    metrics = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "dataset": "UNSW-NB15",
        "task": task,
        "train_file": Path(train_path).name,
        "test_file": Path(test_path).name,
        "train_rows": len(train_frame),
        "test_rows": len(test_frame),
        "random_seed": seed,
        "model": "class-balanced linear classifier with logistic loss (SGD)",
        "labels": labels,
        "accuracy": float(dependencies["accuracy_score"](test_y, predictions)),
        "balanced_accuracy": float(dependencies["balanced_accuracy_score"](test_y, predictions)),
        "macro_f1": float(dependencies["f1_score"](test_y, predictions, average="macro")),
        "weighted_f1": float(dependencies["f1_score"](test_y, predictions, average="weighted")),
        "roc_auc": roc_auc,
        "false_positive_rate": _false_positive_rate(confusion, labels),
        "false_negative_rate": _false_negative_rate(confusion, labels),
        "confusion_matrix": confusion,
        "classification_report": report,
        "top_coefficients": _top_coefficients(pipeline, labels),
        "limitations": [
            "Results describe the official UNSW-NB15 split and not current production traffic.",
            "Dataset-specific artifacts and distribution shift may affect measured performance.",
            "A second dataset is required before making cross-dataset generalization claims.",
        ],
    }

    model_destination = Path(model_path)
    model_destination.parent.mkdir(parents=True, exist_ok=True)
    dependencies["joblib"].dump(
        {
            "pipeline": pipeline,
            "features": UNSW_FEATURES,
            "labels": labels,
            "dataset": "UNSW-NB15",
            "task": task,
            "version": "0.5.0",
            "trained_at": metrics["generated_at"],
        },
        model_destination,
    )

    metrics_destination = Path(metrics_path)
    metrics_destination.parent.mkdir(parents=True, exist_ok=True)
    metrics_destination.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    _save_markdown_summary(metrics, summary_path)
    return metrics


def calibrate_unsw_threshold(
    train_path: str | Path,
    test_path: str | Path,
    model_path: str | Path,
    metrics_path: str | Path,
    summary_path: str | Path,
    target_fpr: float = 0.10,
    validation_size: float = 0.20,
    seed: int = 42,
) -> dict:
    if not 0 < target_fpr < 1:
        raise ValueError("target_fpr must be between 0 and 1")
    if not 0.1 <= validation_size <= 0.4:
        raise ValueError("validation_size must be between 0.1 and 0.4")

    dependencies = _load_dependencies()
    train_frame = _read_dataset(train_path, dependencies)
    test_frame = _read_dataset(test_path, dependencies)
    train_targets = _targets(train_frame, "binary")
    test_targets = _targets(test_frame, "binary")
    fit_frame, validation_frame, fit_targets, validation_targets = dependencies["train_test_split"](
        train_frame,
        train_targets,
        test_size=validation_size,
        random_state=seed,
        stratify=train_targets,
    )

    pipeline = _build_pipeline(dependencies, seed)
    pipeline.fit(fit_frame[UNSW_FEATURES], fit_targets)
    attack_index = list(pipeline.named_steps["classifier"].classes_).index("attack")
    validation_probabilities = pipeline.predict_proba(validation_frame[UNSW_FEATURES])[
        :, attack_index
    ]
    selection = _select_threshold(
        validation_targets, validation_probabilities, target_fpr, dependencies
    )

    test_probabilities = pipeline.predict_proba(test_frame[UNSW_FEATURES])[:, attack_index]
    default_metrics = _binary_evaluation(test_targets, test_probabilities, 0.5, dependencies)
    calibrated_metrics = _binary_evaluation(
        test_targets, test_probabilities, selection["threshold"], dependencies
    )
    metrics = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "dataset": "UNSW-NB15",
        "task": "binary-threshold-calibration",
        "train_file": Path(train_path).name,
        "test_file": Path(test_path).name,
        "fit_rows": len(fit_frame),
        "validation_rows": len(validation_frame),
        "test_rows": len(test_frame),
        "random_seed": seed,
        "validation_size": validation_size,
        "target_validation_fpr": target_fpr,
        "selected_threshold": selection["threshold"],
        "achieved_validation_fpr": selection["validation_fpr"],
        "achieved_validation_recall": selection["validation_recall"],
        "default_test_metrics": default_metrics,
        "calibrated_test_metrics": calibrated_metrics,
        "methodology": (
            "Threshold selected on a held-out validation subset of the official training split; "
            "the official test split is used once for final comparison."
        ),
    }

    model_destination = Path(model_path)
    model_destination.parent.mkdir(parents=True, exist_ok=True)
    dependencies["joblib"].dump(
        {
            "pipeline": pipeline,
            "threshold": selection["threshold"],
            "target_validation_fpr": target_fpr,
            "features": UNSW_FEATURES,
            "labels": ["normal", "attack"],
            "dataset": "UNSW-NB15",
            "task": "binary-threshold-calibration",
            "version": "0.5.0",
            "trained_at": metrics["generated_at"],
        },
        model_destination,
    )

    metrics_destination = Path(metrics_path)
    metrics_destination.parent.mkdir(parents=True, exist_ok=True)
    metrics_destination.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    _save_calibration_summary(metrics, summary_path)
    return metrics


def _save_calibration_summary(metrics: dict, path: str | Path) -> None:
    default = metrics["default_test_metrics"]
    calibrated = metrics["calibrated_test_metrics"]
    content = "\n".join(
        [
            "# UNSW-NB15 threshold-calibration results",
            "",
            f"- Target validation FPR: {metrics['target_validation_fpr']:.4f}",
            f"- Selected threshold: {metrics['selected_threshold']:.6f}",
            f"- Achieved validation FPR: {metrics['achieved_validation_fpr']:.4f}",
            f"- Achieved validation recall: {metrics['achieved_validation_recall']:.4f}",
            "",
            "## Untouched test-set comparison",
            "",
            "| Setting | Threshold | Macro F1 | Attack recall | FPR | FNR |",
            "| --- | ---: | ---: | ---: | ---: | ---: |",
            (
                f"| Default | {default['threshold']:.6f} | {default['macro_f1']:.4f} | "
                f"{default['classification_report']['attack']['recall']:.4f} | "
                f"{default['false_positive_rate']:.4f} | {default['false_negative_rate']:.4f} |"
            ),
            (
                f"| Calibrated | {calibrated['threshold']:.6f} | "
                f"{calibrated['macro_f1']:.4f} | "
                f"{calibrated['classification_report']['attack']['recall']:.4f} | "
                f"{calibrated['false_positive_rate']:.4f} | "
                f"{calibrated['false_negative_rate']:.4f} |"
            ),
            "",
            "The threshold was selected without consulting the official test labels.",
            "A gap between validation and test FPR is evidence of distribution shift.",
        ]
    )
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(content + "\n", encoding="utf-8")


def _save_markdown_summary(metrics: dict, path: str | Path) -> None:
    fpr = metrics["false_positive_rate"]
    fpr_text = "N/A" if fpr is None else f"{fpr:.4f}"
    fnr = metrics["false_negative_rate"]
    fnr_text = "N/A" if fnr is None else f"{fnr:.4f}"
    roc_auc = metrics["roc_auc"]
    roc_auc_text = "N/A" if roc_auc is None else f"{roc_auc:.4f}"
    labels = metrics["labels"]
    matrix_header = "| Actual \\ Predicted | " + " | ".join(labels) + " |"
    matrix_separator = "| --- | " + " | ".join("---:" for _ in labels) + " |"
    matrix_rows = [
        f"| {label} | " + " | ".join(str(value) for value in row) + " |"
        for label, row in zip(labels, metrics["confusion_matrix"])
    ]
    content = "\n".join(
        [
            "# UNSW-NB15 baseline results",
            "",
            f"- Task: `{metrics['task']}`",
            f"- Training rows: {metrics['train_rows']:,}",
            f"- Testing rows: {metrics['test_rows']:,}",
            f"- Accuracy: {metrics['accuracy']:.4f}",
            f"- Balanced accuracy: {metrics['balanced_accuracy']:.4f}",
            f"- Macro F1: {metrics['macro_f1']:.4f}",
            f"- Weighted F1: {metrics['weighted_f1']:.4f}",
            f"- ROC AUC: {roc_auc_text}",
            f"- False-positive rate: {fpr_text}",
            f"- False-negative rate: {fnr_text}",
            "",
            "## Confusion matrix",
            "",
            matrix_header,
            matrix_separator,
            *matrix_rows,
            "",
            "These results are specific to the official UNSW-NB15 split. They do not establish",
            "cross-dataset or production-network performance.",
        ]
    )
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(content + "\n", encoding="utf-8")
