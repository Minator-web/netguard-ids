from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import csv
import json
import random


FEATURE_COLUMNS = [
    "duration_ms",
    "packet_count",
    "total_bytes",
    "avg_packet_size",
    "syn_count",
    "ack_count",
    "unique_dst_ports",
    "dst_port",
    "protocol",
]
NUMERIC_COLUMNS = FEATURE_COLUMNS[:-1]
CATEGORICAL_COLUMNS = ["protocol"]
LABEL_COLUMN = "label"


def _load_ml_dependencies():
    try:
        import joblib
        import pandas as pd
        from sklearn.compose import ColumnTransformer
        from sklearn.linear_model import LogisticRegression
        from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score
        from sklearn.model_selection import train_test_split
        from sklearn.pipeline import Pipeline
        from sklearn.preprocessing import OneHotEncoder, StandardScaler
    except ImportError as exc:
        raise RuntimeError("ML support requires: pip install '.[ml]'") from exc
    return {
        "joblib": joblib,
        "pd": pd,
        "ColumnTransformer": ColumnTransformer,
        "LogisticRegression": LogisticRegression,
        "accuracy_score": accuracy_score,
        "classification_report": classification_report,
        "confusion_matrix": confusion_matrix,
        "f1_score": f1_score,
        "train_test_split": train_test_split,
        "Pipeline": Pipeline,
        "OneHotEncoder": OneHotEncoder,
        "StandardScaler": StandardScaler,
    }


def validate_dataset(frame, require_label: bool = True) -> None:
    required = set(FEATURE_COLUMNS)
    if require_label:
        required.add(LABEL_COLUMN)
    missing = sorted(required.difference(frame.columns))
    if missing:
        raise ValueError(f"Dataset is missing columns: {', '.join(missing)}")
    if frame.empty:
        raise ValueError("Dataset contains no rows")
    if require_label and frame[LABEL_COLUMN].nunique() < 2:
        raise ValueError("Training requires at least two label classes")


def generate_demo_dataset(path: str | Path, rows_per_class: int = 100, seed: int = 42) -> None:
    """Create deterministic synthetic flows for pipeline testing, not research claims."""
    if rows_per_class < 10:
        raise ValueError("rows_per_class must be at least 10")
    rng = random.Random(seed)
    rows: list[dict] = []
    common_ports = [53, 80, 123, 443, 587, 993]

    for _ in range(rows_per_class):
        packets = rng.randint(5, 90)
        average = rng.randint(90, 1100)
        syn = rng.randint(0, min(4, packets))
        rows.append({
            "duration_ms": rng.randint(400, 12000),
            "packet_count": packets,
            "total_bytes": packets * average,
            "avg_packet_size": average,
            "syn_count": syn,
            "ack_count": rng.randint(max(0, packets // 4), packets),
            "unique_dst_ports": rng.randint(1, 3),
            "dst_port": rng.choice(common_ports),
            "protocol": rng.choice(["TCP", "TCP", "UDP"]),
            "label": "benign",
        })

    for _ in range(rows_per_class):
        packets = rng.randint(20, 160)
        average = rng.randint(54, 180)
        rows.append({
            "duration_ms": rng.randint(150, 6000),
            "packet_count": packets,
            "total_bytes": packets * average,
            "avg_packet_size": average,
            "syn_count": rng.randint(max(8, packets // 3), packets),
            "ack_count": rng.randint(0, max(1, packets // 8)),
            "unique_dst_ports": rng.randint(8, 60),
            "dst_port": rng.randint(1, 65535),
            "protocol": "TCP",
            "label": "port_scan",
        })

    for _ in range(rows_per_class):
        packets = rng.randint(180, 1500)
        average = rng.randint(54, 90)
        rows.append({
            "duration_ms": rng.randint(100, 3500),
            "packet_count": packets,
            "total_bytes": packets * average,
            "avg_packet_size": average,
            "syn_count": rng.randint(int(packets * 0.75), packets),
            "ack_count": rng.randint(0, max(1, packets // 30)),
            "unique_dst_ports": rng.randint(1, 3),
            "dst_port": rng.choice([80, 443, 8080]),
            "protocol": "TCP",
            "label": "syn_flood",
        })

    rng.shuffle(rows)
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FEATURE_COLUMNS + [LABEL_COLUMN])
        writer.writeheader()
        writer.writerows(rows)


def train_model(
    dataset_path: str | Path,
    model_path: str | Path,
    metrics_path: str | Path,
    test_size: float = 0.25,
    seed: int = 42,
) -> dict:
    if not 0.1 <= test_size <= 0.5:
        raise ValueError("test_size must be between 0.1 and 0.5")
    ml = _load_ml_dependencies()
    pd = ml["pd"]
    frame = pd.read_csv(dataset_path)
    validate_dataset(frame)

    features = frame[FEATURE_COLUMNS]
    labels = frame[LABEL_COLUMN].astype(str)
    train_x, test_x, train_y, test_y = ml["train_test_split"](
        features,
        labels,
        test_size=test_size,
        random_state=seed,
        stratify=labels,
    )

    preprocessing = ml["ColumnTransformer"]([
        ("numeric", ml["StandardScaler"](), NUMERIC_COLUMNS),
        ("categorical", ml["OneHotEncoder"](handle_unknown="ignore"), CATEGORICAL_COLUMNS),
    ])
    pipeline = ml["Pipeline"]([
        ("preprocessing", preprocessing),
        ("classifier", ml["LogisticRegression"](
            max_iter=1500, class_weight="balanced", random_state=seed
        )),
    ])
    pipeline.fit(train_x, train_y)
    predictions = pipeline.predict(test_x)
    classes = sorted(labels.unique().tolist())
    metrics = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "dataset": str(dataset_path),
        "dataset_rows": int(len(frame)),
        "train_rows": int(len(train_x)),
        "test_rows": int(len(test_x)),
        "random_seed": seed,
        "test_size": test_size,
        "labels": classes,
        "accuracy": float(ml["accuracy_score"](test_y, predictions)),
        "macro_f1": float(ml["f1_score"](test_y, predictions, average="macro")),
        "confusion_matrix": ml["confusion_matrix"](
            test_y, predictions, labels=classes
        ).tolist(),
        "classification_report": ml["classification_report"](
            test_y, predictions, labels=classes, output_dict=True, zero_division=0
        ),
        "warning": "Synthetic demo data is only a pipeline smoke test, not a research result.",
    }

    model_destination = Path(model_path)
    model_destination.parent.mkdir(parents=True, exist_ok=True)
    ml["joblib"].dump({
        "pipeline": pipeline,
        "features": FEATURE_COLUMNS,
        "labels": classes,
        "version": "0.3.0",
        "trained_at": metrics["generated_at"],
    }, model_destination)

    metrics_destination = Path(metrics_path)
    metrics_destination.parent.mkdir(parents=True, exist_ok=True)
    metrics_destination.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    return metrics


def predict_csv(model_path: str | Path, input_path: str | Path, output_path: str | Path) -> int:
    ml = _load_ml_dependencies()
    frame = ml["pd"].read_csv(input_path)
    validate_dataset(frame, require_label=False)
    bundle = ml["joblib"].load(model_path)
    pipeline = bundle["pipeline"]
    predictions = pipeline.predict(frame[FEATURE_COLUMNS])
    probabilities = pipeline.predict_proba(frame[FEATURE_COLUMNS]).max(axis=1)
    result = frame.copy()
    result["predicted_label"] = predictions
    result["confidence"] = probabilities
    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    result.to_csv(destination, index=False)
    return int(len(result))
