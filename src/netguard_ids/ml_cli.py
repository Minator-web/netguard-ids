from __future__ import annotations

import argparse

from .cross_dataset import benchmark_cross_dataset_models, run_cross_dataset_experiment
from .ml import generate_demo_dataset, predict_csv, train_model
from .unsw import calibrate_unsw_threshold, train_unsw_model


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="NetGuard reproducible ML pipeline")
    commands = parser.add_subparsers(dest="command", required=True)

    generate = commands.add_parser("generate-demo", help="Generate synthetic flow data")
    generate.add_argument("--output", default="data/demo_flows.csv")
    generate.add_argument("--rows-per-class", type=int, default=100)
    generate.add_argument("--seed", type=int, default=42)

    train = commands.add_parser("train", help="Train and evaluate the baseline model")
    train.add_argument("--dataset", required=True)
    train.add_argument("--model", default="artifacts/netguard-model.joblib")
    train.add_argument("--metrics", default="reports/ml-metrics.json")
    train.add_argument("--test-size", type=float, default=0.25)
    train.add_argument("--seed", type=int, default=42)

    predict = commands.add_parser("predict", help="Predict labels for flow rows")
    predict.add_argument("--model", required=True)
    predict.add_argument("--input", required=True)
    predict.add_argument("--output", default="reports/predictions.csv")

    unsw = commands.add_parser("train-unsw", help="Train on the official UNSW-NB15 split")
    unsw.add_argument("--train", default="data/UNSW_NB15_training-set.csv")
    unsw.add_argument("--test", default="data/UNSW_NB15_testing-set.csv")
    unsw.add_argument("--task", choices=["binary", "multiclass"], default="binary")
    unsw.add_argument("--model", default="artifacts/unsw-nb15-model.joblib")
    unsw.add_argument("--metrics", default="reports/unsw-nb15-metrics.json")
    unsw.add_argument("--summary", default="reports/unsw-nb15-summary.md")
    unsw.add_argument("--seed", type=int, default=42)

    calibrate = commands.add_parser(
        "calibrate-unsw",
        help="Select a binary alert threshold on validation data",
    )
    calibrate.add_argument("--train", default="data/UNSW_NB15_training-set.csv")
    calibrate.add_argument("--test", default="data/UNSW_NB15_testing-set.csv")
    calibrate.add_argument("--target-fpr", type=float, default=0.10)
    calibrate.add_argument("--validation-size", type=float, default=0.20)
    calibrate.add_argument("--model", default="artifacts/unsw-calibrated.joblib")
    calibrate.add_argument("--metrics", default="reports/unsw-calibration.json")
    calibrate.add_argument("--summary", default="reports/unsw-calibration.md")
    calibrate.add_argument("--seed", type=int, default=42)

    cross = commands.add_parser(
        "cross-dataset",
        help="Train on UNSW-NB15 and evaluate on CIC-IDS2017",
    )
    cross.add_argument("--unsw-train", default="data/UNSW_NB15_training-set.csv")
    cross.add_argument("--cic", default="data/CIC-IDS2017")
    cross.add_argument("--target-fpr", type=float, default=0.10)
    cross.add_argument("--validation-size", type=float, default=0.20)
    cross.add_argument("--chunk-size", type=int, default=100_000)
    cross.add_argument("--max-cic-rows", type=int)
    cross.add_argument("--model", default="artifacts/unsw-to-cic-model.joblib")
    cross.add_argument("--metrics", default="reports/cross-dataset-metrics.json")
    cross.add_argument("--summary", default="reports/cross-dataset-summary.md")
    cross.add_argument("--seed", type=int, default=42)

    benchmark = commands.add_parser(
        "benchmark-models",
        help="Compare three models across UNSW-NB15 and CIC-IDS2017",
    )
    benchmark.add_argument("--unsw-train", default="data/UNSW_NB15_training-set.csv")
    benchmark.add_argument("--cic", default="data/CIC-IDS2017")
    benchmark.add_argument("--target-fpr", type=float, default=0.10)
    benchmark.add_argument("--validation-size", type=float, default=0.20)
    benchmark.add_argument("--chunk-size", type=int, default=100_000)
    benchmark.add_argument("--max-cic-rows", type=int)
    benchmark.add_argument("--models", default="artifacts/model-benchmark.joblib")
    benchmark.add_argument("--metrics", default="reports/model-benchmark.json")
    benchmark.add_argument("--summary", default="reports/model-benchmark.md")
    benchmark.add_argument("--seed", type=int, default=42)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        if args.command == "generate-demo":
            generate_demo_dataset(args.output, args.rows_per_class, args.seed)
            print(f"Synthetic demo dataset created: {args.output}")
            print("Warning: demo data is not valid evidence for a research claim.")
        elif args.command == "train":
            metrics = train_model(
                args.dataset,
                args.model,
                args.metrics,
                test_size=args.test_size,
                seed=args.seed,
            )
            print(f"Rows: {metrics['dataset_rows']}")
            print(f"Accuracy: {metrics['accuracy']:.4f}")
            print(f"Macro F1: {metrics['macro_f1']:.4f}")
            print(f"Model: {args.model}")
            print(f"Metrics: {args.metrics}")
        elif args.command == "predict":
            row_count = predict_csv(args.model, args.input, args.output)
            print(f"Predicted {row_count} rows: {args.output}")
        elif args.command == "train-unsw":
            metrics = train_unsw_model(
                args.train,
                args.test,
                args.model,
                args.metrics,
                args.summary,
                task=args.task,
                seed=args.seed,
            )
            print(f"UNSW-NB15 task: {metrics['task']}")
            print(f"Train rows: {metrics['train_rows']}")
            print(f"Test rows: {metrics['test_rows']}")
            print(f"Accuracy: {metrics['accuracy']:.4f}")
            print(f"Balanced accuracy: {metrics['balanced_accuracy']:.4f}")
            print(f"Macro F1: {metrics['macro_f1']:.4f}")
            if metrics["roc_auc"] is not None:
                print(f"ROC AUC: {metrics['roc_auc']:.4f}")
            if metrics["false_positive_rate"] is not None:
                print(f"False-positive rate: {metrics['false_positive_rate']:.4f}")
                print(f"False-negative rate: {metrics['false_negative_rate']:.4f}")
            print(f"Model: {args.model}")
            print(f"Metrics: {args.metrics}")
            print(f"Summary: {args.summary}")
        elif args.command == "cross-dataset":
            metrics = run_cross_dataset_experiment(
                args.unsw_train,
                args.cic,
                args.model,
                args.metrics,
                args.summary,
                target_fpr=args.target_fpr,
                validation_size=args.validation_size,
                seed=args.seed,
                chunk_size=args.chunk_size,
                max_cic_rows=args.max_cic_rows,
            )
            source = metrics["source_validation_metrics"]
            target = metrics["target_test_metrics"]
            gap = metrics["generalization_gap"]
            print("Cross-dataset experiment: UNSW-NB15 -> CIC-IDS2017")
            print(f"Shared features: {len(metrics['shared_features'])}")
            print(f"CIC rows: {metrics['target_test_rows']}")
            print(f"Selected threshold: {metrics['selected_threshold']:.6f}")
            print(
                f"UNSW validation: Macro-F1={source['macro_f1']:.4f} "
                f"FPR={source['false_positive_rate']:.4f}"
            )
            print(
                f"CIC target test: Macro-F1={target['macro_f1']:.4f} "
                f"FPR={target['false_positive_rate']:.4f}"
            )
            print(f"Macro-F1 generalization gap: {gap['macro_f1']:+.4f}")
            print(f"Model: {args.model}")
            print(f"Metrics: {args.metrics}")
            print(f"Summary: {args.summary}")
        elif args.command == "benchmark-models":
            metrics = benchmark_cross_dataset_models(
                args.unsw_train,
                args.cic,
                args.models,
                args.metrics,
                args.summary,
                target_fpr=args.target_fpr,
                validation_size=args.validation_size,
                seed=args.seed,
                chunk_size=args.chunk_size,
                max_cic_rows=args.max_cic_rows,
            )
            print("Model benchmark: UNSW-NB15 -> CIC-IDS2017")
            print(f"CIC rows: {metrics['target_test_rows']}")
            for name, result in metrics["models"].items():
                source = result["source_validation_metrics"]
                target = result["target_test_metrics"]
                print(
                    f"{name}: source-F1={source['macro_f1']:.4f} "
                    f"target-F1={target['macro_f1']:.4f} "
                    f"target-FPR={target['false_positive_rate']:.4f} "
                    f"target-AUC={target['roc_auc']:.4f}"
                )
            print(f"Models: {args.models}")
            print(f"Metrics: {args.metrics}")
            print(f"Summary: {args.summary}")
        elif args.command == "calibrate-unsw":
            metrics = calibrate_unsw_threshold(
                args.train,
                args.test,
                args.model,
                args.metrics,
                args.summary,
                target_fpr=args.target_fpr,
                validation_size=args.validation_size,
                seed=args.seed,
            )
            default = metrics["default_test_metrics"]
            calibrated = metrics["calibrated_test_metrics"]
            print(f"Target validation FPR: {metrics['target_validation_fpr']:.4f}")
            print(f"Selected threshold: {metrics['selected_threshold']:.6f}")
            print(f"Achieved validation FPR: {metrics['achieved_validation_fpr']:.4f}")
            print(f"Achieved validation recall: {metrics['achieved_validation_recall']:.4f}")
            print("Official test comparison:")
            print(
                f"  Default    FPR={default['false_positive_rate']:.4f} "
                f"FNR={default['false_negative_rate']:.4f} "
                f"Macro-F1={default['macro_f1']:.4f}"
            )
            print(
                f"  Calibrated FPR={calibrated['false_positive_rate']:.4f} "
                f"FNR={calibrated['false_negative_rate']:.4f} "
                f"Macro-F1={calibrated['macro_f1']:.4f}"
            )
            print(f"Model: {args.model}")
            print(f"Metrics: {args.metrics}")
            print(f"Summary: {args.summary}")
    except (OSError, ValueError, RuntimeError) as exc:
        raise SystemExit(f"ML command failed: {exc}") from exc
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
