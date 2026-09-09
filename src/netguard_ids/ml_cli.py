from __future__ import annotations

import argparse

from .ml import generate_demo_dataset, predict_csv, train_model


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
    except (OSError, ValueError, RuntimeError) as exc:
        raise SystemExit(f"ML command failed: {exc}") from exc
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
