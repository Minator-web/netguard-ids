import tempfile
import unittest
from pathlib import Path

try:
    import pandas as pd
    import sklearn  # noqa: F401

    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

from netguard_ids.cross_dataset import (
    MODEL_NAMES,
    benchmark_cross_dataset_models,
    run_cross_dataset_experiment,
)
from netguard_ids.drift import analyze_domain_shift
from netguard_ids.robustness import PREPROCESSING_NAMES, compare_source_only_preprocessing
from netguard_ids.unsw import UNSW_NUMERIC_FEATURES


@unittest.skipUnless(ML_AVAILABLE, "ML optional dependencies are not installed")
class CrossDatasetTests(unittest.TestCase):
    @staticmethod
    def _unsw_frame(rows: int):
        values = []
        for index in range(rows):
            attack = index % 2 == 1
            magnitude = 50.0 + index % 5 if attack else 1.0 + index % 3
            row = {feature: magnitude for feature in UNSW_NUMERIC_FEATURES}
            row.update(
                {
                    "dur": 5.0 if attack else 1.0,
                    "spkts": magnitude,
                    "dpkts": magnitude,
                    "sbytes": magnitude * 100,
                    "dbytes": magnitude * 80,
                    "rate": magnitude * 2,
                    "sinpkt": magnitude,
                    "dinpkt": magnitude,
                    "proto": "tcp",
                    "service": "http",
                    "state": "FIN",
                    "attack_cat": "Exploits" if attack else "Normal",
                    "label": 1 if attack else 0,
                }
            )
            values.append(row)
        return pd.DataFrame(values)

    @staticmethod
    def _cic_frame(rows: int):
        values = []
        for index in range(rows):
            attack = index % 2 == 1
            magnitude = 50.0 + index % 5 if attack else 1.0 + index % 3
            duration_seconds = 5.0 if attack else 1.0
            values.append(
                {
                    " Flow Duration": duration_seconds * 1_000_000,
                    " Total Fwd Packets": magnitude,
                    " Total Backward Packets": magnitude,
                    "Total Length of Fwd Packets": magnitude * 100,
                    " Total Length of Bwd Packets": magnitude * 80,
                    " Fwd IAT Mean": magnitude * 1_000,
                    " Bwd IAT Mean": magnitude * 1_000,
                    " Label": "DoS Hulk" if attack else "BENIGN",
                }
            )
        return pd.DataFrame(values)

    def test_unsw_to_cic_pipeline_creates_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            unsw = root / "UNSW_NB15_training-set.csv"
            cic_directory = root / "CIC-IDS2017"
            extracted_directory = cic_directory / "MachineLearningCVE"
            extracted_directory.mkdir(parents=True)
            cic = extracted_directory / "Wednesday-WorkingHours.csv"
            model = root / "cross-model.joblib"
            metrics_file = root / "cross-metrics.json"
            summary = root / "cross-summary.md"
            self._unsw_frame(100).to_csv(unsw, index=False)
            self._cic_frame(40).to_csv(cic, index=False)

            metrics = run_cross_dataset_experiment(
                unsw,
                cic_directory,
                model,
                metrics_file,
                summary,
                chunk_size=11,
            )

            self.assertEqual(metrics["source_dataset"], "UNSW-NB15")
            self.assertEqual(metrics["target_dataset"], "CIC-IDS2017")
            self.assertEqual(metrics["target_test_rows"], 40)
            self.assertEqual(len(metrics["shared_features"]), 10)
            self.assertGreater(metrics["target_test_metrics"]["macro_f1"], 0.9)
            self.assertTrue(model.exists())
            self.assertTrue(metrics_file.exists())
            self.assertIn(
                "Generalization gap",
                summary.read_text(encoding="utf-8"),
            )

    def test_three_model_benchmark_uses_same_target_rows(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            unsw = root / "UNSW_NB15_training-set.csv"
            cic = root / "CIC.csv"
            models = root / "models.joblib"
            metrics_file = root / "metrics.json"
            summary = root / "summary.md"
            self._unsw_frame(120).to_csv(unsw, index=False)
            self._cic_frame(50).to_csv(cic, index=False)

            metrics = benchmark_cross_dataset_models(
                unsw,
                cic,
                models,
                metrics_file,
                summary,
                chunk_size=13,
            )

            self.assertEqual(list(metrics["models"]), MODEL_NAMES)
            self.assertEqual(metrics["target_test_rows"], 50)
            for result in metrics["models"].values():
                self.assertIn("source_validation_metrics", result)
                self.assertIn("target_test_metrics", result)
                self.assertGreater(result["target_rows_per_second"], 0)
            self.assertTrue(models.exists())
            self.assertTrue(metrics_file.exists())
            self.assertIn("random_forest", summary.read_text(encoding="utf-8"))

    def test_domain_shift_analysis_detects_changed_features(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            unsw = root / "UNSW_NB15_training-set.csv"
            cic = root / "CIC.csv"
            metrics_file = root / "drift.json"
            summary = root / "drift.md"
            self._unsw_frame(140).to_csv(unsw, index=False)
            cic_frame = self._cic_frame(140)
            cic_frame[" Total Fwd Packets"] *= 1_000
            cic_frame.to_csv(cic, index=False)

            metrics = analyze_domain_shift(
                unsw,
                cic,
                metrics_file,
                summary,
                sample_rows=100,
                chunk_size=31,
            )

            self.assertEqual(metrics["target_rows"], 140)
            self.assertEqual(metrics["target_sample_rows"], 100)
            self.assertEqual(len(metrics["features"]), 10)
            self.assertGreaterEqual(metrics["severity_counts"]["high"], 1)
            forward = next(
                item for item in metrics["features"] if item["feature"] == "forward_packets"
            )
            self.assertEqual(forward["severity"], "high")
            self.assertTrue(metrics_file.exists())
            self.assertIn("No CIC labels were used", summary.read_text(encoding="utf-8"))

    def test_source_only_preprocessing_selection_is_recorded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            unsw = root / "UNSW_NB15_training-set.csv"
            cic = root / "CIC.csv"
            models = root / "robust.joblib"
            metrics_file = root / "robust.json"
            summary = root / "robust.md"
            self._unsw_frame(140).to_csv(unsw, index=False)
            self._cic_frame(60).to_csv(cic, index=False)

            metrics = compare_source_only_preprocessing(
                unsw,
                cic,
                models,
                metrics_file,
                summary,
                chunk_size=17,
            )

            self.assertEqual(metrics["target_test_rows"], 60)
            self.assertIn(metrics["selected_on_source_validation"], PREPROCESSING_NAMES)
            self.assertTrue(metrics["selection_locked_before_target_evaluation"])
            self.assertEqual(
                list(metrics["preprocessing_candidates"]), PREPROCESSING_NAMES
            )
            self.assertTrue(models.exists())
            self.assertTrue(metrics_file.exists())
            self.assertIn(
                "Selection locked before target evaluation: yes",
                summary.read_text(encoding="utf-8"),
            )


if __name__ == "__main__":
    unittest.main()
