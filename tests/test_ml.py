import tempfile
import unittest
from pathlib import Path

try:
    import pandas  # noqa: F401
    import sklearn  # noqa: F401
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

from netguard_ids.ml import generate_demo_dataset, predict_csv, train_model


@unittest.skipUnless(ML_AVAILABLE, "ML optional dependencies are not installed")
class MachineLearningTests(unittest.TestCase):
    def test_training_and_prediction_pipeline(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dataset = root / "flows.csv"
            model = root / "model.joblib"
            metrics_file = root / "metrics.json"
            predictions = root / "predictions.csv"

            generate_demo_dataset(dataset, rows_per_class=20, seed=7)
            metrics = train_model(dataset, model, metrics_file, test_size=0.25, seed=7)
            row_count = predict_csv(model, dataset, predictions)

            self.assertEqual(metrics["dataset_rows"], 60)
            self.assertEqual(set(metrics["labels"]), {"benign", "port_scan", "syn_flood"})
            self.assertGreaterEqual(metrics["macro_f1"], 0.8)
            self.assertEqual(row_count, 60)
            self.assertTrue(model.exists())
            self.assertTrue(metrics_file.exists())
            self.assertIn("predicted_label", predictions.read_text(encoding="utf-8").splitlines()[0])


if __name__ == "__main__":
    unittest.main()
