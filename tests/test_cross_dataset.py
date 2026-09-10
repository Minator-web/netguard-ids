import tempfile
import unittest
from pathlib import Path

try:
    import pandas as pd
    import sklearn  # noqa: F401

    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

from netguard_ids.cross_dataset import run_cross_dataset_experiment
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


if __name__ == "__main__":
    unittest.main()
