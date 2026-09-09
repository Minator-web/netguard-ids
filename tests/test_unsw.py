import tempfile
import unittest
from pathlib import Path

try:
    import pandas as pd
    import sklearn  # noqa: F401
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

from netguard_ids.unsw import UNSW_NUMERIC_FEATURES, train_unsw_model


@unittest.skipUnless(ML_AVAILABLE, "ML optional dependencies are not installed")
class UnswAdapterTests(unittest.TestCase):
    @staticmethod
    def _frame(rows: int):
        values = []
        for index in range(rows):
            attack = index % 2 == 1
            row = {
                feature: float(index + 50 if attack else index % 4)
                for feature in UNSW_NUMERIC_FEATURES
            }
            row.update({
                "proto": "tcp" if attack else "udp",
                "service": "http" if attack else "dns",
                "state": "FIN" if attack else "CON",
                "attack_cat": "Exploits" if attack else "Normal",
                "label": 1 if attack else 0,
            })
            values.append(row)
        return pd.DataFrame(values)

    def test_official_split_training_creates_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            train = root / "UNSW_NB15_training-set.csv"
            test = root / "UNSW_NB15_testing-set.csv"
            model = root / "model.joblib"
            metrics_file = root / "metrics.json"
            summary = root / "summary.md"
            self._frame(80).to_csv(train, index=False)
            self._frame(40).to_csv(test, index=False)

            metrics = train_unsw_model(train, test, model, metrics_file, summary)

            self.assertEqual(metrics["dataset"], "UNSW-NB15")
            self.assertEqual(metrics["train_rows"], 80)
            self.assertEqual(metrics["test_rows"], 40)
            self.assertEqual(metrics["labels"], ["normal", "attack"])
            self.assertGreaterEqual(metrics["macro_f1"], 0.9)
            self.assertTrue(model.exists())
            self.assertTrue(metrics_file.exists())
            self.assertIn("Confusion matrix", summary.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
