import unittest

from netguard_ids.dashboard import build_dashboard


class DashboardTests(unittest.TestCase):
    def test_dashboard_contains_summary_and_escaped_alert(self):
        report = {
            "generated_at": "2026-09-09T12:00:00+00:00",
            "processed_events": 12,
            "alert_count": 1,
            "alerts_by_severity": {"high": 1},
            "alerts": [{
                "severity": "high",
                "rule_id": "PORT_SCAN",
                "src_ip": "10.0.0.1",
                "dst_ip": "10.0.0.2",
                "description": "Attempt <blocked>",
                "timestamp_iso": "2026-09-09T12:00:00+00:00",
            }],
        }
        html = build_dashboard(report)
        self.assertIn("NetGuard IDS", html)
        self.assertIn(">12<", html)
        self.assertIn("PORT_SCAN", html)
        self.assertIn("Attempt &lt;blocked&gt;", html)
        self.assertNotIn("Attempt <blocked>", html)


if __name__ == "__main__":
    unittest.main()
