import unittest

from netguard_ids.detector import RuleEngine
from netguard_ids.models import NetworkEvent


def event(timestamp: float, port: int, flags: str = "S", src: str = "10.0.0.9"):
    return NetworkEvent(timestamp, src, "10.0.0.2", 45000, port, "TCP", flags, 60)


class RuleEngineTests(unittest.TestCase):
    def setUp(self):
        self.rules = {
            "port_scan": {
                "enabled": True,
                "window_seconds": 10,
                "unique_ports": 4,
                "cooldown_seconds": 15,
            },
            "syn_flood": {
                "enabled": True,
                "window_seconds": 5,
                "syn_packets": 5,
                "cooldown_seconds": 10,
            },
            "sensitive_ports": {
                "enabled": True,
                "ports": [22, 3389],
                "allowlist": ["10.0.0.10"],
                "cooldown_seconds": 30,
            },
        }

    def test_detects_port_scan(self):
        engine = RuleEngine(self.rules)
        alerts = []
        for index, port in enumerate([80, 81, 82, 83]):
            alerts.extend(engine.process(event(float(index), port, flags="A")))
        self.assertEqual([alert.rule_id for alert in alerts], ["PORT_SCAN"])

    def test_detects_syn_flood(self):
        engine = RuleEngine(self.rules)
        alerts = []
        for index in range(5):
            alerts.extend(engine.process(event(index * 0.5, 443)))
        self.assertIn("SYN_FLOOD", [alert.rule_id for alert in alerts])

    def test_sensitive_port_respects_allowlist(self):
        engine = RuleEngine(self.rules)
        blocked = engine.process(event(1, 3389))
        allowed = engine.process(event(1, 3389, src="10.0.0.10"))
        self.assertIn("SENSITIVE_PORT", [alert.rule_id for alert in blocked])
        self.assertNotIn("SENSITIVE_PORT", [alert.rule_id for alert in allowed])


if __name__ == "__main__":
    unittest.main()

