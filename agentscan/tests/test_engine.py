import unittest
from pathlib import Path
from agentscan.collect import collect_claude_code
from agentscan.engine import load_rules, evaluate

FIX = Path(__file__).parent / "fixtures"
RULES = Path(__file__).parents[1] / "agentscan" / "rules"


class TestEngine(unittest.TestCase):
    def setUp(self):
        self.rules = load_rules(RULES)

    def _ids(self, target_dir):
        t = collect_claude_code(FIX / target_dir)
        return {f.rule_id for f in evaluate(t, self.rules)}

    def test_vuln_target_trips_expected_rules(self):
        ids = self._ids("vuln_target")
        for rid in {"PERM-001", "PERM-002", "MCP-001", "MCP-002",
                    "HOOK-001", "SEC-001", "MEM-001", "PROMPT-002"}:
            self.assertIn(rid, ids, f"expected {rid} to fire on vuln_target")

    def test_clean_target_has_no_findings(self):
        self.assertEqual(self._ids("clean_target"), set())

    def test_missing_target_not_recognized(self):
        self.assertFalse(collect_claude_code(Path("/tmp/agentscan-nope-xyz")).recognized)


if __name__ == "__main__":
    unittest.main()
