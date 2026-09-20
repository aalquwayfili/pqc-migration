from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest

from analyze import CHECKS, REFERENCE, STATUSES, distribution, read_attempt, summarize, wilson


class AnalysisTest(unittest.TestCase):
    def test_paired_results_and_refusals(self):
        with tempfile.TemporaryDirectory(prefix="quantigence-synthetic-analysis-") as folder:
            paths = []
            for condition in ("baseline", "feedback"):
                for seed in (1, 2, 3, 4):
                    path = Path(folder) / f"{condition}-{seed}"
                    (path / "agent").mkdir(parents=True)
                    (path / "final").mkdir()
                    passed = seed in ({1, 2} if condition == "baseline" else {1, 3, 4})
                    build_failed = condition == "baseline" and seed == 4
                    statuses = {name: "PASS" for name in CHECKS}
                    if build_failed:
                        statuses = {"openssl-present": "PASS", "openssl-has-mldsa44": "PASS",
                                    "binary-filesigner-mldsa": "DEPMISS", "binary-filesigner-rsa": "PASS"}
                    elif not passed:
                        statuses["reject-wrong-context"] = "FAIL"
                    totals = {s.lower(): list(statuses.values()).count(s) for s in STATUSES}
                    run = {"phase": "main", "condition": condition, "seed": seed,
                           "reference_freeze": REFERENCE, "executed_actions": 1,
                           "elapsed_s": 100 * seed, "stopping_reason": "Submitted"}
                    result = {"mode": "final", "build": "failed" if build_failed else "ok",
                              "checker_exit": 3 if build_failed else 0 if passed else 1,
                              "check_ms": 50, "msg_seed": seed + 100}
                    check = {"totals": totals, "msg_seed": seed + 100,
                             "checks": [{"check": k, "status": v} for k, v in statuses.items()]}
                    if build_failed:
                        del check["msg_seed"]
                    messages = [
                        {"role": "assistant", "extra": {"actions": [{"command": "check"}]}},
                        {"role": "user", "extra": {"returncode": 0}},
                        {"role": "assistant", "extra": {"actions": []}},
                        {"role": "user", "extra": {"interrupt_type": "FormatError"}},
                    ]
                    for name, value in (("agent/run.json", run), ("final/result.json", result),
                                        ("final/check.json", check), ("agent/trajectory.json", {"messages": messages})):
                        (path / name).write_text(json.dumps(value))
                    (path / "final/src.sha256").write_text("synthetic fixture, not a real snapshot\n")
                    paths.append(path)
            rows = [read_attempt(path) for path in paths]
            report = summarize(rows, [1, 2, 3, 4])
            self.assertEqual(report["paired_counts"], {"both": 1, "baseline_only": 1, "feedback_only": 2, "neither": 0})
            self.assertEqual(report["difference_percentage_points"], 25)
            self.assertEqual(report["conditions"]["baseline"]["attempts"], 4)
            self.assertEqual(report["conditions"]["baseline"]["counts"]["build_failed"], 1)
            self.assertEqual(report["conditions"]["baseline"]["counts"]["local_pass_external_fail"], 1)
            self.assertEqual(report["conditions"]["feedback"]["counts"]["local_pass_external_fail"], 1)
            self.assertFalse(rows[3]["local_pass_external_fail"])
            self.assertEqual(rows[3]["raw_checks"]["reject-wrong-context"], "UNKNOWN")
            self.assertEqual(rows[4]["development_check_calls"], 1)
            self.assertEqual(rows[0]["development_check_calls"], 0)
            self.assertEqual(distribution([100, 200, 300, 400]), {"median": 250, "q1": 175, "q3": 325, "iqr": 150})
            self.assertEqual(distribution([5])["iqr"], 0)
            self.assertAlmostEqual(wilson(5, 10)[0], 0.236593090512564, places=12)
            self.assertAlmostEqual(wilson(0, 10)[1], 0.277532799862889, places=12)
            self.assertAlmostEqual(wilson(10, 10)[1], 1)
            for data, seeds in ((rows[:-1], [1, 2, 3, 4]), (rows + rows[:1], [1, 2, 3, 4]),
                                (rows, [1, 1, 2, 3, 4]), ([], [])):
                with self.assertRaises(ValueError):
                    summarize(data, seeds)
            path = paths[0]
            run_file = path / "agent/run.json"
            original = json.loads(run_file.read_text())
            for field, value in (("phase", "smoke"), ("invalid", True), ("reference_freeze", "different"),
                                 ("executed_actions", 2)):
                modified = deepcopy(original)
                modified[field] = value
                run_file.write_text(json.dumps(modified))
                with self.assertRaises(ValueError):
                    read_attempt(path)
            run_file.write_text(json.dumps(original))
            run_file.write_text(json.dumps({**original, "phase": "qwen38q4-main"}))
            with self.assertRaises(ValueError):
                read_attempt(path)
            self.assertTrue(read_attempt(path, "qwen38q4-main")["full_pass"])
            with self.assertRaises(ValueError):
                read_attempt(path, "smoke")
            run_file.write_text(json.dumps(original))
            for name in ("invalid.json", "infra-interrupted.json", "infra-terminated.json"):
                marker = path / "agent" / name
                marker.write_text("{}")
                with self.assertRaises(ValueError):
                    read_attempt(path)
                marker.unlink()
            check_file = path / "final/check.json"
            check = json.loads(check_file.read_text())
            result_file = path / "final/result.json"
            result = json.loads(result_file.read_text())
            for status in ("FAIL", "ERROR", "DEPMISS", "UNKNOWN"):
                modified = deepcopy(check)
                modified["checks"] = [r for r in modified["checks"] if r["check"] != "reject-wrong-context"]
                if status != "UNKNOWN":
                    modified["checks"].append({"check": "reject-wrong-context", "status": status})
                modified["totals"] = {s.lower(): sum(r["status"] == s for r in modified["checks"]) for s in STATUSES}
                check_file.write_text(json.dumps(modified))
                result_file.write_text(json.dumps({**result, "checker_exit": 1}))
                self.assertEqual(read_attempt(path)["local_pass_external_fail"], status == "FAIL")
                next(r for r in modified["checks"] if r["check"] == "app-verify-own-signature")["status"] = "FAIL"
                modified["totals"] = {s.lower(): sum(r["status"] == s for r in modified["checks"]) for s in STATUSES}
                check_file.write_text(json.dumps(modified))
                self.assertFalse(read_attempt(path)["local_pass_external_fail"])
            check_file.write_text(json.dumps(check))
            result_file.write_text(json.dumps(result))
            for seed in (None, 999):
                modified = deepcopy(check)
                if seed is None:
                    del modified["msg_seed"]
                else:
                    modified["msg_seed"] = seed
                check_file.write_text(json.dumps(modified))
                with self.assertRaises(ValueError):
                    read_attempt(path)
            check["checks"].append(check["checks"][0])
            check_file.write_text(json.dumps(check))
            with self.assertRaises(ValueError):
                read_attempt(path)
            (path / "final/result.json").write_text('{"mode":')
            with self.assertRaises(ValueError):
                read_attempt(path)


if __name__ == "__main__":
    unittest.main()
