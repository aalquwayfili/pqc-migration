import argparse
from collections import Counter
import hashlib
import json
import math
from pathlib import Path
import statistics


REFERENCE = "134aa67d9d64b29b2c8ec0b09282f5035c3033343554d70c3518df91cc60534b"
CHECKS = set("""
openssl-present openssl-has-mldsa44 binary-filesigner-mldsa binary-filesigner-rsa
app-keygen app-sign app-verify-own-signature signature-size
openssl-reads-app-private-key openssl-reads-app-public-key app-public-key-is-mldsa44
openssl-verifies-app-signature openssl-signs-with-app-key app-verifies-openssl-signature
openssl-generates-key openssl-signs-with-own-key app-verifies-foreign-key-signature
app-signs-with-openssl-key openssl-verifies-that-roundtrip reject-tampered-message
app-keygen-second-key-pair reject-wrong-key openssl-signs-wrong-context reject-wrong-context
openssl-signs-empty-context reject-empty-context reject-flipped-bit
malformed-truncated-signature malformed-overlong-signature malformed-garbage-public-key
rsa-keygen-for-wrong-algorithm-test malformed-wrong-algorithm-key sign-with-reloaded-key
verify-with-reloaded-key openssl-verifies-reloaded-key-signature
private-key-carries-matching-public-key app-accepts-crlf-public-key
app-sign-second-signature signing-is-randomized second-signature-also-verifies
""".split())
STATUSES = ("PASS", "FAIL", "DEPMISS", "ERROR")
PHASES = ("main", "qwen38q4-main", "qwen38q4-32k", "nemotron-main")
EXTERNAL_OR_REJECTION = set("""
openssl-reads-app-private-key openssl-reads-app-public-key app-public-key-is-mldsa44
openssl-verifies-app-signature openssl-signs-with-app-key app-verifies-openssl-signature
app-verifies-foreign-key-signature app-signs-with-openssl-key openssl-verifies-that-roundtrip
openssl-verifies-reloaded-key-signature private-key-carries-matching-public-key
app-accepts-crlf-public-key openssl-signs-wrong-context openssl-signs-empty-context
reject-tampered-message reject-wrong-key reject-wrong-context reject-empty-context
reject-flipped-bit malformed-truncated-signature malformed-overlong-signature
malformed-garbage-public-key malformed-wrong-algorithm-key
""".split())


def require(ok, message):
    if not ok:
        raise ValueError(message)


def wilson(k, n):
    # https://www.itl.nist.gov/div898/handbook/prc/section2/prc241.htm
    require(0 <= k <= n and n > 0, "invalid success count or denominator")
    z = statistics.NormalDist().inv_cdf(0.975)
    p, denominator = k / n, 1 + z * z / n
    center = (p + z * z / (2 * n)) / denominator
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denominator
    return [max(0.0, center - half), min(1.0, center + half)]


def distribution(values):
    q1, _, q3 = statistics.quantiles(values, n=4, method="inclusive") if len(values) > 1 else values * 3
    return {"median": statistics.median(values), "q1": q1, "q3": q3, "iqr": q3 - q1}


def read_attempt(path, phase="main"):
    require(phase in PHASES, "only counted experiment phases are supported")
    path = Path(path).resolve()
    evidence = {}

    def read(name):
        data = (path / name).read_bytes()
        evidence[name] = hashlib.sha256(data).hexdigest()
        return json.loads(data)

    run = read("agent/run.json")
    require(run.get("phase") == phase, f"{path}: expected {phase}; pilots and other configurations are excluded")
    require(not run.get("invalid") and not any((path / "agent" / name).exists() for name in
            ("invalid.json", "infra-interrupted.json", "infra-terminated.json")),
            f"{path}: infrastructure exclusions require separate review")
    require(run.get("reference_freeze") == REFERENCE, f"{path}: reference revision differs")
    require(run.get("condition") in ("baseline", "feedback"), f"{path}: unknown condition")
    require(type(run.get("seed")) is int, f"{path}: missing integer seed")
    require(bool(run.get("stopping_reason")), f"{path}: missing stopping reason")
    result = read("final/result.json")
    require(result.get("mode") == "final", f"{path}: development check used as final result")
    require(result.get("build") in ("ok", "failed"), f"{path}: unknown build status")
    require(type(result.get("checker_exit")) is int, f"{path}: missing checker exit")
    check = read("final/check.json")
    rows = check["checks"]
    require(len({row["check"] for row in rows}) == len(rows), f"{path}: duplicate check names")
    outcomes = {row["check"]: row["status"] for row in rows}
    require(outcomes.keys() <= CHECKS, f"{path}: unrecognized check names")
    require(set(outcomes.values()) <= set(STATUSES), f"{path}: unrecognized status")
    totals = Counter(outcomes.values())
    require(check["totals"] == {s.lower(): totals[s] for s in STATUSES},
            f"{path}: totals disagree with named checks")
    build_abort = result["build"] == "failed" and result["checker_exit"] == 3 and outcomes == {
        "openssl-present": "PASS", "openssl-has-mldsa44": "PASS",
        "binary-filesigner-mldsa": "DEPMISS", "binary-filesigner-rsa": "PASS",
    }
    require(type(result.get("msg_seed")) is int and
            (result["msg_seed"] == check.get("msg_seed") or (build_abort and "msg_seed" not in check)),
            f"{path}: fresh-input seed missing or inconsistent")
    complete_pass = outcomes.keys() == CHECKS and set(outcomes.values()) == {"PASS"}
    require(result["checker_exit"] != 0 or (result["build"] == "ok" and complete_pass),
            f"{path}: successful checker exit contradicts recorded outcomes")
    messages = read("agent/trajectory.json")["messages"]
    executed, checks, actions = 0, 0, []
    for message in messages:
        extra = message.get("extra") or {}
        if message.get("role") == "assistant":
            actions = extra.get("actions", [])
        elif message.get("role") == "user" and "returncode" in extra:
            require(len(actions) == 1, f"{path}: executed action cannot be matched to its request")
            executed += 1
            checks += int(run["condition"] == "feedback" and actions[0]["command"].strip() == "check")
            actions = []
    require(executed == run.get("executed_actions"), f"{path}: executed-action count disagrees")
    require(type(run.get("elapsed_s")) is int and run["elapsed_s"] >= 0, f"{path}: invalid elapsed time")
    require(type(result.get("check_ms")) is int and result["check_ms"] >= 0, f"{path}: invalid checker time")
    evidence["final/src.sha256"] = hashlib.sha256((path / "final/src.sha256").read_bytes()).hexdigest()
    return {
        "path": str(path), "condition": run["condition"], "seed": run["seed"],
        "full_pass": complete_pass and result["checker_exit"] == 0 and result["build"] == "ok",
        "local_pass": outcomes.get("app-verify-own-signature") == "PASS",
        "local_pass_external_fail": outcomes.get("app-verify-own-signature") == "PASS"
        and any(outcomes.get(name) == "FAIL" for name in EXTERNAL_OR_REJECTION),
        "build_failed": result["build"] == "failed", "execution_error": totals["ERROR"] > 0,
        "missing_dependency": totals["DEPMISS"] > 0, "executed_actions": executed,
        "development_check_calls": checks, "elapsed_s": run["elapsed_s"],
        "final_check_ms": result["check_ms"], "stopping_reason": run["stopping_reason"],
        "raw_checks": {name: outcomes.get(name, "UNKNOWN") for name in sorted(CHECKS)},
        "evidence_sha256": evidence,
    }


def summarize(attempts, seeds):
    require(bool(seeds) and len(seeds) == len(set(seeds)), "supply unique seeds from the main freeze")
    identities = [(r["condition"], r["seed"]) for r in attempts]
    require(len(identities) == len(set(identities)), "duplicate condition/seed; resolve replacements first")
    require(set(identities) == {(c, s) for c in ("baseline", "feedback") for s in seeds},
            "attempts do not match the complete paired seed list; no partial main summary")
    output = {"reference_freeze": REFERENCE, "expected_seeds": sorted(seeds), "conditions": {}}
    flags = ("full_pass", "local_pass", "local_pass_external_fail", "build_failed", "execution_error", "missing_dependency")
    costs = ("executed_actions", "development_check_calls", "elapsed_s", "final_check_ms")
    for condition in ("baseline", "feedback"):
        group = [r for r in attempts if r["condition"] == condition]
        count = sum(r["full_pass"] for r in group)
        output["conditions"][condition] = {
            "attempts": len(group), "counts": {f: sum(r[f] for r in group) for f in flags},
            "full_pass_proportion": count / len(group), "wilson95": wilson(count, len(group)),
            "costs": {f: distribution([r[f] for r in group]) for f in costs},
            "raw_checks": {name: dict(Counter(r["raw_checks"][name] for r in group)) for name in sorted(CHECKS)},
        }
    by_id = dict(zip(identities, attempts))
    paired = Counter()
    for seed in seeds:
        baseline, feedback = (by_id[c, seed]["full_pass"] for c in ("baseline", "feedback"))
        paired["both" if baseline and feedback else "baseline_only" if baseline else "feedback_only" if feedback else "neither"] += 1
    output["paired_counts"] = {k: paired[k] for k in ("both", "baseline_only", "feedback_only", "neither")}
    output["difference_percentage_points"] = 100 * (paired["feedback_only"] - paired["baseline_only"]) / len(seeds)
    output["attempts"] = sorted(attempts, key=lambda r: (r["seed"], r["condition"]))
    output["audit_remaining"] = "Verify main authorization/settings freeze, model provenance, snapshot contents, and all infrastructure exclusions separately. Raw check failures are not causal error labels."
    return output


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Read completed main attempts; print an auditable JSON summary without editing the paper.")
    parser.add_argument("attempts", nargs="+", type=Path)
    parser.add_argument("--phase", choices=PHASES, default="main")
    parser.add_argument("--seeds", nargs="+", type=int, required=True, help="complete paired seed list from the frozen main settings")
    args = parser.parse_args()
    try:
        report = summarize([read_attempt(p, args.phase) for p in args.attempts], args.seeds)
        report["phase"] = args.phase
    except (ValueError, OSError, KeyError, TypeError) as error:
        parser.exit(2, f"analysis stopped: {error}\n")
    print(json.dumps(report, indent=2, allow_nan=False))
