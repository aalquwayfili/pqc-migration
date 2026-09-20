import csv
import json
from pathlib import Path

from analyze import CHECKS, EXTERNAL_OR_REJECTION, STATUSES, require, summarize


ROOT = Path(__file__).resolve().parents[1]


def checked_flags(row, built):
    checks = row["raw_checks"]
    require(set(checks) == CHECKS, "missing or unknown check names")
    require(set(checks.values()) <= set(STATUSES) | {"UNKNOWN"}, "unknown verdict")
    return {
        "full_pass": built and all(s == "PASS" for s in checks.values()),
        "local_pass": checks["app-verify-own-signature"] == "PASS",
        "local_pass_external_fail": checks["app-verify-own-signature"] == "PASS"
        and any(checks[name] == "FAIL" for name in EXTERNAL_OR_REJECTION),
        "execution_error": "ERROR" in checks.values(),
        "missing_dependency": "DEPMISS" in checks.values(),
    }


def reproduce():
    measurements = json.loads((ROOT / "data/attempts.json").read_text())
    require(set(measurements) == {"coder", "q38", "q38_32", "nemo", "astra", "fable"},
            "unexpected configuration set")
    reports, table = {}, []
    for key in ("coder", "q38", "q38_32", "nemo"):
        attempts = measurements[key]
        for row in attempts:
            for name, value in checked_flags(row, not row["build_failed"]).items():
                require(row[name] == value, f"{key}: inconsistent {name}")
            for name in ("executed_actions", "development_check_calls", "elapsed_s", "final_check_ms"):
                require(type(row[name]) is int and row[name] >= 0, f"invalid {name}")
        reports[key] = summarize(attempts, list(range(1, 21)))
        for condition, group in reports[key]["conditions"].items():
            n, counts = group["attempts"], group["counts"]
            table.append([key, condition, n, n - counts["build_failed"], counts["full_pass"]])
    for key in ("astra", "fable"):
        rows = measurements[key]
        require(len(rows) == 2 and {r["condition"] for r in rows} == {"baseline", "feedback"},
                "incomplete native pair")
        reports[key] = rows
        for row in rows:
            require(row["full_pass"] == checked_flags(row, row["build"])["full_pass"],
                    "inconsistent native outcome")
            table.append([key, row["condition"], 1, int(row["build"]), int(row["full_pass"])])
    expected = {"coder": [0, 0], "q38": [18, 18], "q38_32": [3, 1],
                "nemo": [0, 0], "astra": [1, 1], "fable": [1, 1]}
    for key, counts in expected.items():
        require([r[4] for r in table if r[0] == key] == counts, f"paper mismatch: {key}")
    output = ROOT / "out"
    output.mkdir(exist_ok=True)
    (output / "results.json").write_text(json.dumps(reports, indent=2) + "\n")
    with (output / "results.csv").open("w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["configuration", "condition", "attempts", "builds", "full_passes"])
        writer.writerows(table)
    print(f"Verified measurements for {sum(r[2] for r in table)} attempts: {output / 'results.csv'}")


if __name__ == "__main__":
    reproduce()
