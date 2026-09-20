package main

import (
	"encoding/json"
	"math"
	"os"
	"reflect"
	"testing"
)

func TestPairedSummary(t *testing.T) {
	var rows []record
	for _, condition := range conditions {
		for seed := 1; seed <= 4; seed++ {
			pass := (condition == "baseline" && seed <= 2) || (condition == "feedback" && seed != 2)
			outcomes := make(map[string]any)
			for _, name := range checks {
				outcomes[name] = "PASS"
			}
			if !pass {
				outcomes["reject-wrong-context"] = "FAIL"
			}
			rows = append(rows, record{
				"condition": condition, "seed": float64(seed), "full_pass": pass,
				"local_pass": true, "local_pass_external_fail": !pass,
				"build_failed": false, "execution_error": false, "missing_dependency": false,
				"executed_actions": float64(seed), "development_check_calls": float64(0),
				"elapsed_s": float64(100 * seed), "final_check_ms": float64(50),
				"stopping_reason": "Submitted", "raw_checks": outcomes,
			})
		}
	}
	report, err := summarize(rows, []int{1, 2, 3, 4})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int{"both": 1, "baseline_only": 1, "feedback_only": 2, "neither": 0}
	if !reflect.DeepEqual(report["paired_counts"], want) || report["difference_percentage_points"] != float64(25) {
		t.Fatalf("wrong paired comparison: %v", report["paired_counts"])
	}
	stats := distribution([]float64{400, 100, 300, 200})
	if !reflect.DeepEqual(stats, map[string]float64{"median": 250, "q1": 175, "q3": 325, "iqr": 150}) || distribution([]float64{5})["iqr"] != 0 {
		t.Fatalf("incorrect inclusive quartiles: %v", stats)
	}
	if math.Abs(wilson(5, 10)[0]-0.236593090512564) > 1e-12 || math.Abs(wilson(0, 10)[1]-0.277532799862889) > 1e-12 || math.Abs(wilson(10, 10)[1]-1) > 1e-12 {
		t.Fatal("incorrect Wilson interval")
	}
	for _, bad := range [][]record{rows[:7], append(append([]record{}, rows...), rows[0]), append(append([]record{}, rows[:7]...), rows[0])} {
		if _, err := summarize(bad, []int{1, 2, 3, 4}); err == nil {
			t.Fatal("accepted missing or duplicate attempt")
		}
	}
	for _, seeds := range [][]int{nil, {1, 1, 2, 3}, {1, 2, 3, 5}} {
		if _, err := summarize(rows, seeds); err == nil {
			t.Fatal("accepted invalid seed list")
		}
	}
	row := rows[0]
	for _, status := range []string{"FAIL", "ERROR", "DEPMISS", "UNKNOWN"} {
		row["raw_checks"].(map[string]any)["reject-wrong-context"] = status
		row["full_pass"] = false
		row["local_pass_external_fail"] = status == "FAIL"
		row["execution_error"] = status == "ERROR"
		row["missing_dependency"] = status == "DEPMISS"
		if err := validate(row, false); err != nil {
			t.Fatalf("misclassified %s: %v", status, err)
		}
	}
}

func TestPublishedMeasurements(t *testing.T) {
	data, err := os.ReadFile("../../data/attempts.json")
	if err != nil {
		t.Fatal(err)
	}
	reports, table, err := reproduce(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(reports) != 6 || len(table) != 13 {
		t.Fatalf("incomplete results: %d configurations, %d rows", len(reports), len(table))
	}
	for name, mutate := range map[string]func(map[string][]record){
		"missing configuration": func(d map[string][]record) { delete(d, "nemo") },
		"duplicate pair":        func(d map[string][]record) { d["coder"][1] = d["coder"][0] },
		"missing native":        func(d map[string][]record) { d["astra"] = d["astra"][:1] },
		"duplicate native":      func(d map[string][]record) { d["astra"][1] = d["astra"][0] },
		"bad condition type":    func(d map[string][]record) { d["astra"][0]["condition"] = []string{"baseline"} },
		"native wrong outcome":  func(d map[string][]record) { d["astra"][0]["full_pass"] = false },
		"missing flag":          func(d map[string][]record) { delete(d["coder"][0], "full_pass") },
		"wrong flag":            func(d map[string][]record) { d["coder"][0]["full_pass"] = true },
		"missing check": func(d map[string][]record) {
			delete(d["coder"][0]["raw_checks"].(map[string]any), "app-sign")
		},
		"unknown check": func(d map[string][]record) {
			d["coder"][0]["raw_checks"].(map[string]any)["invented"] = "PASS"
		},
		"bad status": func(d map[string][]record) {
			d["coder"][0]["raw_checks"].(map[string]any)["app-sign"] = "OK"
		},
		"negative time":    func(d map[string][]record) { d["coder"][0]["elapsed_s"] = -1 },
		"fractional count": func(d map[string][]record) { d["coder"][0]["executed_actions"] = 0.5 },
		"missing count":    func(d map[string][]record) { delete(d["coder"][0], "executed_actions") },
		"missing stop":     func(d map[string][]record) { delete(d["coder"][0], "stopping_reason") },
	} {
		t.Run(name, func(t *testing.T) {
			var d map[string][]record
			if err := json.Unmarshal(data, &d); err != nil {
				t.Fatal(err)
			}
			mutate(d)
			bad, err := json.Marshal(d)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := reproduce(bad); err == nil {
				t.Fatal("accepted invalid measurements")
			}
		})
	}
	if _, _, err := reproduce(append(data, '{')); err == nil {
		t.Fatal("accepted malformed JSON")
	}
}
