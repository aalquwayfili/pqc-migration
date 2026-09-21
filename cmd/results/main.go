package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

const reference = "134aa67d9d64b29b2c8ec0b09282f5035c3033343554d70c3518df91cc60534b"

var checks = strings.Fields(`
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
app-sign-second-signature signing-is-randomized second-signature-also-verifies`)

var external = strings.Fields(`
openssl-reads-app-private-key openssl-reads-app-public-key app-public-key-is-mldsa44
openssl-verifies-app-signature openssl-signs-with-app-key app-verifies-openssl-signature
app-verifies-foreign-key-signature app-signs-with-openssl-key openssl-verifies-that-roundtrip
openssl-verifies-reloaded-key-signature private-key-carries-matching-public-key
app-accepts-crlf-public-key openssl-signs-wrong-context openssl-signs-empty-context
reject-tampered-message reject-wrong-key reject-wrong-context reject-empty-context
reject-flipped-bit malformed-truncated-signature malformed-overlong-signature
malformed-garbage-public-key malformed-wrong-algorithm-key`)

var conditions = []string{"baseline", "feedback"}
var flags = strings.Fields("full_pass local_pass local_pass_external_fail build_failed execution_error missing_dependency")
var costs = strings.Fields("executed_actions development_check_calls elapsed_s final_check_ms")

type record map[string]any

func validate(row record, native bool) error {
	condition, ok := row["condition"].(string)
	if !ok || !slices.Contains(conditions, condition) {
		return fmt.Errorf("unknown condition")
	}
	buildField := "build_failed"
	if native {
		buildField = "build"
	}
	built, ok := row[buildField].(bool)
	if !ok {
		return fmt.Errorf("missing or invalid %s", buildField)
	}
	if !native {
		built = !built
	}
	outcomes, ok := row["raw_checks"].(map[string]any)
	if !ok || len(outcomes) != len(checks) {
		return fmt.Errorf("missing or unknown check names")
	}
	derived := map[string]bool{"full_pass": built}
	for _, name := range checks {
		status, ok := outcomes[name].(string)
		if !ok || !slices.Contains([]string{"PASS", "FAIL", "ERROR", "DEPMISS", "UNKNOWN"}, status) {
			return fmt.Errorf("missing or invalid verdict: %s", name)
		}
		derived["full_pass"] = derived["full_pass"] && status == "PASS"
		derived["execution_error"] = derived["execution_error"] || status == "ERROR"
		derived["missing_dependency"] = derived["missing_dependency"] || status == "DEPMISS"
	}
	derived["local_pass"] = outcomes["app-verify-own-signature"] == "PASS"
	derived["local_pass_external_fail"] = false
	for _, name := range external {
		if derived["local_pass"] && outcomes[name] == "FAIL" {
			derived["local_pass_external_fail"] = true
		}
	}
	for name, value := range derived {
		if native && name != "full_pass" {
			continue
		}
		if recorded, ok := row[name].(bool); !ok || recorded != value {
			return fmt.Errorf("inconsistent %s", name)
		}
	}
	fields := append([]string{"seed"}, costs...)
	if native {
		fields = []string{"actions", "elapsed_s"}
	}
	for _, name := range fields {
		n, ok := row[name].(float64)
		if !ok || n < 0 || n > 1<<53-1 || math.Trunc(n) != n {
			return fmt.Errorf("missing or invalid %s", name)
		}
	}
	textField := "stopping_reason"
	if native {
		textField = "attempt"
	}
	if text, ok := row[textField].(string); !ok || text == "" {
		return fmt.Errorf("missing %s", textField)
	}
	return nil
}

func wilson(k, n int) [2]float64 {
	// https://www.itl.nist.gov/div898/handbook/prc/section2/prc241.htm
	z := math.Sqrt2 * math.Erfinv(0.95)
	p, size := float64(k)/float64(n), float64(n)
	denominator := 1 + z*z/size
	center := (p + z*z/(2*size)) / denominator
	half := z * math.Sqrt(p*(1-p)/size+z*z/(4*size*size)) / denominator
	return [2]float64{math.Max(0, center-half), math.Min(1, center+half)}
}

func distribution(values []float64) map[string]float64 {
	values = slices.Clone(values)
	slices.Sort(values)
	quantile := func(p float64) float64 {
		x := p * float64(len(values)-1)
		i := int(x)
		return values[i] + (values[min(i+1, len(values)-1)]-values[i])*(x-float64(i))
	}
	q1, q3 := quantile(0.25), quantile(0.75)
	return map[string]float64{"median": quantile(0.5), "q1": q1, "q3": q3, "iqr": q3 - q1}
}

func summarize(rows []record, seeds []int) (record, error) {
	bySeed := make(map[int]map[string]record)
	for _, seed := range seeds {
		if seed < 1 || bySeed[seed] != nil {
			return nil, fmt.Errorf("expected unique positive seeds")
		}
		bySeed[seed] = make(map[string]record)
	}
	if len(seeds) == 0 || len(rows) != 2*len(seeds) {
		return nil, fmt.Errorf("incomplete paired seed list")
	}
	for _, row := range rows {
		if err := validate(row, false); err != nil {
			return nil, err
		}
		seed, condition := int(row["seed"].(float64)), row["condition"].(string)
		if bySeed[seed] == nil || bySeed[seed][condition] != nil {
			return nil, fmt.Errorf("unexpected or duplicate condition/seed: %s/%d", condition, seed)
		}
		bySeed[seed][condition] = row
	}
	groups := make(map[string]record)
	for _, condition := range conditions {
		counts, samples := make(map[string]int), make(map[string][]float64)
		outcomes := make(map[string]map[string]int)
		for _, flag := range flags {
			counts[flag] = 0
		}
		for _, name := range checks {
			outcomes[name] = make(map[string]int)
		}
		for _, row := range rows {
			if row["condition"] != condition {
				continue
			}
			for _, flag := range flags {
				if row[flag].(bool) {
					counts[flag]++
				}
			}
			for _, cost := range costs {
				samples[cost] = append(samples[cost], row[cost].(float64))
			}
			for name, status := range row["raw_checks"].(map[string]any) {
				outcomes[name][status.(string)]++
			}
		}
		stats := make(map[string]map[string]float64)
		for _, cost := range costs {
			stats[cost] = distribution(samples[cost])
		}
		groups[condition] = record{
			"attempts": len(seeds), "counts": counts,
			"full_pass_proportion": float64(counts["full_pass"]) / float64(len(seeds)),
			"wilson95":             wilson(counts["full_pass"], len(seeds)), "costs": stats, "raw_checks": outcomes,
		}
	}
	paired := map[string]int{"both": 0, "baseline_only": 0, "feedback_only": 0, "neither": 0}
	for _, pair := range bySeed {
		baseline, feedback := pair["baseline"]["full_pass"].(bool), pair["feedback"]["full_pass"].(bool)
		switch {
		case baseline && feedback:
			paired["both"]++
		case baseline:
			paired["baseline_only"]++
		case feedback:
			paired["feedback_only"]++
		default:
			paired["neither"]++
		}
	}
	rows, seeds = slices.Clone(rows), slices.Clone(seeds)
	slices.Sort(seeds)
	slices.SortFunc(rows, func(a, b record) int {
		if a["seed"] != b["seed"] {
			return int(a["seed"].(float64) - b["seed"].(float64))
		}
		return strings.Compare(a["condition"].(string), b["condition"].(string))
	})
	return record{
		"reference_freeze": reference, "expected_seeds": seeds, "conditions": groups,
		"paired_counts": paired, "attempts": rows,
		"difference_percentage_points": 100 * float64(paired["feedback_only"]-paired["baseline_only"]) / float64(len(seeds)),
	}, nil
}

func reproduce(data []byte) (record, [][]string, error) {
	var measurements map[string][]record
	if err := json.Unmarshal(data, &measurements); err != nil {
		return nil, nil, err
	}
	keys := []string{"coder", "q38", "q38_32", "nemo", "astra", "fable"}
	if len(measurements) != len(keys) {
		return nil, nil, fmt.Errorf("unexpected configuration set")
	}
	reports := make(record)
	table := [][]string{{"configuration", "condition", "attempts", "builds", "full_passes"}}
	seeds := make([]int, 20)
	for i := range seeds {
		seeds[i] = i + 1
	}
	expected := map[string][2]int{"coder": {0, 0}, "q38": {18, 18}, "q38_32": {3, 1}, "nemo": {0, 0}, "astra": {1, 1}, "fable": {1, 1}}
	for _, key := range keys {
		rows := measurements[key]
		if key == "astra" || key == "fable" {
			if len(rows) != 2 {
				return nil, nil, fmt.Errorf("%s: incomplete native pair", key)
			}
			for i, row := range rows {
				if err := validate(row, true); err != nil {
					return nil, nil, fmt.Errorf("%s: %w", key, err)
				}
				if i == 1 && rows[0]["condition"] == row["condition"] {
					return nil, nil, fmt.Errorf("%s: duplicate native condition", key)
				}
				build, pass := 0, 0
				if row["build"].(bool) {
					build = 1
				}
				if row["full_pass"].(bool) {
					pass = 1
				}
				table = append(table, []string{key, row["condition"].(string), "1", strconv.Itoa(build), strconv.Itoa(pass)})
			}
			reports[key] = rows
		} else {
			report, err := summarize(rows, seeds)
			if err != nil {
				return nil, nil, fmt.Errorf("%s: %w", key, err)
			}
			reports[key] = report
			for _, condition := range conditions {
				group := report["conditions"].(map[string]record)[condition]
				counts := group["counts"].(map[string]int)
				table = append(table, []string{key, condition, "20", strconv.Itoa(20 - counts["build_failed"]), strconv.Itoa(counts["full_pass"])})
			}
		}
		for i, condition := range conditions {
			for _, row := range table[1:] {
				if row[0] == key && row[1] == condition && row[4] != strconv.Itoa(expected[key][i]) {
					return nil, nil, fmt.Errorf("paper mismatch: %s/%s", key, condition)
				}
			}
		}
	}
	return reports, table, nil
}

func run() error {
	data, err := os.ReadFile("data/attempts.json")
	if err != nil {
		return err
	}
	reports, table, err := reproduce(data)
	if err != nil {
		return err
	}
	output, err := json.MarshalIndent(reports, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll("out", 0755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join("out", "results.json"), append(output, '\n'), 0644); err != nil {
		return err
	}
	file, err := os.Create(filepath.Join("out", "results.csv"))
	if err != nil {
		return err
	}
	writer := csv.NewWriter(file)
	writer.UseCRLF = true
	writeErr := writer.WriteAll(table)
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}
	fmt.Println("Verified measurements for 164 attempts: out/results.csv")
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "analysis stopped:", err)
		os.Exit(1)
	}
}
