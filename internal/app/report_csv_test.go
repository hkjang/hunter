package app

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
)

type csvSafetyVector struct {
	Name     string `json:"name"`
	Input    string `json:"input"`
	Expected string `json:"expected"`
}

func csvSafetyVectors(t *testing.T) []csvSafetyVector {
	t.Helper()
	b, err := os.ReadFile("testdata/csv-safety.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []csvSafetyVector
	if err := json.Unmarshal(b, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) == 0 {
		t.Fatal("empty CSV safety fixture")
	}
	return vectors
}

func TestCSVSafeSharedVectors(t *testing.T) {
	for _, v := range csvSafetyVectors(t) {
		t.Run(v.Name, func(t *testing.T) {
			if got := csvSafe(v.Input); got != v.Expected {
				t.Errorf("csvSafe(%q) = %q, want %q", v.Input, got, v.Expected)
			}
		})
	}
}

func TestReportCSVFormulaSafety(t *testing.T) {
	_, s := testApp(t)
	admin := loginTest(t, s, "admin", "test-password-1234")
	mustRequest(t, s, "GET", "/api/reports/export?format=csv", nil, "", 401)
	mustRequest(t, s, "POST", "/api/users", map[string]any{
		"username": "csv-reader", "name": "CSV reader", "password": "test-password-1234", "role": "analyst", "team": "csv-team",
	}, admin, 201)
	reader := loginTest(t, s, "csv-reader", "test-password-1234")
	service := mustRequest(t, s, "POST", "/api/services", map[string]any{
		"name": "CSV 보고서", "environment": "staging", "team": "csv-team",
	}, reader, 200)
	hidden := mustRequest(t, s, "POST", "/api/services", map[string]any{
		"name": "Other team", "environment": "staging", "team": "other-team",
	}, admin, 200)
	mustRequest(t, s, "POST", "/api/findings", map[string]any{
		"title": " =hidden", "service_id": hidden["id"], "severity": "high",
	}, admin, 200)
	expected := map[string]csvSafetyVector{}
	for i, v := range csvSafetyVectors(t) {
		// PostgreSQL cannot store NUL; the API requires a nonblank title.
		if strings.ContainsRune(v.Input, 0) || strings.TrimSpace(v.Input) == "" {
			continue
		}
		finding := mustRequest(t, s, "POST", "/api/findings", map[string]any{
			"title": v.Input, "service_id": service["id"], "severity": "high",
			"cve": "CVE-2026-1234", "location": fmt.Sprintf("/csv/%d", i),
		}, reader, 200)
		expected[str(finding, "id")] = v
	}
	status, body, headers := request(t, s, "GET", "/api/reports/export?format=csv", nil, reader, true)
	if status != 200 {
		t.Fatalf("CSV status %d: %s", status, body)
	}
	if headers.Get("Content-Type") != "text/csv; charset=utf-8" ||
		headers.Get("Content-Disposition") != "attachment; filename=hunter-findings.csv" {
		t.Fatalf("CSV download headers: %v", headers)
	}
	bom := []byte{0xef, 0xbb, 0xbf}
	if !bytes.HasPrefix(body, bom) {
		t.Fatal("missing UTF-8 BOM")
	}
	rows, err := csv.NewReader(bytes.NewReader(bytes.TrimPrefix(body, bom))).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	header := []string{"ID", "제목", "서비스 ID", "심각도", "상태", "출처", "CVE", "기여 점수"}
	if len(rows) != len(expected)+1 {
		t.Fatalf("CSV row count %d, want %d", len(rows), len(expected)+1)
	}
	if !reflect.DeepEqual(rows[0], header) {
		t.Fatalf("CSV header: %q", rows[0])
	}
	seen := map[string]bool{}
	for _, row := range rows[1:] {
		v, ok := expected[row[0]]
		if !ok || seen[row[0]] {
			t.Fatalf("unexpected or duplicate finding %q", row[0])
		}
		seen[row[0]] = true
		want := []string{row[0], v.Expected, str(service, "id"), "high", "candidate", "manual", "CVE-2026-1234", "0"}
		if !reflect.DeepEqual(row, want) {
			t.Errorf("%s: CSV row %q, want %q", v.Name, row, want)
		}
	}
	status, body, headers = request(t, s, "GET", "/api/reports/export?format=json", nil, reader, true)
	if status != 200 || headers.Get("Content-Disposition") != "attachment; filename=hunter-findings.json" {
		t.Fatalf("JSON download: status %d headers %v", status, headers)
	}
	var report struct {
		Findings []map[string]any `json:"findings"`
	}
	if err := json.Unmarshal(body, &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != len(expected) {
		t.Fatalf("JSON finding count %d, want %d", len(report.Findings), len(expected))
	}
	seen = map[string]bool{}
	for _, f := range report.Findings {
		id := str(f, "id")
		v, ok := expected[id]
		if !ok || seen[id] {
			t.Fatalf("unexpected or duplicate JSON finding %q", id)
		}
		seen[id] = true
		if str(f, "title") != v.Input {
			t.Errorf("%s: JSON title %q, want original %q", v.Name, str(f, "title"), v.Input)
		}
	}
}
