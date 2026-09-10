package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

func findingFingerprint(m map[string]any) string {
	parts := []string{str(m, "service_id"), str(m, "source"), str(m, "rule_id"), str(m, "cve"), str(m, "component"), str(m, "location")}
	if parts[2] == "" && parts[3] == "" {
		parts = append(parts, str(m, "title"))
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:])
}
func object(v any) map[string]any {
	m, _ := v.(map[string]any)
	if m == nil {
		return map[string]any{}
	}
	return m
}
func array(v any) []any { a, _ := v.([]any); return a }
func nested(v any, keys ...string) any {
	for _, key := range keys {
		v = object(v)[key]
	}
	return v
}
func firstString(m map[string]any, keys ...string) string {
	for _, key := range keys {
		if s := str(m, key); s != "" {
			return s
		}
	}
	return ""
}
func normalizeSeverity(s string) string {
	switch strings.ToLower(s) {
	case "critical", "4":
		return "critical"
	case "high", "error", "3":
		return "high"
	case "medium", "moderate", "warning", "2":
		return "medium"
	case "low", "note", "1":
		return "low"
	default:
		return "info"
	}
}

var sensitiveEvidence = regexp.MustCompile(`(?im)((?:authorization|proxy-authorization|cookie|set-cookie|password|passwd|api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret)\s*[:=]\s*)[^\r\n,;&]+`)
var jwtEvidence = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`)

func maskEvidence(s string) string {
	s = sensitiveEvidence.ReplaceAllString(s, "${1}[REDACTED]")
	s = jwtEvidence.ReplaceAllString(s, "[REDACTED JWT]")
	if len(s) > 32000 {
		s = s[:32000] + "\n[truncated]"
	}
	return s
}

// Only normalized metadata is retained: raw response bodies and scanner secret
// matches are never copied into findings. Tool-specific detail stays optional.
func normalizeImport(format string, raw any) ([]map[string]any, error) {
	out := []map[string]any{}
	appendFinding := func(m map[string]any) {
		m["source"] = format
		m["severity"] = normalizeSeverity(str(m, "severity"))
		m["status"] = "candidate"
		m["evidence"] = maskEvidence(str(m, "evidence"))
		m["description"] = maskEvidence(str(m, "description"))
		out = append(out, m)
	}
	switch format {
	case "generic":
		items, ok := raw.([]any)
		if !ok {
			items, ok = object(raw)["findings"].([]any)
		}
		if !ok {
			return nil, errors.New("generic 결과는 배열 또는 findings 배열이 필요합니다")
		}
		for _, item := range items {
			m := object(item)
			if str(m, "title") == "" {
				return nil, errors.New("모든 발견 결과에 title이 필요합니다")
			}
			clean := map[string]any{}
			for _, key := range []string{"title", "severity", "description", "evidence", "remediation", "rule_id", "cve", "component", "location", "assignee"} {
				clean[key] = str(m, key)
			}
			appendFinding(clean)
		}
	case "trivy":
		results, ok := object(raw)["Results"].([]any)
		if !ok {
			return nil, errors.New("Trivy JSON의 Results 배열이 필요합니다")
		}
		for _, item := range results {
			r := object(item)
			for _, entry := range array(r["Vulnerabilities"]) {
				v := object(entry)
				appendFinding(map[string]any{"title": firstString(v, "Title", "VulnerabilityID"), "severity": str(v, "Severity"), "description": str(v, "Description"), "cve": str(v, "VulnerabilityID"), "component": str(v, "PkgName") + "@" + str(v, "InstalledVersion"), "location": str(r, "Target"), "rule_id": str(v, "VulnerabilityID"), "evidence": "설치 버전: " + str(v, "InstalledVersion"), "remediation": "수정 버전: " + str(v, "FixedVersion")})
			}
			for _, entry := range array(r["Misconfigurations"]) {
				v := object(entry)
				appendFinding(map[string]any{"title": firstString(v, "Title", "ID"), "severity": str(v, "Severity"), "description": str(v, "Description"), "rule_id": str(v, "ID"), "location": str(r, "Target"), "evidence": str(v, "Message"), "remediation": str(v, "Resolution")})
			}
			for _, entry := range array(r["Secrets"]) {
				v := object(entry)
				appendFinding(map[string]any{"title": "비밀정보 노출 의심: " + firstString(v, "Title", "RuleID"), "severity": str(v, "Severity"), "rule_id": str(v, "RuleID"), "location": str(r, "Target"), "evidence": "비밀정보 원문은 수입하지 않았습니다.", "remediation": "노출 위치를 검토하고 해당 비밀정보를 폐기·교체하세요."})
			}
		}
	case "nuclei":
		items, ok := raw.([]any)
		if !ok {
			if _, exists := object(raw)["template-id"]; !exists {
				return nil, errors.New("Nuclei JSON 객체 또는 객체 배열이 필요합니다")
			}
			items = []any{raw}
		}
		for _, entry := range items {
			v := object(entry)
			info := object(v["info"])
			appendFinding(map[string]any{"title": firstString(info, "name"), "severity": str(info, "severity"), "description": str(info, "description"), "rule_id": str(v, "template-id"), "location": safeLocation(firstString(v, "matched-at", "host")), "evidence": "템플릿: " + str(v, "template-id") + " / 일치 유형: " + str(v, "type"), "remediation": str(info, "remediation")})
		}
	case "zap":
		sites, ok := object(raw)["site"].([]any)
		if !ok {
			return nil, errors.New("ZAP JSON 보고서의 site 배열이 필요합니다")
		}
		for _, site := range sites {
			for _, entry := range array(object(site)["alerts"]) {
				v := object(entry)
				for _, instance := range array(v["instances"]) {
					i := object(instance)
					appendFinding(map[string]any{"title": firstString(v, "name", "alert"), "severity": str(v, "riskcode"), "description": str(v, "desc"), "rule_id": firstString(v, "pluginid", "alertRef"), "location": safeLocation(str(i, "uri")), "evidence": "매개변수: " + str(i, "param") + " / 메서드: " + str(i, "method"), "remediation": str(v, "solution")})
				}
			}
		}
	case "sarif":
		runs, ok := object(raw)["runs"].([]any)
		if !ok {
			return nil, errors.New("SARIF runs 배열이 필요합니다")
		}
		for _, run := range runs {
			r := object(run)
			for _, entry := range array(r["results"]) {
				v := object(entry)
				location := ""
				locs := array(v["locations"])
				if len(locs) > 0 {
					physical := object(object(locs[0])["physicalLocation"])
					location = fmt.Sprint(nested(physical, "artifactLocation", "uri"))
					if region := object(physical["region"]); len(region) > 0 {
						location += fmt.Sprintf(":%d", number(region, "startLine", 0))
					}
				}
				appendFinding(map[string]any{"title": str(v, "ruleId"), "severity": str(v, "level"), "description": str(object(v["message"]), "text"), "rule_id": str(v, "ruleId"), "location": location, "evidence": "SARIF 정적 분석 결과 / 도구: " + str(object(nested(r, "tool", "driver")), "name")})
			}
		}
	case "gitleaks":
		items, ok := raw.([]any)
		if !ok {
			return nil, errors.New("Gitleaks JSON 결과 배열이 필요합니다")
		}
		for _, entry := range items {
			v := object(entry)
			appendFinding(map[string]any{"title": "비밀정보 노출 의심: " + firstString(v, "Description", "RuleID"), "severity": "high", "rule_id": str(v, "RuleID"), "location": str(v, "File") + fmt.Sprintf(":%d", number(v, "StartLine", 0)), "evidence": "커밋: " + str(v, "Commit") + " / 비밀정보 원문은 수입하지 않았습니다.", "remediation": "노출된 키를 폐기·교체하고 저장소 이력의 접근 범위를 점검하세요."})
		}
	default:
		return nil, errors.New("지원 형식: trivy, nuclei, zap, sarif, gitleaks, generic")
	}
	if len(out) > 10000 {
		return nil, errors.New("한 번에 최대 10,000건까지 수입할 수 있습니다")
	}
	for _, m := range out {
		if strings.TrimSpace(str(m, "title")) == "" {
			m["title"] = "스캐너 발견 항목"
		}
	}
	return out, nil
}

func safeLocation(s string) string {
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		s = s[:i]
	}
	if len(s) > 2000 {
		s = s[:2000]
	}
	return s
}

func (a *App) importResults(w http.ResponseWriter, r *http.Request) {
	m := map[string]any{}
	if decode(r, &m) != nil {
		fail(w, 400, "올바른 결과 JSON이 필요합니다")
		return
	}
	service, err := a.resource(r.Context(), "services", str(m, "service_id"))
	if err != nil || !a.canAccess(r.Context(), currentUser(r), service) {
		fail(w, 404, "접근 가능한 서비스가 필요합니다")
		return
	}
	normalized, err := normalizeImport(str(m, "format"), m["results"])
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	scanID := str(m, "scan_id")
	if scanID != "" {
		scan, err := a.resource(r.Context(), "scans", scanID)
		if err != nil || !a.canAccess(r.Context(), currentUser(r), scan) || str(scan.Data, "service_id") != service.ID || str(scan.Data, "profile") != "import-only" || str(scan.Data, "status") != "awaiting_import" {
			fail(w, 400, "결과 수입 대기 중인 동일 서비스 진단이 필요합니다")
			return
		}
	}
	created, updated, err := a.ingestFindings(r.Context(), currentUser(r), service.ID, normalized, scanID)
	if err != nil {
		fail(w, 500, "결과 수입에 실패했습니다")
		return
	}
	if scanID != "" {
		patch, _ := json.Marshal(map[string]any{"status": "completed", "finished_at": time.Now().UTC(), "result": map[string]any{"format": str(m, "format"), "new_findings": created, "updated_findings": updated, "execution": "external-result-import"}})
		_, err = a.DB.Exec(r.Context(), `UPDATE resources SET data=data||$2::jsonb,updated_at=now() WHERE id=$1 AND data->>'status'='awaiting_import'`, scanID, patch)
		if err != nil {
			fail(w, 500, "발견 결과는 저장했으나 진단 상태 갱신에 실패했습니다")
			return
		}
	}
	a.audit(r, "findings.import", service.ID, map[string]any{"format": str(m, "format"), "created": created, "updated": updated})
	jsonResponse(w, 200, map[string]any{"created": created, "updated": updated, "total": len(normalized), "auto_resolved": 0})
}

func (a *App) ingestFindings(ctx context.Context, u User, serviceID string, findings []map[string]any, scanID string) (int, int, error) {
	tx, err := a.DB.Begin(ctx)
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback(ctx)
	created, updated := 0, 0
	// Serialize same-service imports so duplicate observations are never lost.
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, serviceID); err != nil {
		return 0, 0, err
	}
	for _, input := range findings {
		m := cloneMap(input)
		m["service_id"] = serviceID
		m["fingerprint"] = findingFingerprint(m)
		m["last_seen_at"] = time.Now().UTC()
		observation := map[string]any{"scan_id": scanID, "observed_at": time.Now().UTC(), "source": str(m, "source"), "severity": str(m, "severity")}
		m["observations"] = []any{observation}
		if str(m, "status") == "" {
			m["status"] = "candidate"
		}
		if str(m, "evidence") != "" {
			sealed, e := a.encrypt(maskEvidence(str(m, "evidence")))
			if e != nil {
				return created, updated, e
			}
			m["evidence"] = sealed
			m["evidence_encrypted"] = true
		}
		var id string
		var existing map[string]any
		err := tx.QueryRow(ctx, `SELECT id,data FROM resources WHERE kind='findings' AND data->>'service_id'=$1 AND data->>'fingerprint'=$2 FOR UPDATE`, serviceID, str(m, "fingerprint")).Scan(&id, &existing)
		if err == nil {
			observations := array(existing["observations"])
			observations = append(observations, observation)
			if len(observations) > 100 {
				observations = observations[len(observations)-100:]
			}
			existing["observations"] = observations
			existing["last_seen_at"] = m["last_seen_at"]
			existing["evidence"] = m["evidence"]
			existing["evidence_encrypted"] = m["evidence_encrypted"]
			if str(existing, "status") == "resolved" {
				existing["status"] = "retest"
				existing["recurrence"] = true
				existing["recurrence_count"] = number(existing, "recurrence_count", 0) + 1
			}
			raw, _ := json.Marshal(existing)
			if _, err = tx.Exec(ctx, `UPDATE resources SET data=$2,updated_at=now() WHERE id=$1`, id, raw); err != nil {
				return created, updated, err
			}
			updated++
		} else if errors.Is(err, pgx.ErrNoRows) {
			raw, _ := json.Marshal(m)
			if _, err = tx.Exec(ctx, `INSERT INTO resources(id,kind,owner_id,data) VALUES($1,'findings',$2,$3)`, newID(), u.ID, raw); err != nil {
				return created, updated, err
			}
			created++
		} else {
			return created, updated, err
		}
	}
	return created, updated, tx.Commit(ctx)
}
