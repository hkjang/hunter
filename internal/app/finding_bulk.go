package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/jackc/pgx/v5"
)

type findingBulkItem struct {
	ID        string `json:"id"`
	UpdatedAt string `json:"updated_at"`
}
type findingBulkRequest struct {
	Items []findingBulkItem `json:"items"`
	Patch map[string]any    `json:"patch"`
}
type findingBulkError struct {
	Status  int
	Message string
}

func (e findingBulkError) Error() string { return e.Message }

func (a *App) registerFindingBulk(m *http.ServeMux) {
	m.HandleFunc("POST /api/findings/bulk", a.protect("findings:write", a.bulkFindings))
}

func validateFindingBulk(in *findingBulkRequest) (map[string]time.Time, error) {
	bad := func(message string) error { return findingBulkError{400, message} }
	if len(in.Items) < 1 || len(in.Items) > 100 {
		return nil, bad("발견 건은 1~100개를 선택하세요")
	}
	if len(in.Patch) == 0 {
		return nil, bad("변경할 담당자, 기한 또는 상태를 선택하세요")
	}
	revisions := map[string]time.Time{}
	for _, item := range in.Items {
		if item.ID == "" || len(item.ID) > 200 {
			return nil, bad("올바른 발견 건 식별자가 필요합니다")
		}
		if _, exists := revisions[item.ID]; exists {
			return nil, bad("같은 발견 건을 중복 선택할 수 없습니다")
		}
		revision, err := time.Parse(time.RFC3339Nano, item.UpdatedAt)
		if err != nil {
			return nil, bad("각 발견 건에 조회한 updated_at 변경 일시가 필요합니다")
		}
		revisions[item.ID] = revision
	}
	for field, value := range in.Patch {
		switch field {
		case "assignee":
			name, ok := value.(string)
			if !ok || len(name) > 200 || strings.ContainsFunc(name, unicode.IsControl) {
				return nil, bad("조치 담당자는 줄바꿈 없이 UTF-8 200바이트 이하로 입력하세요")
			}
			in.Patch[field] = strings.TrimSpace(name)
		case "due_date":
			if err := validateFindingOpsResource(map[string]any{field: value}); err != nil {
				return nil, bad(err.Error())
			}
		case "status":
			state, ok := value.(string)
			if !ok || !hasString([]string{"candidate", "confirmed", "in_progress", "retest", "inconclusive"}, state) {
				return nil, bad("일괄 상태 변경은 탐지 후보, 확인됨, 개선 중, 재검증 대기, 판단 불가만 지원합니다")
			}
		default:
			return nil, bad("일괄 변경은 assignee, due_date, status 필드만 지원합니다")
		}
	}
	return revisions, nil
}

// Authorization is checked again through this transaction after acquiring the
// selected row locks. Revocation or reassignment while waiting cannot reuse the
// principal or parent metadata originally read by the HTTP middleware.
func findingBulkPrincipal(ctx context.Context, tx pgx.Tx, initial User) (User, error) {
	var u User
	err := tx.QueryRow(ctx, `SELECT id,username,name,role,team FROM users WHERE id=$1 AND NOT disabled FOR SHARE`, initial.ID).Scan(&u.ID, &u.Username, &u.Name, &u.Role, &u.Team)
	if errors.Is(err, pgx.ErrNoRows) {
		return u, findingBulkError{403, "현재 사용자 권한을 확인할 수 없습니다"}
	}
	if err != nil {
		return u, err
	}
	var stored map[string]any
	err = tx.QueryRow(ctx, `SELECT value FROM settings WHERE key='roles' FOR SHARE`).Scan(&stored)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return u, err
	}
	if u.Role == "admin" {
		u.Scopes = append([]string{}, allScopes...)
	} else {
		configured := defaultSettings()["roles"][u.Role]
		if value, exists := stored[u.Role]; exists {
			configured = value
		}
		u.Scopes = stringSlice(configured)
	}
	if initial.KeyID != "" {
		var scopes []string
		err = tx.QueryRow(ctx, `SELECT scopes FROM api_keys WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL AND expires_at>clock_timestamp() FOR SHARE`, initial.KeyID, u.ID).Scan(&scopes)
		if errors.Is(err, pgx.ErrNoRows) {
			return u, findingBulkError{403, "개인 API 키가 만료되거나 폐기되었습니다"}
		}
		if err != nil {
			return u, err
		}
		effective := []string{}
		for _, scope := range u.Scopes {
			if hasString(scopes, scope) {
				effective = append(effective, scope)
			}
		}
		u.Scopes = effective
		u.KeyID = initial.KeyID
	}
	if !hasString(u.Scopes, "findings:write") || !hasString(u.Scopes, "findings:read") {
		return u, findingBulkError{403, "현재 발견 건 조회·수정 권한이 없습니다"}
	}
	return u, nil
}

func (a *App) applyFindingBulk(ctx context.Context, initial User, in findingBulkRequest) (map[string]any, error) {
	revisions, err := validateFindingBulk(&in)
	if err != nil {
		return nil, err
	}
	if !hasString(initial.Scopes, "findings:write") || !hasString(initial.Scopes, "findings:read") {
		return nil, findingBulkError{403, "발견 건 조회·수정 권한이 모두 필요합니다"}
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := a.DB.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	ids := make([]string, 0, len(revisions))
	for id := range revisions {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	rows, err := tx.Query(ctx, `SELECT id,kind,owner_id,data,created_at,updated_at FROM resources WHERE kind='findings' AND id=ANY($1::text[]) ORDER BY id FOR UPDATE`, ids)
	if err != nil {
		return nil, err
	}
	findings := []domainResource{}
	parents := map[string]bool{}
	for rows.Next() {
		v, e := scanResource(rows)
		if e != nil {
			rows.Close()
			return nil, e
		}
		findings = append(findings, v)
		parents[str(v.Data, "service_id")] = true
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return nil, err
	}
	if len(findings) != len(ids) {
		return nil, findingBulkError{404, "선택한 발견 건 중 접근 가능한 항목이 없습니다. 목록을 다시 확인하세요"}
	}
	serviceIDs := make([]string, 0, len(parents))
	for id := range parents {
		serviceIDs = append(serviceIDs, id)
	}
	sort.Strings(serviceIDs)
	rows, err = tx.Query(ctx, `SELECT id,kind,owner_id,data,created_at,updated_at FROM resources WHERE kind='services' AND id=ANY($1::text[]) ORDER BY id FOR SHARE`, serviceIDs)
	if err != nil {
		return nil, err
	}
	services := map[string]domainResource{}
	for rows.Next() {
		v, e := scanResource(rows)
		if e != nil {
			rows.Close()
			return nil, e
		}
		services[v.ID] = v
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return nil, err
	}
	u, err := findingBulkPrincipal(ctx, tx, initial)
	if err != nil {
		return nil, err
	}
	for _, v := range findings {
		parent, exists := services[str(v.Data, "service_id")]
		if !exists || !(elevated(u) || v.OwnerID == u.ID || parent.OwnerID == u.ID || u.Role == "lead" && u.Team != "" && str(parent.Data, "team") == u.Team) {
			return nil, findingBulkError{404, "선택한 발견 건 중 접근 가능한 항목이 없습니다. 목록을 다시 확인하세요"}
		}
		if !revisions[v.ID].Equal(v.UpdatedAt) {
			return nil, findingBulkError{409, "선택한 발견 건이 변경되었습니다. 목록을 새로고침한 뒤 다시 선택하세요"}
		}
		if _, changesStatus := in.Patch["status"]; changesStatus && hasString([]string{"resolved", "accepted", "false_positive"}, str(v.Data, "status")) {
			return nil, findingBulkError{409, "해결·위험 수용·오탐 항목의 상태 변경은 개별 발견 건에서 검토하세요"}
		}
	}
	operationID := newID()
	out := []map[string]any{}
	for i := range findings {
		v := &findings[i]
		oldData := cloneMap(v.Data)
		changes := map[string]any{}
		for field, value := range in.Patch {
			before, _ := json.Marshal(v.Data[field])
			after, _ := json.Marshal(value)
			if string(before) == string(after) {
				continue
			}
			changes[field] = map[string]any{"before": findingBulkAuditValue(v.Data[field]), "after": findingBulkAuditValue(value)}
			v.Data[field] = value
		}
		if len(changes) == 0 {
			continue
		}
		if err := a.sealDomainSecrets(v, oldData, in.Patch); err != nil {
			return nil, err
		}
		raw, err := json.Marshal(v.Data)
		if err != nil {
			return nil, err
		}
		err = tx.QueryRow(ctx, `UPDATE resources SET data=$2,updated_at=clock_timestamp() WHERE kind='findings' AND id=$1 AND updated_at=$3 RETURNING updated_at`, v.ID, raw, v.UpdatedAt).Scan(&v.UpdatedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, findingBulkError{409, errResourceConflict.Error()}
		}
		if err != nil {
			return nil, err
		}
		detail, _ := json.Marshal(map[string]any{"operation_id": operationID, "fields": changes})
		_, err = tx.Exec(ctx, `INSERT INTO audit_logs(id,user_id,username,action,target,detail) VALUES($1,$2,$3,'finding.bulk_update',$4,$5)`, newID(), u.ID, u.Username, v.ID, detail)
		if err != nil {
			return nil, err
		}
		out = append(out, a.resourceOutput(*v))
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return map[string]any{"updated": len(out), "items": out, "operation_id": operationID}, nil
}

func findingBulkAuditValue(value any) any {
	if text, ok := value.(string); ok {
		return maskAgentText(maskEvidence(text))
	}
	if value == nil {
		return nil
	}
	// Legacy malformed metadata is never copied verbatim into the audit log.
	return "[이전 값 형식 확인 필요]"
}

func (a *App) bulkFindings(w http.ResponseWriter, r *http.Request) {
	var in findingBulkRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&in) != nil || decoder.Decode(new(any)) != io.EOF {
		fail(w, 400, "일괄 변경 요청 형식을 확인하세요")
		return
	}
	result, err := a.applyFindingBulk(r.Context(), currentUser(r), in)
	if err != nil {
		var problem findingBulkError
		if errors.As(err, &problem) {
			fail(w, problem.Status, problem.Message)
		} else {
			fail(w, 500, "일괄 저장 결과를 확인하지 못했습니다. 목록을 새로고침하여 확인하세요")
		}
		return
	}
	jsonResponse(w, http.StatusOK, result)
}

func findingBulkSummary(fields map[string]any) string {
	labels := []string{}
	for _, key := range []string{"assignee", "due_date", "status"} {
		if _, exists := fields[key]; exists {
			labels = append(labels, map[string]string{"assignee": "조치 담당자", "due_date": "조치 기한", "status": "상태"}[key])
		}
	}
	if len(labels) == 0 {
		return "발견 건을 일괄 변경했습니다"
	}
	return fmt.Sprintf("%s를 일괄 변경했습니다", strings.Join(labels, ", "))
}
