package app

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type findingActivityItem struct {
	ID         string         `json:"id"`
	Kind       string         `json:"kind"`
	AuthorID   string         `json:"author_id,omitempty"`
	AuthorName string         `json:"author_name,omitempty"`
	CreatedAt  time.Time      `json:"created_at"`
	Body       string         `json:"body,omitempty"`
	Action     string         `json:"action,omitempty"`
	Summary    string         `json:"summary"`
	Details    map[string]any `json:"details,omitempty"`
}

func (a *App) addFindingComment(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Body string `json:"body"`
	}
	if decode(r, &input) != nil {
		fail(w, 400, "댓글 본문을 확인하세요")
		return
	}
	body := strings.TrimSpace(input.Body)
	if body == "" || len(body) > 16000 {
		fail(w, 400, "댓글은 비어 있지 않은 16000바이트 이하의 내용이어야 합니다")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	u := currentUser(r)
	tx, err := a.DB.Begin(ctx)
	if err != nil {
		fail(w, 500, "댓글 저장을 시작할 수 없습니다")
		return
	}
	defer tx.Rollback(ctx)
	finding, err := scanResource(tx.QueryRow(ctx, `SELECT id,kind,owner_id,data,created_at,updated_at FROM resources WHERE kind='findings' AND id=$1 FOR SHARE`, r.PathValue("id")))
	if err != nil || !a.canAccess(ctx, u, finding) {
		fail(w, 404, "접근 가능한 발견 건이 없습니다")
		return
	}
	body = maskEvidence(body)
	sealed, err := a.encrypt(body)
	if err != nil {
		fail(w, 500, "댓글을 암호화하지 못했습니다")
		return
	}
	item := findingActivityItem{ID: newID(), Kind: "comment", AuthorID: u.ID, AuthorName: u.Name, Body: body, Summary: "댓글을 남겼습니다"}
	if item.AuthorName == "" {
		item.AuthorName = u.Username
	}
	err = tx.QueryRow(ctx, `INSERT INTO finding_comments(id,finding_id,author_id,author_name,body_encrypted) VALUES($1,$2,$3,$4,$5) RETURNING created_at`, item.ID, finding.ID, u.ID, item.AuthorName, sealed).Scan(&item.CreatedAt)
	if err != nil {
		fail(w, 500, "댓글을 저장하지 못했습니다")
		return
	}
	detail, _ := json.Marshal(map[string]any{"comment_id": item.ID, "body_bytes": len(body)})
	_, err = tx.Exec(ctx, `INSERT INTO audit_logs(id,user_id,username,action,target,detail) VALUES($1,$2,$3,'finding.comment', $4,$5)`, newID(), u.ID, u.Username, finding.ID, detail)
	if err != nil || tx.Commit(ctx) != nil {
		fail(w, 500, "댓글 저장을 확정하지 못했습니다")
		return
	}
	jsonResponse(w, 201, item)
}

func (a *App) findingActivity(w http.ResponseWriter, r *http.Request) {
	page, size := 1, 25
	if raw := r.URL.Query().Get("page"); raw != "" {
		n, e := strconv.Atoi(raw)
		if e != nil || n < 1 || n > 10000000 {
			fail(w, 400, "활동 페이지를 확인하세요")
			return
		}
		page = n
	}
	if raw := r.URL.Query().Get("size"); raw != "" {
		n, e := strconv.Atoi(raw)
		if e != nil || n < 1 || n > 100 {
			fail(w, 400, "활동 표시 수는 1~100 범위입니다")
			return
		}
		size = n
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	finding, err := a.resource(ctx, "findings", r.PathValue("id"))
	if err != nil || !a.canAccess(ctx, currentUser(r), finding) {
		fail(w, 404, "접근 가능한 발견 건이 없습니다")
		return
	}
	// Existing audit entries contain operation metadata, not a complete field
	// diff. Scanner observations remain the existing last-100 observation window.
	const query = `WITH timeline AS (
 SELECT id,'comment' AS kind,author_id,author_name,created_at,body_encrypted,'' AS action,'{}'::jsonb AS detail FROM finding_comments WHERE finding_id=$1
 UNION ALL
 SELECT id,'audit',user_id,username,created_at,'',action,detail FROM audit_logs
 WHERE target=$1 AND action IN ('findings.save','finding.acceptance_expired')
 UNION ALL
 SELECT 'observation-'||ord::text,'observation','','',hunter_finding_timestamp(obs->>'observed_at'),'','scanner.observed',obs
 FROM jsonb_array_elements(CASE WHEN jsonb_typeof($2::jsonb->'observations')='array' THEN $2::jsonb->'observations' ELSE '[]'::jsonb END) WITH ORDINALITY AS values(obs,ord)
 WHERE hunter_finding_timestamp(obs->>'observed_at') IS NOT NULL
 UNION ALL
 SELECT 'verification','verification','','',hunter_finding_timestamp($2::jsonb->'verification'->>'verified_at'),'','finding.verified',$2::jsonb->'verification'
 WHERE hunter_finding_timestamp($2::jsonb->'verification'->>'verified_at') IS NOT NULL
), page AS (SELECT * FROM timeline ORDER BY created_at DESC,id DESC LIMIT $3 OFFSET $4)
 SELECT coalesce((SELECT jsonb_agg(to_jsonb(p) ORDER BY created_at DESC,id DESC) FROM page p),'[]'::jsonb),(SELECT count(*) FROM timeline)`
	data, _ := json.Marshal(finding.Data)
	var raw []byte
	var total int64
	err = a.DB.QueryRow(ctx, query, finding.ID, data, size, (page-1)*size).Scan(&raw, &total)
	if err != nil {
		fail(w, 500, "발견 활동을 불러오지 못했습니다")
		return
	}
	var entries []struct {
		ID            string         `json:"id"`
		Kind          string         `json:"kind"`
		AuthorID      string         `json:"author_id"`
		AuthorName    string         `json:"author_name"`
		CreatedAt     time.Time      `json:"created_at"`
		BodyEncrypted string         `json:"body_encrypted"`
		Action        string         `json:"action"`
		Detail        map[string]any `json:"detail"`
	}
	if json.Unmarshal(raw, &entries) != nil {
		fail(w, 500, "발견 활동을 읽을 수 없습니다")
		return
	}
	items := make([]findingActivityItem, 0, len(entries))
	for _, entry := range entries {
		item := findingActivityItem{ID: entry.ID, Kind: entry.Kind, AuthorID: entry.AuthorID, AuthorName: entry.AuthorName, CreatedAt: entry.CreatedAt, Action: entry.Action, Details: map[string]any{}}
		switch entry.Kind {
		case "comment":
			plain, e := a.decrypt(entry.BodyEncrypted)
			if e != nil {
				fail(w, 500, "댓글 복호화에 실패했습니다")
				return
			}
			item.Body = plain
			item.Summary = "댓글을 남겼습니다"
		case "audit":
			item.Summary = "발견 건을 저장했습니다"
			if entry.Action == "finding.acceptance_expired" {
				item.Summary = "위험 수용 기간이 만료되어 재검토 대상으로 돌아왔습니다"
			}
			for _, key := range []string{"title", "name", "reason"} {
				if value, ok := entry.Detail[key].(string); ok {
					item.Details[key] = maskEvidence(value)
				}
			}
		case "observation":
			item.Summary = "스캐너가 발견 건을 관찰했습니다"
			for _, key := range []string{"source", "severity", "scan_id"} {
				if value, ok := entry.Detail[key].(string); ok {
					item.Details[key] = maskEvidence(value)
				}
			}
		case "verification":
			item.Summary = "재검증 결과가 기록되었습니다"
			for _, key := range []string{"scan_id", "control", "result"} {
				if value, ok := entry.Detail[key].(string); ok {
					item.Details[key] = maskEvidence(value)
				}
			}
		}
		items = append(items, item)
	}
	jsonResponse(w, 200, map[string]any{"items": items, "total": total, "page": page, "page_size": size, "observation_limit": 100, "history_definition": "댓글·기존 저장 감사·최근 스캐너 관찰·현재 재검증 결과의 통합 기록이며 모든 필드의 변경 이력은 아닙니다"})
}
