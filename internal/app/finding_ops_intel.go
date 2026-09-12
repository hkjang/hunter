package app

import (
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

const findingIntelContentLimit = 32 << 20
const findingIntelRowsLimit = 500000

var findingCVEPattern = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)

type findingIntelEntry struct {
	CVE        string
	EPSS       *float64
	Percentile *float64
	Metadata   map[string]any
}

func parseFindingIntelligence(format, content, sourceDate string) ([]findingIntelEntry, error) {
	date, err := time.Parse("2006-01-02", sourceDate)
	if err != nil || date.After(time.Now().UTC()) {
		return nil, errors.New("자료 기준일은 오늘까지의 YYYY-MM-DD 형식으로 입력하세요")
	}
	if len(content) == 0 || len(content) > findingIntelContentLimit {
		return nil, errors.New("반입 본문은 1바이트~32 MiB 범위입니다")
	}
	content = strings.TrimPrefix(content, "\ufeff")
	out := []findingIntelEntry{}
	seen := map[string]bool{}
	add := func(entry findingIntelEntry) error {
		entry.CVE = strings.ToUpper(strings.TrimSpace(entry.CVE))
		if !findingCVEPattern.MatchString(entry.CVE) {
			return errors.New("CVE 식별자 형식이 올바르지 않습니다")
		}
		if seen[entry.CVE] {
			return errors.New("동일 CVE가 중복되어 있습니다")
		}
		if len(out) >= findingIntelRowsLimit {
			return errors.New("반입 항목은 최대 500000개입니다")
		}
		seen[entry.CVE] = true
		out = append(out, entry)
		return nil
	}
	switch format {
	case "kev":
		var document struct {
			Count           *int   `json:"count"`
			DateReleased    string `json:"dateReleased"`
			Vulnerabilities []struct {
				CVE            string `json:"cveID"`
				Vendor         string `json:"vendorProject"`
				Product        string `json:"product"`
				Name           string `json:"vulnerabilityName"`
				DateAdded      string `json:"dateAdded"`
				RequiredAction string `json:"requiredAction"`
			} `json:"vulnerabilities"`
		}
		if json.Unmarshal([]byte(content), &document) != nil || document.Vulnerabilities == nil {
			return nil, errors.New("KEV JSON의 vulnerabilities 배열이 필요합니다")
		}
		if document.Count != nil && *document.Count != len(document.Vulnerabilities) {
			return nil, errors.New("KEV count와 항목 수가 일치하지 않습니다")
		}
		if document.DateReleased != "" {
			if len(document.DateReleased) < 10 || document.DateReleased[:10] != sourceDate {
				return nil, errors.New("입력한 기준일과 KEV dateReleased가 일치해야 합니다")
			}
		}
		for _, value := range document.Vulnerabilities {
			metadata := map[string]any{"vendor": value.Vendor, "product": value.Product, "name": value.Name, "date_added": value.DateAdded, "required_action": value.RequiredAction}
			for _, raw := range metadata {
				if len(raw.(string)) > 10000 {
					return nil, errors.New("KEV 항목 설명이 너무 깁니다")
				}
			}
			if value.DateAdded != "" {
				added, e := time.Parse("2006-01-02", value.DateAdded)
				if e != nil || added.After(date) {
					return nil, errors.New("KEV dateAdded는 자료 기준일까지의 날짜여야 합니다")
				}
			}
			if e := add(findingIntelEntry{CVE: value.CVE, Metadata: metadata}); e != nil {
				return nil, e
			}
		}
	case "epss":
		// FIRST exports include a #model_version/date preamble. Check its date
		// when present rather than silently relabelling an old dataset as fresh.
		for _, line := range strings.Split(content, "\n") {
			if !strings.HasPrefix(strings.TrimSpace(line), "#") {
				break
			}
			for _, part := range strings.Split(strings.TrimSpace(line), ",") {
				part = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(part), "#"))
				if strings.HasPrefix(part, "score_date:") || strings.HasPrefix(part, "date:") {
					value := strings.TrimSpace(strings.SplitN(part, ":", 2)[1])
					if value != sourceDate {
						return nil, errors.New("입력한 기준일과 EPSS CSV 기준일이 일치해야 합니다")
					}
				}
			}
		}
		reader := csv.NewReader(strings.NewReader(content))
		reader.Comment = '#'
		reader.TrimLeadingSpace = true
		header, e := reader.Read()
		if e != nil {
			return nil, errors.New("EPSS CSV 헤더가 필요합니다")
		}
		columns := map[string]int{}
		for i, name := range header {
			key := strings.ToLower(strings.TrimSpace(name))
			if _, exists := columns[key]; exists {
				return nil, errors.New("EPSS CSV 열 이름이 중복되어 있습니다")
			}
			columns[key] = i
		}
		if _, ok := columns["cve"]; !ok {
			return nil, errors.New("EPSS CSV에 cve 열이 필요합니다")
		}
		if _, ok := columns["epss"]; !ok {
			return nil, errors.New("EPSS CSV에 epss 열이 필요합니다")
		}
		parseProbability := func(raw string) (*float64, error) {
			n, e := strconv.ParseFloat(strings.TrimSpace(raw), 64)
			if e != nil || math.IsNaN(n) || math.IsInf(n, 0) || n < 0 || n > 1 {
				return nil, errors.New("EPSS 확률과 백분위는 0~1 사이의 유한한 값이어야 합니다")
			}
			return &n, nil
		}
		for {
			row, e := reader.Read()
			if errors.Is(e, io.EOF) {
				break
			}
			if e != nil {
				return nil, errors.New("EPSS CSV 행 형식이 올바르지 않습니다")
			}
			epss, e := parseProbability(row[columns["epss"]])
			if e != nil {
				return nil, e
			}
			var percentile *float64
			if i, ok := columns["percentile"]; ok && strings.TrimSpace(row[i]) != "" {
				percentile, e = parseProbability(row[i])
				if e != nil {
					return nil, e
				}
			}
			if i, ok := columns["date"]; ok && strings.TrimSpace(row[i]) != sourceDate {
				return nil, errors.New("EPSS 행의 날짜와 기준일이 일치해야 합니다")
			}
			if e = add(findingIntelEntry{CVE: row[columns["cve"]], EPSS: epss, Percentile: percentile, Metadata: map[string]any{}}); e != nil {
				return nil, e
			}
		}
	default:
		return nil, errors.New("지원 형식은 kev 또는 epss 입니다")
	}
	if len(out) == 0 {
		return nil, errors.New("반입할 CVE 항목이 없습니다")
	}
	return out, nil
}

func (a *App) listFindingIntelligence(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	risk, err := a.findingOpsSettings(ctx, "risk")
	if err != nil {
		fail(w, 500, "위협 정보 설정을 읽을 수 없습니다")
		return
	}
	rows, err := a.DB.Query(ctx, `SELECT format,source_date::text,imported_at,sha256,entry_count FROM finding_intel_datasets ORDER BY format`)
	if err != nil {
		fail(w, 500, "반입 이력을 불러오지 못했습니다")
		return
	}
	defer rows.Close()
	feeds := map[string]map[string]any{"kev": {"format": "kev", "configured": false, "source_date": nil, "imported_at": nil, "sha256": nil, "entry_count": 0, "stale": nil}, "epss": {"format": "epss", "configured": false, "source_date": nil, "imported_at": nil, "sha256": nil, "entry_count": 0, "stale": nil}}
	for rows.Next() {
		var format, date, sha string
		var imported time.Time
		var count int
		if rows.Scan(&format, &date, &imported, &sha, &count) != nil {
			fail(w, 500, "반입 정보를 읽을 수 없습니다")
			return
		}
		feeds[format] = map[string]any{"format": format, "configured": true, "source_date": date, "imported_at": imported, "sha256": sha, "entry_count": count, "stale": findingDateStale(&date, number(risk, "stale_after_days", 30), time.Now())}
	}
	if rows.Err() != nil {
		fail(w, 500, "반입 정보를 읽을 수 없습니다")
		return
	}
	jsonResponse(w, 200, map[string]any{"datasets": []any{feeds["kev"], feeds["epss"]}, "max_content_bytes": findingIntelContentLimit, "max_entries": findingIntelRowsLimit, "mode": "offline-import", "stale_after_days": risk["stale_after_days"]})
}

func (a *App) importFindingIntelligence(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Format     string `json:"format"`
		Content    string `json:"content"`
		SourceDate string `json:"source_date"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<20))
	if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF {
		fail(w, 400, "32 MiB 이하 본문을 포함한 하나의 반입 JSON이 필요합니다")
		return
	}
	entries, err := parseFindingIntelligence(input.Format, input.Content, input.SourceDate)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	tx, err := a.DB.Begin(ctx)
	if err != nil {
		fail(w, 500, "반입 트랜잭션을 시작할 수 없습니다")
		return
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext(current_schema()||':finding-intel:'||$1))`, input.Format); err != nil {
		fail(w, 500, "반입 잠금을 얻지 못했습니다")
		return
	}
	var previous string
	err = tx.QueryRow(ctx, `SELECT source_date::text FROM finding_intel_datasets WHERE format=$1 FOR UPDATE`, input.Format).Scan(&previous)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		fail(w, 500, "현재 반입 정보를 읽지 못했습니다")
		return
	}
	if previous != "" && previous > input.SourceDate {
		fail(w, 409, "이미 반입한 자료보다 오래된 기준일로 되돌릴 수 없습니다")
		return
	}
	hash := sha256.Sum256([]byte(input.Content))
	checksum := hex.EncodeToString(hash[:])
	_, err = tx.Exec(ctx, `INSERT INTO finding_intel_datasets(format,source_date,sha256,entry_count) VALUES($1,$2,$3,$4) ON CONFLICT(format) DO UPDATE SET source_date=EXCLUDED.source_date,sha256=EXCLUDED.sha256,entry_count=EXCLUDED.entry_count,imported_at=now()`, input.Format, input.SourceDate, checksum, len(entries))
	if err == nil {
		_, err = tx.Exec(ctx, `DELETE FROM finding_intel_entries WHERE format=$1`, input.Format)
	}
	if err != nil {
		fail(w, 500, "기존 반입 정보를 갱신하지 못했습니다")
		return
	}
	_, err = tx.CopyFrom(ctx, pgx.Identifier{"finding_intel_entries"}, []string{"format", "cve", "epss", "percentile", "metadata"}, pgx.CopyFromSlice(len(entries), func(i int) ([]any, error) {
		e := entries[i]
		return []any{input.Format, e.CVE, e.EPSS, e.Percentile, e.Metadata}, nil
	}))
	if err != nil {
		fail(w, 500, "CVE 정보를 반입하지 못했습니다")
		return
	}
	u := currentUser(r)
	detail, _ := json.Marshal(map[string]any{"format": input.Format, "source_date": input.SourceDate, "sha256": checksum, "entry_count": len(entries)})
	_, err = tx.Exec(ctx, `INSERT INTO audit_logs(id,user_id,username,action,target,detail) VALUES($1,$2,$3,'intelligence.import',$4,$5)`, newID(), u.ID, u.Username, input.Format, detail)
	if err != nil || tx.Commit(ctx) != nil {
		fail(w, 500, "반입 정보를 확정하지 못했습니다")
		return
	}
	jsonResponse(w, 200, map[string]any{"format": input.Format, "source_date": input.SourceDate, "sha256": checksum, "entry_count": len(entries), "replaced": previous != "", "message": fmt.Sprintf("%d개 CVE를 반입했습니다", len(entries))})
}
