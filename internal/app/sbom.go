package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
)

// SBOMs retain normalized package metadata, never arbitrary supplier properties,
// embedded files, credentials or executable content from the uploaded document.
type sbomComponent struct {
	ID              string   `json:"id"`
	Ref             string   `json:"bom_ref"`
	Identity        string   `json:"identity"`
	Name            string   `json:"name"`
	Group           string   `json:"group"`
	Type            string   `json:"type"`
	Version         string   `json:"version"`
	PURL            string   `json:"purl"`
	Licenses        []string `json:"licenses"`
	DependencyCount int      `json:"dependency_count"`
}
type sbomDependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"depends_on"`
}
type normalizedSBOM struct {
	Format       string           `json:"format"`
	SpecVersion  string           `json:"spec_version"`
	Components   []sbomComponent  `json:"components"`
	Dependencies []sbomDependency `json:"dependencies"`
	Warnings     []string         `json:"warnings"`
}

func hashText(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
func componentIdentity(c sbomComponent) string {
	if c.PURL != "" {
		base, tail := c.PURL, ""
		if i := strings.IndexAny(base, "?#"); i >= 0 {
			tail = base[i:]
			base = base[:i]
		}
		if i := strings.LastIndex(base, "@"); i > strings.LastIndex(base, "/") {
			base = base[:i]
		}
		return base + tail
	}
	encoded, _ := json.Marshal([]string{c.Type, c.Group, c.Name})
	return "name:" + string(encoded)
}

func componentVariant(c sbomComponent) string {
	licenses := append([]string{}, c.Licenses...)
	sort.Strings(licenses)
	encoded, _ := json.Marshal([]any{c.Identity, c.Name, c.Group, c.Type, c.Version, c.PURL, licenses})
	return hashText(string(encoded))
}

var sbomPURLType = regexp.MustCompile(`^[a-z][a-z0-9.+-]*$`)

func sbomSafeIdentifier(value string, limit int) bool {
	return len(value) <= limit && !strings.ContainsFunc(value, unicode.IsControl)
}
func validateSBOMPURL(c *sbomComponent) error {
	if c.PURL == "" {
		return nil
	}
	if !strings.HasPrefix(c.PURL, "pkg:") || strings.ContainsAny(c.PURL, " \t\r\n") {
		return errors.New("purl은 pkg: 형식의 패키지 식별자여야 합니다")
	}
	base := strings.SplitN(strings.SplitN(strings.TrimPrefix(c.PURL, "pkg:"), "#", 2)[0], "?", 2)[0]
	parts := strings.Split(base, "/")
	if len(parts) < 2 || !sbomPURLType.MatchString(parts[0]) || parts[len(parts)-1] == "" {
		return errors.New("purl에는 패키지 유형과 이름이 필요합니다")
	}
	if i := strings.LastIndex(base, "@"); i > strings.LastIndex(base, "/") {
		if i == strings.LastIndex(base, "/")+1 {
			return errors.New("purl에는 패키지 이름이 필요합니다")
		}
		version, e := url.PathUnescape(base[i+1:])
		if e != nil || version == "" {
			return errors.New("purl 버전이 올바르지 않습니다")
		}
		if c.Version != "" && c.Version != version {
			return errors.New("구성요소 버전과 purl 버전이 일치해야 합니다")
		}
		if c.Version == "" {
			c.Version = version
		}
	}
	decoded, e := url.PathUnescape(c.PURL)
	if e != nil || !sbomSafeIdentifier(decoded, 2048) {
		return errors.New("purl 인코딩 또는 식별자가 올바르지 않습니다")
	}
	if i := strings.Index(c.PURL, "?"); i >= 0 {
		query := strings.SplitN(c.PURL[i+1:], "#", 2)[0]
		values, e := url.ParseQuery(query)
		if e != nil {
			return errors.New("purl 한정자 형식이 올바르지 않습니다")
		}
		for key, entries := range values {
			if containsNestedSecret(map[string]any{key: "x"}) {
				return errors.New("purl 한정자에 인증 정보를 넣을 수 없습니다")
			}
			for _, value := range entries {
				if parsed, e := url.Parse(value); e == nil && parsed.User != nil {
					return errors.New("purl 한정자 URL에 계정 정보를 넣을 수 없습니다")
				}
			}
		}
	}
	return nil
}

func sbomArray(m map[string]any, key string) ([]any, error) {
	v, exists := m[key]
	if !exists {
		return nil, nil
	}
	values, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("%s 항목은 배열이어야 합니다", key)
	}
	return values, nil
}

func sbomStringFields(m map[string]any, keys ...string) error {
	for _, key := range keys {
		if value, exists := m[key]; exists {
			if _, ok := value.(string); !ok {
				return fmt.Errorf("%s 항목은 문자열이어야 합니다", key)
			}
		}
	}
	return nil
}

func parseSBOM(raw json.RawMessage) (normalizedSBOM, error) {
	out := normalizedSBOM{Components: []sbomComponent{}, Dependencies: []sbomDependency{}, Warnings: []string{}}
	var doc map[string]any
	if len(raw) > 8<<20 || json.Unmarshal(raw, &doc) != nil || doc == nil {
		return out, errors.New("8 MiB 이하의 SBOM JSON 객체가 필요합니다")
	}
	refs := map[string]bool{}
	edges := map[string][]string{}
	rawEdgeCount := 0
	addEdges := func(ref string, targets []string) error {
		if ref == "" || !sbomSafeIdentifier(ref, 2048) {
			return errors.New("의존관계 참조 ID를 확인하세요")
		}
		rawEdgeCount += len(targets)
		if rawEdgeCount > 100000 {
			return errors.New("의존관계는 최대 100,000개입니다")
		}
		for _, target := range targets {
			if target == "" || !sbomSafeIdentifier(target, 2048) {
				return errors.New("의존 대상 ID를 확인하세요")
			}
		}
		edges[ref] = append(edges[ref], targets...)
		return nil
	}
	add := func(c sbomComponent) error {
		if len(out.Components) >= 10000 {
			return errors.New("문서당 구성요소는 최대 10,000개입니다")
		}
		for _, s := range []string{c.Name, c.Group, c.Type, c.Version, c.Ref, c.PURL} {
			if !sbomSafeIdentifier(s, 2048) {
				return errors.New("구성요소 식별자는 줄바꿈 없이 2,048바이트 이하여야 합니다")
			}
		}
		if strings.TrimSpace(c.Name) == "" {
			return errors.New("모든 구성요소에 이름이 필요합니다")
		}
		if err := validateSBOMPURL(&c); err != nil {
			return err
		}
		if c.Ref == "" {
			c.Ref = fmt.Sprintf("hunter-component-%d", len(out.Components)+1)
		}
		if refs[c.Ref] {
			return errors.New("구성요소 참조 ID가 중복되었습니다")
		}
		refs[c.Ref] = true
		if len(c.Licenses) > 50 {
			return errors.New("구성요소별 라이선스는 최대 50개입니다")
		}
		licenses := map[string]bool{}
		for _, l := range c.Licenses {
			if !sbomSafeIdentifier(l, 1024) || strings.TrimSpace(l) == "" {
				return errors.New("라이선스 표현식은 1,024바이트 이하여야 합니다")
			}
			licenses[strings.TrimSpace(l)] = true
		}
		c.Licenses = []string{}
		for license := range licenses {
			c.Licenses = append(c.Licenses, license)
		}
		sort.Strings(c.Licenses)
		if c.Type == "" {
			c.Type = "library"
		}
		c.Identity = componentIdentity(c)
		// A document can contain repeated instances of one variant. Instance IDs
		// include bom-ref, while inventory grouping uses the metadata variant.
		c.ID = hashText(componentVariant(c) + "\x00" + c.Ref)
		out.Components = append(out.Components, c)
		return nil
	}
	switch {
	case str(doc, "bomFormat") == "CycloneDX":
		out.Format = "cyclonedx"
		out.SpecVersion = str(doc, "specVersion")
		if !hasString([]string{"1.4", "1.5", "1.6"}, out.SpecVersion) {
			return out, errors.New("CycloneDX 1.4, 1.5, 1.6 JSON을 지원합니다")
		}
		components, ok := doc["components"].([]any)
		if !ok {
			return out, errors.New("CycloneDX components 배열이 필요합니다")
		}
		var walk func([]any, int) error
		walk = func(items []any, depth int) error {
			if depth > 64 {
				return errors.New("구성요소 중첩이 64단계를 초과합니다")
			}
			for _, item := range items {
				m := object(item)
				if err := sbomStringFields(m, "bom-ref", "name", "group", "version", "type", "purl"); err != nil {
					return err
				}
				c := sbomComponent{Ref: str(m, "bom-ref"), Name: str(m, "name"), Group: str(m, "group"), Version: str(m, "version"), Type: str(m, "type"), PURL: str(m, "purl"), Licenses: []string{}}
				licenses, e := sbomArray(m, "licenses")
				if e != nil {
					return e
				}
				for _, v := range licenses {
					entry := object(v)
					l := firstString(object(entry["license"]), "id", "name")
					if l == "" {
						l = str(entry, "expression")
					}
					if l == "" {
						return errors.New("라이선스 항목에 id, name 또는 expression이 필요합니다")
					}
					c.Licenses = append(c.Licenses, l)
				}
				if err := add(c); err != nil {
					return err
				}
				if nested, exists := m["components"]; exists {
					children, ok := nested.([]any)
					if !ok {
						return errors.New("중첩 components는 배열이어야 합니다")
					}
					if err := walk(children, depth+1); err != nil {
						return err
					}
				}
			}
			return nil
		}
		if err := walk(components, 0); err != nil {
			return out, err
		}
		// Metadata's root component may be the dependency graph root; it is not
		// silently counted as an installed library.
		if root := str(object(object(doc["metadata"])["component"]), "bom-ref"); root != "" {
			if !sbomSafeIdentifier(root, 2048) {
				return out, errors.New("문서 루트 참조 ID를 확인하세요")
			}
			refs[root] = true
		}
		dependencies, e := sbomArray(doc, "dependencies")
		if e != nil {
			return out, e
		}
		for _, v := range dependencies {
			d := object(v)
			ref := str(d, "ref")
			if _, exists := edges[ref]; exists {
				return out, errors.New("의존관계 참조가 중복되었습니다")
			}
			targets, e := sbomArray(d, "dependsOn")
			if e != nil {
				return out, e
			}
			stringsOnly := []string{}
			for _, target := range targets {
				value, ok := target.(string)
				if !ok {
					return out, errors.New("dependsOn에는 문자열 참조 ID만 사용할 수 있습니다")
				}
				stringsOnly = append(stringsOnly, value)
			}
			if e = addEdges(ref, stringsOnly); e != nil {
				return out, e
			}
		}
	case strings.HasPrefix(str(doc, "spdxVersion"), "SPDX-"):
		out.Format = "spdx"
		out.SpecVersion = strings.TrimPrefix(str(doc, "spdxVersion"), "SPDX-")
		if !hasString([]string{"2.2", "2.3"}, out.SpecVersion) {
			return out, errors.New("SPDX 2.2 또는 2.3 JSON을 지원합니다")
		}
		packages, ok := doc["packages"].([]any)
		if !ok {
			return out, errors.New("SPDX packages 배열이 필요합니다")
		}
		for _, v := range packages {
			m := object(v)
			if err := sbomStringFields(m, "SPDXID", "name", "versionInfo", "licenseConcluded", "licenseDeclared"); err != nil {
				return out, err
			}
			c := sbomComponent{Ref: str(m, "SPDXID"), Name: str(m, "name"), Version: str(m, "versionInfo"), Type: "library", Licenses: []string{}}
			if c.Ref == "" {
				return out, errors.New("SPDX 패키지에 SPDXID가 필요합니다")
			}
			externals, e := sbomArray(m, "externalRefs")
			if e != nil {
				return out, e
			}
			for _, v := range externals {
				r := object(v)
				if err := sbomStringFields(r, "referenceType", "referenceLocator"); err != nil {
					return out, err
				}
				if str(r, "referenceType") == "purl" {
					if c.PURL != "" && c.PURL != str(r, "referenceLocator") {
						return out, errors.New("동일 SPDX 패키지의 purl 참조가 서로 다릅니다")
					}
					c.PURL = str(r, "referenceLocator")
				}
			}
			for _, key := range []string{"licenseConcluded", "licenseDeclared"} {
				if l := str(m, key); l != "" {
					c.Licenses = append(c.Licenses, l)
				}
			}
			if err := add(c); err != nil {
				return out, err
			}
		}
		relationships, e := sbomArray(doc, "relationships")
		if e != nil {
			return out, e
		}
		for _, v := range relationships {
			r := object(v)
			from, to := str(r, "spdxElementId"), str(r, "relatedSpdxElement")
			switch str(r, "relationshipType") {
			case "DEPENDS_ON":
				if e = addEdges(from, []string{to}); e != nil {
					return out, e
				}
			case "DEPENDENCY_OF":
				if e = addEdges(to, []string{from}); e != nil {
					return out, e
				}
			}
		}
	default:
		return out, errors.New("CycloneDX 또는 SPDX 형식을 인식할 수 없습니다")
	}
	if len(out.Components) == 0 {
		return out, errors.New("SBOM에는 최소 1개의 구성요소가 필요합니다")
	}
	unknown := 0
	edgeCount := 0
	keys := make([]string, 0, len(edges))
	for k := range edges {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, ref := range keys {
		if !refs[ref] {
			unknown++
			continue
		}
		targets := []string{}
		seen := map[string]bool{}
		for _, to := range edges[ref] {
			edgeCount++
			if edgeCount > 100000 {
				return out, errors.New("의존관계는 최대 100,000개입니다")
			}
			if !refs[to] {
				unknown++
				continue
			}
			if !seen[to] {
				targets = append(targets, to)
				seen[to] = true
			}
		}
		sort.Strings(targets)
		out.Dependencies = append(out.Dependencies, sbomDependency{ref, targets})
	}
	if unknown > 0 {
		out.Warnings = append(out.Warnings, fmt.Sprintf("문서 내 구성요소와 연결되지 않는 의존관계 참조 %d개를 제외했습니다", unknown))
	}
	counts := map[string]int{}
	for _, d := range out.Dependencies {
		counts[d.Ref] = len(d.DependsOn)
	}
	for i := range out.Components {
		out.Components[i].DependencyCount = counts[out.Components[i].Ref]
	}
	return out, nil
}

func (a *App) initSBOM(ctx context.Context) error {
	_, err := a.DB.Exec(ctx, `CREATE TABLE IF NOT EXISTS sbom_documents (
	 id text PRIMARY KEY,service_id text NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
	 owner_id text NOT NULL REFERENCES users(id),label text NOT NULL,sha256 text NOT NULL,
	 data jsonb NOT NULL,created_at timestamptz NOT NULL DEFAULT now(), UNIQUE(service_id,sha256));
	 CREATE INDEX IF NOT EXISTS sbom_service_latest ON sbom_documents(service_id,created_at DESC,id DESC);`)
	return err
}
func (a *App) registerSBOM(m *http.ServeMux) {
	m.HandleFunc("GET /api/sboms", a.protect("services:read", a.listSBOMs))
	m.HandleFunc("POST /api/sboms/import", a.protect("services:write", a.importSBOM))
	m.HandleFunc("GET /api/sboms/{id}", a.protect("services:read", a.getSBOM))
	m.HandleFunc("DELETE /api/sboms/{id}", a.protect("services:write", a.deleteSBOM))
	m.HandleFunc("GET /api/sboms/{id}/compare", a.protect("services:read", a.compareSBOMs))
	m.HandleFunc("GET /api/components", a.protect("services:read", func(w http.ResponseWriter, r *http.Request) {
		out, err := a.Components(r.Context(), currentUser(r), r.URL.Query().Get("service_id"), r.URL.Query().Get("q"))
		if err != nil {
			fail(w, 500, "구성요소를 불러오지 못했습니다")
			return
		}
		jsonResponse(w, 200, out)
	}))
}

type sbomRecord struct {
	ID, ServiceID, OwnerID, Label, SHA, ServiceName string
	Data                                            normalizedSBOM
	Created                                         time.Time
}

func (a *App) sbomRecord(ctx context.Context, u User, id string) (sbomRecord, error) {
	var v sbomRecord
	err := a.DB.QueryRow(ctx, `SELECT b.id,b.service_id,b.owner_id,b.label,b.sha256,b.data,b.created_at,s.data->>'name' FROM sbom_documents b JOIN resources s ON s.id=b.service_id AND s.kind='services' WHERE `+sbomAccessSQL+` AND b.id=$4`, elevated(u), u.ID, leadTeam(u), id).Scan(&v.ID, &v.ServiceID, &v.OwnerID, &v.Label, &v.SHA, &v.Data, &v.Created, &v.ServiceName)
	return v, err
}
func sbomMeta(v sbomRecord, staleDays int) map[string]any {
	return map[string]any{"id": v.ID, "service_id": v.ServiceID, "service_name": v.ServiceName, "label": v.Label, "sha256": v.SHA, "format": v.Data.Format, "spec_version": v.Data.SpecVersion, "created_at": v.Created, "component_count": len(v.Data.Components), "dependency_count": len(v.Data.Dependencies), "warnings": v.Data.Warnings, "stale": time.Since(v.Created) > time.Duration(staleDays)*24*time.Hour}
}

// Every aggregate is selected through the current parent service. Document
// ownership must not preserve access after a service moves to another team.
const sbomAccessSQL = `($1::boolean OR s.owner_id=$2 OR ($3<>'' AND s.data->>'team'=$3))`

func (a *App) sbomRecords(ctx context.Context, u User, serviceID string, latest bool) ([]sbomRecord, error) {
	query := `SELECT b.id,b.service_id,b.owner_id,b.label,b.sha256,b.data,b.created_at,s.data->>'name' FROM sbom_documents b JOIN resources s ON s.id=b.service_id AND s.kind='services' WHERE ` + sbomAccessSQL + ` AND ($4='' OR b.service_id=$4)`
	if latest {
		query += ` AND NOT EXISTS (SELECT 1 FROM sbom_documents newer WHERE newer.service_id=b.service_id AND (newer.created_at,newer.id)>(b.created_at,b.id))`
	}
	query += ` ORDER BY b.created_at DESC,b.id DESC`
	rows, err := a.DB.Query(ctx, query, elevated(u), u.ID, leadTeam(u), serviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []sbomRecord{}
	for rows.Next() {
		var v sbomRecord
		if err = rows.Scan(&v.ID, &v.ServiceID, &v.OwnerID, &v.Label, &v.SHA, &v.Data, &v.Created, &v.ServiceName); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
func (a *App) listSBOMs(w http.ResponseWriter, r *http.Request) {
	cfg, err := a.setting(r.Context(), "inventory")
	if err != nil {
		fail(w, 500, "설정 조회 실패")
		return
	}
	u := currentUser(r)
	// The history list needs metadata only: avoid transferring and decoding every
	// historical component graph just to obtain its counts.
	rows, err := a.DB.Query(r.Context(), `SELECT b.id,b.service_id,b.label,b.sha256,b.created_at,s.data->>'name',b.data->>'format',b.data->>'spec_version',jsonb_array_length(b.data->'components'),jsonb_array_length(b.data->'dependencies'),b.data->'warnings' FROM sbom_documents b JOIN resources s ON s.id=b.service_id AND s.kind='services' WHERE `+sbomAccessSQL+` AND ($4='' OR b.service_id=$4) AND ($5='' OR strpos(lower(b.label||' '||coalesce(s.data->>'name','')||' '||b.sha256),$5)>0) ORDER BY b.created_at DESC,b.id DESC`, elevated(u), u.ID, leadTeam(u), r.URL.Query().Get("service_id"), strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q"))))
	if err != nil {
		fail(w, 500, "SBOM 조회 실패")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var v sbomRecord
		var components, dependencies int
		if err = rows.Scan(&v.ID, &v.ServiceID, &v.Label, &v.SHA, &v.Created, &v.ServiceName, &v.Data.Format, &v.Data.SpecVersion, &components, &dependencies, &v.Data.Warnings); err != nil {
			fail(w, 500, "SBOM 조회 실패")
			return
		}
		item := sbomMeta(v, number(cfg, "stale_after_days", 30))
		item["component_count"], item["dependency_count"] = components, dependencies
		items = append(items, item)
	}
	if rows.Err() != nil {
		fail(w, 500, "SBOM 조회 실패")
		return
	}
	jsonResponse(w, 200, map[string]any{"items": items, "total": len(items)})
}
func (a *App) importSBOM(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ServiceID string          `json:"service_id"`
		Label     string          `json:"label"`
		Document  json.RawMessage `json:"document"`
	}
	if decode(r, &in) != nil {
		fail(w, 400, "서비스와 UTF-8 200바이트 이내 이름, SBOM JSON이 필요합니다")
		return
	}
	s, err := a.resource(r.Context(), "services", in.ServiceID)
	if err != nil || !a.canAccess(r.Context(), currentUser(r), s) {
		fail(w, 404, "서비스를 찾을 수 없습니다")
		return
	}
	doc, err := parseSBOM(in.Document)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	if strings.TrimSpace(in.Label) == "" {
		name := str(s.Data, "name")
		if len(name) > 195 {
			cut := 195
			for cut > 0 && !utf8.RuneStart(name[cut]) {
				cut--
			}
			name = name[:cut]
		}
		in.Label = name + " SBOM"
	}
	if !sbomSafeIdentifier(in.Label, 200) {
		fail(w, 400, "문서 이름은 줄바꿈 없이 UTF-8 200바이트 이하로 입력하세요")
		return
	}
	// The digest identifies the exact submitted JSON bytes, not a claim of a
	// supplier signature or a vulnerability database verification.
	sha := hashText(string(in.Document))
	id := newID()
	data, _ := json.Marshal(doc)
	var created time.Time
	err = a.DB.QueryRow(r.Context(), `INSERT INTO sbom_documents(id,service_id,owner_id,label,sha256,data) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(service_id,sha256) DO NOTHING RETURNING created_at`, id, in.ServiceID, currentUser(r).ID, in.Label, sha, data).Scan(&created)
	duplicate := errors.Is(err, pgx.ErrNoRows)
	if duplicate {
		err = a.DB.QueryRow(r.Context(), `SELECT id FROM sbom_documents WHERE service_id=$1 AND sha256=$2`, in.ServiceID, sha).Scan(&id)
	}
	if err != nil {
		fail(w, 500, "SBOM 저장 실패")
		return
	}
	v, err := a.sbomRecord(r.Context(), currentUser(r), id)
	if err != nil {
		fail(w, 404, "서비스 접근 권한을 확인하세요")
		return
	}
	a.audit(r, "sbom.import", id, map[string]any{"service_id": in.ServiceID, "sha256": sha, "component_count": len(doc.Components), "duplicate": duplicate})
	out := sbomMeta(v, 30)
	out["duplicate"] = duplicate
	jsonResponse(w, 200, out)
}
func licenseNeedsReview(licenses, review []string) bool {
	if len(licenses) == 0 {
		return true
	}
	for _, l := range licenses {
		if l == "NOASSERTION" || l == "NONE" || strings.ContainsAny(l, " ()") || strings.HasPrefix(l, "LicenseRef-") {
			return true
		}
		for _, configured := range review {
			if strings.TrimSpace(configured) == l {
				return true
			}
		}
	}
	return false
}
func componentMap(c sbomComponent, review []string) map[string]any {
	b, _ := json.Marshal(c)
	m := map[string]any{}
	_ = json.Unmarshal(b, &m)
	m["license_review"] = licenseNeedsReview(c.Licenses, review)
	m["findings_count"] = 0
	m["findings"] = []map[string]any{}
	m["services"] = []map[string]any{}
	return m
}
func (a *App) componentFindings(ctx context.Context, u User, serviceID string) ([]map[string]any, error) {
	out := []map[string]any{}
	if !hasString(u.Scopes, "findings:read") {
		return out, nil
	}
	rows, err := a.DB.Query(ctx, `SELECT f.id,jsonb_build_object('title',f.data->>'title','severity',f.data->>'severity','status',f.data->>'status','component',f.data->>'component','cve',f.data->>'cve') FROM resources f JOIN resources s ON s.id=f.data->>'service_id' AND s.kind='services' WHERE f.kind='findings' AND `+sbomAccessSQL+` AND s.id=$4 ORDER BY f.created_at DESC,f.id`, elevated(u), u.ID, leadTeam(u), serviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var m map[string]any
		if err = rows.Scan(&id, &m); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{"id": id, "title": str(m, "title"), "severity": str(m, "severity"), "status": str(m, "status"), "component": str(m, "component"), "cve": str(m, "cve")})
	}
	return out, rows.Err()
}
func componentAlias(c sbomComponent) string {
	if c.Version == "" {
		return ""
	}
	name := c.Name
	if c.Group != "" {
		name = c.Group + "/" + name
	}
	return name + "@" + c.Version
}

// Name/version alone is usable only when it identifies one package in this
// document. Shared display names across ecosystems must not attach findings.
func indexComponentFindings(components []sbomComponent, findings []map[string]any) map[string][]map[string]any {
	aliases := map[string]map[string]bool{}
	for _, c := range components {
		alias := componentAlias(c)
		if alias == "" {
			continue
		}
		if aliases[alias] == nil {
			aliases[alias] = map[string]bool{}
		}
		aliases[alias][c.Identity] = true
	}
	byAlias := map[string][]map[string]any{}
	for _, f := range findings {
		alias := str(f, "component")
		if alias != "" {
			byAlias[alias] = append(byAlias[alias], f)
		}
	}
	indexed := map[string][]map[string]any{}
	for _, c := range components {
		variant := componentVariant(c)
		if _, exists := indexed[variant]; exists {
			continue
		}
		matches := []map[string]any{}
		seen := map[string]bool{}
		for _, alias := range []string{c.PURL, componentAlias(c)} {
			if alias == "" || (alias != c.PURL && len(aliases[alias]) != 1) {
				continue
			}
			for _, f := range byAlias[alias] {
				if id := str(f, "id"); !seen[id] {
					matches = append(matches, f)
					seen[id] = true
				}
			}
		}
		indexed[variant] = matches
	}
	return indexed
}
func attachComponentFindings(c sbomComponent, m map[string]any, indexed map[string][]map[string]any) {
	matches := indexed[componentVariant(c)]
	if matches == nil {
		matches = []map[string]any{}
	}
	m["findings"] = matches
	m["findings_count"] = len(matches)
}
func (a *App) getSBOM(w http.ResponseWriter, r *http.Request) {
	v, err := a.sbomRecord(r.Context(), currentUser(r), r.PathValue("id"))
	if err != nil {
		fail(w, 404, "SBOM을 찾을 수 없습니다")
		return
	}
	cfg, err := a.setting(r.Context(), "inventory")
	if err != nil {
		fail(w, 500, "설정 조회 실패")
		return
	}
	findings, err := a.componentFindings(r.Context(), currentUser(r), v.ServiceID)
	if err != nil {
		fail(w, 500, "발견 건 조회 실패")
		return
	}
	out := sbomMeta(v, number(cfg, "stale_after_days", 30))
	items := []map[string]any{}
	indexed := indexComponentFindings(v.Data.Components, findings)
	for _, c := range v.Data.Components {
		m := componentMap(c, stringSlice(cfg["review_licenses"]))
		attachComponentFindings(c, m, indexed)
		items = append(items, m)
	}
	out["components"] = items
	out["dependencies"] = v.Data.Dependencies
	out["findings_visible"] = hasString(currentUser(r).Scopes, "findings:read")
	jsonResponse(w, 200, out)
}
func (a *App) deleteSBOM(w http.ResponseWriter, r *http.Request) {
	v, err := a.sbomRecord(r.Context(), currentUser(r), r.PathValue("id"))
	if err != nil {
		fail(w, 404, "SBOM을 찾을 수 없습니다")
		return
	}
	if _, err = a.DB.Exec(r.Context(), `DELETE FROM sbom_documents WHERE id=$1`, v.ID); err != nil {
		fail(w, 500, "삭제 실패")
		return
	}
	a.audit(r, "sbom.delete", v.ID, map[string]any{"service_id": v.ServiceID})
	jsonResponse(w, 200, map[string]any{"deleted": true})
}

func compareComponents(before, after []sbomComponent) map[string]any {
	old, newer := map[string][]sbomComponent{}, map[string][]sbomComponent{}
	for _, c := range before {
		old[c.Identity] = append(old[c.Identity], c)
	}
	for _, c := range after {
		newer[c.Identity] = append(newer[c.Identity], c)
	}
	added, removed := []sbomComponent{}, []sbomComponent{}
	changed := []map[string]any{}
	keys := map[string]bool{}
	for k := range old {
		keys[k] = true
	}
	for k := range newer {
		keys[k] = true
	}
	sorted := []string{}
	for k := range keys {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)
	for _, k := range sorted {
		a, b := old[k], newer[k]
		if len(a) == 1 && len(b) == 1 {
			if componentVariant(a[0]) != componentVariant(b[0]) {
				changed = append(changed, map[string]any{"identity": k, "before": a[0], "after": b[0]})
			}
			continue
		}
		counts := map[string]int{}
		for _, c := range a {
			counts[componentVariant(c)]++
		}
		for _, c := range b {
			if counts[componentVariant(c)] > 0 {
				counts[componentVariant(c)]--
			} else {
				added = append(added, c)
			}
		}
		for _, c := range a {
			if counts[componentVariant(c)] > 0 {
				removed = append(removed, c)
				counts[componentVariant(c)]--
			}
		}
	}
	return map[string]any{"added": added, "removed": removed, "changed": changed}
}
func (a *App) compareSBOMs(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	v, err := a.sbomRecord(r.Context(), u, r.PathValue("id"))
	if err != nil {
		fail(w, 404, "SBOM을 찾을 수 없습니다")
		return
	}
	baseline, err := a.sbomRecord(r.Context(), u, r.URL.Query().Get("baseline"))
	if err != nil {
		fail(w, 404, "기준 SBOM을 찾을 수 없습니다")
		return
	}
	if v.ServiceID != baseline.ServiceID {
		fail(w, 400, "동일 서비스의 SBOM끼리 비교할 수 있습니다")
		return
	}
	out := compareComponents(baseline.Data.Components, v.Data.Components)
	out["baseline"] = sbomMeta(baseline, 30)
	out["current"] = sbomMeta(v, 30)
	jsonResponse(w, 200, out)
}

func (a *App) Components(ctx context.Context, u User, serviceID, q string) (map[string]any, error) {
	if !hasString(u.Scopes, "services:read") {
		return nil, errors.New("서비스 조회 권한이 필요합니다")
	}
	records, err := a.sbomRecords(ctx, u, serviceID, true)
	if err != nil {
		return nil, err
	}
	cfg, err := a.setting(ctx, "inventory")
	if err != nil {
		return nil, err
	}
	groups := map[string]map[string]any{}
	q = strings.ToLower(strings.TrimSpace(q))
	for _, v := range records {
		findings, err := a.componentFindings(ctx, u, v.ServiceID)
		if err != nil {
			return nil, err
		}
		seen := map[string]bool{}
		indexed := indexComponentFindings(v.Data.Components, findings)
		for _, c := range v.Data.Components {
			variant := componentVariant(c)
			if seen[variant] {
				continue
			}
			seen[variant] = true
			if q != "" && !strings.Contains(strings.ToLower(strings.Join([]string{c.Name, c.Group, c.Version, c.PURL, strings.Join(c.Licenses, " "), v.ServiceName}, " ")), q) {
				continue
			}
			m, ok := groups[variant]
			if !ok {
				m = componentMap(c, stringSlice(cfg["review_licenses"]))
				m["id"] = variant
				groups[variant] = m
			}
			one := componentMap(c, nil)
			attachComponentFindings(c, one, indexed)
			m["findings"] = append(m["findings"].([]map[string]any), one["findings"].([]map[string]any)...)
			m["findings_count"] = len(m["findings"].([]map[string]any))
			m["services"] = append(m["services"].([]map[string]any), map[string]any{"id": v.ServiceID, "name": v.ServiceName, "sbom_id": v.ID, "stale": time.Since(v.Created) > time.Duration(number(cfg, "stale_after_days", 30))*24*time.Hour})
		}
	}
	items := []map[string]any{}
	for _, m := range groups {
		items = append(items, m)
	}
	sort.Slice(items, func(i, j int) bool {
		a, b := str(items[i], "name"), str(items[j], "name")
		if a == b {
			return str(items[i], "id") < str(items[j], "id")
		}
		return a < b
	})
	return map[string]any{"items": items, "total": len(items), "as_of": time.Now().UTC(), "findings_visible": hasString(u.Scopes, "findings:read")}, nil
}
