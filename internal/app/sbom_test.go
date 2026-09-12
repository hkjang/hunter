package app

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func sampleSBOM(version string) map[string]any {
	return map[string]any{"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []any{
		map[string]any{"bom-ref": "pkg-a", "type": "library", "name": "auth-library", "version": version, "purl": "pkg:npm/auth-library@" + version, "licenses": []any{map[string]any{"license": map[string]any{"id": "MIT"}}}, "properties": []any{map[string]any{"name": "password", "value": "not-retained-password"}}},
		map[string]any{"bom-ref": "pkg-b", "type": "library", "name": "common-core", "version": "3.0", "licenses": []any{map[string]any{"expression": "MIT OR Apache-2.0"}}},
	}, "dependencies": []any{map[string]any{"ref": "pkg-a", "dependsOn": []string{"pkg-b", "missing"}}}}
}

func TestSBOMLabelsEnforceUTF8ByteLimits(t *testing.T) {
	_, s := testApp(t)
	admin := loginTest(t, s, "admin", "test-password-1234")
	service := mustRequest(t, s, "POST", "/api/services", map[string]any{"name": strings.Repeat("한", 100), "environment": "staging"}, admin, 200)
	out := mustRequest(t, s, "POST", "/api/sboms/import", map[string]any{"service_id": service["id"], "document": sampleSBOM("1")}, admin, 200)
	label := str(out, "label")
	if len(label) > 200 || !utf8.ValidString(label) || !strings.HasSuffix(label, " SBOM") {
		t.Fatal("default label is too long or breaks UTF-8")
	}
	for _, label := range []string{strings.Repeat("한", 67), strings.Repeat("a", 201), "line\nbreak"} {
		mustRequest(t, s, "POST", "/api/sboms/import", map[string]any{"service_id": service["id"], "label": label, "document": sampleSBOM("2")}, admin, 400)
	}
	valid := strings.Repeat("한", 66)
	out = mustRequest(t, s, "POST", "/api/sboms/import", map[string]any{"service_id": service["id"], "label": valid, "document": sampleSBOM("2")}, admin, 200)
	if str(out, "label") != valid {
		t.Fatal("valid multibyte label changed")
	}
}
func TestSBOMParsersAndAmbiguousComparison(t *testing.T) {
	raw, _ := json.Marshal(sampleSBOM("1.0"))
	doc, err := parseSBOM(raw)
	if err != nil || len(doc.Components) != 2 || len(doc.Warnings) != 1 || doc.Components[0].DependencyCount != 1 {
		t.Fatalf("CycloneDX normalization failed: %+v %v", doc, err)
	}
	if doc.Components[0].Identity != "pkg:npm/auth-library" || licenseNeedsReview(doc.Components[0].Licenses, nil) || !licenseNeedsReview(doc.Components[1].Licenses, nil) {
		t.Fatal("package identity/license review incorrect")
	}
	spdx := json.RawMessage(`{"spdxVersion":"SPDX-2.3","packages":[{"SPDXID":"SPDXRef-A","name":"auth-library","versionInfo":"2.0","licenseDeclared":"MIT","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:npm/auth-library@2.0"}]},{"SPDXID":"SPDXRef-B","name":"common-core","versionInfo":"3.0","licenseConcluded":"NOASSERTION"}],"relationships":[{"spdxElementId":"SPDXRef-B","relationshipType":"DEPENDENCY_OF","relatedSpdxElement":"SPDXRef-A"}]}`)
	other, err := parseSBOM(spdx)
	if err != nil || other.Components[0].DependencyCount != 1 {
		t.Fatalf("SPDX normalization failed: %v", err)
	}
	compared := compareComponents(doc.Components, other.Components)
	if len(compared["changed"].([]map[string]any)) != 2 {
		t.Fatalf("version/license change missing: %+v", compared)
	}
	duplicate := sampleSBOM("1")
	duplicate["components"] = append(array(duplicate["components"]), array(duplicate["components"])[0])
	b, _ := json.Marshal(duplicate)
	if _, err = parseSBOM(b); err == nil {
		t.Fatal("duplicate bom-ref accepted")
	}
	for _, invalid := range []string{`{"bomFormat":"CycloneDX","specVersion":"9","components":[]}`, `{"spdxVersion":"SPDX-3.0","packages":[]}`, `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":""}]}`, `{"spdxVersion":"SPDX-2.3","packages":[{"name":"a"}]}`} {
		if _, err = parseSBOM([]byte(invalid)); err == nil {
			t.Fatalf("invalid document accepted %s", invalid)
		}
	}
	// Multiple installed versions must not be paired arbitrarily as an upgrade.
	a := doc.Components[0]
	bComp := a
	bComp.Version = "2"
	bComp.ID = "two"
	c := a
	c.Version = "3"
	c.ID = "three"
	multi := compareComponents([]sbomComponent{a, bComp}, []sbomComponent{a, c})
	if len(multi["changed"].([]map[string]any)) != 0 || len(multi["added"].([]sbomComponent)) != 1 || len(multi["removed"].([]sbomComponent)) != 1 {
		t.Fatal("ambiguous installed versions paired incorrectly")
	}
}

func TestSBOMStorageScopeAndLatestInventory(t *testing.T) {
	a, s := testApp(t)
	admin := loginTest(t, s, "admin", "test-password-1234")
	for _, input := range []map[string]any{{"username": "sbom-author", "name": "Author", "role": "analyst", "team": "red"}, {"username": "sbom-lead", "name": "Lead", "role": "lead", "team": "red"}, {"username": "sbom-blue", "name": "Blue", "role": "lead", "team": "blue"}} {
		input["password"] = "test-password-1234"
		mustRequest(t, s, "POST", "/api/users", input, admin, 201)
	}
	author := loginTest(t, s, "sbom-author", "test-password-1234")
	red := loginTest(t, s, "sbom-lead", "test-password-1234")
	blue := loginTest(t, s, "sbom-blue", "test-password-1234")
	service := mustRequest(t, s, "POST", "/api/services", map[string]any{"name": "Inventory service", "environment": "staging", "team": "red"}, author, 200)
	sid := str(service, "id")
	first := mustRequest(t, s, "POST", "/api/sboms/import", map[string]any{"service_id": sid, "label": "1.0", "document": sampleSBOM("1.0")}, red, 200)
	duplicate := mustRequest(t, s, "POST", "/api/sboms/import", map[string]any{"service_id": sid, "label": "duplicate", "document": sampleSBOM("1.0")}, author, 200)
	if str(first, "id") != str(duplicate, "id") || !boolean(duplicate, "duplicate") {
		t.Fatal("duplicate import created a new snapshot")
	}
	second := mustRequest(t, s, "POST", "/api/sboms/import", map[string]any{"service_id": sid, "label": "2.0", "document": sampleSBOM("2.0")}, author, 200)
	mustRequest(t, s, "POST", "/api/sboms/import", map[string]any{"service_id": sid, "document": map[string]any{"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []any{}}}, author, 400)
	history := mustRequest(t, s, "GET", "/api/sboms?q=2.0", nil, red, 200)
	if len(array(history["items"])) != 1 || number(object(array(history["items"])[0]), "component_count", 0) != 2 {
		t.Fatalf("metadata-only history incorrect: %v", history)
	}
	mustRequest(t, s, "POST", "/api/findings", map[string]any{"title": "inventory-restricted-finding", "service_id": sid, "severity": "high", "component": "auth-library@2.0"}, author, 200)
	items := mustRequest(t, s, "GET", "/api/components", nil, red, 200)
	if len(array(items["items"])) != 2 || number(object(array(items["items"])[0]), "findings_count", 0) != 1 {
		t.Fatalf("latest SBOM/finding mapping failed: %v", items)
	}
	comparison := mustRequest(t, s, "GET", "/api/sboms/"+str(second, "id")+"/compare?baseline="+str(first, "id"), nil, author, 200)
	if len(array(comparison["changed"])) != 1 {
		t.Fatalf("version comparison incorrect: %v", comparison)
	}
	key := mustRequest(t, s, "POST", "/api/keys", map[string]any{"name": "inventory-read", "scopes": []string{"services:read"}, "expires_days": 7}, admin, 201)
	_, body, _ := request(t, s, "GET", "/api/sboms/"+str(second, "id"), nil, str(key, "token"), true)
	if bytes.Contains(body, []byte("inventory-restricted-finding")) || bytes.Contains(body, []byte("not-retained-password")) {
		t.Fatal("restricted data leaked from SBOM")
	}
	mustRequest(t, s, "DELETE", "/api/sboms/"+str(first, "id"), nil, str(key, "token"), 403)
	if len(array(mustRequest(t, s, "GET", "/api/components", nil, blue, 200)["items"])) != 0 {
		t.Fatal("cross-team inventory leaked")
	}
	mustRequest(t, s, "GET", "/api/sboms/"+str(first, "id"), nil, blue, 404)
	mustRequest(t, s, "PUT", "/api/services/"+sid, map[string]any{"team": "blue"}, admin, 200)
	// The red lead imported the first document, but no longer owns its parent.
	mustRequest(t, s, "GET", "/api/sboms/"+str(first, "id"), nil, red, 404)
	redUser := User{ID: "irrelevant", Role: "lead", Team: "red", Scopes: []string{"findings:read"}}
	if records, e := a.componentFindings(context.Background(), redUser, sid); e != nil || len(records) != 0 {
		t.Fatalf("current parent access not reapplied: %v %v", records, e)
	}
	mustRequest(t, s, "GET", "/api/sboms/"+str(first, "id"), nil, blue, 200)
	var stored []byte
	if err := a.DB.QueryRow(context.Background(), `SELECT data FROM sbom_documents WHERE id=$1`, str(first, "id")).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stored, []byte("not-retained-password")) {
		t.Fatal("arbitrary supplier properties persisted")
	}
	mustRequest(t, s, "DELETE", "/api/sboms/"+str(second, "id"), nil, author, 200)
	latest := mustRequest(t, s, "GET", "/api/components", nil, author, 200)
	if str(object(array(latest["items"])[0]), "version") != "1.0" {
		t.Fatal("deleting latest did not expose remaining snapshot")
	}
}

func TestOperationsAndInventorySettings(t *testing.T) {
	a, s := testApp(t)
	admin := loginTest(t, s, "admin", "test-password-1234")
	for _, value := range []any{0, 1.5, 3651, "30"} {
		mustRequest(t, s, "PUT", "/api/settings/inventory", map[string]any{"stale_after_days": value}, admin, 400)
	}
	mustRequest(t, s, "PUT", "/api/settings/inventory", map[string]any{"review_licenses": []any{42}}, admin, 400)
	mustRequest(t, s, "PUT", "/api/settings/inventory", map[string]any{"stale_after_days": 60, "review_licenses": []string{"GPL-3.0-only"}}, admin, 200)
	if !licenseNeedsReview([]string{"GPL-3.0-only"}, []string{"GPL-3.0-only"}) {
		t.Fatal("review list not applied")
	}
	if err := a.registerWorker(context.Background(), "readiness-worker"); err != nil {
		t.Fatal(err)
	}
	// An administrator editing the worker must not refresh its heartbeat.
	if _, err := a.DB.Exec(context.Background(), `UPDATE resources SET data=data||jsonb_build_object('enabled',true,'last_seen',now()-interval '3 minutes'),updated_at=now() WHERE id='readiness-worker'`); err != nil {
		t.Fatal(err)
	}
	out := mustRequest(t, s, "GET", "/api/operations", nil, admin, 200)
	if len(array(out["checks"])) < 10 || out["as_of"] == nil {
		t.Fatal("readiness checks missing")
	}
	if number(object(out["counts"]), "stale_workers", 0) != 1 {
		t.Fatalf("administrative update revived a stale worker: %v", out)
	}
	if _, err := a.DB.Exec(context.Background(), `UPDATE resources SET data=data||jsonb_build_object('last_seen','malformed') WHERE id='readiness-worker'`); err != nil {
		t.Fatal(err)
	}
	out = mustRequest(t, s, "GET", "/api/operations", nil, admin, 200)
	if number(object(out["counts"]), "stale_workers", 0) != 1 {
		t.Fatal("missing or malformed heartbeat considered healthy")
	}
	key := mustRequest(t, s, "POST", "/api/keys", map[string]any{"name": "service-read", "scopes": []string{"services:read"}, "expires_days": 7}, admin, 201)
	mustRequest(t, s, "GET", "/api/operations", nil, str(key, "token"), 403)
}

func TestSBOMStrictInputAndUnknownDependencyLimit(t *testing.T) {
	invalid := []string{
		`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}`,
		`{"spdxVersion":"SPDX-2.3","packages":[]}`,
		`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"a","version":42}]}`,
		`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"a","licenses":{"license":"MIT"}}]}`,
		`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"a","licenses":[{}]}]}`,
		`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"a"}],"dependencies":{}}`,
		`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"a"}],"dependencies":[{"ref":"missing","dependsOn":"a"}]}`,
		`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"a"}],"dependencies":[{"ref":"missing","dependsOn":[42]}]}`,
		`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"a","version":"1","purl":"pkg:npm/a@2"}]}`,
		`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"a","purl":"https://supplier/a"}]}`,
		`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"a","purl":"pkg:npm/a@1?token=private"}]}`,
		`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"a","purl":"pkg:npm/a@1?repository_url=https%3A%2F%2Fuser%3Aprivate%40supplier"}]}`,
		`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"a","purl":"pkg:npm/a%0Aevil@1"}]}`,
		`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"a","purl":"pkg:npm/@1"}]}`,
		`{"spdxVersion":"SPDX-2.3","packages":[{"name":"a","SPDXID":"SPDXRef-A","externalRefs":{}}]}`,
	}
	for _, raw := range invalid {
		if _, err := parseSBOM([]byte(raw)); err == nil {
			t.Fatalf("malformed input accepted: %s", raw)
		}
	}
	doc := sampleSBOM("1")
	targets := make([]string, 100001)
	for i := range targets {
		targets[i] = "unknown"
	}
	doc["dependencies"] = []any{map[string]any{"ref": "unknown", "dependsOn": targets}}
	raw, _ := json.Marshal(doc)
	if _, err := parseSBOM(raw); err == nil || !strings.Contains(err.Error(), "100,000") {
		t.Fatalf("unrecognized edges bypassed cap: %v", err)
	}
	doc = sampleSBOM("1")
	c := object(array(doc["components"])[0])
	delete(c, "version")
	raw, _ = json.Marshal(doc)
	parsed, err := parseSBOM(raw)
	if err != nil || parsed.Components[0].Version != "1" {
		t.Fatalf("purl version fallback failed: %v", err)
	}
}

func TestSBOMVariantIdentityAndFindingAmbiguity(t *testing.T) {
	x := sbomComponent{Type: "library", Group: "a|b", Name: "c"}
	y := sbomComponent{Type: "library", Group: "a", Name: "b|c"}
	if componentIdentity(x) == componentIdentity(y) {
		t.Fatal("fallback tuple delimiter collision")
	}
	x = sbomComponent{Type: "library", Name: "shared", Version: "1", PURL: "pkg:npm/shared@1", Ref: "a", Licenses: []string{"MIT"}}
	x.Identity = componentIdentity(x)
	y = x
	y.PURL = "pkg:golang/shared@1"
	y.Ref = "b"
	y.Identity = componentIdentity(y)
	indexed := indexComponentFindings([]sbomComponent{x, y}, []map[string]any{{"id": "ambiguous", "component": "shared@1"}, {"id": "exact", "component": x.PURL}})
	if len(indexed[componentVariant(x)]) != 1 || str(indexed[componentVariant(x)][0], "id") != "exact" || len(indexed[componentVariant(y)]) != 0 {
		t.Fatalf("ambiguous name attached to multiple ecosystems: %v", indexed)
	}
	refOnly := x
	refOnly.Ref = "replacement"
	refOnly.ID = "new"
	if len(compareComponents([]sbomComponent{x}, []sbomComponent{refOnly})["changed"].([]map[string]any)) != 0 {
		t.Fatal("bom-ref-only replacement claimed a metadata change")
	}
	licenseOnly := x
	licenseOnly.Licenses = []string{"GPL-3.0-only"}
	otherVersion := x
	otherVersion.Version = "2"
	otherVersion.PURL = "pkg:npm/shared@2"
	change := compareComponents([]sbomComponent{x, otherVersion}, []sbomComponent{licenseOnly, otherVersion})
	if len(change["added"].([]sbomComponent)) != 1 || len(change["removed"].([]sbomComponent)) != 1 {
		t.Fatalf("license changes lost with multiple versions: %v", change)
	}
	if !licenseNeedsReview([]string{"GPL-3.0-only"}, []string{" GPL-3.0-only "}) {
		t.Fatal("review configuration whitespace bypassed review")
	}
}

func TestSBOMRepeatedInstancesPreserveLicenseVariants(t *testing.T) {
	_, s := testApp(t)
	admin := loginTest(t, s, "admin", "test-password-1234")
	service := mustRequest(t, s, "POST", "/api/services", map[string]any{"name": "Variant service", "environment": "staging"}, admin, 200)
	doc := sampleSBOM("1")
	base := object(array(doc["components"])[0])
	copyOne := map[string]any{}
	copyTwo := map[string]any{}
	for k, v := range base {
		copyOne[k] = v
		copyTwo[k] = v
	}
	copyOne["bom-ref"] = "repeat"
	copyTwo["bom-ref"] = "alternate"
	copyTwo["licenses"] = []any{map[string]any{"license": map[string]any{"id": "GPL-3.0-only"}}}
	doc["components"] = []any{base, copyOne, copyTwo}
	delete(doc, "dependencies")
	meta := mustRequest(t, s, "POST", "/api/sboms/import", map[string]any{"service_id": str(service, "id"), "document": doc}, admin, 200)
	detail := mustRequest(t, s, "GET", "/api/sboms/"+str(meta, "id"), nil, admin, 200)
	ids := map[string]bool{}
	for _, item := range array(detail["components"]) {
		id := str(object(item), "id")
		if ids[id] {
			t.Fatal("document instance IDs collide")
		}
		ids[id] = true
	}
	items := array(mustRequest(t, s, "GET", "/api/components", nil, admin, 200)["items"])
	if len(items) != 2 || str(object(items[0]), "id") == str(object(items[1]), "id") {
		t.Fatalf("license variants silently merged or duplicate instances retained: %v", items)
	}
	// Calendar-day staleness agrees with the intelligence page at the boundary.
	now := time.Now().UTC()
	date := now.AddDate(0, 0, -30).Format("2006-01-02")
	if stale := findingDateStale(&date, 30, now); stale == nil || *stale {
		t.Fatal("feed boundary considered stale before the next date")
	}
}
