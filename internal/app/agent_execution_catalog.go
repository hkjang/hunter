package app

import (
	"context"
	"net/http"
)

func (a *App) availableExecutionProfiles(ctx context.Context, u User, serviceID string) ([]map[string]any, bool, error) {
	items := []map[string]any{}
	if !hasString(u.Scopes, "services:read") || !hasString(u.Scopes, "scans:write") {
		return items, false, nil
	}
	s, e := a.resource(ctx, "services", serviceID)
	if e != nil || !a.canAccess(ctx, u, s) {
		return items, false, e
	}
	c := defaultAgentExecution()
	_, e = a.loadPlatformConfig(ctx, "execution", &c)
	if e != nil || !c.Enabled {
		return items, false, e
	}
	for _, p := range c.Profiles {
		if !p.Enabled {
			continue
		}
		for _, server := range c.Servers {
			if server.Enabled && executionServiceNetwork(server) == str(s.Data, "network") && hasString(p.ServerIDs, server.ID) {
				items = append(items, map[string]any{"id": p.ID, "name": p.Name, "kind": p.Kind, "network": executionServiceNetwork(server)})
				break
			}
		}
	}
	return items, true, nil
}
func (a *App) listExecutionProfiles(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	if !hasString(u.Scopes, "services:read") {
		fail(w, 403, "서비스 조회 권한이 필요합니다")
		return
	}
	s, e := a.resource(r.Context(), "services", r.URL.Query().Get("service_id"))
	if e != nil || !a.canAccess(r.Context(), u, s) {
		fail(w, 404, "서비스를 찾을 수 없습니다")
		return
	}
	items, enabled, e := a.availableExecutionProfiles(r.Context(), u, s.ID)
	if e != nil {
		jsonResponse(w, 200, map[string]any{"enabled": false, "items": []any{}, "degraded": true})
		return
	}
	jsonResponse(w, 200, map[string]any{"enabled": enabled, "items": items})
}
