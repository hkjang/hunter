package app

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
)

// An optional execution integration being unavailable must not be mistaken for
// an authorization or target-policy failure by the agent's tool boundary.
type executionSetupUnavailable struct {
	code, detail string
}

func (e *executionSetupUnavailable) Error() string { return e.detail }

func (a *App) prepareIsolatedScan(ctx context.Context, u User, input map[string]any, service domainResource, p probePolicy) (map[string]any, error) {
	if !hasString(u.Scopes, "scans:write") || !hasString(u.Scopes, "services:read") || !a.canAccess(ctx, u, service) {
		return nil, errors.New("격리 진단에 필요한 현재 권한이 없습니다")
	}
	c := defaultAgentExecution()
	rev, e := a.loadPlatformConfig(ctx, "execution", &c)
	if e != nil {
		return nil, &executionSetupUnavailable{code: "configuration_unavailable", detail: "격리 실행 설정을 읽지 못했습니다. 기본 진단은 계속 사용할 수 있습니다"}
	}
	if !c.Enabled {
		return nil, &executionSetupUnavailable{code: "execution_disabled", detail: "격리 실행이 비활성화되었습니다. 기본 HTTP 진단을 사용할 수 있습니다"}
	}
	for _, profile := range c.Profiles {
		if profile.ID != str(input, "execution_profile_id") || !profile.Enabled {
			continue
		}
		if e := p.validateURL(p.Target); e != nil {
			return nil, e
		}
		if p.Target.RawQuery != "" {
			return nil, errors.New("격리 진단 대상은 비밀값 보호를 위해 URL 쿼리를 허용하지 않습니다")
		}
		if profile.Kind == "http_headers" && !hasString(p.AllowedMethods, "HEAD") {
			return nil, errors.New("범위 정책에서 HEAD를 허용해야 합니다")
		}
		if profile.Kind == "tls_certificate" && p.Target.Scheme != "https" {
			return nil, errors.New("TLS 인증서 진단에는 HTTPS 서비스가 필요합니다")
		}
		for _, server := range c.Servers {
			if server.Enabled && hasString(profile.ServerIDs, server.ID) && executionServiceNetwork(server) == str(service.Data, "network") {
				return map[string]any{"execution_profile_id": profile.ID, "execution_profile_kind": profile.Kind, "execution_revision": rev.Format(time.RFC3339Nano)}, nil
			}
		}
		return nil, &executionSetupUnavailable{code: "no_available_server", detail: "서비스 망과 일치하는 활성 실행 서버가 없습니다"}
	}
	return nil, &executionSetupUnavailable{code: "profile_unavailable", detail: "활성화된 관리자 등록 격리 프로파일이 필요합니다"}
}

type executionJob struct {
	ScanID, ServerID, Name, ContainerID, Image, ProfileID, PolicyHash, Status, Code, ResultCipher string
	Server                                                                                        agentExecutionServer
	Revision                                                                                      time.Time
}

func (a *App) executionJob(ctx context.Context, id string) (executionJob, error) {
	var j executionJob
	var cipher string
	e := a.DB.QueryRow(ctx, `SELECT scan_id,server_id,server_encrypted,container_name,container_id,image_id,profile_id,revision,policy_hash,status,code,result_encrypted FROM agent_execution_jobs WHERE scan_id=$1`, id).Scan(&j.ScanID, &j.ServerID, &cipher, &j.Name, &j.ContainerID, &j.Image, &j.ProfileID, &j.Revision, &j.PolicyHash, &j.Status, &j.Code, &j.ResultCipher)
	if e != nil {
		return j, e
	}
	plain, e := a.decrypt(cipher)
	if e == nil {
		e = json.Unmarshal([]byte(plain), &j.Server)
	}
	return j, e
}
func executionUnavailable(code string) map[string]any {
	return map[string]any{"status": "inconclusive", "degraded": true, "code": code, "engine": "isolated", "instruction": "격리 실행 결과를 확정할 수 없습니다. 기본 서비스와 내장 진단은 계속 사용할 수 있습니다. 생성 후 불명확한 작업은 자동으로 다시 실행하지 않습니다"}
}
func (a *App) executionJobState(ctx context.Context, id, status, code string, result map[string]any) error {
	var cipher string
	var e error
	if result != nil {
		raw, err := json.Marshal(redactAgentValue(result))
		if err != nil {
			return err
		}
		cipher, e = a.encrypt(string(raw))
		if e != nil {
			return e
		}
	}
	_, e = a.DB.Exec(ctx, `UPDATE agent_execution_jobs SET status=$2,code=$3,result_encrypted=CASE WHEN $4<>'' THEN $4 ELSE result_encrypted END,updated_at=now() WHERE scan_id=$1`, id, status, code, cipher)
	return e
}
func (a *App) executionCleaned(ctx context.Context, id string) error {
	_, e := a.DB.Exec(ctx, `UPDATE agent_execution_jobs SET cleanup_at=now(),updated_at=now() WHERE scan_id=$1`, id)
	return e
}
func (a *App) executeIsolatedScan(ctx context.Context, scan domainResource, p probePolicy, check func() error) (map[string]any, error) {
	if e := check(); e != nil {
		return executionUnavailable("policy_changed"), e
	}
	if existing, e := a.executionJob(ctx, scan.ID); e == nil {
		return a.resumeIsolatedObservation(ctx, existing, p, check)
	} else if !errors.Is(e, pgx.ErrNoRows) {
		return executionUnavailable("storage_unavailable"), nil
	}
	c := defaultAgentExecution()
	rev, e := a.loadPlatformConfig(ctx, "execution", &c)
	if e != nil || !c.Enabled || rev.Format(time.RFC3339Nano) != str(scan.Data, "execution_revision") {
		return executionUnavailable("configuration_changed"), nil
	}
	var profile agentExecutionProfile
	for _, v := range c.Profiles {
		if v.ID == str(scan.Data, "execution_profile_id") && v.Enabled {
			profile = v
		}
	}
	if profile.ID == "" {
		return executionUnavailable("profile_disabled"), nil
	}
	service, e := a.resource(ctx, "services", str(scan.Data, "service_id"))
	if e != nil {
		return executionUnavailable("service_unavailable"), e
	}
	ips, e := net.DefaultResolver.LookupNetIP(ctx, "ip", p.Target.Hostname())
	if e != nil || len(ips) == 0 {
		return executionUnavailable("dns_unavailable"), nil
	}
	for _, ip := range ips {
		if e := validateProbeIP(ip, p.CIDRs); e != nil {
			return executionUnavailable("address_outside_scope"), e
		}
	}
	sort.SliceStable(c.Servers, func(i, j int) bool { return c.Servers[i].Priority < c.Servers[j].Priority })
	var selected agentExecutionServer
	image := ""
	for _, server := range c.Servers {
		if !server.Enabled || executionServiceNetwork(server) != str(service.Data, "network") || !hasString(profile.ServerIDs, server.ID) {
			continue
		}
		if e := check(); e != nil {
			return executionUnavailable("policy_changed"), e
		}
		resolved, _, code := a.executionPreflight(ctx, server, profile.Image, rev)
		if code == "ok" {
			selected = server
			image = resolved
			break
		}
	}
	if selected.ID == "" {
		return executionUnavailable("no_available_server"), nil
	}
	if e := check(); e != nil {
		return executionUnavailable("policy_changed"), e
	}
	if !a.knowledgeRevisionCurrent(ctx, "execution", rev) {
		return executionUnavailable("configuration_changed"), nil
	}
	seconds := min(c.TimeoutSeconds, p.Timeout)
	deadline := time.Now().Add(time.Duration(seconds) * time.Second)
	if p.ExpiresAt.Before(deadline) {
		deadline = p.ExpiresAt
	}
	security, e := a.setting(ctx, "security")
	if e != nil {
		return executionUnavailable("target_ca_unavailable"), nil
	}
	probe := executionProbeInput{Kind: profile.Kind, Target: p.Target.String(), IP: ips[0].String(), TimeoutSeconds: seconds, Deadline: deadline, CAPEM: str(security, "trusted_ca_pem")}
	encoded, e := encodeExecutionProbe(probe)
	if e != nil {
		return executionUnavailable("probe_input_too_large"), nil
	}
	command := []string{"--execution-probe", encoded}
	// The durable intent precedes create. Once inserted, this scan can never choose
	// a different daemon/name, even if the POST response or control process is lost.
	j := executionJob{ScanID: scan.ID, ServerID: selected.ID, Server: selected, Name: "hunter-probe-" + a.memoryGroup("execution", scan.ID)[7:39], Image: image, ProfileID: profile.ID, Revision: rev, PolicyHash: p.Fingerprint, Status: "creating"}
	serverRaw, _ := json.Marshal(selected)
	serverCipher, e := a.encrypt(string(serverRaw))
	if e != nil {
		return executionUnavailable("storage_unavailable"), e
	}
	tx, e := a.DB.Begin(ctx)
	if e != nil {
		return executionUnavailable("storage_unavailable"), e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(748621099)`); e != nil {
		return executionUnavailable("storage_unavailable"), e
	}
	var count int
	if e = tx.QueryRow(ctx, `SELECT count(*) FROM agent_execution_jobs WHERE status IN ('creating','created','starting','running','uncertain')`).Scan(&count); e != nil {
		return executionUnavailable("storage_unavailable"), e
	}
	if count >= c.MaxConcurrent {
		return executionUnavailable("capacity_deferred"), nil
	}
	var lease bool
	if e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM scan_jobs WHERE scan_id=$1 AND status='leased' AND lease_until>now()) AND NOT (SELECT emergency FROM domain_runtime WHERE id=1)`, scan.ID).Scan(&lease); e != nil || !lease {
		return executionUnavailable("scan_not_active"), nil
	}
	_, e = tx.Exec(ctx, `INSERT INTO agent_execution_jobs(scan_id,server_id,server_encrypted,container_name,image_id,profile_id,revision,policy_hash,status) VALUES($1,$2,$3,$4,$5,$6,$7,$8,'creating')`, scan.ID, selected.ID, serverCipher, j.Name, image, profile.ID, rev, p.Fingerprint)
	if e != nil {
		return executionUnavailable("intent_conflict"), nil
	}
	if e = tx.Commit(ctx); e != nil {
		return executionUnavailable("intent_uncertain"), nil
	}

	body := map[string]any{"Image": image, "Entrypoint": []string{"/usr/local/bin/hunter"}, "Cmd": command, "User": "10001:10001", "WorkingDir": "/tmp", "Env": []string{}, "AttachStdout": false, "AttachStderr": false, "OpenStdin": false, "Tty": false, "Healthcheck": map[string]any{"Test": []string{"NONE"}}, "Labels": map[string]string{"hunter.scan_id": scan.ID, "hunter.execution": "fixed-probe-v1"}, "HostConfig": map[string]any{"ReadonlyRootfs": true, "Privileged": false, "CapDrop": []string{"ALL"}, "SecurityOpt": []string{"no-new-privileges:true"}, "NetworkMode": selected.Network, "Memory": 134217728, "NanoCpus": 500000000, "PidsLimit": 32, "RestartPolicy": map[string]any{"Name": "no"}, "Binds": []string{}, "Mounts": []any{}, "LogConfig": map[string]any{"Type": "json-file", "Config": map[string]string{"max-size": "64k", "max-file": "1"}}}}
	if e = check(); e != nil {
		result := executionUnavailable("policy_changed_before_create")
		bounded, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		if a.executionJobState(bounded, j.ScanID, "cancelled", "policy_changed_before_create", result) == nil {
			_ = a.executionCleaned(bounded, j.ScanID)
		}
		return result, e
	}
	_, _, code := executionDockerRequest(ctx, selected, "POST", "/v1.43/containers/create?name="+url.QueryEscape(j.Name), body)
	if code != "ok" {
		return a.deferExecution(ctx, j, "create_uncertain"), nil
	}
	container, code := executionInspect(ctx, selected, j.Name, scan.ID, image)
	if code != "ok" {
		return a.deferExecution(ctx, j, "create_verification_failed"), nil
	}
	j.ContainerID = container.ID
	if container.State.Status != "created" {
		return a.deferExecution(ctx, j, "unexpected_initial_state"), nil
	}
	_, e = a.DB.Exec(ctx, `UPDATE agent_execution_jobs SET container_id=$2,status='starting',updated_at=now() WHERE scan_id=$1`, scan.ID, container.ID)
	if e != nil {
		return a.deferExecution(ctx, j, "storage_unavailable"), nil
	}
	if e = check(); e != nil {
		return a.deferExecution(ctx, j, "policy_changed_before_start"), e
	}
	if !a.knowledgeRevisionCurrent(ctx, "execution", rev) {
		return a.deferExecution(ctx, j, "configuration_changed"), nil
	}
	_, _, code = executionDockerRequest(ctx, selected, "POST", "/v1.43/containers/"+url.PathEscape(j.Name)+"/start", nil)
	if code != "ok" {
		return a.deferExecution(ctx, j, "start_uncertain"), nil
	}
	j.Status = "running"
	_ = a.executionJobState(ctx, j.ScanID, "running", "started", nil)
	return a.resumeIsolatedObservation(ctx, j, p, check)
}
func (a *App) deferExecution(ctx context.Context, j executionJob, code string) map[string]any {
	result := executionUnavailable(code)
	bounded, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancel()
	_ = a.executionJobState(bounded, j.ScanID, "uncertain", code, result)
	// Cancellation must reach the actual daemon promptly; the maintenance loop
	// retries this same identity if the control connection is unavailable.
	if container, status := executionInspect(bounded, j.Server, j.Name, j.ScanID, j.Image); status == "ok" {
		// A verified identity also distinguishes a lost DELETE response from an
		// initial unknown create. Preserve it before attempting cleanup.
		_, _ = a.DB.Exec(bounded, `UPDATE agent_execution_jobs SET container_id=$2 WHERE scan_id=$1`, j.ScanID, container.ID)
		stopped := true
		if container.State.Running {
			_, _, status = executionDockerRequest(bounded, j.Server, "POST", "/v1.43/containers/"+url.PathEscape(j.Name)+"/kill?signal=SIGKILL", nil)
			stopped = status == "ok"
		}
		if stopped {
			_, _, status = executionDockerRequest(bounded, j.Server, "DELETE", "/v1.43/containers/"+url.PathEscape(j.Name)+"?force=1&v=0", nil)
			if status == "ok" {
				_ = a.executionJobState(bounded, j.ScanID, "cancelled", code, result)
				_ = a.executionCleaned(bounded, j.ScanID)
			}
		}
	}
	return result
}
func (a *App) resumeIsolatedObservation(ctx context.Context, j executionJob, p probePolicy, check func() error) (map[string]any, error) {
	if j.PolicyHash != p.Fingerprint || !a.knowledgeRevisionCurrent(ctx, "execution", j.Revision) {
		return a.deferExecution(ctx, j, "configuration_changed"), nil
	}
	if j.Status == "completed" && j.ResultCipher != "" {
		plain, e := a.decrypt(j.ResultCipher)
		if e != nil {
			return executionUnavailable("stored_result_unavailable"), e
		}
		var result map[string]any
		e = json.Unmarshal([]byte(plain), &result)
		return result, e
	}
	if hasString([]string{"cancelled", "failed"}, j.Status) {
		return executionUnavailable(j.Code), nil
	}
	for {
		if e := check(); e != nil {
			return a.deferExecution(ctx, j, "policy_changed"), e
		}
		if !a.knowledgeRevisionCurrent(ctx, "execution", j.Revision) {
			return a.deferExecution(ctx, j, "configuration_changed"), nil
		}
		container, code := executionInspect(ctx, j.Server, j.Name, j.ScanID, j.Image)
		if code != "ok" {
			return a.deferExecution(ctx, j, "inspection_unavailable"), nil
		}
		if container.State.Status == "exited" {
			if container.State.ExitCode != 0 {
				return a.deferExecution(ctx, j, "probe_exit_failed"), nil
			}
			result, code := executionLogs(ctx, j.Server, j.Name)
			if code != "ok" {
				return a.deferExecution(ctx, j, code), nil
			}
			if e := check(); e != nil {
				return a.deferExecution(ctx, j, "policy_changed"), e
			}
			result["engine"] = "isolated"
			result["degraded"] = str(result, "status") != "completed"
			state := "completed"
			if asBool(result["degraded"]) {
				state = "failed"
			}
			if e := a.executionJobState(ctx, j.ScanID, state, str(result, "code"), result); e != nil {
				return a.deferExecution(ctx, j, "result_storage_failed"), e
			}
			_, _, cleanup := executionDockerRequest(ctx, j.Server, "DELETE", "/v1.43/containers/"+url.PathEscape(j.Name)+"?v=0", nil)
			if cleanup == "ok" {
				_ = a.executionCleaned(ctx, j.ScanID)
			}
			return result, nil
		}
		if !container.State.Running {
			return a.deferExecution(ctx, j, "not_started_no_automatic_restart"), nil
		}
		timer := time.NewTimer(500 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return a.deferExecution(ctx, j, "execution_timeout"), nil
		case <-timer.C:
		}
	}
}
func (a *App) StartAgentExecutionMaintenance(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				bounded, cancel := context.WithTimeout(ctx, 15*time.Second)
				_ = a.executionMaintenance(bounded)
				cancel()
			}
		}
	}()
}
func (a *App) executionMaintenance(ctx context.Context) error {
	rows, e := a.DB.Query(ctx, `SELECT e.scan_id FROM agent_execution_jobs e WHERE e.cleanup_at IS NULL AND ((e.status IN ('completed','failed','cancelled') AND e.container_id<>'') OR (e.status IN ('creating','created','starting','running','uncertain') AND (e.status='uncertain' OR NOT EXISTS(SELECT 1 FROM scan_jobs j WHERE j.scan_id=e.scan_id AND j.status='leased' AND j.lease_until>now())))) ORDER BY e.updated_at LIMIT 10`)
	if e != nil {
		return e
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			rows.Close()
			return e
		}
		ids = append(ids, id)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	for _, id := range ids {
		j, e := a.executionJob(ctx, id)
		if e != nil {
			continue
		}
		container, code := executionInspect(ctx, j.Server, j.Name, j.ScanID, j.Image)
		terminal := hasString([]string{"completed", "failed", "cancelled"}, j.Status)
		if code == "http_404" && (terminal || j.ContainerID != "") {
			if !terminal {
				_ = a.executionJobState(ctx, id, "cancelled", "verified_container_no_longer_present", nil)
			}
			_ = a.executionCleaned(ctx, id)
			continue
		}
		if code == "http_404" { // Unknown initial create remains quarantined; never replace it.
			_ = a.executionJobState(ctx, id, "uncertain", "container_not_found_no_recreate", nil)
			continue
		}
		if code != "ok" {
			continue
		}
		if container.State.Running {
			_, _, code = executionDockerRequest(ctx, j.Server, "POST", "/v1.43/containers/"+url.PathEscape(j.Name)+"/kill?signal=SIGKILL", nil)
			if code != "ok" {
				continue
			}
		}
		_, _, code = executionDockerRequest(ctx, j.Server, "DELETE", "/v1.43/containers/"+url.PathEscape(j.Name)+"?force=1&v=0", nil)
		if code == "ok" {
			if !terminal {
				_ = a.executionJobState(ctx, id, "cancelled", "container_stopped_removed", nil)
			}
			_ = a.executionCleaned(ctx, id)
		}
	}
	return nil
}
