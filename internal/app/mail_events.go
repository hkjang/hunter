package app

import (
	"context"
	"fmt"
	"net/url"
	"strings"
)

// The five mail events and where they are raised. Each site passes the querier it is
// already using so the outbox row commits together with the change it announces.
//
//	approval_requested  insertPreparedScan  a scan now waits for a lead or administrator
//	approval_decided    approveScan         the requester learns the decision
//	scan_failed         finishScan          a scan ended failed/inconclusive (not by the agent, not cancelled)
//	agent_waiting       suspendAgent        the agent run needs the requester's input
//	agent_failed        finishAgent         the agent run stopped failed/inconclusive

func mailSubject(text string) string {
	return "[Hunter] " + strings.Join(strings.Fields(text), " ")
}

func mailItemPath(kind, id string) string {
	return "/" + kind + "?item=" + url.QueryEscape(id)
}

func mailScanStatusLabel(status string) string {
	switch status {
	case "failed":
		return "실패"
	case "inconclusive":
		return "결과 미확정"
	case "approved", "queued":
		return "승인됨"
	case "rejected":
		return "반려됨"
	}
	return status
}

// mailApprovalRequested tells every administrator and the service team's leads, except the
// requester, that a review is waiting. Campaign bursts are bundled by the sender.
func (a *App) mailApprovalRequested(ctx context.Context, q mailStore, u User, scanID string, scan map[string]any) {
	var team string
	_ = q.QueryRow(ctx, `SELECT coalesce(data->>'team','') FROM resources WHERE id=$1 AND kind='services'`, str(scan, "service_id")).Scan(&team)
	approvers, err := mailApprovers(ctx, q, team)
	if err != nil {
		return
	}
	name := str(scan, "name")
	body := fmt.Sprintf("%s 님이 진단 실행 검토를 요청했습니다.\n\n진단: %s\n서비스: %s\n프로파일: %s\n\n검토·승인 화면에서 승인하거나 반려해 주세요.", u.Name, name, str(scan, "service_name"), str(scan, "profile"))
	a.mailNotify(ctx, q, u.ID, approvers, mailNotice{Event: "approval_requested", EntityID: scanID, Subject: mailSubject("진단 검토 요청: " + name), Body: body, Path: "/approvals"})
}

// mailApprovalDecided tells the requester how their review ended.
func (a *App) mailApprovalDecided(ctx context.Context, q mailStore, reviewer User, scan domainResource, decision, reason string) {
	name := str(scan.Data, "name")
	body := fmt.Sprintf("요청한 진단 검토가 %s 처리되었습니다.\n\n진단: %s\n서비스: %s\n검토자: %s\n사유: %s", mailScanStatusLabel(decision), name, str(scan.Data, "service_name"), reviewer.Name, strings.TrimSpace(reason))
	a.mailNotify(ctx, q, reviewer.ID, []string{str(scan.Data, "requested_by"), scan.OwnerID}, mailNotice{Event: "approval_decided", EntityID: scan.ID, Subject: mailSubject("진단 검토 결과 (" + mailScanStatusLabel(decision) + "): " + name), Body: body, Path: mailItemPath("scans", scan.ID)})
}

// mailScanFailed tells the requester a scan did not complete. Scans an agent run started are
// left to the run's own event so one stopped run does not turn into a pile of messages.
func (a *App) mailScanFailed(ctx context.Context, q mailStore, scanID, status string) {
	var ownerID string
	var data map[string]any
	if err := q.QueryRow(ctx, `SELECT owner_id,data FROM resources WHERE id=$1 AND kind='scans'`, scanID).Scan(&ownerID, &data); err != nil || str(data, "agent_run_id") != "" {
		return
	}
	name := str(data, "name")
	body := fmt.Sprintf("진단이 완료되지 못했습니다.\n\n진단: %s\n서비스: %s\n상태: %s\n\n진단 실행 화면에서 기록을 확인하고 필요하면 다시 요청하세요.", name, str(data, "service_name"), mailScanStatusLabel(status))
	a.mailNotify(ctx, q, "", []string{str(data, "requested_by"), ownerID}, mailNotice{Event: "scan_failed", EntityID: scanID, Subject: mailSubject("진단 " + mailScanStatusLabel(status) + ": " + name), Body: body, Path: mailItemPath("scans", scanID)})
}

// mailAgentRun tells the requester their agent run needs them or stopped.
func (a *App) mailAgentRun(ctx context.Context, q mailStore, v agentRun, event, status, reason string) {
	title := strings.TrimSpace(v.Title)
	if title == "" {
		title = v.ServiceName + " 에이전트 진단"
	}
	reason = notificationText(strings.TrimSpace(reason), 300)
	var subject, body string
	if event == "agent_waiting" {
		subject = mailSubject("에이전트 진단이 입력을 기다립니다: " + title)
		body = fmt.Sprintf("에이전트 진단이 추가 입력을 기다리며 멈춰 있습니다.\n\n실행: %s\n서비스: %s\n\n%s\n\n에이전트 진단 화면에서 답을 입력하고 재개하세요.", title, v.ServiceName, reason)
	} else {
		subject = mailSubject("에이전트 진단 중단 (" + mailScanStatusLabel(status) + "): " + title)
		body = fmt.Sprintf("에이전트 진단이 완료되지 못하고 멈췄습니다.\n\n실행: %s\n서비스: %s\n상태: %s\n\n%s\n\n에이전트 진단 화면에서 내용을 확인하고 필요하면 새 실행을 시작하세요.", title, v.ServiceName, mailScanStatusLabel(status), reason)
	}
	a.mailNotify(ctx, q, "", []string{v.OwnerID}, mailNotice{Event: event, EntityID: v.ID, Subject: subject, Body: body, Path: "/agents/" + url.PathEscape(v.ID)})
}
