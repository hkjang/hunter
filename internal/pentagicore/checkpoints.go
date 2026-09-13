package pentagicore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/vxcontrol/langchaingo/llms"
)

type coreCheckpoint struct {
	FlowID         int64  `json:"flow_id"`
	TaskID         int64  `json:"task_id"`
	Phase          string `json:"phase"`
	SubtaskID      int64  `json:"subtask_id"`
	ChainID        int64  `json:"chain_id"`
	Executions     int    `json:"executions"`
	Calls          int64  `json:"calls"`
	Input          int64  `json:"input"`
	Output         int64  `json:"output"`
	WaitInputAfter int64  `json:"wait_input_after"`
}

func (e *Engine) openCheckpoint(ctx context.Context, req Request) (coreCheckpoint, error) {
	var cp coreCheckpoint
	tx, err := e.db.BeginTx(ctx, nil)
	if err != nil {
		return cp, err
	}
	defer tx.Rollback()
	var raw []byte
	var service, status string
	err = tx.QueryRowContext(ctx, `SELECT f.service_id,f.status,c.payload FROM flows f LEFT JOIN hunter_checkpoints c ON c.flow_id=f.id WHERE f.hunter_run_id=$1 FOR UPDATE OF f`, req.RunID).Scan(&service, &status, &raw)
	if err == nil {
		if !req.Resume || service != req.ServiceID || len(raw) == 0 {
			return cp, errors.New("existing agent flow requires an explicit compatible resume")
		}
		if err = json.Unmarshal(raw, &cp); err != nil {
			return cp, err
		}
		if cp.Phase == "done" {
			return cp, errors.New("completed flow cannot be resumed")
		}
		_, err = tx.ExecContext(ctx, `UPDATE flows SET status='running',updated_at=now() WHERE id=$1`, cp.FlowID)
		if err != nil {
			return cp, err
		}
		return cp, tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return cp, err
	}
	err = tx.QueryRowContext(ctx, `INSERT INTO flows(hunter_run_id,service_id,status) VALUES($1,$2,'running') RETURNING id`, req.RunID, req.ServiceID).Scan(&cp.FlowID)
	if err != nil {
		return cp, fmt.Errorf("create unique agent run: %w", err)
	}
	err = tx.QueryRowContext(ctx, `INSERT INTO tasks(status,title,input,flow_id) VALUES('running','Hunter 보안 검증',$1,$2) RETURNING id`, req.Prompt, cp.FlowID).Scan(&cp.TaskID)
	if err != nil {
		return cp, err
	}
	cp.Phase = "plan"
	raw, err = json.Marshal(cp)
	if err != nil {
		return cp, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO hunter_checkpoints(flow_id,payload) VALUES($1,$2)`, cp.FlowID, raw)
	if err != nil {
		return cp, err
	}
	return cp, tx.Commit()
}
func (e *Engine) saveCheckpoint(ctx context.Context, cp coreCheckpoint) error {
	b, err := json.Marshal(cp)
	if err != nil {
		return err
	}
	_, err = e.db.ExecContext(ctx, `UPDATE hunter_checkpoints SET payload=$2,updated_at=now() WHERE flow_id=$1`, cp.FlowID, b)
	return err
}

// A suspended call may have persisted the assistant request without its tool
// response. Complete the protocol with an explicit unknown observation, never
// by replaying the command. Actual scan/tool receipts remain in Hunter.
func (e *Engine) restoreSuspendedChain(ctx context.Context, id int64) error {
	tx, err := e.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var raw []byte
	if err = tx.QueryRowContext(ctx, `SELECT chain FROM msgchains WHERE id=$1 FOR UPDATE`, id).Scan(&raw); err != nil {
		return err
	}
	var chain []llms.MessageContent
	if err = json.Unmarshal(raw, &chain); err != nil {
		return err
	}
	pending := map[string]string{}
	order := []string{}
	for _, m := range chain {
		for _, p := range m.Parts {
			switch v := p.(type) {
			case llms.ToolCall:
				if v.FunctionCall != nil {
					pending[v.ID] = v.FunctionCall.Name
					order = append(order, v.ID)
				}
			case llms.ToolCallResponse:
				delete(pending, v.ToolCallID)
			}
		}
	}
	for _, callID := range order {
		if name, ok := pending[callID]; ok {
			chain = append(chain, llms.MessageContent{Role: llms.ChatMessageTypeTool, Parts: []llms.ContentPart{llms.ToolCallResponse{ToolCallID: callID, Name: name, Content: "이전 실행이 일시 중단되어 이 도구 응답의 저장 완료를 확인할 수 없습니다. 성공으로 간주하거나 같은 외부 작업을 다시 실행하지 마세요. service_context, list_findings, scan_result로 현재 기록을 확인하세요."}}})
			delete(pending, callID)
		}
	}
	chain = append(chain, llms.TextParts(llms.ChatMessageTypeHuman, "저장된 같은 실행을 재개합니다. 기존의 완료한 작업과 불명 상태를 먼저 확인하고, 완료·접수된 외부 진단은 반복하지 마세요. 추가 사용자 입력이 있으면 반영하되 기존 승인 범위와 정책은 유지하세요."))
	raw, err = json.Marshal(chain)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE msgchains SET chain=$2,updated_at=now() WHERE id=$1`, id, raw)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (e *Engine) checkpointChains(ctx context.Context, flowID int64) ([]int64, error) {
	rows, err := e.db.QueryContext(ctx, `SELECT id FROM msgchains WHERE flow_id=$1 ORDER BY id LIMIT 501`, flowID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := []int64{}
	for rows.Next() {
		var id int64
		if err = rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	if len(ids) > 500 {
		return nil, errors.New("agent checkpoint chain bound exceeded")
	}
	return ids, rows.Err()
}
