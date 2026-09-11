package pentagicore

import (
	"context"
	"database/sql"

	"pentagi/pkg/database"
)

type runLogs struct {
	q    *database.Queries
	run  *runState
	flow int64
}

func (l *runLogs) PutMsg(ctx context.Context, t database.MsglogType, task, subtask *int64, stream int64, thinking, msg string) (int64, error) {
	// Detailed reasoning is retained by the private message chain when the model
	// needs it; public event/log views contain only content and tool summaries.
	row, err := l.q.CreateMsgLog(ctx, database.CreateMsgLogParams{Type: t, Message: msg, FlowID: l.flow, TaskID: database.Int64ToNullInt64(task), SubtaskID: database.Int64ToNullInt64(subtask)})
	if err == nil && msg != "" {
		l.run.emit(Event{Type: "message", Role: string(t), Message: msg, Data: map[string]any{"message_id": row.ID}})
	}
	return row.ID, err
}
func (l *runLogs) UpdateMsgResult(ctx context.Context, id, stream int64, result string, format database.MsglogResultFormat) error {
	_, err := l.q.UpdateMsgLogResult(ctx, database.UpdateMsgLogResultParams{ID: id, Result: result, ResultFormat: format})
	if err == nil {
		l.run.emit(Event{Type: "message_result", Message: result, Data: map[string]any{"message_id": id, "format": string(format)}})
	}
	return err
}
func (l *runLogs) PutLog(ctx context.Context, initiator, executor database.MsgchainType, task, result string, taskID, subtaskID *int64) (int64, error) {
	row, err := l.q.CreateResultMsgLog(ctx, database.CreateResultMsgLogParams{Type: database.MsglogTypeAnswer, Message: task, Result: result, ResultFormat: database.MsglogResultFormatMarkdown, FlowID: l.flow, TaskID: database.Int64ToNullInt64(taskID), SubtaskID: database.Int64ToNullInt64(subtaskID), Thinking: sql.NullString{}})
	if err == nil {
		l.run.emit(Event{Type: "delegation", Role: string(executor), Message: result, Status: "finished", Data: map[string]any{"initiator": string(initiator), "message_id": row.ID}})
	}
	return row.ID, err
}
