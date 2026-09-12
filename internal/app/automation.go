package app

import (
	"context"
	"log/slog"
	"time"
)

// Only the control server starts automation. Database leases and uniqueness
// constraints also protect deployments with more than one control instance.
func (a *App) StartAutomation(ctx context.Context) {
	run := func(name string, interval time.Duration, tick func(context.Context, time.Time) error) {
		go func() {
			timer := time.NewTicker(interval)
			defer timer.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case now := <-timer.C:
					if err := tick(ctx, now); err != nil && ctx.Err() == nil {
						slog.Warn("automation cycle failed", "component", name, "error", err)
					}
				}
			}
		}()
	}
	run("notification_policy", 10*time.Second, func(c context.Context, now time.Time) error {
		_, err := a.processNotificationAutomation(c, now)
		return err
	})
	run("notification_delivery", 5*time.Second, func(c context.Context, now time.Time) error {
		_, err := a.processNotificationOperations(c, now)
		return err
	})
	run("workflow", 30*time.Second, func(c context.Context, _ time.Time) error { return a.WorkflowAutomationTick(c) })
}
