package main

import (
	"context"
	"flag"
	"github.com/hkjang/hunter/internal/app"
	"github.com/hkjang/hunter/internal/webassets"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

var version = "1.14.0"

func main() {
	workerOnly := flag.Bool("worker-only", false, "run the network worker without the web control server")
	workerID := flag.String("worker-id", "", "stable worker identity; manage its enabled state and network in the administrator page")
	executionProbe := flag.String("execution-probe", "", "run a fixed administrator-approved diagnostic probe payload")
	flag.Parse()
	if *workerOnly && *workerID == "" {
		slog.Error("--worker-only requires a stable --worker-id")
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *executionProbe != "" {
		if err := app.RunExecutionProbe(ctx, *executionProbe, os.Stdout); err != nil {
			slog.Error("fixed diagnostic probe failed")
			os.Exit(1)
		}
		return
	}
	a, e := app.New(ctx, version, webassets.FS())
	if e != nil {
		slog.Error("hunter startup failed", "error", e)
		os.Exit(1)
	}
	defer a.DB.Close()
	a.WorkerID = *workerID
	a.StartWorkers(ctx)
	if *workerOnly {
		slog.Info("hunter worker started", "version", version, "worker_id", *workerID)
		<-ctx.Done()
		return
	}
	a.StartScheduler(ctx)
	a.StartMaintenance(ctx)
	a.StartNotifications(ctx)
	a.StartAutomation(ctx)
	a.StartAgents(ctx)
	a.StartAgentTelemetry(ctx)
	a.StartAgentExecutionMaintenance(ctx)
	srv := &http.Server{Addr: ":8080", Handler: a.Routes(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 1 << 20}
	go func() {
		<-ctx.Done()
		c, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = srv.Shutdown(c)
	}()
	slog.Info("hunter started", "version", version, "listen", ":8080")
	if e = srv.ListenAndServe(); e != nil && e != http.ErrServerClosed {
		slog.Error("HTTP server failed", "error", e)
		os.Exit(1)
	}
}
