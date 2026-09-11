// Copyright (c) 2026 Hunter contributors. SPDX-License-Identifier: MIT
// Hunter integration seam. All other files in this package are pinned upstream
// bytes. This constructor deliberately does not initialize Docker, telemetry,
// provider discovery/probes, embedding services, or graph services.
package providers

import (
	"fmt"
	"sync"
	"sync/atomic"

	"pentagi/pkg/cast"
	"pentagi/pkg/config"
	"pentagi/pkg/csum"
	"pentagi/pkg/database"
	"pentagi/pkg/graphiti"
	"pentagi/pkg/providers/provider"
	"pentagi/pkg/templates"
	"pentagi/pkg/tools"
)

type EmbeddedConfig struct {
	DB            database.Querier
	Provider      provider.Provider
	Executor      tools.FlowToolsExecutor
	Prompter      templates.Prompter
	FlowID        int64
	Title         string
	MaxIterations int
	Stream        StreamMessageHandler
}

func NewEmbeddedFlow(c EmbeddedConfig) (FlowProvider, error) {
	if c.DB == nil || c.Provider == nil || c.Executor == nil || c.Prompter == nil || c.FlowID <= 0 {
		return nil, fmt.Errorf("embedded core requires database, provider, executor, prompter and flow ID")
	}
	if c.MaxIterations < 6 || c.MaxIterations > 100 {
		return nil, fmt.Errorf("embedded core iteration limit must be 6..100")
	}
	return &flowProvider{
		db: c.DB, mx: &sync.RWMutex{}, cfg: &config.Config{},
		flowID: c.FlowID, callCounter: &atomic.Int64{},
		image: "Hunter approved tools (no shell)", title: c.Title, language: "Korean",
		askUser: true, planning: true, tcIDTemplate: cast.ToolCallIDTemplate,
		prompter: c.Prompter, executor: c.Executor, Provider: c.Provider,
		graphitiClient: &graphiti.Client{}, streamCb: c.Stream,
		summarizer:      csum.NewSummarizer(csum.SummarizerConfig{PreserveLast: true, UseQA: true, KeepQASections: 1}),
		summarizerCache: newSummarizerCache(),
		maxGACallsLimit: c.MaxIterations, maxLACallsLimit: c.MaxIterations,
		buildMonitor: func() *executionMonitor {
			return &executionMonitor{enabled: true, sameThreshold: 5, totalThreshold: 15}
		},
	}, nil
}
