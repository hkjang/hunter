VERSION := $(shell cat VERSION)
.PHONY: build test frontend image docs
frontend:
	cd web && npm ci && npm run build
build: frontend
	rm -rf internal/webassets/dist
	mkdir -p internal/webassets/dist bin
	touch internal/webassets/dist/.gitkeep
	cp -a web/dist/. internal/webassets/dist/
	go build -trimpath -ldflags "-X main.version=$(VERSION)" -o bin/hunter ./cmd/hunter
test:
	go vet ./...
	go test -race ./...
image:
	bash scripts/release.sh $(VERSION)
docs:
	cd docs && npm ci && npx playwright install chromium
	node scripts/render-guides.mjs
	node scripts/check-docs.mjs
