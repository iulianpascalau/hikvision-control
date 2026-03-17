SHELL := $(shell which bash)

.DEFAULT_GOAL := help

.PHONY: clean-test test build run-backend run-frontend run-solution

help:
	@echo -e ""
	@echo -e "Make commands:"
	@grep -E '^[a-zA-Z_-]+:.*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":"}; {printf "\t\033[36m%-30s\033[0m\n", $$1}'
	@echo -e ""

# #########################
# Base commands
# #########################

clean-tests:
	go clean -testcache

tests: clean-tests
	go test ./...

build: /
	go build -v -ldflags="-X main.appVersion=$(shell git describe --tags --long --dirty) -X main.commitID=$(shell git rev-parse HEAD)"

lint-install:
ifeq (,$(wildcard test -f bin/golangci-lint))
	@echo "Installing golint"
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s
endif

run-lint:
	@echo "Running golint"
	bin/golangci-lint run --max-issues-per-linter 0 --max-same-issues 0 --timeout=2m

run-frontend:
	cd frontend && \
	export NVM_DIR="$$HOME/.nvm" && \
	[ -s "$$NVM_DIR/nvm.sh" ] && \. "$$NVM_DIR/nvm.sh" && \
	nvm exec 22.12.0 npm run dev

run-backend: build
	./unifi-control --log-level *:DEBUG
