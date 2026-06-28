# PlainQ performance / AB-testing harness.
#
# Quick start:
#   make ab                 # build both variants, run the AB test, report
#   make ab DURATION=5m VUS=50
#   make ab BASELINE_REF=v0.1.0
#   make up / make down     # manage an already-built stack
#   make clean              # tear everything down and remove images/worktree

COMPOSE := docker compose -f docker-compose.yml

# Workload knobs (forwarded to scripts/run.sh and the k6 container).
BASELINE_REF ?= origin/main
VUS          ?= 20
DURATION     ?= 2m
BATCH_SIZE   ?= 1
MSG_BYTES    ?= 256

export VUS DURATION BATCH_SIZE MSG_BYTES

.PHONY: ab
ab: ## Build both variants, run the AB test, render the report
	BASELINE_REF=$(BASELINE_REF) ./scripts/run.sh

.PHONY: up
up: ## Start the stack (requires images already built by `make ab`)
	$(COMPOSE) up -d victoriametrics grafana plainq-baseline plainq-candidate

.PHONY: k6
k6: ## Re-run only the k6 workload against the running stack
	@mkdir -p results && chmod 0777 results
	$(COMPOSE) run --rm k6

.PHONY: down
down: ## Stop the stack
	$(COMPOSE) down

.PHONY: logs
logs: ## Follow stack logs
	$(COMPOSE) logs -f

.PHONY: dashboard
dashboard: ## Print the Grafana dashboard URL
	@echo "Grafana:        http://localhost:3000  (PlainQ AB Performance)"
	@echo "VictoriaMetrics http://localhost:8428"

.PHONY: clean
clean: ## Tear down, remove volumes, images, results, and baseline worktree
	-$(COMPOSE) down -v
	-docker image rm plainq-perf:candidate plainq-perf:baseline 2>/dev/null || true
	-git worktree remove --force .baseline 2>/dev/null || true
	-rm -rf .baseline results

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

.DEFAULT_GOAL := help
