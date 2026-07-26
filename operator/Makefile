# PlainQ operator.
#
# A separate module from the server on purpose: controller-runtime pulls in the
# whole Kubernetes client tree, and PlainQ's headline property is one small
# static binary.

IMAGE ?= ghcr.io/marsolab/plainq-operator
VERSION ?= dev
CONTROLLER_GEN ?= $(CURDIR)/bin/controller-gen
CONTROLLER_TOOLS_VERSION ?= v0.19.0

.PHONY: help
help: ## Print this help.
	@grep -hE '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'

.PHONY: deps
deps: ## Download module dependencies.
	go mod tidy && go mod download

$(CONTROLLER_GEN):
	GOBIN=$(CURDIR)/bin go install sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_TOOLS_VERSION)

.PHONY: generate
generate: $(CONTROLLER_GEN) ## Regenerate deepcopy functions.
	$(CONTROLLER_GEN) object:headerFile="" paths=./api/...

.PHONY: manifests
manifests: $(CONTROLLER_GEN) ## Regenerate CRDs, RBAC and webhook manifests.
	$(CONTROLLER_GEN) crd rbac:roleName=plainq-operator webhook paths=./... \
		output:crd:artifacts:config=config/crd/bases \
		output:rbac:artifacts:config=config/rbac \
		output:webhook:artifacts:config=config/webhook

.PHONY: fmt
fmt: ## Format the code.
	gofmt -w ./api ./cmd ./internal

.PHONY: vet
vet: ## Run go vet.
	go vet ./...

.PHONY: lint
lint: ## Run golangci-lint using the repository configuration.
	golangci-lint run ./...

.PHONY: test
test: generate manifests ## Run the unit tests with the race detector.
	go test -race ./...

.PHONY: build
build: generate ## Build the manager binary.
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/manager ./cmd/manager

.PHONY: docker
docker: ## Build the operator image.
	docker build -t $(IMAGE):$(VERSION) -f Dockerfile ..

.PHONY: install
install: manifests ## Install the CRDs into the current cluster.
	kubectl apply -f config/crd/bases

.PHONY: uninstall
uninstall: ## Remove the CRDs from the current cluster.
	kubectl delete --ignore-not-found -f config/crd/bases

.PHONY: deploy
deploy: install ## Deploy the operator into the current cluster.
	kubectl apply -f config/manager/manager.yaml
	kubectl apply -f config/rbac/role.yaml
	kubectl apply -f config/rbac/role_binding.yaml

.PHONY: undeploy
undeploy: ## Remove the operator from the current cluster.
	kubectl delete --ignore-not-found -f config/rbac/role_binding.yaml
	kubectl delete --ignore-not-found -f config/rbac/role.yaml
	kubectl delete --ignore-not-found -f config/manager/manager.yaml

.PHONY: run
run: generate ## Run the manager locally against the current kubecontext.
	go run ./cmd/manager -leader-elect=false -enable-webhooks=false

.PHONY: check
check: fmt vet test ## Format, vet and test.
