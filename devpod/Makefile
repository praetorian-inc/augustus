# Augustus LLM Research DevPod
# CPU-only, API-focused research environment

IMAGE := ghcr.io/praetorian-inc/augustus-research
TAG := $(shell date -u +"%Y%m%d-%H%M%S")

.PHONY: build push run shell test deploy help

help:
	@echo "Augustus Research DevPod"
	@echo ""
	@echo "  make build    - Build Docker image (~4GB)"
	@echo "  make push     - Push to ghcr.io"
	@echo "  make run      - Run locally with .env"
	@echo "  make shell    - Interactive shell"
	@echo "  make test     - Test API providers"
	@echo "  make deploy   - Deploy to AWS EC2"
	@echo ""

build:
	docker build -t $(IMAGE):$(TAG) -t $(IMAGE):latest -f Dockerfile ..

push: build
	docker push $(IMAGE):$(TAG)
	docker push $(IMAGE):latest

run:
	@test -f .env || (echo "Create .env first: cp .env.example .env" && exit 1)
	docker run -it --rm \
		-v $(PWD)/../:/workspace/augustus:rw \
		-v $(PWD)/results:/workspace/results:rw \
		-p 8888:8888 \
		--env-file .env \
		$(IMAGE):latest

shell:
	docker run -it --rm \
		-v $(PWD)/../:/workspace/augustus:rw \
		--env-file .env \
		$(IMAGE):latest /bin/bash

test:
	@test -f .env || (echo "Create .env first" && exit 1)
	docker run --rm --env-file .env $(IMAGE):latest python3 /workspace/scripts/test-providers.py

deploy:
	@./deploy.sh
