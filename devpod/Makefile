# Augustus Benchmark DevPod Configuration
# Workspace naming: $USER-augustus (e.g., nathan-augustus)

USERNAME ?= $(shell whoami)
WORKSPACE := $(USERNAME)-augustus

# Instance configurations
INSTANCE_CPU ?= t3.large
INSTANCE_GPU ?= g4dn.xlarge
INSTANCE_GPU_PRO ?= g6.xlarge

# Provider configuration
# Override with: AWS_PROVIDER=aws-us-west-2 make devpod-up-gpu
AWS_PROVIDER ?= aws-us-east-1

# AMI configurations
# GPU instances REQUIRE a Deep Learning AMI with NVIDIA Container Toolkit.
# The default AMI is for us-east-1. For other regions, find the equivalent:
#   aws ec2 describe-images --region <region> \
#     --filters "Name=name,Values=*Deep Learning Base OSS Nvidia*Ubuntu 24.04*" \
#     --query 'Images | sort_by(@, &CreationDate) | [-1].ImageId' --output text
#
# Azure and GCP providers handle GPU images natively - no AMI override needed.
AMI_GPU ?= ami-0e352d4aa794f5377

# Availability zone (must match your region; override if using non-default AZ)
AWS_AVAILABILITY_ZONE ?= us-east-1a

# Disk configurations (models need space: ~5GB per model + Docker + Go cache)
DISK_CPU ?= 40
DISK_GPU ?= 150
DISK_GPU_PRO ?= 200

# IDE configuration (cursor, vscode, goland, none)
IDE ?= cursor

# Source directory (repo root - devpod mounts this as the workspace)
SOURCE_DIR := ..

# Devcontainer paths (relative to SOURCE_DIR)
DEVCONTAINER_CPU := .devcontainer/cpu/devcontainer.json
DEVCONTAINER_GPU := .devcontainer/gpu/devcontainer.json

# Legacy REGION override
ifdef REGION
	AWS_PROVIDER := aws-$(REGION)
endif

.PHONY: help devpod-up-cpu devpod-up-gpu devpod-up-gpu-pro \
        devpod-recreate-cpu devpod-recreate-gpu devpod-recreate-gpu-pro

help: ## Show this help
	@echo "Augustus Benchmark DevPod"
	@echo "========================"
	@echo "Workspace: $(WORKSPACE)"
	@echo "Provider:  $(AWS_PROVIDER)"
	@echo "IDE:       $(IDE)"
	@echo ""
	@echo "Create Workspace:"
	@echo "  make devpod-up-cpu              CPU only - cloud APIs           ~$$0.08/hr"
	@echo "  make devpod-up-gpu              NVIDIA T4 16GB - models ≤14B   ~$$0.53/hr"
	@echo "  make devpod-up-gpu-pro          NVIDIA L4 24GB - models ≤32B   ~$$0.80/hr"
	@echo ""
	@echo "Recreate (delete + create):"
	@echo "  make devpod-recreate-cpu"
	@echo "  make devpod-recreate-gpu"
	@echo "  make devpod-recreate-gpu-pro"
	@echo ""
	@echo "Management:"
	@echo "  devpod up $(WORKSPACE)       Start workspace"
	@echo "  devpod stop $(WORKSPACE)     Stop workspace"
	@echo "  devpod ssh $(WORKSPACE)      SSH into workspace"
	@echo "  devpod delete $(WORKSPACE)   Delete workspace"
	@echo ""
	@echo "Inside the devpod:"
	@echo "  devpod/scripts/setup.sh        Configure LLM providers"
	@echo "  devpod/scripts/pull-models.sh  Pull local models (GPU only)"
	@echo "  devpod/scripts/benchmark.sh    Run benchmarks"
	@echo ""
	@echo "Cost (24/7):"
	@echo "  CPU (t3.large):     ~$$60/month  - Cloud APIs only"
	@echo "  GPU (g4dn.xlarge):  ~$$390/month - T4 16GB, models ≤14B"
	@echo "  GPU Pro (g6.xlarge):~$$590/month - L4 24GB, models ≤32B"
	@echo ""
	@echo "Configuration (override via environment):"
	@echo "  AWS_PROVIDER=aws-us-west-2     Override AWS provider/region"
	@echo "  AMI_GPU=ami-xxx                Override GPU AMI (region-specific)"
	@echo "  AWS_AVAILABILITY_ZONE=us-west-2a  Override availability zone"
	@echo "  USERNAME=other                  Override username (default: $(USERNAME))"
	@echo "  IDE=vscode                      Override IDE (cursor, vscode, goland, none)"

devpod-up-cpu: ## Create CPU instance for cloud APIs only
	@echo "Creating Augustus Benchmark workspace: $(WORKSPACE)"
	@echo "  Instance: $(INSTANCE_CPU) (CPU only)"
	@echo "  Provider: $(AWS_PROVIDER)"
	@devpod up $(SOURCE_DIR) \
		--devcontainer-path $(DEVCONTAINER_CPU) \
		--provider $(AWS_PROVIDER) \
		--id $(WORKSPACE) \
		--ide $(IDE) \
		--provider-option AWS_INSTANCE_TYPE=$(INSTANCE_CPU) \
		--provider-option AWS_DISK_SIZE=$(DISK_CPU)
	@echo ""
	@echo "Workspace ready. Run: devpod/scripts/setup.sh"

devpod-up-gpu: ## Create GPU instance with NVIDIA T4 (16GB) for models ≤14B
	@echo "Creating Augustus Benchmark workspace: $(WORKSPACE)"
	@echo "  Instance: $(INSTANCE_GPU) (NVIDIA T4, 16GB VRAM)"
	@echo "  Provider: $(AWS_PROVIDER)"
	@devpod up $(SOURCE_DIR) \
		--devcontainer-path $(DEVCONTAINER_GPU) \
		--provider $(AWS_PROVIDER) \
		--id $(WORKSPACE) \
		--ide $(IDE) \
		--provider-option AWS_INSTANCE_TYPE=$(INSTANCE_GPU) \
		--provider-option AWS_AMI=$(AMI_GPU) \
		--provider-option AWS_AVAILABILITY_ZONE=$(AWS_AVAILABILITY_ZONE) \
		--provider-option AWS_DISK_SIZE=$(DISK_GPU)
	@echo ""
	@echo "GPU workspace ready. Run: devpod/scripts/setup.sh"

devpod-up-gpu-pro: ## Create GPU Pro instance with NVIDIA L4 (24GB) for models ≤32B
	@echo "Creating Augustus Benchmark workspace: $(WORKSPACE)"
	@echo "  Instance: $(INSTANCE_GPU_PRO) (NVIDIA L4, 24GB VRAM)"
	@echo "  Provider: $(AWS_PROVIDER)"
	@devpod up $(SOURCE_DIR) \
		--devcontainer-path $(DEVCONTAINER_GPU) \
		--provider $(AWS_PROVIDER) \
		--id $(WORKSPACE) \
		--ide $(IDE) \
		--provider-option AWS_INSTANCE_TYPE=$(INSTANCE_GPU_PRO) \
		--provider-option AWS_AMI=$(AMI_GPU) \
		--provider-option AWS_AVAILABILITY_ZONE=$(AWS_AVAILABILITY_ZONE) \
		--provider-option AWS_DISK_SIZE=$(DISK_GPU_PRO)
	@echo ""
	@echo "GPU Pro workspace ready. Run: devpod/scripts/setup.sh"

devpod-recreate-cpu: ## Delete and recreate CPU workspace
	@devpod delete $(WORKSPACE) || true
	@$(MAKE) devpod-up-cpu

devpod-recreate-gpu: ## Delete and recreate GPU workspace
	@devpod delete $(WORKSPACE) || true
	@$(MAKE) devpod-up-gpu

devpod-recreate-gpu-pro: ## Delete and recreate GPU Pro workspace
	@devpod delete $(WORKSPACE) || true
	@$(MAKE) devpod-up-gpu-pro
