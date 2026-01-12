#!/bin/bash
# Deploy r8i.48xlarge instance, run setup script, create Augustus High-Memory AMI
# Includes ALL frontier models (Llama 4, Qwen3, DeepSeek R1, Mistral Large 3, Kimi K2)
# Usage: ./create-ami-highmem.sh

set -e

REGION="${AWS_REGION:-us-east-2}"
INSTANCE_TYPE="r8i.48xlarge"  # 384 vCPU, 3TB RAM
KEY_NAME="${KEY_NAME:-}"
AMI_NAME="augustus-research-highmem-$(date +%Y%m%d-%H%M%S)"
DISK_SIZE=2000  # 2TB for all models

echo "=========================================="
echo "Augustus Research AMI Creation (High Memory)"
echo "=========================================="
echo ""
echo "This will create an AMI with ALL frontier models:"
echo "  - Llama 4 (Scout 109B, Maverick 400B)"
echo "  - Qwen3 (4B → 235B MoE)"
echo "  - DeepSeek R1 (671B MoE)"
echo "  - Mistral Large 3 (675B MoE)"
echo "  - Kimi K2 (1T MoE)"
echo ""
echo "Instance: r8i.48xlarge (384 vCPU, 3TB RAM)"
echo "Disk: ${DISK_SIZE}GB"
echo ""
echo "⚠️  COST WARNING:"
echo "  - Instance: ~\$20/hr while running setup (~3-5 hours)"
echo "  - Estimated setup cost: ~\$60-100"
echo "  - Running cost after: ~\$20/hr (only pay when running)"
echo ""

# Check prerequisites
if ! command -v aws &> /dev/null; then
    echo "Error: AWS CLI not installed"
    exit 1
fi

if ! aws sts get-caller-identity &> /dev/null; then
    echo "Error: AWS credentials not configured"
    exit 1
fi

# Get key name if not set
if [ -z "$KEY_NAME" ]; then
    echo "Available SSH keys:"
    aws ec2 describe-key-pairs --query 'KeyPairs[].KeyName' --output text --region "$REGION"
    echo ""
    read -p "Enter key name: " KEY_NAME
fi

# Find latest Ubuntu 24.04 AMI
echo "Finding Ubuntu 24.04 AMI..."
BASE_AMI=$(aws ec2 describe-images \
    --owners 099720109477 \
    --filters "Name=name,Values=ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*" \
    --query 'sort_by(Images, &CreationDate)[-1].ImageId' \
    --output text --region "$REGION")

# Get or create security group
SG_NAME="augustus-research-sg"
SG_ID=$(aws ec2 describe-security-groups --filters "Name=group-name,Values=$SG_NAME" \
    --query 'SecurityGroups[0].GroupId' --output text --region "$REGION" 2>/dev/null || echo "None")

if [ "$SG_ID" = "None" ] || [ -z "$SG_ID" ]; then
    echo "Creating security group..."
    SG_ID=$(aws ec2 create-security-group \
        --group-name "$SG_NAME" \
        --description "Augustus Research - SSH only" \
        --region "$REGION" \
        --query 'GroupId' --output text)

    aws ec2 authorize-security-group-ingress --group-id "$SG_ID" \
        --protocol tcp --port 22 --cidr 0.0.0.0/0 --region "$REGION"

    echo "Created security group: $SG_ID"
fi

echo ""
echo "Configuration:"
echo "  Region: $REGION"
echo "  Instance: $INSTANCE_TYPE (384 vCPU, 3TB RAM)"
echo "  Disk: ${DISK_SIZE}GB"
echo "  Base AMI: $BASE_AMI (Ubuntu 24.04)"
echo "  Key: $KEY_NAME"
echo "  Security Group: $SG_ID"
echo "  AMI Name: $AMI_NAME"
echo ""
read -p "Launch instance and create AMI? (y/n) " -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Cancelled"
    exit 0
fi

# Launch instance
echo "Launching r8i.48xlarge instance..."
INSTANCE_ID=$(aws ec2 run-instances \
    --image-id "$BASE_AMI" \
    --instance-type "$INSTANCE_TYPE" \
    --key-name "$KEY_NAME" \
    --security-group-ids "$SG_ID" \
    --block-device-mappings "[{\"DeviceName\":\"/dev/sda1\",\"Ebs\":{\"VolumeSize\":$DISK_SIZE,\"VolumeType\":\"gp3\",\"Iops\":16000,\"Throughput\":1000}}]" \
    --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=augustus-highmem-ami-builder}]" \
    --region "$REGION" \
    --query 'Instances[0].InstanceId' --output text)

echo "Instance launched: $INSTANCE_ID"
echo "Waiting for instance to be running..."

aws ec2 wait instance-running --instance-ids "$INSTANCE_ID" --region "$REGION"

PUBLIC_IP=$(aws ec2 describe-instances \
    --instance-ids "$INSTANCE_ID" \
    --query 'Reservations[0].Instances[0].PublicIpAddress' \
    --output text --region "$REGION")

echo "Instance running at: $PUBLIC_IP"
echo ""
echo "Waiting 90 seconds for SSH to be ready..."
sleep 90

# Copy setup script
echo "Uploading setup script..."
scp -i ~/.ssh/id_ed25519 -o StrictHostKeyChecking=no \
    setup-ami-highmem.sh ubuntu@$PUBLIC_IP:/tmp/setup-ami-highmem.sh

# Run setup script
echo ""
echo "=========================================="
echo "Running setup script (3-5 hours)..."
echo "This will install:"
echo "  - Go, Python, system tools"
echo "  - Ollama with optimized settings"
echo "  - ALL frontier models (~1.5TB)"
echo "  - Augustus + research tools"
echo "=========================================="
echo ""
echo "You can monitor progress by SSH'ing to: ssh ubuntu@$PUBLIC_IP"
echo ""

ssh -i ~/.ssh/id_ed25519 -o StrictHostKeyChecking=no ubuntu@$PUBLIC_IP \
    "sudo bash /tmp/setup-ami-highmem.sh"

echo ""
echo "Setup complete! Stopping instance..."
aws ec2 stop-instances --instance-ids "$INSTANCE_ID" --region "$REGION" > /dev/null
aws ec2 wait instance-stopped --instance-ids "$INSTANCE_ID" --region "$REGION"

echo "Creating AMI (this will take 30-60 minutes for 2TB disk)..."
AMI_ID=$(aws ec2 create-image \
    --instance-id "$INSTANCE_ID" \
    --name "$AMI_NAME" \
    --description "Augustus LLM Research - High Memory with ALL Frontier Models (Llama4, Qwen3, DeepSeek R1, Mistral Large 3, Kimi K2)" \
    --region "$REGION" \
    --query 'ImageId' --output text)

echo ""
echo "=========================================="
echo "AMI Creation Started!"
echo "=========================================="
echo ""
echo "AMI ID: $AMI_ID"
echo "Name: $AMI_NAME"
echo "Status: Creating (will take 30-60 minutes for 2TB disk)"
echo ""
echo "Terminating builder instance..."
aws ec2 terminate-instances --instance-ids "$INSTANCE_ID" --region "$REGION" > /dev/null

echo ""
echo "Wait for AMI to be available:"
echo "  aws ec2 wait image-available --image-ids $AMI_ID --region $REGION"
echo ""
echo "Launch instance when needed:"
echo "  aws ec2 run-instances \\"
echo "    --image-id $AMI_ID \\"
echo "    --instance-type r8i.48xlarge \\"
echo "    --key-name $KEY_NAME \\"
echo "    --security-group-ids $SG_ID \\"
echo "    --region $REGION"
echo ""
echo "Stop when done (stops billing):"
echo "  aws ec2 stop-instances --instance-ids <instance-id>"
echo ""
echo "Remember: You only pay when the instance is RUNNING!"
echo ""
