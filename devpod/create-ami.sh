#!/bin/bash
# Deploy instance, run setup script, create Augustus AMI
# Usage: ./create-ami.sh

set -e

REGION="${AWS_REGION:-us-east-2}"
INSTANCE_TYPE="c7i.4xlarge"  # GPU instance for local models
KEY_NAME="${KEY_NAME:-}"
AMI_NAME="augustus-research-$(date +%Y%m%d-%H%M%S)"

echo "=========================================="
echo "Augustus Research AMI Creation"
echo "=========================================="
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
echo "  Instance: $INSTANCE_TYPE"
echo "  Base AMI: $BASE_AMI (Ubuntu 24.04)"
echo "  Key: $KEY_NAME"
echo "  Security Group: $SG_ID"
echo "  AMI Name: $AMI_NAME"
echo ""
echo "Cost: ~$0.68/hr while running setup (~1-2 hours)"
echo ""
read -p "Launch instance and create AMI? (y/n) " -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Cancelled"
    exit 0
fi

# Launch instance
echo "Launching c7i.4xlarge instance..."
INSTANCE_ID=$(aws ec2 run-instances \
    --image-id "$BASE_AMI" \
    --instance-type "$INSTANCE_TYPE" \
    --key-name "$KEY_NAME" \
    --security-group-ids "$SG_ID" \
    --block-device-mappings '[{"DeviceName":"/dev/sda1","Ebs":{"VolumeSize":150,"VolumeType":"gp3"}}]' \
    --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=augustus-ami-builder}]" \
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
echo "Waiting 60 seconds for SSH to be ready..."
sleep 60

# Copy setup script
echo "Uploading setup script..."
scp -i ~/.ssh/id_ed25519 -o StrictHostKeyChecking=no \
    setup-ami-cpu.sh ubuntu@$PUBLIC_IP:/tmp/setup-ami-cpu.sh

# Run setup script
echo ""
echo "=========================================="
echo "Running setup script (1-2 hours)..."
echo "This will install:"
echo "  - Go, Python, NVIDIA drivers"
echo "  - Ollama + models (qwen, llama, deepseek)"
echo "  - Augustus + research tools"
echo "=========================================="
echo ""

ssh -i ~/.ssh/id_ed25519 -o StrictHostKeyChecking=no ubuntu@$PUBLIC_IP \
    "sudo bash /tmp/setup-ami-cpu.sh"

echo ""
echo "Setup complete! Stopping instance..."
aws ec2 stop-instances --instance-ids "$INSTANCE_ID" --region "$REGION" > /dev/null
aws ec2 wait instance-stopped --instance-ids "$INSTANCE_ID" --region "$REGION"

echo "Creating AMI..."
AMI_ID=$(aws ec2 create-image \
    --instance-id "$INSTANCE_ID" \
    --name "$AMI_NAME" \
    --description "Augustus LLM Research Environment - CPU-optimized with local models" \
    --region "$REGION" \
    --query 'ImageId' --output text)

echo ""
echo "=========================================="
echo "AMI Creation Started!"
echo "=========================================="
echo ""
echo "AMI ID: $AMI_ID"
echo "Name: $AMI_NAME"
echo "Status: Creating (will take 10-15 minutes)"
echo ""
echo "Terminating builder instance..."
aws ec2 terminate-instances --instance-ids "$INSTANCE_ID" --region "$REGION" > /dev/null

echo ""
echo "Wait for AMI to be available:"
echo "  aws ec2 wait image-available --image-ids $AMI_ID --region $REGION"
echo ""
echo "Then register with DevPod:"
echo "  devpod provider add aws \\"
echo "    -o AWS_REGION=$REGION \\"
echo "    -o AWS_AMI=$AMI_ID \\"
echo "    -o AWS_INSTANCE_TYPE=c7i.4xlarge \\"
echo "    -o AWS_DISK_SIZE=150 \\"
echo "    -o AWS_VPC_ID=vpc-04ded0246f0e1cbb9 \\"
echo "    --name augustus-provider"
echo ""
echo "Launch workspace:"
echo "  devpod up --provider augustus-provider \\"
echo "    github.com/praetorian-inc/chariot-development-platform \\"
echo "    --ide cursor --id augustus-research"
echo ""
echo "Or launch directly as EC2 instance:"
echo "  aws ec2 run-instances \\"
echo "    --image-id $AMI_ID \\"
echo "    --instance-type c7i.4xlarge \\"
echo "    --key-name $KEY_NAME \\"
echo "    --security-group-ids $SG_ID \\"
echo "    --region $REGION"
echo ""
