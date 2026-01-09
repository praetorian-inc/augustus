#!/bin/bash
# Create Augustus AMI with automatic setup (no SSH required)
# Setup runs via user-data at boot time

set -e

REGION="${AWS_REGION:-us-east-2}"
INSTANCE_TYPE="c7i.4xlarge"
AMI_NAME="augustus-research-$(date +%Y%m%d-%H%M%S)"

echo "=========================================="
echo "Augustus AMI Creation (Automated)"
echo "=========================================="
echo ""
echo "Instance: $INSTANCE_TYPE (~$0.68/hr)"
echo "Setup time: 1-2 hours (automatic via user-data)"
echo "Models: llama3.2:3b, llama3.1:8b, qwen2.5:7b, deepseek-coder"
echo ""
read -p "Continue? (y/n) " -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Cancelled"
    exit 0
fi

# Find Ubuntu AMI
BASE_AMI=$(aws ec2 describe-images \
    --owners 099720109477 \
    --filters "Name=name,Values=ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*" \
    --query 'sort_by(Images, &CreationDate)[-1].ImageId' \
    --output text --region "$REGION")

# Get security group
SG_ID=$(aws ec2 describe-security-groups \
    --filters "Name=group-name,Values=augustus-research-sg" \
    --query 'SecurityGroups[0].GroupId' \
    --output text --region "$REGION" 2>/dev/null || echo "None")

if [ "$SG_ID" = "None" ]; then
    SG_ID=$(aws ec2 create-security-group \
        --group-name augustus-research-sg \
        --description "Augustus Research" \
        --region "$REGION" \
        --query 'GroupId' --output text)
    aws ec2 authorize-security-group-ingress --group-id "$SG_ID" \
        --protocol tcp --port 22 --cidr 0.0.0.0/0 --region "$REGION"
fi

# Embed setup script in user-data
USER_DATA=$(cat setup-ami-cpu.sh | base64)

echo "Launching instance..."
INSTANCE_ID=$(aws ec2 run-instances \
    --image-id "$BASE_AMI" \
    --instance-type "$INSTANCE_TYPE" \
    --key-name nathans-ed25519 --security-group-ids "$SG_ID" \
    --user-data "$USER_DATA" \
    --block-device-mappings '[{"DeviceName":"/dev/sda1","Ebs":{"VolumeSize":150,"VolumeType":"gp3"}}]' \
    --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=augustus-ami-builder}]" \
    --region "$REGION" \
    --query 'Instances[0].InstanceId' --output text)

echo "Instance: $INSTANCE_ID"
echo "Setup is running via user-data (1-2 hours)..."
echo ""
echo "Monitor progress:"
echo "  aws ec2 get-console-output --instance-id $INSTANCE_ID --region $REGION --query 'Output' --output text"
echo ""
echo "When done (check console for 'Setup Complete'), create AMI:"
echo "  aws ec2 stop-instances --instance-ids $INSTANCE_ID --region $REGION"
echo "  aws ec2 wait instance-stopped --instance-ids $INSTANCE_ID --region $REGION"
echo "  aws ec2 create-image --instance-id $INSTANCE_ID --name $AMI_NAME --region $REGION"
echo ""
echo "Or wait and I'll do it automatically in 2 hours..."
sleep 7200  # 2 hours

echo "Checking if setup completed..."
if aws ec2 get-console-output --instance-id "$INSTANCE_ID" --region "$REGION" | grep -q "Setup Complete"; then
    echo "✓ Setup complete! Creating AMI..."

    aws ec2 stop-instances --instance-ids "$INSTANCE_ID" --region "$REGION" > /dev/null
    aws ec2 wait instance-stopped --instance-ids "$INSTANCE_ID" --region "$REGION"

    AMI_ID=$(aws ec2 create-image \
        --instance-id "$INSTANCE_ID" \
        --name "$AMI_NAME" \
        --description "Augustus Research (CPU)" \
        --region "$REGION" \
        --query 'ImageId' --output text)

    echo ""
    echo "=========================================="
    echo "AMI Created!"
    echo "=========================================="
    echo ""
    echo "AMI ID: $AMI_ID"
    echo "Name: $AMI_NAME"
    echo ""
    echo "Terminating builder..."
    aws ec2 terminate-instances --instance-ids "$INSTANCE_ID" --region "$REGION" > /dev/null

    echo ""
    echo "Register with DevPod:"
    echo "  devpod provider add aws \\"
    echo "    -o AWS_REGION=$REGION \\"
    echo "    -o AWS_AMI=$AMI_ID \\"
    echo "    -o AWS_INSTANCE_TYPE=c7i.4xlarge \\"
    echo "    -o AWS_DISK_SIZE=150 \\"
    echo "    --name augustus-provider"
else
    echo "⚠️  Setup still running. Check manually:"
    echo "  aws ec2 get-console-output --instance-id $INSTANCE_ID --region $REGION"
fi
