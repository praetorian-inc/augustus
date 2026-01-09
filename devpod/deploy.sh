#!/bin/bash
# Deploy Augustus Research to AWS EC2
# Usage: ./deploy.sh

set -e

IMAGE="ghcr.io/praetorian-inc/augustus-research:latest"
INSTANCE_TYPE="${INSTANCE_TYPE:-c7i.2xlarge}"
KEY_NAME="${KEY_NAME:-}"
REGION="${AWS_REGION:-us-east-2}"

echo "=== Augustus Research Deployment ==="
echo ""

# Check prerequisites
if ! command -v aws &> /dev/null; then
    echo "Error: AWS CLI not installed"
    exit 1
fi

if ! aws sts get-caller-identity &> /dev/null; then
    echo "Error: AWS credentials not configured"
    echo "Run: aws configure"
    exit 1
fi

# Get key name if not set
if [ -z "$KEY_NAME" ]; then
    echo "Available SSH keys:"
    aws ec2 describe-key-pairs --query 'KeyPairs[].KeyName' --output text --region "$REGION"
    echo ""
    read -p "Enter key name: " KEY_NAME
fi

# Get or create security group
SG_NAME="augustus-research-sg"
SG_ID=$(aws ec2 describe-security-groups --filters "Name=group-name,Values=$SG_NAME" \
    --query 'SecurityGroups[0].GroupId' --output text --region "$REGION" 2>/dev/null || echo "None")

if [ "$SG_ID" = "None" ] || [ -z "$SG_ID" ]; then
    echo "Creating security group..."
    SG_ID=$(aws ec2 create-security-group \
        --group-name "$SG_NAME" \
        --description "Augustus Research - SSH and Jupyter" \
        --region "$REGION" \
        --query 'GroupId' --output text)

    # Allow SSH
    aws ec2 authorize-security-group-ingress --group-id "$SG_ID" \
        --protocol tcp --port 22 --cidr 0.0.0.0/0 --region "$REGION"

    # Allow Jupyter
    aws ec2 authorize-security-group-ingress --group-id "$SG_ID" \
        --protocol tcp --port 8888 --cidr 0.0.0.0/0 --region "$REGION"

    echo "Created security group: $SG_ID"
fi

# Find latest Ubuntu 24.04 AMI
AMI_ID=$(aws ec2 describe-images \
    --owners 099720109477 \
    --filters "Name=name,Values=ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*" \
    --query 'sort_by(Images, &CreationDate)[-1].ImageId' \
    --output text --region "$REGION")

echo ""
echo "Configuration:"
echo "  Region: $REGION"
echo "  Instance: $INSTANCE_TYPE"
echo "  AMI: $AMI_ID (Ubuntu 24.04)"
echo "  Key: $KEY_NAME"
echo "  Security Group: $SG_ID"
echo ""
read -p "Launch instance? (y/n) " -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Cancelled"
    exit 0
fi

# Create user data script
USER_DATA=$(cat << 'USERDATA'
#!/bin/bash
set -e

# Install Docker
curl -fsSL https://get.docker.com | sh
usermod -aG docker ubuntu

# Pull image
docker pull ghcr.io/praetorian-inc/augustus-research:latest

# Create workspace
mkdir -p /home/ubuntu/augustus-research/results
chown -R ubuntu:ubuntu /home/ubuntu/augustus-research

# Create run script
cat > /home/ubuntu/run-augustus.sh << 'EOF'
#!/bin/bash
docker run -it --rm \
    -v /home/ubuntu/augustus-research:/workspace/results \
    -p 8888:8888 \
    --env-file /home/ubuntu/.env \
    ghcr.io/praetorian-inc/augustus-research:latest
EOF
chmod +x /home/ubuntu/run-augustus.sh

echo "Setup complete! Create /home/ubuntu/.env with API keys, then run ./run-augustus.sh"
USERDATA
)

# Launch instance
echo "Launching instance..."
INSTANCE_ID=$(aws ec2 run-instances \
    --image-id "$AMI_ID" \
    --instance-type "$INSTANCE_TYPE" \
    --key-name "$KEY_NAME" \
    --security-group-ids "$SG_ID" \
    --user-data "$USER_DATA" \
    --block-device-mappings '[{"DeviceName":"/dev/sda1","Ebs":{"VolumeSize":50,"VolumeType":"gp3"}}]' \
    --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=augustus-research}]" \
    --region "$REGION" \
    --query 'Instances[0].InstanceId' --output text)

echo "Instance launched: $INSTANCE_ID"
echo "Waiting for public IP..."

# Wait for instance and get IP
sleep 10
PUBLIC_IP=$(aws ec2 describe-instances \
    --instance-ids "$INSTANCE_ID" \
    --query 'Reservations[0].Instances[0].PublicIpAddress' \
    --output text --region "$REGION")

echo ""
echo "=== Deployment Complete ==="
echo ""
echo "Instance: $INSTANCE_ID"
echo "IP: $PUBLIC_IP"
echo ""
echo "Next steps:"
echo "1. Wait ~2 min for Docker install to complete"
echo "2. SSH: ssh -i ~/.ssh/$KEY_NAME.pem ubuntu@$PUBLIC_IP"
echo "3. Create .env file with API keys"
echo "4. Run: ./run-augustus.sh"
echo ""
echo "To terminate: aws ec2 terminate-instances --instance-ids $INSTANCE_ID --region $REGION"
