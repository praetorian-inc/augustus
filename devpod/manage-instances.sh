#!/bin/bash
# Augustus Research Instance Management
# Usage: ./manage-instances.sh [list|start|stop|terminate|ssh] [instance-id]

set -e

REGION="${AWS_REGION:-us-east-2}"
CMD="${1:-list}"
INSTANCE_ID="$2"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

usage() {
    echo "Augustus Research Instance Management"
    echo ""
    echo "Usage: $0 <command> [instance-id]"
    echo ""
    echo "Commands:"
    echo "  list                    List all Augustus research instances"
    echo "  start <instance-id>     Start a stopped instance"
    echo "  stop <instance-id>      Stop a running instance (preserves data, stops billing)"
    echo "  terminate <instance-id> Permanently delete instance (cannot be undone!)"
    echo "  ssh <instance-id>       SSH into a running instance"
    echo "  cost                    Show running instance costs"
    echo ""
    echo "Examples:"
    echo "  $0 list"
    echo "  $0 stop i-0b237d15f5b4fa729"
    echo "  $0 ssh i-0b237d15f5b4fa729"
    echo ""
}

list_instances() {
    echo "Augustus Research Instances (${REGION})"
    echo "=========================================="
    echo ""

    aws ec2 describe-instances \
        --filters "Name=tag:Name,Values=*augustus*,*venator*,*research*" \
        --query 'Reservations[].Instances[].[
            InstanceId,
            State.Name,
            InstanceType,
            PublicIpAddress || `(no public IP)`,
            Tags[?Key==`Name`].Value | [0],
            LaunchTime
        ]' \
        --output table \
        --region "$REGION" 2>/dev/null || echo "No instances found"

    echo ""
    echo "Tip: Use './manage-instances.sh stop <id>' to stop billing"
}

start_instance() {
    if [ -z "$INSTANCE_ID" ]; then
        echo -e "${RED}Error: Instance ID required${NC}"
        echo "Usage: $0 start <instance-id>"
        exit 1
    fi

    echo "Starting instance: $INSTANCE_ID"
    aws ec2 start-instances --instance-ids "$INSTANCE_ID" --region "$REGION"

    echo "Waiting for instance to be running..."
    aws ec2 wait instance-running --instance-ids "$INSTANCE_ID" --region "$REGION"

    PUBLIC_IP=$(aws ec2 describe-instances \
        --instance-ids "$INSTANCE_ID" \
        --query 'Reservations[0].Instances[0].PublicIpAddress' \
        --output text --region "$REGION")

    echo ""
    echo -e "${GREEN}Instance started!${NC}"
    echo "IP: $PUBLIC_IP"
    echo "SSH: ssh ubuntu@$PUBLIC_IP"
}

stop_instance() {
    if [ -z "$INSTANCE_ID" ]; then
        echo -e "${RED}Error: Instance ID required${NC}"
        echo "Usage: $0 stop <instance-id>"
        exit 1
    fi

    echo -e "${YELLOW}Stopping instance: $INSTANCE_ID${NC}"
    echo "This will stop billing but preserve all data."
    read -p "Continue? (y/n) " -n 1 -r
    echo ""

    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Cancelled"
        exit 0
    fi

    aws ec2 stop-instances --instance-ids "$INSTANCE_ID" --region "$REGION"

    echo "Waiting for instance to stop..."
    aws ec2 wait instance-stopped --instance-ids "$INSTANCE_ID" --region "$REGION"

    echo -e "${GREEN}Instance stopped. Billing paused.${NC}"
    echo "Use '$0 start $INSTANCE_ID' to restart."
}

terminate_instance() {
    if [ -z "$INSTANCE_ID" ]; then
        echo -e "${RED}Error: Instance ID required${NC}"
        echo "Usage: $0 terminate <instance-id>"
        exit 1
    fi

    echo -e "${RED}WARNING: This will PERMANENTLY DELETE the instance!${NC}"
    echo "Instance ID: $INSTANCE_ID"
    echo "All data will be lost. This cannot be undone."
    echo ""
    read -p "Type 'DELETE' to confirm: " CONFIRM

    if [ "$CONFIRM" != "DELETE" ]; then
        echo "Cancelled"
        exit 0
    fi

    aws ec2 terminate-instances --instance-ids "$INSTANCE_ID" --region "$REGION"
    echo -e "${GREEN}Instance terminated.${NC}"
}

ssh_instance() {
    if [ -z "$INSTANCE_ID" ]; then
        echo -e "${RED}Error: Instance ID required${NC}"
        echo "Usage: $0 ssh <instance-id>"
        exit 1
    fi

    PUBLIC_IP=$(aws ec2 describe-instances \
        --instance-ids "$INSTANCE_ID" \
        --query 'Reservations[0].Instances[0].PublicIpAddress' \
        --output text --region "$REGION")

    if [ "$PUBLIC_IP" = "None" ] || [ -z "$PUBLIC_IP" ]; then
        echo -e "${RED}Error: Instance has no public IP (is it running?)${NC}"
        exit 1
    fi

    echo "Connecting to $PUBLIC_IP..."
    ssh -o StrictHostKeyChecking=no ubuntu@"$PUBLIC_IP"
}

show_costs() {
    echo "Running Instance Costs (${REGION})"
    echo "=========================================="
    echo ""

    # Get running instances
    INSTANCES=$(aws ec2 describe-instances \
        --filters "Name=instance-state-name,Values=running" \
        --query 'Reservations[].Instances[].[InstanceId,InstanceType,Tags[?Key==`Name`].Value | [0]]' \
        --output text --region "$REGION")

    if [ -z "$INSTANCES" ]; then
        echo "No running instances."
        return
    fi

    echo "Instance costs (approximate):"
    echo ""

    TOTAL=0
    while IFS=$'\t' read -r id type name; do
        case "$type" in
            c7i.4xlarge)   COST="0.68" ;;
            c7i.8xlarge)   COST="1.36" ;;
            r7i.24xlarge)  COST="6.35" ;;
            r7i.48xlarge)  COST="12.70" ;;
            r8i.48xlarge)  COST="20.00" ;;
            t3.2xlarge)    COST="0.33" ;;
            t3.xlarge)     COST="0.17" ;;
            *)             COST="0.00" ;;  # Unknown - don't add to total
        esac

        printf "  %-20s %-15s \$%s/hr\n" "${name:-$id}" "$type" "$COST"
        if [ "$COST" != "0.00" ]; then
            TOTAL=$(echo "$TOTAL + $COST" | bc)
        fi
    done <<< "$INSTANCES"

    echo ""
    echo "Total: \$${TOTAL}/hr (\$$(echo "$TOTAL * 24" | bc)/day)"
    echo ""
    echo "Tip: Stop instances when not in use to save money!"
}

# Main
case "$CMD" in
    list)
        list_instances
        ;;
    start)
        start_instance
        ;;
    stop)
        stop_instance
        ;;
    terminate)
        terminate_instance
        ;;
    ssh)
        ssh_instance
        ;;
    cost|costs)
        show_costs
        ;;
    help|-h|--help)
        usage
        ;;
    *)
        echo -e "${RED}Unknown command: $CMD${NC}"
        echo ""
        usage
        exit 1
        ;;
esac
