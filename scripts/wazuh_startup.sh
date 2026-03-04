#!/bin/bash
# ============================================================
# wazuh_startup.sh
# Wazuh Enrichment Pipeline - Full Startup Script
# Run this every time you open WSL2
# Usage: bash ~/wazuh_startup.sh
# ============================================================

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

ok()   { echo -e "${GREEN}✅ $1${NC}"; }
warn() { echo -e "${YELLOW}⚠️  $1${NC}"; }
fail() { echo -e "${RED}❌ $1${NC}"; }
info() { echo -e "${BLUE}ℹ️  $1${NC}"; }

echo ""
echo -e "${BLUE}================================================${NC}"
echo -e "${BLUE}  Wazuh Enrichment Pipeline - Startup Script  ${NC}"
echo -e "${BLUE}================================================${NC}"
echo ""

# ── Step 1: Start Docker ─────────────────────────────────────
info "Step 1/5 - Starting Docker..."
if sudo service docker start > /dev/null 2>&1; then
    ok "Docker started"
else
    warn "Docker may already be running"
fi

if docker info > /dev/null 2>&1; then
    ok "Docker is running"
else
    fail "Docker failed to start - run: sudo service docker start"
    exit 1
fi

# ── Step 2: Ensure k3s is running ────────────────────────────
info "Step 2/5 - Checking k3s..."
if ! sudo systemctl is-active k3s > /dev/null 2>&1; then
    warn "k3s not running - starting..."
    sudo systemctl start k3s
    sleep 10
fi

export KUBECONFIG=~/.kube/config

if kubectl get nodes > /dev/null 2>&1; then
    NODE_STATUS=$(kubectl get nodes --no-headers | awk '{print $2}')
    if [ "$NODE_STATUS" = "Ready" ]; then
        ok "k3s is running - node Ready"
    else
        warn "k3s node status: $NODE_STATUS - waiting..."
        sleep 15
    fi
else
    fail "kubectl failed - check k3s"
    exit 1
fi

# ── Step 3: Check enrichment pods ────────────────────────────
info "Step 3/5 - Checking enrichment pods..."
REDIS_STATUS=$(kubectl get pod redis-0 -n enrichment --no-headers 2>/dev/null | awk '{print $3}')
WORKER_STATUS=$(kubectl get pods -n enrichment -l app=enrichment-worker --no-headers 2>/dev/null | awk '{print $3}' | head -1)

if [ "$REDIS_STATUS" = "Running" ]; then
    ok "Redis pod - Running"
else
    warn "Redis not running (status: ${REDIS_STATUS:-not found}) - redeploying..."
    cd ~/wazuh-enrichment
    helm upgrade --install redis ./helm/charts/redis --namespace enrichment
    sleep 20
    ok "Redis redeployed"
fi

if [ "$WORKER_STATUS" = "Running" ]; then
    ok "Enrichment worker - Running"
else
    warn "Worker not running (status: ${WORKER_STATUS:-not found}) - redeploying..."
    cd ~/wazuh-enrichment
    helm upgrade --install enrichment-worker ./helm/charts/enrichment-worker --namespace enrichment
    sleep 15
    ok "Worker redeployed"
fi

# ── Step 4: Start SSH tunnel ──────────────────────────────────
info "Step 4/5 - Starting SSH tunnel to EC2..."

# Kill any existing tunnel
pkill -f "R 6379" 2>/dev/null || true
sleep 2

# Start fresh tunnel in background
ssh -i ~/.ssh/wazuh.pem \
    -o StrictHostKeyChecking=no \
    -o ServerAliveInterval=30 \
    -o ServerAliveCountMax=3 \
    -o ExitOnForwardFailure=yes \
    -N -R 6379:10.43.131.89:6379 \
    ubuntu@ec2-15-207-7-85.ap-south-1.compute.amazonaws.com &

TUNNEL_PID=$!
sleep 4

# Verify tunnel works
PING_RESULT=$(ssh -i ~/.ssh/wazuh.pem \
    -o StrictHostKeyChecking=no \
    -o ConnectTimeout=5 \
    ubuntu@ec2-15-207-7-85.ap-south-1.compute.amazonaws.com \
    "redis-cli -h 127.0.0.1 -p 6379 ping" 2>/dev/null)

if [ "$PING_RESULT" = "PONG" ]; then
    ok "SSH tunnel active - EC2 can reach Redis (PID: $TUNNEL_PID)"
else
    fail "SSH tunnel failed - EC2 cannot reach Redis"
    warn "Try manually: ssh -i ~/.ssh/wazuh.pem ubuntu@ec2-15-207-7-85.ap-south-1.compute.amazonaws.com"
fi

# ── Step 5: Final status ──────────────────────────────────────
info "Step 5/5 - Final status check..."
echo ""
echo -e "${BLUE}─── Pod Status ──────────────────────────────────${NC}"
kubectl get pods -n enrichment
echo ""
echo -e "${BLUE}─── Tunnel Status ───────────────────────────────${NC}"
if pgrep -f "R 6379" > /dev/null; then
    ok "SSH tunnel process running (PID: $(pgrep -f 'R 6379'))"
else
    fail "SSH tunnel not running"
fi
echo ""
echo -e "${BLUE}════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Pipeline is LIVE - Wazuh alerts will be       ${NC}"
echo -e "${GREEN}  enriched and sent to Slack automatically      ${NC}"
echo -e "${BLUE}════════════════════════════════════════════════${NC}"
echo ""
echo -e "To watch live alerts:  ${YELLOW}kubectl logs -n enrichment -l app=enrichment-worker -f${NC}"
echo -e "To stop tunnel:        ${YELLOW}pkill -f 'R 6379'${NC}"
echo -e "To push test alert:    ${YELLOW}bash ~/wazuh_test_alert.sh${NC}"
echo ""
