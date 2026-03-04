#!/bin/bash
# ============================================================
# wazuh_test_alert.sh
# Push a test alert directly to Redis and watch it process
# Usage: bash ~/wazuh_test_alert.sh
# ============================================================

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

export KUBECONFIG=~/.kube/config

ALERT_ID="test-$(date +%s)"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo ""
echo -e "${BLUE}Pushing test alert ID: $ALERT_ID${NC}"

kubectl run redis-test-$$ \
  --image=redis:7.2-alpine \
  --restart=Never --rm -it \
  -n enrichment \
  -- redis-cli -h redis -p 6379 RPUSH wazuh:alerts \
  "{\"id\":\"$ALERT_ID\",\"timestamp\":\"$TIMESTAMP\",\"rule\":{\"id\":\"5710\",\"description\":\"SSH brute force attempt\",\"level\":10,\"groups\":[\"syslog\",\"sshd\"]},\"agent\":{\"id\":\"001\",\"name\":\"test-host\",\"ip\":\"10.0.0.5\"},\"data\":{\"srcip\":\"185.220.101.45\",\"dstip\":\"10.0.0.5\"}}" 2>/dev/null

echo -e "${GREEN}✅ Alert pushed - watching logs (Ctrl+C to stop)...${NC}"
echo ""
kubectl logs -n enrichment -l app=enrichment-worker -f --since=10s
