#!/bin/bash
# setup_monitoring.sh
# Run this on EC2 to deploy Prometheus + Grafana alongside Wazuh.
# Usage: bash setup_monitoring.sh YOUR_EC2_ELASTIC_IP SLACK_WEBHOOK_URL

set -e

EC2_IP="${1:?Usage: bash setup_monitoring.sh YOUR_EC2_IP SLACK_WEBHOOK_URL}"
SLACK_WEBHOOK="${2:?Usage: bash setup_monitoring.sh YOUR_EC2_IP SLACK_WEBHOOK_URL}"

echo ""
echo "========================================"
echo "  Wazuh Enrichment Monitoring Setup"
echo "========================================"
echo ""

# ── Step 1: Upload monitoring folder to EC2 ──────────────────────────────────
echo "[1/6] Uploading monitoring stack to EC2..."
scp -i ~/.ssh/wazuh.pem -r \
  "$(dirname "$0")/monitoring" \
  ubuntu@"${EC2_IP}":/home/ubuntu/monitoring
echo "      Done."

# ── Step 2: Install Docker on EC2 (if not already installed) ─────────────────
echo "[2/6] Installing Docker on EC2..."
ssh -i ~/.ssh/wazuh.pem ubuntu@"${EC2_IP}" bash << 'REMOTE'
if ! command -v docker &>/dev/null; then
  curl -fsSL https://get.docker.com -o /tmp/get-docker.sh
  sh /tmp/get-docker.sh
  sudo usermod -aG docker ubuntu
  echo "Docker installed."
else
  echo "Docker already installed: $(docker --version)"
fi

if ! command -v docker-compose &>/dev/null && ! docker compose version &>/dev/null 2>&1; then
  sudo curl -SL "https://github.com/docker/compose/releases/download/v2.24.6/docker-compose-linux-x86_64" \
    -o /usr/local/bin/docker-compose
  sudo chmod +x /usr/local/bin/docker-compose
  echo "Docker Compose installed."
else
  echo "Docker Compose already available."
fi
REMOTE
echo "      Done."

# ── Step 3: Inject Slack webhook into Grafana contact point ──────────────────
echo "[3/6] Configuring Grafana Slack alert contact point..."
ssh -i ~/.ssh/wazuh.pem ubuntu@"${EC2_IP}" bash << REMOTE
mkdir -p /home/ubuntu/monitoring/grafana/provisioning/notifiers
cat > /home/ubuntu/monitoring/grafana/provisioning/notifiers/slack.yml << EOF
apiVersion: 1
contactPoints:
  - orgId: 1
    name: Slack-Security
    receivers:
      - uid: slack-security-uid
        type: slack
        settings:
          url: "${SLACK_WEBHOOK}"
          channel: "#wazuh-alerts"
          title: "{{ .CommonAnnotations.summary }}"
          text: "{{ .CommonAnnotations.description }}"
          iconEmoji: ":red_circle:"
        disableResolveMessage: false

policies:
  - orgId: 1
    receiver: Slack-Security
    groupBy: ["severity"]
    groupWait: 10s
    groupInterval: 5m
    repeatInterval: 1h
    matchers:
      - severity = critical
EOF
echo "Slack contact point written."
REMOTE
echo "      Done."

# ── Step 4: Open EC2 security group ports ─────────────────────────────────────
echo "[4/6] Reminder — open these ports in your EC2 Security Group:"
echo "      Port 3000  (TCP) — Grafana dashboard"
echo "      Port 9090  (TCP) — Prometheus (optional, restrict to your IP)"
echo ""
read -rp "      Press Enter once ports are open to continue..."

# ── Step 5: Start the monitoring stack ───────────────────────────────────────
echo "[5/6] Starting Prometheus + Grafana + Redis Exporter on EC2..."
ssh -i ~/.ssh/wazuh.pem ubuntu@"${EC2_IP}" bash << 'REMOTE'
cd /home/ubuntu/monitoring
sudo docker compose up -d --remove-orphans
sleep 5
sudo docker compose ps
REMOTE
echo "      Done."

# ── Step 6: Extend SSH tunnel to forward worker metrics port ─────────────────
echo "[6/6] Adding metrics port (9091) to SSH tunnel..."
echo ""
echo "  Your start-tunnel alias needs one extra port forward."
echo "  Update ~/.bashrc and replace your start-tunnel alias with:"
echo ""
echo "  alias start-tunnel='pkill -f \"R 6379\" 2>/dev/null; pkill -f \"R 9091\" 2>/dev/null; sleep 1; \\"
echo "    ssh -i ~/.ssh/wazuh.pem \\"
echo "    -o StrictHostKeyChecking=no \\"
echo "    -o ServerAliveInterval=30 \\"
echo "    -o ServerAliveCountMax=3 \\"
echo "    -N \\"
echo "    -R 6379:REDIS_CLUSTER_IP:6379 \\"
echo "    -R 9091:localhost:9090 \\"
echo "    ubuntu@${EC2_IP} &'"
echo ""
echo "  This forwards the worker's /metrics port (9090) to EC2 localhost:9091"
echo "  so Prometheus on EC2 can scrape it."
echo ""

# ── Summary ──────────────────────────────────────────────────────────────────
echo "========================================"
echo "  Setup Complete!"
echo "========================================"
echo ""
echo "  Grafana:    http://${EC2_IP}:3000"
echo "  Username:   admin"
echo "  Password:   wazuh_monitor_2026"
echo ""
echo "  Dashboard auto-loads at:"
echo "  http://${EC2_IP}:3000/d/wazuh-enrichment-v1"
echo ""
echo "  Slack alerts fire to #wazuh-alerts when"
echo "  a CRITICAL risk IOC is detected."
echo ""
