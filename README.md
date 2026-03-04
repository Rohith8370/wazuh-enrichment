# Wazuh IOC Enrichment Pipeline

Automated threat intelligence enrichment for Wazuh SIEM alerts. Extracts IOCs from every alert, enriches them against VirusTotal, AbuseIPDB, and AlienVault OTX, scores risk, and delivers structured reports to Slack — automatically, with zero manual intervention.

---

## What It Does

```
Wazuh Alert → IOC Extraction → Threat Intel Enrichment → Risk Scoring → Slack Notification
```

Every Wazuh security alert is automatically:
- Parsed for IOCs (IPs, file hashes, domains, URLs)
- Checked against 3 threat intelligence platforms simultaneously
- Scored as INFO / LOW / MEDIUM / HIGH / CRITICAL
- Delivered to Slack with per-platform verdicts and recommended actions

---

## Architecture

```
EC2 (Wazuh Manager)
       |
custom-enrichment.py
       |
  SSH Tunnel (reverse)
       |
WSL2 / Linux Machine
       |
  k3s Kubernetes Cluster
  ├── Redis (queue + cache)
  └── enrichment-worker (Python)
             |
        Slack Webhook
```

---

## Prerequisites

### API Keys (all free tier)

| Service | Register At | Free Limit |
|---------|-------------|------------|
| VirusTotal | https://www.virustotal.com/gui/join-us | 4 req/min, 500/day |
| AbuseIPDB | https://www.abuseipdb.com/register | 1000 req/day |
| AlienVault OTX | https://otx.alienvault.com | Unlimited (free account) |
| Slack Webhook | https://api.slack.com/apps | Free |

### Infrastructure

- Linux machine (Ubuntu 22.04/24.04) or WSL2 on Windows
- Minimum 4GB RAM, 10GB free disk
- AWS EC2 running Wazuh Manager (Ubuntu 22.04)
- EC2 key pair (.pem file)
- Elastic IP on EC2 (recommended — prevents IP changes on restart)

---

## Installation

### Stage 1 — Prepare System

```bash
# Switch to non-root user
su - YOUR_USERNAME

# Update packages
sudo apt update && sudo apt upgrade -y

# Install dependencies
sudo apt install -y curl wget git apt-transport-https ca-certificates gnupg lsb-release
```

### Stage 2 — Install Docker

```bash
curl -fsSL https://get.docker.com -o get-docker.sh && sh get-docker.sh
sudo usermod -aG docker $USER
newgrp docker

# Verify
docker run hello-world
```

### Stage 3 — Install k3s

```bash
curl -sfL https://get.k3s.io | sh -

# Configure kubectl for non-root user
mkdir -p ~/.kube && sudo cp /etc/rancher/k3s/k3s.yaml ~/.kube/config && sudo chown $USER:$USER ~/.kube/config
echo 'export KUBECONFIG=~/.kube/config' >> ~/.bashrc && source ~/.bashrc

# Verify
kubectl get nodes   # Should show Ready
```

### Stage 4 — Install Helm

```bash
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
helm version
```

### Stage 5 — Clone This Repository

```bash
git clone https://github.com/YOUR_USERNAME/wazuh-enrichment.git
cd wazuh-enrichment
```

### Stage 6 — Configure Secrets

```bash
cp .env.example .env
nano .env
```

Fill in your real values:

```env
VIRUSTOTAL_API_KEY=your_real_key_here
ABUSEIPDB_API_KEY=your_real_key_here
OTX_API_KEY=your_real_key_here
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
SMTP_HOST=                    # Leave empty if not using email
SMTP_PORT=587
SMTP_USER=
SMTP_PASSWORD=
SMTP_FROM=
SMTP_TO=
TEAMS_WEBHOOK_URL=            # Leave empty if not using Teams
REDIS_PASSWORD=               # Leave empty for no auth
LOG_LEVEL=INFO
QUEUE_KEY=wazuh:alerts
CACHE_TTL_SECONDS=86400
```

Verify no placeholders remain:
```bash
grep -c "your_" .env    # Must return 0
```

### Stage 7 — Build Container Image

```bash
cd enrichment-worker
docker build -t enrichment-worker:latest .
docker save enrichment-worker:latest | sudo k3s ctr images import -

# Verify
sudo k3s ctr images list | grep enrichment-worker
```

### Stage 8 — Deploy to Kubernetes

```bash
cd ..   # back to project root

# Create namespace and secrets
kubectl create namespace enrichment
kubectl create secret generic enrichment-secrets \
  --from-env-file=.env \
  --namespace=enrichment

# Deploy Redis
helm install redis ./helm/charts/redis --namespace enrichment

# Wait for Redis to be ready (1/1 Running)
kubectl get pods -n enrichment

# Deploy enrichment worker
helm install enrichment-worker ./helm/charts/enrichment-worker --namespace enrichment

# Verify both pods running
kubectl get pods -n enrichment
```

### Stage 9 — Set Up SSH Tunnel (EC2 to Local Redis)

```bash
# Copy your EC2 key
mkdir -p ~/.ssh
cp /path/to/your-key.pem ~/.ssh/wazuh.pem
chmod 600 ~/.ssh/wazuh.pem

# Test SSH connection
ssh -i ~/.ssh/wazuh.pem ubuntu@YOUR_EC2_IP "echo 'SSH works'"

# Get Redis ClusterIP
kubectl get svc redis -n enrichment
# Note the CLUSTER-IP value

# Start reverse SSH tunnel
ssh -i ~/.ssh/wazuh.pem \
  -o StrictHostKeyChecking=no \
  -o ServerAliveInterval=30 \
  -o ServerAliveCountMax=3 \
  -N -R 6379:REDIS_CLUSTER_IP:6379 \
  ubuntu@YOUR_EC2_IP &

# Verify tunnel works
ssh -i ~/.ssh/wazuh.pem ubuntu@YOUR_EC2_IP \
  "redis-cli -h 127.0.0.1 -p 6379 ping"
# Expected: PONG

# Save as alias for easy reuse
echo "alias start-tunnel='pkill -f \"R 6379\" 2>/dev/null; sleep 1; ssh -i ~/.ssh/wazuh.pem -o StrictHostKeyChecking=no -o ServerAliveInterval=30 -o ServerAliveCountMax=3 -N -R 6379:REDIS_CLUSTER_IP:6379 ubuntu@YOUR_EC2_IP &'" >> ~/.bashrc
source ~/.bashrc
```

### Stage 10 — Install Wazuh Integration on EC2

```bash
# Install redis-py on EC2
ssh -i ~/.ssh/wazuh.pem ubuntu@YOUR_EC2_IP \
  "sudo pip3 install redis --break-system-packages"

# Copy integration script to EC2
scp -i ~/.ssh/wazuh.pem \
  wazuh-integration/custom-enrichment.py \
  ubuntu@YOUR_EC2_IP:/tmp/custom-enrichment

# Install with correct permissions
ssh -i ~/.ssh/wazuh.pem ubuntu@YOUR_EC2_IP \
  "sudo cp /tmp/custom-enrichment /var/ossec/integrations/custom-enrichment && \
   sudo chmod 750 /var/ossec/integrations/custom-enrichment && \
   sudo chown root:wazuh /var/ossec/integrations/custom-enrichment"

# Add integration to Wazuh config
ssh -i ~/.ssh/wazuh.pem ubuntu@YOUR_EC2_IP "sudo python3 -c \"
conf = open('/var/ossec/etc/ossec.conf').read()
block = '''  <integration>
    <name>custom-enrichment</name>
    <hook_url>unused</hook_url>
    <level>3</level>
    <alert_format>json</alert_format>
  </integration>'''
if 'custom-enrichment' not in conf:
    conf = conf.replace('</ossec_config>', block + '\n</ossec_config>')
    open('/var/ossec/etc/ossec.conf', 'w').write(conf)
    print('Integration added')
else:
    print('Already configured')
\""

# Set environment variables on EC2
ssh -i ~/.ssh/wazuh.pem ubuntu@YOUR_EC2_IP \
  "sudo bash -c 'echo REDIS_HOST=127.0.0.1 >> /etc/environment && \
   echo REDIS_PORT=6379 >> /etc/environment && \
   echo QUEUE_KEY=wazuh:alerts >> /etc/environment'"

# Restart Wazuh
ssh -i ~/.ssh/wazuh.pem ubuntu@YOUR_EC2_IP \
  "sudo systemctl restart wazuh-manager && \
   sleep 5 && sudo systemctl status wazuh-manager | grep Active"
```

---

## Verification

### End-to-End Test

Push a synthetic alert and watch it process:

```bash
# Push test alert
kubectl run redis-test --image=redis:7.2-alpine --restart=Never --rm -it \
  -n enrichment -- redis-cli -h redis -p 6379 RPUSH wazuh:alerts \
  '{"id":"test-001","rule":{"id":"5710","description":"SSH brute force","level":10,"groups":["syslog","sshd"]},"agent":{"id":"001","name":"test-host","ip":"10.0.0.5"},"data":{"srcip":"185.220.101.45"}}'

# Watch logs
kubectl logs -n enrichment -l app=enrichment-worker -f
```

Expected output:
```
INFO  worker.main - Processing alert_id=test-001
INFO  extractor   - IOC extraction complete | ip_count: 1
INFO  enricher    - Enriching ip: 185.220.101.45
INFO  notifier    - Slack notification sent
INFO  worker.main - AUDIT | risk=CRITICAL ioc_count=1 slack=True elapsed=0.34s
```

Check your Slack channel — you should see a rich formatted message with verdicts from all three platforms.

---

## Daily Usage

### Starting the Pipeline (every session)

```bash
# 1. Start EC2 from AWS Console first
# 2. Open terminal, then:
bash ~/wazuh_startup.sh
```

### Quick Commands

| Task | Command |
|------|---------|
| Watch live alerts | `kubectl logs -n enrichment -l app=enrichment-worker -f` |
| Check pod status | `kubectl get pods -n enrichment` |
| Push test alert | `bash ~/wazuh_test_alert.sh` |
| Start tunnel | `start-tunnel` |
| Stop tunnel | `pkill -f 'R 6379'` |
| Check queue depth | `kubectl exec -n enrichment redis-0 -- redis-cli LLEN wazuh:alerts` |
| Check dead-letter queue | `kubectl exec -n enrichment redis-0 -- redis-cli LLEN wazuh:alerts:dlq` |
| Restart worker | `kubectl rollout restart deployment/enrichment-worker-enrichment-worker -n enrichment` |

### Shutdown

```bash
pkill -f 'R 6379' && echo "Tunnel stopped"
# Then close terminal / shutdown laptop
```

---

## Risk Scoring

| Level | Criteria |
|-------|----------|
| CRITICAL | VirusTotal >= 10 detections OR AbuseIPDB score >= 90 |
| HIGH | VirusTotal >= 5 OR AbuseIPDB >= 70 OR OTX pulses >= 10 |
| MEDIUM | VirusTotal >= 2 OR AbuseIPDB >= 40 OR OTX pulses >= 3 |
| LOW | Any positive detection |
| INFO | No data found |

---

## IOC Types Supported

- **IPv4** — public IPs only, private ranges (RFC1918) automatically filtered
- **SHA256** — extracted first to prevent substring collisions
- **SHA1** — extracted after SHA256 removal
- **MD5** — extracted after SHA256 and SHA1 removal
- **Domains** — validated, internal TLDs excluded
- **URLs** — HTTP/HTTPS, domain deduplication applied

---

## Project Structure

```
wazuh-enrichment/
├── .env.example                    # Secret template (copy to .env)
├── .gitignore                      # .env excluded
├── README.md
├── enrichment-worker/
│   ├── extractor.py                # IOC extraction and validation
│   ├── cache.py                    # Redis caching layer (24h TTL)
│   ├── enricher.py                 # VirusTotal, AbuseIPDB, OTX queries
│   ├── reporter.py                 # Risk scoring and report builder
│   ├── notifier.py                 # Slack / Teams / Email delivery
│   ├── main.py                     # Queue worker entrypoint
│   ├── requirements.txt
│   └── Dockerfile
├── wazuh-integration/
│   └── custom-enrichment.py        # Deploy to EC2 /var/ossec/integrations/
└── helm/
    └── charts/
        ├── enrichment-worker/
        │   ├── Chart.yaml
        │   ├── values.yaml
        │   └── templates/
        │       └── deployment.yaml
        └── redis/
            ├── Chart.yaml
            ├── values.yaml
            └── templates/
                └── statefulset.yaml
```

---

## Security Notes

- Never commit `.env` — it is excluded by `.gitignore`
- All secrets loaded from Kubernetes Secrets at runtime
- Worker runs as non-root (UID 1001), read-only filesystem, all capabilities dropped
- Redis is ClusterIP only — never exposed outside the cluster
- SSH tunnel forwards only port 6379
- API keys never written to logs

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| Worker CrashLoopBackOff | `kubectl logs -n enrichment <pod>` — check for missing env vars |
| Slack not receiving | Verify webhook URL in secret |
| Tunnel not working | Re-run `start-tunnel`, then test with `redis-cli ping` from EC2 |
| No alerts from Wazuh | Check `/var/ossec/logs/integrations.log` on EC2 |
| API errors | Verify keys with a direct curl test to each API |

---

## Roadmap

- [ ] Phase 2: AWS EKS migration (remove SSH tunnel, Redis on ElastiCache)
- [ ] Gmail / SMTP notification support
- [ ] Microsoft Teams Adaptive Cards
- [ ] Grafana dashboard for alert metrics
- [ ] Hash enrichment for malware families
- [ ] MITRE ATT&CK mapping per alert

---

## License

Internal use only. Not for public distribution.
