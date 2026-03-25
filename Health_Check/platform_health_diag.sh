#!/usr/bin/env bash
# =============================================================================
# OpenCTI Platform Health Diagnostic — Domain 1
# Run from ~/opencti-docker
# Usage: bash scripts/platform_health_diag.sh 2>&1 | tee platform_health_$(date +%Y%m%d_%H%M%S).txt
# =============================================================================

COMPOSE="sudo docker compose -f docker-compose.yml -f docker-compose.override.yml"
SEP="================================================================================"

section() { echo -e "\n${SEP}\n## $1\n${SEP}"; }

# ---------------------------------------------------------------------------
section "1.1 — Container State (all containers)"
$COMPOSE ps -a

# ---------------------------------------------------------------------------
section "1.2 — Resource Utilization (CPU / Memory / Swap / PIDs)"
sudo docker stats --no-stream --format \
  "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}\t{{.PIDs}}"

# ---------------------------------------------------------------------------
section "1.3 — Redis Memory State"
REDIS=$(sudo docker ps --format '{{.Names}}' | grep -i redis | head -1)
if [ -n "$REDIS" ]; then
  echo "Container: $REDIS"
  sudo docker exec "$REDIS" redis-cli INFO memory \
    | grep -E "used_memory_human|used_memory_peak_human|maxmemory_human|maxmemory_policy|mem_fragmentation_ratio"
else
  echo "ERROR: Redis container not found"
fi

# ---------------------------------------------------------------------------
section "1.4 — Elasticsearch Cluster Health"
ES=$(sudo docker ps --format '{{.Names}}' | grep -i elastic | head -1)
if [ -n "$ES" ]; then
  echo "Container: $ES"
  echo "--- Node Stats ---"
  sudo docker exec "$ES" curl -s \
    "http://localhost:9200/_cat/nodes?v&h=name,heap.percent,heap.current,heap.max,ram.percent,ram.current,ram.max,cpu,load_1m"
  echo "--- Cluster Health ---"
  sudo docker exec "$ES" curl -s "http://localhost:9200/_cluster/health?pretty"
else
  echo "ERROR: Elasticsearch container not found"
fi

# ---------------------------------------------------------------------------
section "1.5 — Swap Usage and Kernel Parameters"
echo "--- Memory / Swap ---"
free -h
echo ""
echo "--- vm.swappiness ---"
cat /proc/sys/vm/swappiness
echo ""
echo "--- Transparent HugePage ---"
cat /sys/kernel/mm/transparent_hugepage/enabled

# ---------------------------------------------------------------------------
section "1.6 — RabbitMQ Queue Depth"
RABBIT=$(sudo docker ps --format '{{.Names}}' | grep -i rabbit | head -1)
if [ -n "$RABBIT" ]; then
  echo "Container: $RABBIT"
  sudo docker exec "$RABBIT" rabbitmqctl list_queues name messages consumers \
    --formatter pretty_table 2>/dev/null \
  || sudo docker exec "$RABBIT" rabbitmqadmin list queues name messages consumers 2>/dev/null \
  || echo "WARN: Neither rabbitmqctl pretty_table nor rabbitmqadmin succeeded"
else
  echo "ERROR: RabbitMQ container not found"
fi

# ---------------------------------------------------------------------------
section "1.7 — Connector Container States"
echo "--- All connector / known custom containers ---"
$COMPOSE ps | grep -Ei "connector|NIST|nsa|cis|report|feedly|newsapi|threatfox|virustotal|udm|proofpoint|cymru"

echo ""
echo "--- Restart counts for above ---"
sudo docker ps -a --format "table {{.Names}}\t{{.Status}}\t{{.RunningFor}}" \
  | grep -Ei "connector|NIST|nsa|cis|report|feedly|newsapi|threatfox|virustotal|udm|proofpoint|cymru"

# ---------------------------------------------------------------------------
section "1.8 — Disk State"
echo "--- Filesystem Usage ---"
df -h /

echo ""
echo "--- Docker System Disk Usage ---"
sudo docker system df

echo ""
echo "--- Dangling Images ---"
sudo docker images -f "dangling=true"

echo ""
echo "--- Systemd Journal Disk Usage ---"
sudo journalctl --disk-usage

# ---------------------------------------------------------------------------
section "1.9 — MinIO Volume Audit"
echo "--- All Docker volumes (name + size where available) ---"
sudo docker volume ls
echo ""
echo "--- Inspect opencti-docker_minio_data (expected orphan) ---"
sudo docker volume inspect opencti-docker_minio_data 2>/dev/null \
  || echo "Volume opencti-docker_minio_data not found (already removed or named differently)"
echo ""
echo "--- Inspect s3data (expected orphan) ---"
sudo docker volume inspect s3data 2>/dev/null \
  || echo "Volume s3data not found (already removed or named differently)"

# ---------------------------------------------------------------------------
section "DONE"
echo "Diagnostic complete. Review output above or in the tee'd log file."
