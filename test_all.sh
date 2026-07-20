#!/bin/bash
# AES — Full test suite
# Usage: bash test_all.sh

cd ~/aes
source venv/bin/activate

echo ""
echo "========================================"
echo "  AES Test Suite"
echo "========================================"

PASS=0
FAIL=0

check() {
    local label=$1
    local cmd=$2
    if eval "$cmd" &>/dev/null; then
        echo "  ✅  $label"
        ((PASS++))
    else
        echo "  ❌  $label"
        eval "$cmd" 2>&1 | sed 's/^/      /'
        ((FAIL++))
    fi
}

echo ""
echo "── Imports ──────────────────────────────"
check "agents.monitor_agent"      "python3 -c 'from agents.monitor_agent import MonitorAgent'"
check "agents.monitor_agent_mqtt" "python3 -c 'from agents.monitor_agent_mqtt import *'"
check "agents.response_agent"     "python3 -c 'from agents.response_agent import respond'"
check "discord.discord_alerts"    "python3 -c 'from discord.discord_alerts import post_incident_alert'"
check "rag.query_chromadb"        "python3 -c 'from rag.query_chromadb import query_intel'"

echo ""
echo "── Diagnostic ───────────────────────────"
python3 -m tests.diagnostic

echo ""
echo "── Simulation (5s) ──────────────────────"
python3 -c "import paho.mqtt.client; import telemetry_sim" 2>/dev/null && echo "  ✅  telemetry_sim importable" || echo "  ❌  telemetry_sim import failed"

echo ""
echo "========================================"
echo "  $PASS passed   $FAIL failed"
echo "========================================"
echo ""
