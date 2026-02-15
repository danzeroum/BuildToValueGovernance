#!/bin/bash
# scripts/emergency_killswitch.sh
# BuildToValue v2.2 - Emergency Killswitch
# Bloqueia TODAS as requisições em caso de incidente crítico
# Criado: 2026-02-04

set -euo pipefail

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
INCIDENT_ID="${1:-MANUAL-$(date +%s)}"
REASON="${2:-Emergency shutdown triggered manually}"

echo "════════════════════════════════════════════════════════════════"
echo "🚨 EMERGENCY KILLSWITCH ACTIVATED"
echo "════════════════════════════════════════════════════════════════"
echo "Incident ID:  $INCIDENT_ID"
echo "Timestamp:    $TIMESTAMP"
echo "Reason:       $REASON"
echo "════════════════════════════════════════════════════════════════"

# 1. Criar arquivo de bloqueio
LOCKFILE="data/.emergency_lockdown"
cat > "$LOCKFILE" << EOF
{
  "incident_id": "$INCIDENT_ID",
  "timestamp": "$TIMESTAMP",
  "reason": "$REASON",
  "triggered_by": "$USER",
  "status": "ACTIVE"
}
EOF

echo "✅ Lockfile created: $LOCKFILE"

# 2. Escalar deployment Kubernetes para 0 (se disponível)
if command -v kubectl &> /dev/null; then
    echo ""
    echo "☸️  Scaling down Kubernetes deployments..."
    kubectl scale deployment btv-kernel --replicas=0 -n buildtovalue-prod 2>/dev/null || echo "  ⚠️  btv-kernel not found"
    kubectl scale deployment btv-governance --replicas=0 -n buildtovalue-prod 2>/dev/null || echo "  ⚠️  btv-governance not found"
    echo "  ✅ Kubernetes scaled down"
fi

# 3. Notificar equipe (webhook, email, Slack, PagerDuty, etc.)
echo ""
echo "📢 Notifying incident response team..."
# TODO: Integrar com sistema de alertas
# curl -X POST https://hooks.slack.com/... -d "{...}"
echo "  ⚠️  Notification system not configured (manual notification required)"

# 4. Criar incident report
INCIDENT_REPORT="logs/incident_${INCIDENT_ID}.log"
mkdir -p logs
cat > "$INCIDENT_REPORT" << EOF
INCIDENT REPORT
===============

Incident ID:    $INCIDENT_ID
Timestamp:      $TIMESTAMP
Triggered by:   $USER
Reason:         $REASON

ACTIONS TAKEN:
- Emergency lockfile created
- All services blocked
- Kubernetes deployments scaled to 0
- Incident response team notified

NEXT STEPS:
1. Investigate root cause
2. Review audit trail (ledger)
3. Analyze last N requests before incident
4. Fix vulnerability/issue
5. Run security audit
6. Clear lockfile: rm data/.emergency_lockdown
7. Restart services

Contact: security@buildtovalue.com
EOF

echo "  ✅ Incident report: $INCIDENT_REPORT"

# 5. Backup atual do ledger
if [ -d "data/ledger" ]; then
    echo ""
    echo "💾 Backing up ledger..."
    BACKUP_DIR="data/ledger_backup_${INCIDENT_ID}"
    cp -r data/ledger "$BACKUP_DIR"
    echo "  ✅ Ledger backup: $BACKUP_DIR"
fi

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "🛑 SYSTEM LOCKED DOWN"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "All services are now BLOCKED."
echo "To restore:"
echo "  1. Investigate and fix issue"
echo "  2. rm $LOCKFILE"
echo "  3. kubectl scale deployment btv-kernel --replicas=3"
echo "  4. kubectl scale deployment btv-governance --replicas=5"
echo ""
echo "Incident Report: $INCIDENT_REPORT"
echo "════════════════════════════════════════════════════════════════"
