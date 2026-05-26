#!/bin/bash
# =============================================================================
# BuildToValue Trust OS — Stack Startup Script
# Inicia API Python (porta 8000) + Demo Proxy (porta 9090)
# Uso: bash /opt/btv/scripts/start.sh
# Crontab: @reboot /opt/btv/scripts/start.sh
# =============================================================================

set -e

BTV_ROOT="/opt/btv"
VENV="$BTV_ROOT/python/venv"
API_PORT=8000
FRONTEND_PORT=9090
API_LOG="/tmp/btv-api.log"
PROXY_LOG="/tmp/btv-proxy.log"
PID_API="/tmp/btv-api.pid"
PID_PROXY="/tmp/btv-proxy.pid"

echo "[BTV] ====================================================="
echo "[BTV] BuildToValue Trust OS — Startup"
echo "[BTV] $(date '+%Y-%m-%d %H:%M:%S')"
echo "[BTV] ====================================================="

# ── Verificar venv ───────────────────────────────────────────
if [ ! -f "$VENV/bin/activate" ]; then
  echo "[BTV] ERRO: venv não encontrado em $VENV"
  exit 1
fi

source "$VENV/bin/activate"

# ── Matar processos anteriores graciosamente ─────────────────
if [ -f "$PID_API" ]; then
  OLD_PID=$(cat "$PID_API" 2>/dev/null)
  if kill -0 "$OLD_PID" 2>/dev/null; then
    echo "[BTV] Encerrando API anterior (PID $OLD_PID)..."
    kill "$OLD_PID" 2>/dev/null || true
    sleep 1
  fi
  rm -f "$PID_API"
fi

if [ -f "$PID_PROXY" ]; then
  OLD_PID=$(cat "$PID_PROXY" 2>/dev/null)
  if kill -0 "$OLD_PID" 2>/dev/null; then
    echo "[BTV] Encerrando proxy anterior (PID $OLD_PID)..."
    kill "$OLD_PID" 2>/dev/null || true
    sleep 1
  fi
  rm -f "$PID_PROXY"
fi

# Garantir que as portas estão livres
lsof -ti:$API_PORT | xargs kill -9 2>/dev/null || true
lsof -ti:$FRONTEND_PORT | xargs kill -9 2>/dev/null || true
sleep 1

# ── Iniciar API Python ────────────────────────────────────────
echo "[BTV] Iniciando API Python na porta $API_PORT..."
cd "$BTV_ROOT/python"
BTV_API_KEYS="demo-key" \
nohup uvicorn buildtovalue.api.app:app \
  --host 0.0.0.0 \
  --port $API_PORT \
  --workers 1 \
  >> "$API_LOG" 2>&1 &

API_PID=$!
echo $API_PID > "$PID_API"
echo "[BTV] API PID: $API_PID — log: $API_LOG"

# Aguardar API estar pronta
echo -n "[BTV] Aguardando API..."
for i in $(seq 1 15); do
  if curl -sf http://localhost:$API_PORT/health > /dev/null 2>&1; then
    echo " OK (${i}s)"
    break
  fi
  echo -n "."
  sleep 1
  if [ $i -eq 15 ]; then
    echo " TIMEOUT"
    echo "[BTV] AVISO: API não respondeu em 15s. Verifique $API_LOG"
  fi
done

# ── Iniciar Demo Proxy ────────────────────────────────────────
echo "[BTV] Iniciando Demo Proxy na porta $FRONTEND_PORT..."
cd "$BTV_ROOT"
BTV_DEMO_PORT=$FRONTEND_PORT \
BTV_API_BASE="http://localhost:$API_PORT" \
BTV_RUST_BASE="http://localhost:$API_PORT" \
BTV_DEMO_KEY="demo-key" \
nohup python3 demo/proxy.py \
  >> "$PROXY_LOG" 2>&1 &

PROXY_PID=$!
echo $PROXY_PID > "$PID_PROXY"
echo "[BTV] Proxy PID: $PROXY_PID — log: $PROXY_LOG"

sleep 2

# ── Health check final ────────────────────────────────────────
echo "[BTV] ====================================================="
if curl -sf http://localhost:$FRONTEND_PORT/api/health > /dev/null 2>&1; then
  HEALTH=$(curl -s http://localhost:$FRONTEND_PORT/api/health)
  echo "[BTV] ✓ Stack OK — frontend: http://0.0.0.0:$FRONTEND_PORT"
  echo "[BTV] ✓ Health: $HEALTH"
else
  echo "[BTV] ✗ Health check falhou. Verifique os logs:"
  echo "      API:   tail -f $API_LOG"
  echo "      Proxy: tail -f $PROXY_LOG"
fi
echo "[BTV] ====================================================="
