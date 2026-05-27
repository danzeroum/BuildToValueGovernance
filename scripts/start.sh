#!/bin/bash
# =============================================================================
# BuildToValue Trust OS — Stack Startup Script
# Inicia todos os serviços:
#   - API Python/uvicorn    (porta 8000)
#   - Rust gateway binary   (porta 8080, se existir em target/release/)
#   - Demo proxy            (porta 9090, demo/proxy.py)
#   - Docs MkDocs           (porta 9091)
#
# Uso:   bash /opt/btv/scripts/start.sh
# Reboot: @reboot /opt/btv/scripts/start.sh >> /tmp/btv-boot.log 2>&1
# =============================================================================

set -euo pipefail

BTV_ROOT="/opt/btv"
VENV="$BTV_ROOT/python/venv"

# ── Portas ────────────────────────────────────────────────────────────────────
API_PORT=8000          # Python/uvicorn
RUST_PORT=8080         # Rust/Axum gateway
FRONTEND_PORT=9090     # Demo proxy
DOCS_PORT=9091         # MkDocs

# ── PID / logs ────────────────────────────────────────────────────────────────
PID_API="/tmp/btv-api.pid"
PID_RUST="/tmp/btv-rust.pid"
PID_PROXY="/tmp/btv-proxy.pid"
PID_DOCS="/tmp/btv-docs.pid"
API_LOG="/tmp/btv-api.log"
RUST_LOG="/tmp/btv-rust.log"
PROXY_LOG="/tmp/btv-proxy.log"
DOCS_LOG="/tmp/btv-docs.log"

log() { echo "[BTV] $*"; }

log "====================================================="
log "BuildToValue Trust OS — Startup"
log "$(date '+%Y-%m-%d %H:%M:%S')"
log "====================================================="

# ── Verificar venv ────────────────────────────────────────────────────────────
if [ ! -f "$VENV/bin/activate" ]; then
  log "ERRO: venv não encontrado em $VENV"
  log "Execute: python3 -m venv $VENV && source $VENV/bin/activate && pip install -e $BTV_ROOT/python"
  exit 1
fi

source "$VENV/bin/activate"

# ── Garantir dependências ─────────────────────────────────────────────────────
if [ -f "$BTV_ROOT/docs/requirements.txt" ]; then
  pip install -q -r "$BTV_ROOT/docs/requirements.txt"
fi

# ── Parar instâncias anteriores graciosamente ─────────────────────────────────
_stop_pid() {
  local pidfile="$1" label="$2"
  if [ -f "$pidfile" ]; then
    local old_pid
    old_pid=$(cat "$pidfile" 2>/dev/null || true)
    if [ -n "$old_pid" ] && kill -0 "$old_pid" 2>/dev/null; then
      log "Encerrando $label anterior (PID $old_pid)..."
      kill "$old_pid" 2>/dev/null || true
      sleep 1
    fi
    rm -f "$pidfile"
  fi
}

_stop_pid "$PID_API"   "API Python"
_stop_pid "$PID_RUST"  "Rust gateway"
_stop_pid "$PID_PROXY" "Demo proxy"
_stop_pid "$PID_DOCS"  "MkDocs docs"

# Garantir que as portas estão livres
lsof -ti:"$API_PORT"      | xargs kill -9 2>/dev/null || true
lsof -ti:"$RUST_PORT"     | xargs kill -9 2>/dev/null || true
lsof -ti:"$FRONTEND_PORT" | xargs kill -9 2>/dev/null || true
lsof -ti:"$DOCS_PORT"     | xargs kill -9 2>/dev/null || true
sleep 1

# ── 1. API Python ─────────────────────────────────────────────────────────────
log "Iniciando API Python na porta $API_PORT..."
cd "$BTV_ROOT/python"
BTV_API_KEYS="demo-key" \
nohup uvicorn buildtovalue.api.app:app \
  --host 0.0.0.0 \
  --port "$API_PORT" \
  --workers 1 \
  >> "$API_LOG" 2>&1 &

API_PID=$!
echo "$API_PID" > "$PID_API"
log "API PID: $API_PID — log: $API_LOG"

# Aguardar API estar pronta
printf "[BTV] Aguardando API"
for i in $(seq 1 20); do
  if curl -sf "http://localhost:$API_PORT/health" > /dev/null 2>&1; then
    log " OK (${i}s)"
    break
  fi
  printf "."
  sleep 1
  if [ "$i" -eq 20 ]; then
    log " TIMEOUT — verifique $API_LOG"
  fi
done

# ── 2. Rust gateway (opcional) ────────────────────────────────────────────────
RUST_BIN=""
for candidate in \
    "$BTV_ROOT/target/release/btv-gateway" \
    "$BTV_ROOT/target/release/buildtovalue" \
    "$BTV_ROOT/target/release/btv"; do
  if [ -x "$candidate" ]; then
    RUST_BIN="$candidate"
    break
  fi
done

if [ -n "$RUST_BIN" ]; then
  log "Iniciando Rust gateway ($RUST_BIN) na porta $RUST_PORT..."
  cd "$BTV_ROOT"
  BTV_API_KEYS="demo-key" \
  nohup "$RUST_BIN" \
    >> "$RUST_LOG" 2>&1 &

  RUST_PID=$!
  echo "$RUST_PID" > "$PID_RUST"
  log "Rust PID: $RUST_PID — log: $RUST_LOG"
  sleep 2
else
  log "Binário Rust não encontrado em target/release/ — proxy encaminhará /v1/* para API Python."
  log "  (Para compilar: cd $BTV_ROOT && cargo build --release)"
fi

# ── 3. Demo proxy ─────────────────────────────────────────────────────────────
log "Iniciando Demo Proxy na porta $FRONTEND_PORT..."
cd "$BTV_ROOT"
BTV_DEMO_PORT="$FRONTEND_PORT" \
BTV_API_BASE="http://localhost:$API_PORT" \
BTV_RUST_BASE="http://localhost:$RUST_PORT" \
BTV_DEMO_KEY="demo-key" \
nohup python3 demo/proxy.py \
  >> "$PROXY_LOG" 2>&1 &

PROXY_PID=$!
echo "$PROXY_PID" > "$PID_PROXY"
log "Proxy PID: $PROXY_PID — log: $PROXY_LOG"

# ── 4. MkDocs docs ────────────────────────────────────────────────────────────
log "Gerando referência docs/developer/reference..."
cd "$BTV_ROOT"
python3 scripts/autogen_reference.py >> "$DOCS_LOG" 2>&1 || \
  log "AVISO: autogen_reference.py falhou — verifique $DOCS_LOG"

log "Iniciando MkDocs na porta $DOCS_PORT..."
nohup mkdocs serve --dev-addr "0.0.0.0:$DOCS_PORT" \
  >> "$DOCS_LOG" 2>&1 &

DOCS_PID=$!
echo "$DOCS_PID" > "$PID_DOCS"
log "Docs PID: $DOCS_PID — log: $DOCS_LOG"

sleep 3

# ── Health check final ────────────────────────────────────────────────────────
log "====================================================="
if curl -sf "http://localhost:$FRONTEND_PORT/api/health" > /dev/null 2>&1; then
  HEALTH=$(curl -s "http://localhost:$FRONTEND_PORT/api/health")
  log "✓ Stack OK"
  log "✓ Frontend: http://0.0.0.0:$FRONTEND_PORT   (demo + proxy)"
  log "✓ API:      http://0.0.0.0:$API_PORT         (Python/uvicorn)"
  [ -n "$RUST_BIN" ] && log "✓ Rust GW:  http://0.0.0.0:$RUST_PORT       (Axum gateway)"
  log "✓ Docs:     http://0.0.0.0:$DOCS_PORT        (MkDocs)"
  log "✓ Health:   $HEALTH"
else
  log "✗ Health check falhou. Verifique os logs:"
  log "  API:   tail -f $API_LOG"
  log "  Proxy: tail -f $PROXY_LOG"
  log "  Docs:  tail -f $DOCS_LOG"
  [ -n "$RUST_BIN" ] && log "  Rust:  tail -f $RUST_LOG"
fi
log "====================================================="
