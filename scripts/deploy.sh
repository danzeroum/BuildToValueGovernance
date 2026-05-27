#!/bin/bash
# =============================================================================
# BuildToValue Trust OS — Deploy & Reload Script
# Puxa branch do GitHub e reinicia os serviços sem downtime de API
#
# Uso: bash /opt/btv/scripts/deploy.sh [branch]
# Exemplo: bash /opt/btv/scripts/deploy.sh main
#          bash /opt/btv/scripts/deploy.sh claude/minha-feature
# =============================================================================

set -euo pipefail

BTV_ROOT="/opt/btv"
VENV="$BTV_ROOT/python/venv"
MKDOCS_BIN="/opt/btv-mkdocs-venv/bin/mkdocs"
TARGET_BRANCH="${1:-main}"

# ── Portas ───────────────────────────────────────────────────────────────────
API_PORT=8000          # Python/uvicorn (buildtovalue.api.app)
RUST_PORT=8080         # Rust/Axum binary (btv-gateway), se existir
FRONTEND_PORT=9090     # Demo proxy (demo/proxy.py)
DOCS_PORT=9091         # MkDocs

# ── PID / logs ───────────────────────────────────────────────────────────────
PID_API="/tmp/btv-api.pid"
PID_RUST="/tmp/btv-rust.pid"
PID_PROXY="/tmp/btv-proxy.pid"
PID_DOCS="/tmp/btv-docs.pid"
API_LOG="/tmp/btv-api.log"
RUST_LOG="/tmp/btv-rust.log"
PROXY_LOG="/tmp/btv-proxy.log"
DOCS_LOG="/tmp/btv-docs.log"
DEPLOY_LOG="/tmp/btv-deploy.log"

log() { echo "[BTV-DEPLOY] $*"; }

log "================================================"
log "BuildToValue Trust OS — Deploy"
log "Branch: $TARGET_BRANCH"
log "$(date '+%Y-%m-%d %H:%M:%S')"
log "================================================"

# ── 1. Verificar git ──────────────────────────────────────────────────────────
cd "$BTV_ROOT"

if ! git rev-parse --git-dir > /dev/null 2>&1; then
  log "ERRO: $BTV_ROOT não é um repositório git."
  exit 1
fi

BEFORE_HASH=$(git rev-parse --short HEAD)
log "Commit atual: $BEFORE_HASH"

# ── 2. Stash de mudanças locais (dados runtime) ───────────────────────────────
# Sem set -e aqui: stash pode sair com 1 se não há nada a empilhar
git stash push -m "deploy-stash-$(date +%s)" \
  -- python/data/ python/buildtovalue/__pycache__/ \
     python/__pycache__/ 2>/dev/null || true

# ── 3. Checkout + Pull ────────────────────────────────────────────────────────
log "Fazendo checkout em $TARGET_BRANCH..."
git fetch origin
git checkout "$TARGET_BRANCH"
git pull origin "$TARGET_BRANCH"

AFTER_HASH=$(git rev-parse --short HEAD)
log "Commit novo: $AFTER_HASH"

if [ "$BEFORE_HASH" = "$AFTER_HASH" ]; then
  log "Nenhuma mudança detectada. Forçando reload dos serviços mesmo assim..."
else
  log "Mudanças detectadas:"
  git log --oneline "${BEFORE_HASH}..${AFTER_HASH}" | head -10
fi

echo "$(date '+%Y-%m-%d %H:%M:%S') | $BEFORE_HASH -> $AFTER_HASH | branch=$TARGET_BRANCH" >> "$DEPLOY_LOG"

# ── 4. Ativar venv + garantir dependências ────────────────────────────────────
if [ ! -f "$VENV/bin/activate" ]; then
  log "ERRO: venv não encontrado em $VENV. Execute: python3 -m venv $VENV && source $VENV/bin/activate && pip install -e $BTV_ROOT/python"
  exit 1
fi
source "$VENV/bin/activate"

# Instalar/atualizar dependências Python se necessário
if git diff "${BEFORE_HASH}..${AFTER_HASH}" --name-only 2>/dev/null | grep -qE "requirements|pyproject\.toml|setup\.py"; then
  log "Dependências Python alteradas — atualizando..."
  cd "$BTV_ROOT/python"
  pip install -q -e . 2>&1 | tail -5
  cd "$BTV_ROOT"
  log "✓ Dependências Python atualizadas."
fi

# Dependências de docs (sempre garantir)
if [ -f "$BTV_ROOT/docs/requirements.txt" ]; then
  pip install -q -r "$BTV_ROOT/docs/requirements.txt"
fi

# ── 5. API Python — reiniciar se código mudou OU se não estiver rodando ──────
API_CHANGED=$(git diff "${BEFORE_HASH}..${AFTER_HASH}" --name-only 2>/dev/null | grep -c "^python/" || true)
API_ALIVE=false
curl -sf "http://localhost:$API_PORT/health" > /dev/null 2>&1 && API_ALIVE=true

_start_api() {
  if [ -f "$PID_API" ]; then
    kill "$(cat "$PID_API" 2>/dev/null)" 2>/dev/null || true
    rm -f "$PID_API"
  fi
  lsof -ti:"$API_PORT" | xargs kill -9 2>/dev/null || true
  sleep 1

  cd "$BTV_ROOT/python"
  BTV_API_KEYS="demo-key" \
  nohup uvicorn buildtovalue.api.app:app \
    --host 0.0.0.0 \
    --port "$API_PORT" \
    --workers 1 \
    >> "$API_LOG" 2>&1 &

  API_PID=$!
  echo "$API_PID" > "$PID_API"
  log "✓ API iniciada (PID $API_PID)"

  printf "[BTV-DEPLOY] Aguardando API"
  for i in $(seq 1 20); do
    if curl -sf "http://localhost:$API_PORT/health" > /dev/null 2>&1; then
      log " OK (${i}s)"
      return 0
    fi
    printf "."
    sleep 1
  done
  log " TIMEOUT — verifique $API_LOG"
}

if [ "$API_CHANGED" -gt 0 ]; then
  log "Código Python alterado ($API_CHANGED arquivos) — reiniciando API..."
  _start_api
elif [ "$API_ALIVE" = false ]; then
  log "API não está rodando — iniciando..."
  _start_api
else
  log "API OK (sem alterações, já rodando na porta $API_PORT)."
fi

# ── 6. Reiniciar binário Rust se existir e código alterado ───────────────────
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

RUST_CHANGED=$(git diff "${BEFORE_HASH}..${AFTER_HASH}" --name-only 2>/dev/null | grep -cE "^(src/|Cargo)" || true)

if [ -n "$RUST_BIN" ]; then
  if [ "$RUST_CHANGED" -gt 0 ]; then
    log "Código Rust alterado ($RUST_CHANGED arquivos) — reconstruindo..."
    cd "$BTV_ROOT"
    cargo build --release >> "$RUST_LOG" 2>&1 && log "✓ Rust build OK" || log "AVISO: Rust build falhou — mantendo binário anterior."
  fi

  log "Reiniciando serviço Rust ($RUST_BIN)..."
  if [ -f "$PID_RUST" ]; then
    kill "$(cat "$PID_RUST" 2>/dev/null)" 2>/dev/null || true
    rm -f "$PID_RUST"
  fi
  lsof -ti:"$RUST_PORT" | xargs kill -9 2>/dev/null || true
  sleep 1

  cd "$BTV_ROOT"
  BTV_API_KEYS="demo-key" \
  nohup "$RUST_BIN" \
    >> "$RUST_LOG" 2>&1 &

  RUST_PID=$!
  echo "$RUST_PID" > "$PID_RUST"
  log "✓ Rust gateway reiniciado (PID $RUST_PID, porta $RUST_PORT)"
  sleep 2
else
  log "Binário Rust não encontrado em target/release/ — pulando etapa Rust."
fi

# ── 7. Reload do proxy frontend (sempre) ─────────────────────────────────────
log "Recarregando proxy frontend (porta $FRONTEND_PORT)..."

if [ -f "$PID_PROXY" ]; then
  kill "$(cat "$PID_PROXY" 2>/dev/null)" 2>/dev/null || true
  rm -f "$PID_PROXY"
fi
lsof -ti:"$FRONTEND_PORT" | xargs kill -9 2>/dev/null || true
sleep 1

cd "$BTV_ROOT"
BTV_DEMO_PORT="$FRONTEND_PORT" \
BTV_API_BASE="http://localhost:$API_PORT" \
BTV_RUST_BASE="http://localhost:$RUST_PORT" \
BTV_DEMO_KEY="demo-key" \
nohup python3 demo/proxy.py \
  >> "$PROXY_LOG" 2>&1 &

PROXY_PID=$!
echo "$PROXY_PID" > "$PID_PROXY"
log "✓ Proxy recarregado (PID $PROXY_PID)"

# ── 8. Reload dos docs MkDocs (sempre) ───────────────────────────────────────
log "Recarregando MkDocs docs (porta $DOCS_PORT)..."

if [ -f "$PID_DOCS" ]; then
  kill "$(cat "$PID_DOCS" 2>/dev/null)" 2>/dev/null || true
  rm -f "$PID_DOCS"
fi
lsof -ti:"$DOCS_PORT" | xargs kill -9 2>/dev/null || true
sleep 1

cd "$BTV_ROOT"
python3 scripts/autogen_reference.py >> "$DOCS_LOG" 2>&1 || \
  log "AVISO: autogen_reference.py falhou — verifique $DOCS_LOG"

nohup mkdocs serve --dev-addr "0.0.0.0:$DOCS_PORT" \
  >> "$DOCS_LOG" 2>&1 &

DOCS_PID=$!
echo "$DOCS_PID" > "$PID_DOCS"
log "✓ Docs recarregados (PID $DOCS_PID)"

sleep 3

# ── 9. Health check final ─────────────────────────────────────────────────────
log "================================================"
if curl -sf "http://localhost:$FRONTEND_PORT/api/health" > /dev/null 2>&1; then
  HEALTH=$(curl -s "http://localhost:$FRONTEND_PORT/api/health" | python3 -m json.tool 2>/dev/null || echo "ok")
  log "✓ Deploy concluído com sucesso!"
  log "✓ Frontend:  http://0.0.0.0:$FRONTEND_PORT"
  log "✓ API:       http://0.0.0.0:$API_PORT"
  [ -n "$RUST_BIN" ] && log "✓ Rust GW:   http://0.0.0.0:$RUST_PORT"
  log "✓ Docs:      http://0.0.0.0:$DOCS_PORT"
  log "✓ Commit:    $AFTER_HASH (branch: $TARGET_BRANCH)"
  log "✓ Health:    $HEALTH"
else
  log "✗ Health check falhou após deploy."
  log "  API log:   tail -f $API_LOG"
  log "  Proxy log: tail -f $PROXY_LOG"
  log "  Docs log:  tail -f $DOCS_LOG"
  exit 1
fi
log "================================================"

# Restaurar stash de dados se houver
git stash pop 2>/dev/null || true
