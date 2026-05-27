#!/bin/bash
# =============================================================================
# BuildToValue Trust OS — Deploy & Reload Script
# Puxa branch do GitHub e reinicia o frontend sem downtime de API
# Uso: bash /opt/btv/scripts/deploy.sh [branch]
# Exemplo: bash /opt/btv/scripts/deploy.sh main
#          bash /opt/btv/scripts/deploy.sh feat/theme-light-mode
# =============================================================================

set -e

BTV_ROOT="/opt/btv"
VENV="$BTV_ROOT/python/venv"
MKDOCS_BIN="/opt/btv-mkdocs-venv/bin/mkdocs"
TARGET_BRANCH="${1:-main}"
API_PORT=8000
FRONTEND_PORT=9090
DOCS_PORT=9091
PID_PROXY="/tmp/btv-proxy.pid"
PID_DOCS="/tmp/btv-docs.pid"
PROXY_LOG="/tmp/btv-proxy.log"
DOCS_LOG="/tmp/btv-docs.log"
DEPLOY_LOG="/tmp/btv-deploy.log"

echo "[BTV-DEPLOY] ================================================"
echo "[BTV-DEPLOY] BuildToValue Trust OS — Deploy"
echo "[BTV-DEPLOY] Branch: $TARGET_BRANCH"
echo "[BTV-DEPLOY] $(date '+%Y-%m-%d %H:%M:%S')"
echo "[BTV-DEPLOY] ================================================"

# ── 1. Verificar git ─────────────────────────────────────────
cd "$BTV_ROOT"

if ! git rev-parse --git-dir > /dev/null 2>&1; then
  echo "[BTV-DEPLOY] ERRO: $BTV_ROOT não é um repositório git."
  exit 1
fi

# Salvar hash antes do pull
BEFORE_HASH=$(git rev-parse --short HEAD)
echo "[BTV-DEPLOY] Commit atual: $BEFORE_HASH"

# ── 2. Stash de mudanças locais (dados runtime) ──────────────
git stash push -m "deploy-stash-$(date +%s)" \
  -- python/data/ python/buildtovalue/__pycache__/ \
     python/__pycache__/ 2>/dev/null || true

# ── 3. Checkout + Pull ───────────────────────────────────────
echo "[BTV-DEPLOY] Fazendo checkout em $TARGET_BRANCH..."
git fetch origin
git checkout "$TARGET_BRANCH"
git pull origin "$TARGET_BRANCH"

AFTER_HASH=$(git rev-parse --short HEAD)
echo "[BTV-DEPLOY] Commit novo: $AFTER_HASH"

if [ "$BEFORE_HASH" = "$AFTER_HASH" ]; then
  echo "[BTV-DEPLOY] Nenhuma mudança detectada. Forçando reload do proxy mesmo assim..."
else
  echo "[BTV-DEPLOY] Mudanças detectadas:"
  git log --oneline "${BEFORE_HASH}..${AFTER_HASH}" | head -10
fi

# Log do deploy
echo "$(date '+%Y-%m-%d %H:%M:%S') | $BEFORE_HASH -> $AFTER_HASH | branch=$TARGET_BRANCH" >> "$DEPLOY_LOG"

# ── 4. Ativar venv + garantir dependências ───────────────────
source "$VENV/bin/activate"

if git diff "${BEFORE_HASH}..${AFTER_HASH}" --name-only 2>/dev/null | grep -qE "requirements|pyproject\.toml|setup\.py"; then
  echo "[BTV-DEPLOY] Dependências Python alteradas — atualizando..."
  cd "$BTV_ROOT/python"
  pip install -q -e . 2>&1 | tail -5
  cd "$BTV_ROOT"
  echo "[BTV-DEPLOY] ✓ Dependências atualizadas."
fi

# Garantir dependências de docs sempre presentes
if [ -f "$BTV_ROOT/docs/requirements.txt" ]; then
  pip install -q -r "$BTV_ROOT/docs/requirements.txt"
fi

# ── 5. Verificar se API precisa reiniciar ─────────────────────
API_CHANGED=$(git diff "${BEFORE_HASH}..${AFTER_HASH}" --name-only 2>/dev/null | grep -c "^python/" || true)

if [ "$API_CHANGED" -gt 0 ]; then
  echo "[BTV-DEPLOY] Código Python alterado ($API_CHANGED arquivos) — reiniciando API..."
  lsof -ti:$API_PORT | xargs kill -9 2>/dev/null || true
  sleep 1

  cd "$BTV_ROOT/python"
  BTV_API_KEYS="demo-key" \
  nohup uvicorn buildtovalue.api.app:app \
    --host 0.0.0.0 \
    --port $API_PORT \
    --workers 1 \
    >> /tmp/btv-api.log 2>&1 &

  API_PID=$!
  echo $API_PID > /tmp/btv-api.pid
  echo "[BTV-DEPLOY] ✓ API reiniciada (PID $API_PID)"

  # Aguardar API
  echo -n "[BTV-DEPLOY] Aguardando API..."
  for i in $(seq 1 15); do
    if curl -sf http://localhost:$API_PORT/health > /dev/null 2>&1; then
      echo " OK (${i}s)"
      break
    fi
    echo -n "."
    sleep 1
  done
else
  echo "[BTV-DEPLOY] Código Python inalterado — API mantida."
  if ! curl -sf http://localhost:$API_PORT/health > /dev/null 2>&1; then
    echo "[BTV-DEPLOY] AVISO: API não está respondendo. Execute: bash scripts/start.sh"
  fi
fi

# ── 6. Reload do proxy frontend (sempre) ─────────────────────
echo "[BTV-DEPLOY] Recarregando proxy frontend..."

if [ -f "$PID_PROXY" ]; then
  OLD_PID=$(cat "$PID_PROXY" 2>/dev/null)
  if kill -0 "$OLD_PID" 2>/dev/null; then
    kill "$OLD_PID" 2>/dev/null || true
    sleep 1
  fi
  rm -f "$PID_PROXY"
fi

lsof -ti:$FRONTEND_PORT | xargs kill -9 2>/dev/null || true
sleep 1

cd "$BTV_ROOT"
BTV_DEMO_PORT=$FRONTEND_PORT \
BTV_API_BASE="http://localhost:$API_PORT" \
BTV_RUST_BASE="http://localhost:$API_PORT" \
BTV_DEMO_KEY="demo-key" \
nohup python3 demo/proxy.py \
  >> "$PROXY_LOG" 2>&1 &

PROXY_PID=$!
echo $PROXY_PID > "$PID_PROXY"
echo "[BTV-DEPLOY] ✓ Proxy recarregado (PID $PROXY_PID)"

# ── 7. Reload dos docs MkDocs (sempre) ───────────────────────
echo "[BTV-DEPLOY] Recarregando MkDocs docs..."

if [ -f "$PID_DOCS" ]; then
  OLD_PID=$(cat "$PID_DOCS" 2>/dev/null)
  if kill -0 "$OLD_PID" 2>/dev/null; then
    kill "$OLD_PID" 2>/dev/null || true
    sleep 1
  fi
  rm -f "$PID_DOCS"
fi

lsof -ti:$DOCS_PORT | xargs kill -9 2>/dev/null || true
sleep 1

cd "$BTV_ROOT"
python3 scripts/autogen_reference.py >> "$DOCS_LOG" 2>&1 || \
  echo "[BTV-DEPLOY] AVISO: autogen_reference.py falhou — verifique $DOCS_LOG"

# Verificar se o venv de mkdocs existe; se não, criá-lo
if [ ! -f "$MKDOCS_BIN" ]; then
  echo "[BTV-DEPLOY] venv mkdocs não encontrado — criando em /opt/btv-mkdocs-venv..."
  python3 -m venv /opt/btv-mkdocs-venv
  /opt/btv-mkdocs-venv/bin/pip install -q mkdocs-material
  echo "[BTV-DEPLOY] ✓ venv mkdocs criado com mkdocs-material."
fi

nohup "$MKDOCS_BIN" serve \
  --dev-addr 0.0.0.0:$DOCS_PORT \
  --config-file "$BTV_ROOT/mkdocs.yml" \
  >> "$DOCS_LOG" 2>&1 &

DOCS_PID=$!
echo $DOCS_PID > "$PID_DOCS"
echo "[BTV-DEPLOY] ✓ Docs recarregados (PID $DOCS_PID)"

sleep 2

# ── 8. Health check final ─────────────────────────────────────
echo "[BTV-DEPLOY] ================================================"
if curl -sf http://localhost:$FRONTEND_PORT/api/health > /dev/null 2>&1; then
  HEALTH=$(curl -s http://localhost:$FRONTEND_PORT/api/health | python3 -m json.tool 2>/dev/null || echo "ok")
  echo "[BTV-DEPLOY] ✓ Deploy concluído com sucesso!"
  echo "[BTV-DEPLOY] ✓ Frontend: http://0.0.0.0:$FRONTEND_PORT"
  echo "[BTV-DEPLOY] ✓ Docs:     http://0.0.0.0:$DOCS_PORT"
  echo "[BTV-DEPLOY] ✓ Commit:   $AFTER_HASH (branch: $TARGET_BRANCH)"
  echo "[BTV-DEPLOY] ✓ Health:   $HEALTH"
else
  echo "[BTV-DEPLOY] ✗ Health check falhou após deploy."
  echo "        API log:   tail -f /tmp/btv-api.log"
  echo "        Proxy log: tail -f $PROXY_LOG"
  echo "        Docs log:  tail -f $DOCS_LOG"
  exit 1
fi
echo "[BTV-DEPLOY] ================================================"

# Restaurar stash de dados se houver
git stash pop 2>/dev/null || true
