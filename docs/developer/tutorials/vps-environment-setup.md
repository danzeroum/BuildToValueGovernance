---
title: "Tutorial 05 — Configuração de Ambientes VPS (DEV/PROD)"
---

# Tutorial 05 — Configuração de Ambientes VPS (DEV/PROD)

> Estado declarativo, auditável, com limites impostos pelo kernel — não por disciplina do operador.

## Por que dois ambientes no mesmo servidor?

Em projetos com uma única VPS, a tentação é rodar tudo no mesmo processo com scripts em background (`nohup &`, `pkill`). Isso cria **acoplamento de risco**: um experimento em desenvolvimento pode:

- Consumir toda a memória disponível (*resource exhaustion*)
- Colidir com portas de produção
- Expor endpoints não finalizados publicamente
- Impossibilitar auditoria de logs — quem gerou o quê?

A solução não exige dois servidores. A literatura de DevOps (FIA, *DevOps e Integração Contínua*) identifica este como um caso de "mistura de níveis de sensibilidade dos workloads": workloads com diferentes perfis de risco compartilhando o mesmo espaço sem controle formal de mudança. O isolamento lógico forte via primitivas do kernel Linux é a resposta arquitetural — e está documentado no [RISK_REGISTER.md](../RISK_REGISTER.md) como mitigação dos riscos de acoplamento operacional.

---

## Arquitetura: separação topológica de poderes

```
VPS (76.13.238.209)
│
├── UFW (firewall de borda)
│   ├── ALLOW: 22/tcp, 80/tcp, 443/tcp   ← visível da internet
│   └── DENY: tudo mais (9090, 9091 invisíveis externamente)
│
├── Docker Network: btv-prod-net  [bridge pública]
│   ├── nginx-prod   → 0.0.0.0:80 / 0.0.0.0:443  (TLS)
│   ├── docs-prod    → interno (sem porta pública direta)
│   └── demo-prod    → interno (sem porta pública direta)
│
├── Docker Network: btv-dev-net  [internal: true — cega]
│   ├── docs-dev → 127.0.0.1:9091  (loopback)
│   └── demo-dev → 127.0.0.1:9090  (loopback)
│
Filesystem da VPS:
  /var/www/buildtovalue/{docs,demo}  ← PROD (nginx:alpine, montagem :ro)
  /opt/buildtovalue/                 ← git clone da main
  /opt/btv/{docs,demo}               ← laboratório DEV (montagem :rw, hot-reload)
```

A separação não é lógica apenas no nível da aplicação — é física no nível do subsistema de rede do kernel.

---

## Como funciona `internal: true`

A flag `internal: true` em `btv-dev-net`
([`ops/docker-compose.vps.yml`](https://github.com/danzeroum/BuildToValueGovernance/blob/main/ops/docker-compose.vps.yml))
**não é uma regra de firewall**. É uma primitiva do subsistema de rede do Docker que instrui o kernel Linux a *não criar uma rota de gateway padrão* (`0.0.0.0/0`) para aquela bridge. O resultado: os contêineres de DEV são topologicamente incapazes de rotear tráfego para a internet.

Isso importa porque regras de `ufw` podem ser removidas acidentalmente. A ausência de gateway de rota não pode.

> **Rawls — Blind Testing:** a rede `btv-dev-net` é deliberadamente cega às condições externas por design topológico, não por disciplina do operador. Decisões de desenvolvimento não são contaminadas por tráfego real de produção.

Do ponto de vista de *Defesa em Profundidade* (literatura DevSecOps): o UFW é a camada externa, visível e configurável; o `internal: true` é a camada interna, imune a misconfigurações de camada 4. As duas camadas são **independentes** — falha em uma não compromete a outra.

---

## Pré-requisitos

| Requisito | Versão mínima | Comando de verificação |
|---|---|---|
| Ubuntu / Debian VPS | 22.04 LTS | `lsb_release -a` |
| Docker Engine | 24.x | `docker --version` |
| Docker Compose plugin | 2.x | `docker compose version` |
| certbot | qualquer | `certbot --version` |
| Python + pip | 3.11+ | `python3 --version` |
| MkDocs Material | 9.x | `mkdocs --version` |
| Acesso SSH root | — | `ssh root@76.13.238.209` |

!!! warning "Conflito de porta"
    O Nginx do host (`systemd`) deve estar **parado** antes de subir `nginx-prod` via Docker.
    Ambos disputam as portas 80 e 443:
    ```bash
    sudo systemctl stop nginx
    sudo systemctl disable nginx
    ```

---

## Passo 1 — Configurar UFW

UFW é a primeira camada de defesa. Configure-o antes de qualquer outro passo:

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
sudo ufw status verbose
```

!!! note "Portas 9090 e 9091"
    Elas estão **deliberadamente ausentes** desta lista. O acesso ao ambiente DEV
    ocorre exclusivamente via túnel SSH (ver seção abaixo) — não por abertura de
    porta no firewall. Esta é a segunda camada de defesa em profundidade: o bind de
    `127.0.0.1` no Compose é independente do UFW.

---

## Passo 2 — Criar diretórios de trabalho

```bash
# Conteúdo estático servido pelo nginx de produção
sudo mkdir -p /var/www/buildtovalue/{docs,demo}
sudo chown -R www-data:www-data /var/www/buildtovalue

# Código-fonte de produção (git clone da main)
sudo mkdir -p /opt/buildtovalue
sudo chown $USER:$USER /opt/buildtovalue
git clone https://github.com/danzeroum/BuildToValueGovernance.git /opt/buildtovalue

# Laboratório de desenvolvimento (hot-reload)
sudo mkdir -p /opt/btv/{docs,demo}
sudo chown -R $USER:$USER /opt/btv
```

Os diretórios `/opt/btv/` são montados como `:rw` nos contêineres DEV — qualquer
edição local é refletida imediatamente sem necessidade de rebuild.

---

## Passo 3 — Instalar dependências

```bash
cd /opt/buildtovalue
pip install mkdocs-material -r docs/requirements.txt
```

---

## Passo 4 — Provisionar certificado TLS

```bash
sudo certbot --nginx \
  -d demo.buildtovalue.cloud \
  -d docs.buildtovalue.cloud
```

O certbot cria automaticamente os blocos `server` no Nginx do host. Após isso,
o contêiner `nginx-prod` montará `/etc/letsencrypt` como `:ro` para servir TLS.

---

## Passo 5 — Subir os serviços

```bash
cd /opt/buildtovalue
docker compose -f ops/docker-compose.vps.yml up -d
```

Verifique o estado de todos os serviços:

```bash
docker compose -f ops/docker-compose.vps.yml ps
```

Output esperado: 5 contêineres em estado `running` — `docs-prod`, `demo-prod`,
`nginx-prod`, `docs-dev`, `demo-dev`.

---

## Comandos de ciclo de vida

| Operação | Comando |
|---|---|
| Subir todos os serviços | `docker compose -f ops/docker-compose.vps.yml up -d` |
| Subir apenas DEV (laboratório) | `docker compose -f ops/docker-compose.vps.yml up -d docs-dev demo-dev` |
| Ver logs de produção em tempo real | `docker compose -f ops/docker-compose.vps.yml logs -f nginx-prod` |
| Ver últimas 50 linhas de um serviço | `docker compose -f ops/docker-compose.vps.yml logs --tail=50 docs-prod` |
| Parar tudo com segurança | `docker compose -f ops/docker-compose.vps.yml down` |

---

## Acesso ao ambiente DEV via túnel SSH

As portas 9090 e 9091 estão vinculadas a `127.0.0.1` na VPS — invisíveis
externamente. O acesso ocorre via **túnel SSH criptografado**, executado na
**sua máquina local** (não na VPS):

```bash
# Na sua máquina local (usando o alias btv-vps do ~/.ssh/config):
ssh -L 9090:localhost:9090 \
    -L 9091:localhost:9091 \
    btv-vps -N
```

Com o túnel ativo, acesse no navegador local:

| URL local | Serviço | Diretório na VPS |
|---|---|---|
| `http://localhost:9090` | Demo DEV | `/opt/btv/demo/` |
| `http://localhost:9091` | Docs DEV | `/opt/btv/docs/` |

!!! tip "Por que túnel SSH e não abrir a porta no firewall?"
    O túnel SSH usa criptografia nativa do protocolo. Nenhuma credencial ou conteúdo
    em desenvolvimento trafega em texto claro. Abrir 9090/9091 no `ufw` exporia os
    ambientes a qualquer IP do mundo.

> **Levinas — Proteção:** portas vinculadas a `127.0.0.1` garantem que o ambiente
> de laboratório nunca é exposto a terceiros que não têm como auditar o que está
> sendo testado.

**Configuração recomendada** — adicione ao `~/.ssh/config` da sua máquina local para abstrair o IP fora da linha de comando e tornar o alias resiliente a mudanças de endereço:

```
# ~/.ssh/config
Host btv-vps
  HostName <IP_DA_VPS>
  User root
```

Em seguida, adicione o alias no `~/.zshrc` ou `~/.bashrc`:

```bash
alias btv-tunnel='ssh -L 9090:localhost:9090 -L 9091:localhost:9091 btv-vps -N -v'
```

Com esta configuração, uma eventual troca de IP da VPS exige alteração em apenas um lugar (`~/.ssh/config`), sem tocar no alias ou na documentação.

---

## Fluxo de deploy com `btv-deploy`

```
Sua máquina local (/opt/btv/ ou editor)
│
│  git push
▼
GitHub (main)
│
│  btv-deploy [branch]
▼
/opt/buildtovalue/          ← git pull
│
├── mkdocs build ──────────▶ /var/www/buildtovalue/docs ──▶ docs.buildtovalue.cloud
└── rsync demo/ ───────────▶ /var/www/buildtovalue/demo ──▶ demo.buildtovalue.cloud
```

O script [`scripts/deploy.sh`](https://github.com/danzeroum/BuildToValueGovernance/blob/main/scripts/deploy.sh)
implementa uma esteira CD determinística:

1. `git fetch origin` + `git checkout $BRANCH` + `git pull`
2. Verificação de delta de dependências (pip apenas se `requirements.txt` mudou)
3. Rebuild condicional (API Python, gateway Rust, MkDocs — só o que mudou)
4. Health check final — exit 1 se o serviço não responder

Cada execução produz um **commit hash rastreável** — o equivalente ao `TechnicalEvidence`
do protocolo BTV aplicado à infraestrutura.

```bash
# Deploy da branch main (padrão)
btv-deploy

# Deploy de branch específica
btv-deploy develop
```

!!! note "CI/CD como contrato"
    O `btv-deploy` re-executa as mesmas invariantes de validação do pipeline remoto
    (`validate_invariants.py`, `autogen_reference.py`). Um deploy que passa localmente
    deve passar no CI — e vice-versa. Nenhuma alteração em `/opt/btv/` chega a produção
    até que `btv-deploy` seja executado explicitamente. O deploy é um ato consciente e auditável.

---

## Isolamento de recursos (cgroups)

Os contêineres têm limites impostos pelo kernel via **cgroups**:

| Contêiner | `mem_limit` | `cpus` | Rede | `restart` |
|---|---|---|---|---|
| `docs-prod` | 512m | 1.0 | btv-prod-net | `always` |
| `demo-prod` | 512m | 1.0 | btv-prod-net | `always` |
| `nginx-prod` | — | — | btv-prod-net | `always` |
| `docs-dev` | 256m | 0.5 | btv-dev-net | `on-failure:3` |
| `demo-dev` | 256m | 0.5 | btv-dev-net | `on-failure:3` |

A diferença de política de reinício é intencional:

- **`restart: always` (PROD):** o serviço deve voltar a qualquer custo após reinício da VPS.
- **`restart: on-failure:3` (DEV):** após 3 falhas consecutivas, o Docker para de tentar. Isso evita que um serviço DEV defeituoso entre em loop infinito consumindo CPU indefinidamente — é a política **Fail-Secure** em ação.

> **Jonas — Responsabilidade:** limitar CPU e memória de DEV a 50% da alocação de PROD
> é um ato de responsabilidade para com o ambiente de produção que compartilha o mesmo
> host físico. Um contêiner DEV runaway não pode causar inanição (*resource exhaustion*)
> dos serviços que atendem usuários reais.

---

## Segregação de logs e Separação de Deveres

O driver `json-file` com `max-size` e `max-file` garante que:

1. **Logs são gerenciados pelo Docker Engine** — o processo dentro do contêiner não tem
   permissão de alterar seus próprios logs retroativamente.
2. **Rotação automática** impede esgotamento de disco.
3. **Cada entrada contém** timestamp, contêiner e stream (`stdout`/`stderr`).

| Serviço | `max-size` | `max-file` |
|---|---|---|
| `docs-prod`, `demo-prod` | 10m | 3 |
| `nginx-prod` | 20m | 5 |
| `docs-dev`, `demo-dev` | 5m | 2 |

```bash
# Inspecionar logs de qualquer serviço
docker compose -f ops/docker-compose.vps.yml logs --since=1h docs-prod
docker compose -f ops/docker-compose.vps.yml logs --tail=50 nginx-prod
```

Este design implementa o princípio de **Segregação de Deveres (SoD)**: quem gera o log
não controla o log. O Docker Engine atua como a entidade segregada que imobiliza os
registros — condição necessária para auditoria independente e cadeia de custódia íntegra.

> **Gilligan — Misericórdia:** a segregação de logs não é só conformidade técnica; é
> cuidado com a cadeia de custódia que um auditor futuro precisará reconstituir para
> defender ou contestar uma decisão do sistema.

---

## Solução de problemas

| Sintoma | Causa provável | Solução |
|---|---|---|
| `Error: bind: address already in use` porta 80/443 | Nginx do host ainda ativo | `sudo systemctl stop nginx && sudo systemctl disable nginx` |
| `localhost:9090` / `localhost:9091` não responde | Túnel SSH não ativo | Executar `btv-tunnel` na máquina local |
| Contêiner DEV em `Restarting` | Health check falha (diretório vazio) | `ls /opt/btv/demo/` — adicionar `index.html` se vazio |
| `docker compose config` falha | YAML malformado | `docker compose -f ops/docker-compose.vps.yml config` localmente |
| Deploy não reflete mudanças | Cache MkDocs | `mkdocs build --clean` |
| certbot falha | Nginx do host não configurado | Verificar `/etc/nginx/sites-available/` |

---

## Apêndice A — Gestão de Segredos (Zero-Trust)

O `docker-compose.vps.yml` pode consumir variáveis de ambiente (`ENV=production`,
chaves HMAC, tokens de API). Credenciais **nunca** devem ser inseridas diretamente
no YAML ou commitadas no repositório.

**Regra de isolamento:** DEV e PROD devem ter ficheiros `.env` estritamente separados:

```bash
# Criar ficheiros .env separados na VPS
touch /opt/buildtovalue/ops/.env.prod
touch /opt/btv/.env.dev

# Princípio do Menor Privilégio: leitura/escrita apenas para o owner
chmod 600 /opt/buildtovalue/ops/.env.prod
chmod 600 /opt/btv/.env.dev
```

Adicione ao `.gitignore` do projeto:

```
ops/.env.prod
.env.dev
*.env.*
```

Consulte `ops/.env.example` como template dos campos obrigatórios (nunca commitado
com valores reais).

---

## Apêndice B — Isolamento de Estado e Imutabilidade do Ledger

O BuildToValue opera um Ledger criptográfico (`trust.db`, `appeals.db`). Misturar
volumes de desenvolvimento com os de produção corrompe irremediavelmente o histórico
de decisões.

**Regras de volume:**

- **PROD:** contêineres montam `/var/www/buildtovalue/` como `:ro` (read-only).
  O Ledger de produção reside em `/var/lib/btv/ledger/` — acessível apenas via
  serviços PROD autenticados.
- **DEV:** contêineres montam `/opt/btv/` como `:rw`. O estado é efémero ou
  laboratorial. `docker compose down -v` no ambiente DEV **nunca** deve impactar
  o histórico de produção.

Veja os riscos associados em [RISK_REGISTER.md](../RISK_REGISTER.md).

---

## Apêndice C — Procedimento de Rollback Determinístico

O `btv-deploy` avança o estado para o commit mais recente. Para reverter a uma
versão estável após uma anomalia:

```bash
cd /opt/buildtovalue

# 1. Identificar o commit estável anterior
git log --oneline | head -20

# 2. Checkout determinístico (substitua <COMMIT_HASH>)
git checkout <COMMIT_HASH>

# 3. Convergir o estado declarativo
docker compose -f ops/docker-compose.vps.yml down
docker compose -f ops/docker-compose.vps.yml up -d --build

# 4. Verificar saúde
curl -sf https://docs.buildtovalue.cloud/health || echo "FALHOU"
```

!!! tip "Boas práticas"
    Antes de deploys maiores, crie uma tag Git para o estado estável atual:
    ```bash
    git tag stable-$(date +%Y%m%d) && git push origin --tags
    ```
    Isso torna o rollback um único `git checkout stable-YYYYMMDD`.

---

## Apêndice D — Integração de Observabilidade

O isolamento topológico não exime os contêineres de auditoria. As métricas de
cgroups (CPU, memória por contêiner) podem ser exportadas para o Prometheus via
[cAdvisor](https://github.com/google/cadvisor) ou pela API de stats do Docker Engine.

O gateway de PROD já expõe `/metrics` no formato Prometheus, conforme configurado
em [`ops/prometheus.yml`](https://github.com/danzeroum/BuildToValueGovernance/blob/main/ops/prometheus.yml).

Certifique-se de que os limites de `mem_limit` estabelecidos via cgroups são
auditados periodicamente — recursos órfãos (*zombie processes*) não detectados
podem desestabilizar a VPS silenciosamente.

---

## Apêndice E — Padrão de Referência: Arquitetura VPS Segura

> Este apêndice documenta os princípios desta arquitetura de forma reutilizável,
> sem expor detalhes operacionais do ambiente de produção.
> É a versão canônica para referência em outros projetos, revisões de pares ou portfólio público.

### Visão geral do modelo

Esta infraestrutura implementa o modelo **Infrastructure as Code (IaC)** com Docker Compose
e Nginx como Ingress Controller unificado. A premissa central:

- **Produção:** exposta via HTTPS/TLS, atrás de reverse proxy com certificado válido
- **Desenvolvimento:** topologicamente isolado da internet, sem rotas de entrada
  ou saída públicas, acessível exclusivamente via túneis SSH criptografados

Nenhuma linha de código de desenvolvimento trafega em texto claro. Nenhuma porta de
desenvolvimento é aberta publicamente. O isolamento é garantido por primitivas do
kernel — não por disciplina do operador.

### Fase 1 — Segurança de perímetro (Firewall)

A configuração de rede segue o **Princípio do Menor Privilégio** com política padrão `DENY ALL`.
O firewall atua na camada 4, descartando silenciosamente qualquer pacote fora das exceções explícitas:

| Porta | Protocolo | Justificativa |
|---|---|---|
| 22 | TCP | Gestão via SSH com chaves assimétricas (senhas desativadas) |
| 80 | TCP | Redirecionamento HTTP → HTTPS e renovação ACME (Let's Encrypt) |
| 443 | TCP | Único ponto de entrada de tráfego público de produção |

**Autenticação sem senha (chaves assimétricas):**

```bash
# Gerar par de chaves na máquina do desenvolvedor
ssh-keygen -t ed25519 -C "dev@projeto"

# Copiar a chave pública para o servidor
ssh-copy-id -i ~/.ssh/id_ed25519.pub usuario@<SERVIDOR>
```

Em seguida, desative autenticação por senha em `/etc/ssh/sshd_config` no servidor:

```
PasswordAuthentication no
PubkeyAuthentication yes
```

!!! note "ed25519 vs rsa-4096"
    Chaves `ed25519` são preferíveis em novos projetos: mesma resistência criptográfica,
    chaves menores e operações de autenticação mais rápidas.

### Fase 2 — Isolamento Docker (Zero Trust)

A topologia de redes implementa **Zero Trust** em dois níveis independentes:

```yaml
networks:
  prod-net:
    driver: bridge
    # Contêineres têm rota para o host e para a internet via Nginx

  dev-net:
    driver: bridge
    internal: true
    # 'internal: true' remove o default gateway no nível do kernel.
    # Contêineres não alcançam a internet — por design, não por política de firewall.
```

**Exemplo de configuração de serviços:**

```yaml
services:
  # Produção: público, atrás do Ingress Controller
  app-prod:
    image: sua-imagem:tag
    networks: [prod-net]
    restart: unless-stopped
    mem_limit: 512m       # cgroups: previne OOM na VPS compartilhada

  # Desenvolvimento: isolado, acessível apenas via SSH tunnel
  app-dev:
    image: sua-imagem:tag
    networks: [dev-net]
    ports:
      - "127.0.0.1:8080:8000"  # loopback: invisível externamente
    volumes:
      - ./src:/app:rw           # hot-reload sem rebuild
    restart: on-failure:3       # Fail-Secure: para após 3 falhas, não entra em loop
    mem_limit: 256m
```

A diferença entre `restart: unless-stopped` (prod) e `restart: on-failure:3` (dev) é
intencional: produção deve sempre voltar; desenvolvimento deve **sinalizar falha e parar**,
não consumir recursos indefinidamente.

### Fase 3 — Gateway Nginx e TLS

O Nginx opera como único **Ingress Controller**: todo tráfego externo passa por ele antes
de chegar a qualquer contêiner. Padrão de bloco de servidor:

```nginx
# Redirecionamento HTTP → HTTPS (obrigatório)
server {
    listen 80;
    server_name app.exemplo.com;
    return 301 https://$host$request_uri;
}

# Bloco HTTPS com SSL Offloading
server {
    listen 443 ssl;
    server_name app.exemplo.com;

    ssl_certificate     /etc/letsencrypt/live/app.exemplo.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/app.exemplo.com/privkey.pem;

    # Cabeçalhos de segurança obrigatórios
    add_header Strict-Transport-Security "max-age=63072000" always;
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;

    location / {
        proxy_pass         http://app-prod:8000;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Real-IP         $remote_addr;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
    }
}
```

**Emissão e renovação automática de certificados:**

```bash
# Emissão inicial
sudo certbot --nginx -d app.exemplo.com

# Verificar renovação automática
sudo certbot renew --dry-run
```

!!! note "Certbot e contêiner Nginx"
    Após emitir o certificado, pare o Nginx do host antes de subir o contêiner
    `nginx-prod`. O contêiner monta `/etc/letsencrypt` como `:ro` e gerencia
    a terminação TLS de forma independente.

### Fase 4 — Padrão de acesso DEV (SSH Tunnel)

Como os serviços de desenvolvimento estão vinculados a `127.0.0.1` da VPS e a rede
`dev-net` não tem gateway, o acesso do desenvolvedor usa **Port Forwarding via SSH**:

```bash
# Sintaxe geral
ssh -L <PORTA_LOCAL>:localhost:<PORTA_VPS> usuario@<SERVIDOR> -N

# Múltiplos serviços simultâneos
ssh -L 8080:localhost:8080 \
    -L 9091:localhost:9091 \
    usuario@<SERVIDOR> -N
```

**Integração com VS Code Remote-SSH** (tunnel automático ao conectar):

```
# ~/.ssh/config
Host meu-servidor-dev
  HostName <SERVIDOR>
  User usuario
  IdentityFile ~/.ssh/id_ed25519
  LocalForward 8080 localhost:8080
  LocalForward 9091 localhost:9091
```

Com esta configuração, ao conectar via Remote-SSH o túnel é estabelecido automaticamente —
sem terminal separado.

**Fluxo completo de desenvolvimento sem exposição pública:**

```
Editor local (VS Code Remote-SSH)
│  salva arquivo
▼
Volume Docker (:rw mount na VPS)
│  reflete imediatamente
▼
Contêiner DEV (hot-reload ativo)
│  serve na porta 8000 interna
▼
SSH Tunnel (127.0.0.1:8080 → VPS:8080)
│
▼
Navegador local: http://localhost:8080
```

Nenhum byte deste ciclo trafega em texto claro. Nenhuma porta é aberta publicamente.
O risco de exposição acidental é **estruturalmente impossível**.

### Síntese: camadas de proteção independentes

```
Internet
│
▼  CAMADA 1: Firewall (UFW/iptables)
│  DENY ALL exceto 22/80/443
▼  CAMADA 2: Nginx (Ingress Controller)
│  TLS termination · cabeçalhos de segurança · routing
▼  CAMADA 3: Docker Network (prod-net / dev-net)
│  internal: true remove gateway de DEV no kernel
▼  CAMADA 4: Port binding (127.0.0.1)
│  Loopback exclusivo para serviços de desenvolvimento
▼  CAMADA 5: cgroups (mem_limit / cpus)
   Isola consumo de recursos entre DEV e PROD
```

Cada camada é **independente**: desabilitar uma não compromete as outras.
Este é o princípio de **Defesa em Profundidade** aplicado à infraestrutura —
a mesma filosofia que sustenta o modelo de isolamento documentado neste tutorial.

### Referências externas

- [Docker Networking — `internal` networks](https://docs.docker.com/network/)
- [Nginx — Reverse Proxy](https://nginx.org/en/docs/http/ngx_http_proxy_module.html)
- [Certbot — Let's Encrypt](https://certbot.eff.org/)
- [SSH Port Forwarding](https://www.ssh.com/academy/ssh/tunneling/example)
- [Linux cgroups v2](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html)

---

## O que você aprendeu

- A separação DEV/PROD em uma única VPS é implementada via primitivas do kernel
  Linux (Docker networks), não por scripts ou disciplina manual.
- `internal: true` remove o gateway padrão da rede DEV — isolamento imune a
  misconfigurações de firewall.
- O bind de `127.0.0.1` + túnel SSH é o padrão correto para acessar serviços
  de desenvolvimento sem expô-los à internet.
- `restart: on-failure:3` (Fail-Secure) e limites de cgroups protegem PROD de
  um DEV defeituoso no mesmo host.
- Logs gerenciados pelo Docker Engine implementam SoD: quem gera o log não
  controla o log.

## Próximo passo

- **Registrar um risco operacional:** [Registro de Riscos](../RISK_REGISTER.md)
- **Entender Fail-Secure em profundidade:** [Conceito Fail-Secure](../concepts/fail-secure.md)
- **Consultar o Protocolo CAP** para mudanças arquiteturais: [Protocolo CAP](../cap-protocol.md)
- **Tutorial anterior:** [Tutorial 04 — Propor uma Política](04-propose-policy.md)
