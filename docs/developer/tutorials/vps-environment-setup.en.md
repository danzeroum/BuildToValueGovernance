---
title: "Tutorial 05 — VPS Environment Setup (DEV/PROD)"
---

# Tutorial 05 — VPS Environment Setup (DEV/PROD)

> Declarative state, auditable, with limits enforced by the kernel — not by operator discipline.

## Why two environments on the same server?

On projects with a single VPS, the temptation is to run everything in the same process with background scripts (`nohup &`, `pkill`). This creates **risk coupling**: a development experiment may:

- Consume all available memory (*resource exhaustion*)
- Collide with production ports
- Expose unfinished endpoints publicly
- Make log auditing impossible — who generated what?

The solution does not require two servers. DevOps literature (*FIA: DevOps e Integração Contínua*) identifies this as a case of "mixing workload sensitivity levels": workloads with different risk profiles sharing the same space without formal change control. Strong logical isolation via Linux kernel primitives is the architectural response — documented in the [RISK_REGISTER.md](../RISK_REGISTER.md) as mitigation for operational coupling risks.

---

## Architecture: topological separation of powers

```
VPS (76.13.238.209)
│
├── UFW (edge firewall)
│   ├── ALLOW: 22/tcp, 80/tcp, 443/tcp   ← internet-visible
│   └── DENY: everything else (9090, 9091 invisible externally)
│
├── Docker Network: btv-prod-net  [public bridge]
│   ├── nginx-prod   → 0.0.0.0:80 / 0.0.0.0:443  (TLS)
│   ├── docs-prod    → internal (no direct public port)
│   └── demo-prod    → internal (no direct public port)
│
├── Docker Network: btv-dev-net  [internal: true — blind]
│   ├── docs-dev → 127.0.0.1:9091  (loopback)
│   └── demo-dev → 127.0.0.1:9090  (loopback)
│
VPS filesystem:
  /var/www/buildtovalue/{docs,demo}  ← PROD (nginx:alpine, :ro mount)
  /opt/buildtovalue/                 ← git clone of main
  /opt/btv/{docs,demo}               ← DEV lab (:rw mount, hot-reload)
```

The separation is not merely logical at the application level — it is physical at the kernel network subsystem level.

---

## How `internal: true` works

The `internal: true` flag on `btv-dev-net`
([`ops/docker-compose.vps.yml`](https://github.com/danzeroum/BuildToValueGovernance/blob/main/ops/docker-compose.vps.yml))
**is not a firewall rule**. It is a primitive of the Docker network subsystem that instructs the Linux kernel to *not create a default gateway route* (`0.0.0.0/0`) for that bridge. The result: DEV containers are topologically incapable of routing traffic to the internet.

This matters because `ufw` rules can be accidentally removed. The absence of a gateway route cannot.

> **Rawls — Blind Testing:** the `btv-dev-net` network is deliberately blind to external conditions by topological design, not by operator discipline. Development decisions are not contaminated by real production traffic.

From a *Defense in Depth* perspective (DevSecOps literature): UFW is the outer layer, visible and configurable; `internal: true` is the inner layer, immune to layer-4 misconfigurations. The two layers are **independent** — failure in one does not compromise the other.

---

## Prerequisites

| Requirement | Minimum version | Verification command |
|---|---|---|
| Ubuntu / Debian VPS | 22.04 LTS | `lsb_release -a` |
| Docker Engine | 24.x | `docker --version` |
| Docker Compose plugin | 2.x | `docker compose version` |
| certbot | any | `certbot --version` |
| Python + pip | 3.11+ | `python3 --version` |
| MkDocs Material | 9.x | `mkdocs --version` |
| SSH root access | — | `ssh root@76.13.238.209` |

!!! warning "Port conflict"
    The host Nginx (`systemd`) must be **stopped** before starting `nginx-prod` via Docker.
    Both compete for ports 80 and 443:
    ```bash
    sudo systemctl stop nginx
    sudo systemctl disable nginx
    ```

---

## Step 1 — Configure UFW

UFW is the first line of defense. Configure it before anything else:

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
sudo ufw status verbose
```

!!! note "Ports 9090 and 9091"
    These are **deliberately absent** from this list. DEV environment access occurs
    exclusively via SSH tunnel (see section below) — not by opening a port in the
    firewall. This is the second layer of defense in depth: the `127.0.0.1` bind in
    Compose is independent of UFW.

---

## Step 2 — Create working directories

```bash
# Static content served by the production nginx
sudo mkdir -p /var/www/buildtovalue/{docs,demo}
sudo chown -R www-data:www-data /var/www/buildtovalue

# Production source code (git clone of main)
sudo mkdir -p /opt/buildtovalue
sudo chown $USER:$USER /opt/buildtovalue
git clone https://github.com/danzeroum/BuildToValueGovernance.git /opt/buildtovalue

# Development lab (hot-reload)
sudo mkdir -p /opt/btv/{docs,demo}
sudo chown -R $USER:$USER /opt/btv
```

The `/opt/btv/` directories are mounted as `:rw` in DEV containers — any local edit
is reflected immediately without a rebuild.

---

## Step 3 — Install dependencies

```bash
cd /opt/buildtovalue
pip install mkdocs-material -r docs/requirements.txt
```

---

## Step 4 — Provision TLS certificate

```bash
sudo certbot --nginx \
  -d demo.buildtovalue.cloud \
  -d docs.buildtovalue.cloud
```

certbot automatically creates `server` blocks in the host Nginx. After that,
the `nginx-prod` container will mount `/etc/letsencrypt` as `:ro` to serve TLS.

---

## Step 5 — Start the services

```bash
cd /opt/buildtovalue
docker compose -f ops/docker-compose.vps.yml up -d
```

Verify the status of all services:

```bash
docker compose -f ops/docker-compose.vps.yml ps
```

Expected output: 5 containers in `running` state — `docs-prod`, `demo-prod`,
`nginx-prod`, `docs-dev`, `demo-dev`.

---

## Lifecycle commands

| Operation | Command |
|---|---|
| Start all services | `docker compose -f ops/docker-compose.vps.yml up -d` |
| Start DEV only (lab) | `docker compose -f ops/docker-compose.vps.yml up -d docs-dev demo-dev` |
| Watch production logs in real time | `docker compose -f ops/docker-compose.vps.yml logs -f nginx-prod` |
| View last 50 lines of a service | `docker compose -f ops/docker-compose.vps.yml logs --tail=50 docs-prod` |
| Stop everything safely | `docker compose -f ops/docker-compose.vps.yml down` |

---

## Accessing the DEV environment via SSH tunnel

Ports 9090 and 9091 are bound to `127.0.0.1` on the VPS — invisible externally.
Access occurs via an **encrypted SSH tunnel**, run on **your local machine** (not on the VPS):

```bash
# On your local machine (using the btv-vps alias from ~/.ssh/config):
ssh -L 9090:localhost:9090 \
    -L 9091:localhost:9091 \
    btv-vps -N
```

With the tunnel active, access from your local browser:

| Local URL | Service | VPS directory |
|---|---|---|
| `http://localhost:9090` | Demo DEV | `/opt/btv/demo/` |
| `http://localhost:9091` | Docs DEV | `/opt/btv/docs/` |

!!! tip "Why SSH tunnel and not open the port in the firewall?"
    The SSH tunnel uses native protocol-level encryption. No credentials or in-development
    content travel in plain text. Opening 9090/9091 in `ufw` would expose the environments
    to any IP in the world.

> **Levinas — Protection:** ports bound to `127.0.0.1` ensure the lab environment is
> never exposed to third parties who have no way to audit what is being tested.

**Recommended configuration** — add to `~/.ssh/config` on your local machine to abstract the IP out of the command line and make the alias resilient to address changes:

```
# ~/.ssh/config
Host btv-vps
  HostName <VPS_IP>
  User root
```

Then add the alias to your `~/.zshrc` or `~/.bashrc`:

```bash
alias btv-tunnel='ssh -L 9090:localhost:9090 -L 9091:localhost:9091 btv-vps -N -v'
```

With this setup, a VPS IP change only requires updating `~/.ssh/config` — the alias and documentation remain unchanged.

---

## Deploy workflow with `btv-deploy`

```
Your local machine (/opt/btv/ or editor)
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

The [`scripts/deploy.sh`](https://github.com/danzeroum/BuildToValueGovernance/blob/main/scripts/deploy.sh)
script implements a deterministic CD pipeline:

1. `git fetch origin` + `git checkout $BRANCH` + `git pull`
2. Dependency delta check (pip only if `requirements.txt` changed)
3. Conditional rebuild (Python API, Rust gateway, MkDocs — only what changed)
4. Final health check — exit 1 if the service does not respond

Each execution produces a **traceable commit hash** — the equivalent of the `TechnicalEvidence`
from the BTV protocol applied to infrastructure.

```bash
# Deploy from main branch (default)
btv-deploy

# Deploy from a specific branch
btv-deploy develop
```

!!! note "CI/CD as contract"
    `btv-deploy` re-runs the same validation invariants as the remote pipeline
    (`validate_invariants.py`, `autogen_reference.py`). A deploy that passes locally
    should pass in CI — and vice versa. No change in `/opt/btv/` reaches production
    until `btv-deploy` is run explicitly. The deploy is a conscious and auditable act.

---

## Resource isolation (cgroups)

Containers have limits enforced by the kernel via **cgroups**:

| Container | `mem_limit` | `cpus` | Network | `restart` |
|---|---|---|---|---|
| `docs-prod` | 512m | 1.0 | btv-prod-net | `always` |
| `demo-prod` | 512m | 1.0 | btv-prod-net | `always` |
| `nginx-prod` | — | — | btv-prod-net | `always` |
| `docs-dev` | 256m | 0.5 | btv-dev-net | `on-failure:3` |
| `demo-dev` | 256m | 0.5 | btv-dev-net | `on-failure:3` |

The difference in restart policy is intentional:

- **`restart: always` (PROD):** the service must come back at all costs after a VPS restart.
- **`restart: on-failure:3` (DEV):** after 3 consecutive failures, Docker stops retrying. This prevents a faulty DEV service from entering an infinite loop consuming CPU indefinitely — the **Fail-Secure** policy in action.

> **Jonas — Responsibility:** capping DEV CPU and memory at 50% of the PROD allocation
> is an act of responsibility toward the production environment sharing the same physical
> host. A runaway DEV container cannot cause *resource exhaustion* of services serving
> real users.

---

## Log segregation and Separation of Duties

The `json-file` driver with `max-size` and `max-file` guarantees that:

1. **Logs are managed by the Docker Engine** — the process inside the container cannot
   alter its own logs retroactively.
2. **Automatic rotation** prevents disk exhaustion.
3. **Each entry contains** timestamp, container, and stream (`stdout`/`stderr`).

| Service | `max-size` | `max-file` |
|---|---|---|
| `docs-prod`, `demo-prod` | 10m | 3 |
| `nginx-prod` | 20m | 5 |
| `docs-dev`, `demo-dev` | 5m | 2 |

```bash
# Inspect logs for any service
docker compose -f ops/docker-compose.vps.yml logs --since=1h docs-prod
docker compose -f ops/docker-compose.vps.yml logs --tail=50 nginx-prod
```

This design implements the **Separation of Duties (SoD)** principle: whoever generates
the log does not control the log. The Docker Engine acts as the segregated entity that
immobilizes records — a necessary condition for independent audit and an intact chain of
custody.

> **Gilligan — Care:** log segregation is not just technical compliance; it is care for
> the chain of custody that a future auditor will need to reconstruct in order to defend
> or contest a system decision.

---

## Troubleshooting

| Symptom | Likely cause | Solution |
|---|---|---|
| `Error: bind: address already in use` port 80/443 | Host Nginx still running | `sudo systemctl stop nginx && sudo systemctl disable nginx` |
| `localhost:9090` / `localhost:9091` unreachable | SSH tunnel not active | Run `btv-tunnel` on your local machine |
| DEV container in `Restarting` state | Health check fails (empty directory) | `ls /opt/btv/demo/` — add `index.html` if empty |
| `docker compose config` fails | Malformed YAML | `docker compose -f ops/docker-compose.vps.yml config` locally |
| Deploy does not reflect changes | MkDocs cache | `mkdocs build --clean` |
| certbot fails | Host Nginx not configured | Check `/etc/nginx/sites-available/` |

---

## Appendix A — Secrets Management (Zero-Trust)

`docker-compose.vps.yml` may consume environment variables (`ENV=production`,
HMAC keys, API tokens). Credentials **must never** be inserted directly into
the YAML or committed to the repository.

**Isolation rule:** DEV and PROD must have strictly separate `.env` files:

```bash
# Create separate .env files on the VPS
touch /opt/buildtovalue/ops/.env.prod
touch /opt/btv/.env.dev

# Principle of Least Privilege: read/write only for the owner
chmod 600 /opt/buildtovalue/ops/.env.prod
chmod 600 /opt/btv/.env.dev
```

Add to the project's `.gitignore`:

```
ops/.env.prod
.env.dev
*.env.*
```

Use `ops/.env.example` as a template for required fields (never committed with real values).

---

## Appendix B — State Isolation and Ledger Immutability

BuildToValue operates a cryptographic Ledger (`trust.db`, `appeals.db`). Mixing
development volumes with production volumes irremediably corrupts the decision history.

**Volume rules:**

- **PROD:** containers mount `/var/www/buildtovalue/` as `:ro` (read-only).
  The production Ledger resides in `/var/lib/btv/ledger/` — accessible only via
  authenticated PROD services.
- **DEV:** containers mount `/opt/btv/` as `:rw`. The state is ephemeral or
  experimental. `docker compose down -v` in the DEV environment **must never**
  impact the production history.

See associated risks in [RISK_REGISTER.md](../RISK_REGISTER.md).

---

## Appendix C — Deterministic Rollback Procedure

`btv-deploy` advances state to the latest commit. To revert to a stable version
after an anomaly:

```bash
cd /opt/buildtovalue

# 1. Identify the previous stable commit
git log --oneline | head -20

# 2. Deterministic checkout (replace <COMMIT_HASH>)
git checkout <COMMIT_HASH>

# 3. Converge declarative state
docker compose -f ops/docker-compose.vps.yml down
docker compose -f ops/docker-compose.vps.yml up -d --build

# 4. Verify health
curl -sf https://docs.buildtovalue.cloud/health || echo "FAILED"
```

!!! tip "Best practices"
    Before major deploys, create a Git tag for the current stable state:
    ```bash
    git tag stable-$(date +%Y%m%d) && git push origin --tags
    ```
    This reduces rollback to a single `git checkout stable-YYYYMMDD`.

---

## Appendix D — Observability Integration

Topological isolation does not exempt containers from auditing. cgroups metrics
(CPU, memory per container) can be exported to Prometheus via
[cAdvisor](https://github.com/google/cadvisor) or the Docker Engine stats API.

The PROD gateway already exposes `/metrics` in Prometheus format, as configured in
[`ops/prometheus.yml`](https://github.com/danzeroum/BuildToValueGovernance/blob/main/ops/prometheus.yml).

Make sure that the `mem_limit` cgroups boundaries are audited periodically — undetected
orphaned resources (*zombie processes*) can silently destabilize the VPS.

---

## What you learned

- DEV/PROD separation on a single VPS is implemented via Linux kernel primitives
  (Docker networks), not through scripts or manual discipline.
- `internal: true` removes the default gateway from the DEV network — isolation
  immune to firewall misconfigurations.
- The `127.0.0.1` bind + SSH tunnel is the correct pattern for accessing development
  services without exposing them to the internet.
- `restart: on-failure:3` (Fail-Secure) and cgroups limits protect PROD from a
  faulty DEV on the same host.
- Logs managed by the Docker Engine implement SoD: whoever generates the log does
  not control the log.

## Next steps

- **Register an operational risk:** [Risk Register](../RISK_REGISTER.md)
- **Understand Fail-Secure in depth:** [Fail-Secure Concept](../concepts/fail-secure.md)
- **Consult the CAP Protocol** for architectural changes: [CAP Protocol](../cap-protocol.md)
- **Previous tutorial:** [Tutorial 04 — Propose a Policy](04-propose-policy.md)
