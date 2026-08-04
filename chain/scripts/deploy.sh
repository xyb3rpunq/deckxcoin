#!/usr/bin/env bash
#
# Provision a public DeckxCoin node on a fresh Debian or Ubuntu server.
#
#   curl -fsSL https://raw.githubusercontent.com/xyb3rpunq/deckxcoin/main/chain/scripts/deploy.sh | sudo bash
#
# or, from a clone:
#
#   sudo ./chain/scripts/deploy.sh --network testnet --gateway --faucet
#
# ── What it does ─────────────────────────────────────────────────────────────
#   1. Installs Node.js 22+ if the system has something older.
#   2. Creates an unprivileged `deckxd` system user with no login shell.
#   3. Installs the repository to /opt/deckxcoin.
#   4. Writes a hardened systemd unit and starts it.
#   5. Opens the P2P and gateway ports — and only those.
#   6. Waits for the node to answer, checks the genesis hash, and prints the
#      `host:port#identity` string an operator publishes.
#
# ── Two decisions worth knowing about ────────────────────────────────────────
# **The RPC port is never opened.** It is unauthenticated by design and can
# mine, dial arbitrary hosts and stop the process. The public surface is the
# gateway, which is read-only. A firewall rule for the RPC port is the single
# fastest way to turn a testnet into somebody else's regtest.
#
# **The node does not run as root.** systemd's ProtectSystem=strict makes the
# filesystem read-only apart from the datadir, so a bug in the node cannot
# reach anything else on the machine. Running it as root would make all of that
# decorative.
#
# Re-running is safe: every step checks before it acts.

set -euo pipefail

# ── configuration ────────────────────────────────────────────────────────────

REPO_URL="${DECKX_REPO:-https://github.com/xyb3rpunq/deckxcoin.git}"
INSTALL_DIR="${DECKX_INSTALL_DIR:-/opt/deckxcoin}"
DATA_DIR="${DECKX_DATA_DIR:-/var/lib/deckxd}"
SERVICE_USER="${DECKX_USER:-deckxd}"
SERVICE_NAME="deckxd"
NODE_MAJOR_MIN=22

NETWORK="testnet"
P2P_PORT=""
RPC_PORT=""
GATEWAY_PORT="8080"
GATEWAY_RATE=""
GATEWAY_TRUST_PROXY=""
ENABLE_GATEWAY=0
ENABLE_FAUCET=0
FAUCET_AMOUNT="10"
FAUCET_RESERVE=""
FAUCET_DAILY_CAP=""
FAUCET_COOLDOWN=""
MINE_ADDRESS=""
MINE_INTERVAL="30"
CONNECT_PEERS=()
DO_UNINSTALL=0
SKIP_FIREWALL=0
DRY_RUN=0

# ── output ───────────────────────────────────────────────────────────────────

if [ -t 1 ]; then
  BOLD=$'\033[1m'; DIM=$'\033[2m'; RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; OFF=$'\033[0m'
else
  BOLD=""; DIM=""; RED=""; GREEN=""; YELLOW=""; OFF=""
fi

step() { printf '%s==>%s %s\n' "$BOLD" "$OFF" "$1"; }
info() { printf '    %s%s%s\n' "$DIM" "$1" "$OFF"; }
ok()   { printf '    %s✓%s %s\n' "$GREEN" "$OFF" "$1"; }
warn() { printf '    %s!%s %s\n' "$YELLOW" "$OFF" "$1"; }
die()  { printf '%serror:%s %s\n' "$RED" "$OFF" "$1" >&2; exit 1; }

usage() {
  cat <<'EOF'
deploy.sh — provision a public DeckxCoin node

  --network <name>     mainnet | testnet | regtest       (default testnet)
  --port <n>           P2P listen port                   (network default)
  --rpcport <n>        JSON-RPC port, loopback only      (network default)
  --gateway            enable the public read-only gateway
  --gateway-port <n>   gateway listen port               (default 8080)
  --faucet             enable the testnet faucet
  --faucet-amount <n>  DECKX per grant                   (default 10)
  --faucet-reserve <n> DECKX kept back                   (default 100)
  --faucet-daily-cap <n>  DECKX per rolling 24 hours     (default 5000)
  --faucet-cooldown <m>   minutes between grants per address (default 60)
  --gateway-rate <n>   requests per minute per client    (default 60)
  --gateway-trust-proxy <n>  reverse proxies in front    (default 0)
                       Set this if you run nginx or Caddy for TLS. Leave it 0
                       if you do not — see docs/RUNNING-A-PUBLIC-TESTNET.md.
  --mine <address>     mine to this address
  --mine-interval <s>  seconds between attempts          (default 30)
  --connect <h:p#id>   peer to dial on start, repeatable
  --no-firewall        do not touch ufw
  --dry-run            print the plan and the systemd unit, change nothing
  --uninstall          stop, disable and remove the service
  --help               this text

Examples

  # A seed node that mines and serves a public explorer and faucet
  sudo ./deploy.sh --network testnet --gateway --faucet --mine dxc1q...

  # A second node that joins the first
  sudo ./deploy.sh --network testnet --connect seed1.example.org:19333#a3f1...
EOF
}

# ── arguments ────────────────────────────────────────────────────────────────

while [ $# -gt 0 ]; do
  case "$1" in
    --network)        NETWORK="$2"; shift 2 ;;
    --port)           P2P_PORT="$2"; shift 2 ;;
    --rpcport)        RPC_PORT="$2"; shift 2 ;;
    --gateway)        ENABLE_GATEWAY=1; shift ;;
    --gateway-port)   GATEWAY_PORT="$2"; ENABLE_GATEWAY=1; shift 2 ;;
    --faucet)         ENABLE_FAUCET=1; shift ;;
    --faucet-amount)  FAUCET_AMOUNT="$2"; ENABLE_FAUCET=1; shift 2 ;;
    --faucet-reserve) FAUCET_RESERVE="$2"; ENABLE_FAUCET=1; shift 2 ;;
    --faucet-daily-cap) FAUCET_DAILY_CAP="$2"; ENABLE_FAUCET=1; shift 2 ;;
    --faucet-cooldown) FAUCET_COOLDOWN="$2"; ENABLE_FAUCET=1; shift 2 ;;
    --gateway-rate)   GATEWAY_RATE="$2"; ENABLE_GATEWAY=1; shift 2 ;;
    --gateway-trust-proxy) GATEWAY_TRUST_PROXY="$2"; ENABLE_GATEWAY=1; shift 2 ;;
    --mine)           MINE_ADDRESS="$2"; shift 2 ;;
    --mine-interval)  MINE_INTERVAL="$2"; shift 2 ;;
    --connect)        CONNECT_PEERS+=("$2"); shift 2 ;;
    --no-firewall)    SKIP_FIREWALL=1; shift ;;
    --dry-run)        DRY_RUN=1; shift ;;
    --uninstall)      DO_UNINSTALL=1; shift ;;
    --help|-h)        usage; exit 0 ;;
    *)                die "unknown option '$1' — try --help" ;;
  esac
done

case "$NETWORK" in
  mainnet) DEFAULT_P2P=9333;  DEFAULT_RPC=9332 ;;
  testnet) DEFAULT_P2P=19333; DEFAULT_RPC=19332 ;;
  regtest) DEFAULT_P2P=29333; DEFAULT_RPC=29332 ;;
  *)       die "unknown network '$NETWORK'" ;;
esac
P2P_PORT="${P2P_PORT:-$DEFAULT_P2P}"
RPC_PORT="${RPC_PORT:-$DEFAULT_RPC}"

# The faucet gives coins to anyone who asks. On a network whose coins are
# supposed to be scarce that is not a faucet, it is a leak.
if [ "$ENABLE_FAUCET" = 1 ] && [ "$NETWORK" = "mainnet" ]; then
  die "--faucet cannot be used on mainnet"
fi

# ── the unit file ────────────────────────────────────────────────────────────

# Built here rather than inline so that --dry-run shows the operator exactly
# what will be installed. A deploy script whose output can only be inspected
# after it has changed the machine is one people are right not to trust.
build_args() {
  local -a a=(--network "$NETWORK" --datadir "$DATA_DIR" --host 0.0.0.0
              --port "$P2P_PORT" --rpcport "$RPC_PORT" --quiet)
  [ "$ENABLE_GATEWAY" = 1 ] && a+=(--gateway --gateway-port "$GATEWAY_PORT")
  [ -n "$GATEWAY_RATE" ]        && a+=(--gateway-rate "$GATEWAY_RATE")
  [ -n "$GATEWAY_TRUST_PROXY" ] && a+=(--gateway-trust-proxy "$GATEWAY_TRUST_PROXY")
  [ "$ENABLE_FAUCET" = 1 ]  && a+=(--faucet --faucet-amount "$FAUCET_AMOUNT")
  [ -n "$FAUCET_RESERVE" ]   && a+=(--faucet-reserve "$FAUCET_RESERVE")
  [ -n "$FAUCET_DAILY_CAP" ] && a+=(--faucet-daily-cap "$FAUCET_DAILY_CAP")
  [ -n "$FAUCET_COOLDOWN" ]  && a+=(--faucet-cooldown "$FAUCET_COOLDOWN")
  [ -n "$MINE_ADDRESS" ]    && a+=(--mine "$MINE_ADDRESS" --mine-interval "$MINE_INTERVAL")
  for peer in ${CONNECT_PEERS+"${CONNECT_PEERS[@]}"}; do a+=(--connect "$peer"); done
  printf '%q ' "${a[@]}"
}

render_unit() {
  local node_bin
  node_bin="$(command -v node 2>/dev/null || echo /usr/bin/node)"
  # systemd splits ExecStart on whitespace, so a path containing a space
  # becomes two broken arguments. Quoting costs nothing and the failure it
  # prevents is a service that will not start with no useful message.
  case "$node_bin" in *[[:space:]]*) node_bin="\"$node_bin\"" ;; esac
  cat <<EOF
[Unit]
Description=DeckxCoin node (${NETWORK})
Documentation=https://github.com/xyb3rpunq/deckxcoin
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_USER}
WorkingDirectory=${INSTALL_DIR}/chain
ExecStart=${node_bin} src/deckxd.ts $(build_args)
Restart=always
RestartSec=5

# SIGTERM closes the database cleanly. Killing a node mid-write is the one
# reliable way to corrupt a datadir, so give it time to finish.
KillSignal=SIGTERM
TimeoutStopSec=30

# The datadir holds the identity key and, with --faucet, a wallet mnemonic.
# 0077 means files this process creates are unreadable to everyone else.
UMask=0077

# Hardening. The node needs the network, its datadir, and nothing else.
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictRealtime=true
LockPersonality=true
ReadWritePaths=${DATA_DIR}
RestrictAddressFamilies=AF_INET AF_INET6

[Install]
WantedBy=multi-user.target
EOF
}

if [ "$DRY_RUN" = 1 ]; then
  step "Plan (nothing will be changed)"
  printf '    %-16s %s\n' "network" "$NETWORK"
  printf '    %-16s %s\n' "install to" "$INSTALL_DIR"
  printf '    %-16s %s\n' "datadir" "$DATA_DIR (0700, $SERVICE_USER)"
  printf '    %-16s %s\n' "p2p port" "$P2P_PORT (opened)"
  printf '    %-16s %s\n' "rpc port" "$RPC_PORT (loopback, NOT opened)"
  [ "$ENABLE_GATEWAY" = 1 ] && printf '    %-16s %s\n' "gateway port" "$GATEWAY_PORT (opened)"
  [ "$ENABLE_FAUCET" = 1 ]  && printf '    %-16s %s\n' "faucet" "$FAUCET_AMOUNT DECKX per grant"
  [ -n "$MINE_ADDRESS" ]    && printf '    %-16s %s\n' "mining to" "$MINE_ADDRESS"
  printf '\n'
  step "/etc/systemd/system/${SERVICE_NAME}.service"
  printf '\n'
  render_unit | sed 's/^/    /'
  printf '\n'
  exit 0
fi

[ "$(id -u)" -eq 0 ] || die "run as root: sudo $0 ..."

# ── uninstall ────────────────────────────────────────────────────────────────

if [ "$DO_UNINSTALL" = 1 ]; then
  step "Removing $SERVICE_NAME"
  systemctl stop "$SERVICE_NAME" 2>/dev/null || true
  systemctl disable "$SERVICE_NAME" 2>/dev/null || true
  rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
  systemctl daemon-reload
  ok "service removed"
  # The datadir holds the identity key, the faucet wallet and the chain. It is
  # deliberately left behind: deleting a key on the operator's behalf is not a
  # decision a script gets to make.
  warn "$DATA_DIR was left in place — it holds the node identity and faucet key"
  info "remove it yourself with: rm -rf $DATA_DIR"
  exit 0
fi

# ── 1. Node.js ───────────────────────────────────────────────────────────────

step "Checking Node.js"
need_node=1
if command -v node >/dev/null 2>&1; then
  current="$(node -v | sed 's/^v//' | cut -d. -f1)"
  if [ "$current" -ge "$NODE_MAJOR_MIN" ]; then
    ok "node $(node -v) is recent enough"
    need_node=0
  else
    info "node $(node -v) is too old — need $NODE_MAJOR_MIN or newer"
  fi
fi

if [ "$need_node" = 1 ]; then
  # node:sqlite and running TypeScript without a build step both landed in 22.
  # Older releases fail at import time rather than at a useful place.
  info "installing Node.js ${NODE_MAJOR_MIN}.x from NodeSource"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq curl ca-certificates gnupg git >/dev/null
  curl -fsSL "https://deb.nodesource.com/setup_${NODE_MAJOR_MIN}.x" | bash - >/dev/null 2>&1
  apt-get install -y -qq nodejs >/dev/null
  ok "installed $(node -v)"
fi

command -v git >/dev/null 2>&1 || { apt-get install -y -qq git >/dev/null; }

# ── 2. service user ──────────────────────────────────────────────────────────

step "Service user"
if id "$SERVICE_USER" >/dev/null 2>&1; then
  ok "$SERVICE_USER exists"
else
  # --system: no ageing, no mail spool. --shell /usr/sbin/nologin: this account
  # is not a way in.
  useradd --system --home-dir "$DATA_DIR" --shell /usr/sbin/nologin "$SERVICE_USER"
  ok "created $SERVICE_USER"
fi

# ── 3. source ────────────────────────────────────────────────────────────────

step "Source"
if [ -d "$INSTALL_DIR/.git" ]; then
  git -C "$INSTALL_DIR" fetch --quiet origin
  git -C "$INSTALL_DIR" reset --hard --quiet origin/HEAD 2>/dev/null \
    || git -C "$INSTALL_DIR" reset --hard --quiet origin/main
  ok "updated $INSTALL_DIR to $(git -C "$INSTALL_DIR" rev-parse --short HEAD)"
elif [ -f "$(dirname "$0")/../src/deckxd.ts" ]; then
  # Running from a clone: install from here rather than fetching a second copy.
  SOURCE_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
  if [ "$SOURCE_DIR" != "$INSTALL_DIR" ]; then
    mkdir -p "$INSTALL_DIR"
    cp -r "$SOURCE_DIR/." "$INSTALL_DIR/"
  fi
  ok "installed from $SOURCE_DIR"
else
  git clone --quiet --depth 1 "$REPO_URL" "$INSTALL_DIR"
  ok "cloned to $INSTALL_DIR ($(git -C "$INSTALL_DIR" rev-parse --short HEAD))"
fi

step "Dependencies"
( cd "$INSTALL_DIR/chain" && npm install --omit=dev --silent --no-audit --no-fund )
ok "installed"

# ── 4. datadir ───────────────────────────────────────────────────────────────

step "Data directory"
mkdir -p "$DATA_DIR"
chown -R "$SERVICE_USER:$SERVICE_USER" "$DATA_DIR"
# 0700: the datadir holds the node's identity key and, with --faucet, a wallet
# mnemonic. Nothing else on the machine needs to read either.
chmod 700 "$DATA_DIR"
ok "$DATA_DIR (0700, owned by $SERVICE_USER)"

# ── 5. systemd unit ──────────────────────────────────────────────────────────

step "Service definition"

render_unit > "/etc/systemd/system/${SERVICE_NAME}.service"
systemctl daemon-reload
ok "/etc/systemd/system/${SERVICE_NAME}.service"

# ── 6. firewall ──────────────────────────────────────────────────────────────

if [ "$SKIP_FIREWALL" = 0 ] && command -v ufw >/dev/null 2>&1; then
  step "Firewall"
  ufw allow "${P2P_PORT}/tcp" >/dev/null 2>&1 && ok "opened ${P2P_PORT}/tcp (P2P)"
  if [ "$ENABLE_GATEWAY" = 1 ]; then
    ufw allow "${GATEWAY_PORT}/tcp" >/dev/null 2>&1 && ok "opened ${GATEWAY_PORT}/tcp (gateway)"
  fi
  # Stated rather than silently omitted, because "why can't I reach the RPC"
  # is the question this line answers.
  info "${RPC_PORT}/tcp (RPC) deliberately NOT opened — it is unauthenticated"
elif [ "$SKIP_FIREWALL" = 0 ]; then
  warn "ufw not installed — open ${P2P_PORT}/tcp yourself, and keep ${RPC_PORT} closed"
fi

# ── 7. start ─────────────────────────────────────────────────────────────────

step "Starting"
systemctl enable --quiet "$SERVICE_NAME"
systemctl restart "$SERVICE_NAME"

for _ in $(seq 1 30); do
  sleep 1
  if curl -fsS --max-time 2 "http://127.0.0.1:${RPC_PORT}" \
       -H 'content-type: application/json' \
       -d '{"method":"getblockchaininfo"}' >/dev/null 2>&1; then
    break
  fi
done

CHAIN_JSON="$(curl -fsS --max-time 5 "http://127.0.0.1:${RPC_PORT}" \
  -H 'content-type: application/json' \
  -d '{"method":"getblockchaininfo"}' 2>/dev/null || true)"

if [ -z "$CHAIN_JSON" ]; then
  printf '\n'
  die "the node did not answer — check: journalctl -u ${SERVICE_NAME} -n 50 --no-pager"
fi

json_field() { printf '%s' "$CHAIN_JSON" | sed -n "s/.*\"$1\":\"\?\([^,\"}]*\)\"\?.*/\1/p"; }

HEIGHT="$(json_field height)"
GENESIS="$(json_field genesis)"
BALANCED="$(json_field supplyBalanced)"

ok "running — height ${HEIGHT}"

# A genesis mismatch means this node will never agree with the others and will
# sit at height 0 forever without any error that says so. Catching it here is
# worth the four lines.
EXPECTED_GENESIS="$(grep -o "'[0-9a-f]\{64\}'" "$INSTALL_DIR/chain/test/genesis.test.ts" 2>/dev/null | head -1 | tr -d "'" || true)"
if [ -n "$EXPECTED_GENESIS" ] && [ "$NETWORK" = "mainnet" ] && [ "$GENESIS" != "$EXPECTED_GENESIS" ]; then
  die "genesis mismatch: node has $GENESIS, this build expects $EXPECTED_GENESIS"
fi
[ "$BALANCED" = "true" ] && ok "supply audit balanced" || warn "supply audit reports drift"

# ── 8. what to publish ───────────────────────────────────────────────────────

PUBLIC_IP="$(curl -fsS --max-time 5 https://api.ipify.org 2>/dev/null || echo 'YOUR-HOST')"
IDENTITY="$(journalctl -u "$SERVICE_NAME" -n 200 --no-pager 2>/dev/null \
  | grep -oE '#[0-9a-f]{64}' | tail -1 | tr -d '#' || true)"

printf '\n%sdeckxd is running.%s\n\n' "$BOLD" "$OFF"
printf '  %-14s %s\n' "network" "$NETWORK"
printf '  %-14s %s\n' "height" "$HEIGHT"
printf '  %-14s %s\n' "p2p" "${PUBLIC_IP}:${P2P_PORT}"
[ "$ENABLE_GATEWAY" = 1 ] && printf '  %-14s %s\n' "gateway" "http://${PUBLIC_IP}:${GATEWAY_PORT}"
[ "$ENABLE_FAUCET" = 1 ]  && printf '  %-14s %s\n' "faucet" "http://${PUBLIC_IP}:${GATEWAY_PORT}/faucet"
printf '  %-14s %s\n' "logs" "journalctl -u ${SERVICE_NAME} -f"
printf '\n'

if [ -n "$IDENTITY" ]; then
  printf '%sPublish this, not just the host:%s\n\n' "$BOLD" "$OFF"
  printf '    %s%s:%s#%s%s\n\n' "$GREEN" "$PUBLIC_IP" "$P2P_PORT" "$IDENTITY" "$OFF"
  info "without the identity, a newcomer's first connection is trust-on-first-use"
  info "and an attacker on their path at that moment is not detected"
else
  info "find the identity to publish with: journalctl -u ${SERVICE_NAME} | grep 'publish this'"
fi
printf '\n'

if [ "$ENABLE_FAUCET" = 1 ] && [ -z "$MINE_ADDRESS" ]; then
  warn "the faucet starts empty — fund it, or restart with --mine <faucet address>"
  info "its address is in: journalctl -u ${SERVICE_NAME} | grep faucet"
fi
