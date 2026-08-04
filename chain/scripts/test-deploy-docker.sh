#!/usr/bin/env bash
#
# Run deploy.sh against a real Ubuntu with systemd, locally, in Docker.
#
#   ./chain/scripts/test-deploy-docker.sh
#
# ── Why this exists next to the GitHub workflow ──────────────────────────────
# `.github/workflows/deploy-test.yml` does the same checks on a runner and is
# the one that gates the repository. This is the local version: same test, no
# push, answer in a couple of minutes instead of after a round trip through CI.
# Use it while editing deploy.sh; let the workflow be the record.
#
# ── The systemd part ─────────────────────────────────────────────────────────
# A normal container has PID 1 = your command and no service manager, so
# `systemctl` fails and none of this would prove anything. `jrei/systemd-ubuntu`
# boots systemd as PID 1, which is what makes the unit file, the service user
# and the restart behaviour testable at all. That needs --privileged and a
# cgroup mount; the container is thrown away at the end.

set -euo pipefail

IMAGE="${DECKX_TEST_IMAGE:-jrei/systemd-ubuntu:22.04}"
NAME="deckxd-deploy-test"
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

# ── Git Bash on Windows ──────────────────────────────────────────────────────
# MSYS rewrites anything that looks like a Unix path in an argument, so
# `-v /sys/fs/cgroup:...` reaches Docker as `C:\Program Files\Git\sys\...` and
# the run fails with a permission error that has nothing to do with permissions.
# Turning the rewriting off fixes the container paths; the host path then has to
# be converted deliberately, because Docker Desktop wants `C:/Users/…` and not
# the `/c/Users/…` form Git Bash reports.
case "$(uname -s)" in
  MINGW* | MSYS* | CYGWIN*)
    export MSYS_NO_PATHCONV=1
    command -v cygpath >/dev/null 2>&1 && REPO_ROOT="$(cygpath -m "$REPO_ROOT")"
    ;;
esac

if [ -t 1 ]; then
  BOLD=$'\033[1m'; DIM=$'\033[2m'; RED=$'\033[31m'; GREEN=$'\033[32m'; OFF=$'\033[0m'
else
  BOLD=""; DIM=""; RED=""; GREEN=""; OFF=""
fi
step() { printf '\n%s==>%s %s\n' "$BOLD" "$OFF" "$1"; }
ok()   { printf '    %s✓%s %s\n' "$GREEN" "$OFF" "$1"; }
die()  { printf '%serror:%s %s\n' "$RED" "$OFF" "$1" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || die "docker is not on PATH"
docker version >/dev/null 2>&1 || die "docker is installed but not running — start Docker Desktop"

cleanup() {
  docker rm -f "$NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

step "Starting $IMAGE with systemd as PID 1"
cleanup
docker run -d --name "$NAME" --privileged \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
  --cgroupns=host \
  -v "$REPO_ROOT:/src:ro" \
  "$IMAGE" >/dev/null

for _ in $(seq 1 30); do
  if docker exec "$NAME" systemctl is-system-running --wait >/dev/null 2>&1; then break; fi
  sleep 1
done
docker exec "$NAME" systemctl --version >/dev/null || die "systemd did not come up in the container"
ok "systemd is running"

run() { docker exec "$NAME" bash -c "$1"; }

step "Installing prerequisites"
run 'export DEBIAN_FRONTEND=noninteractive; apt-get update -qq && apt-get install -y -qq curl ca-certificates gnupg git >/dev/null'
ok "done"

# Copied rather than mounted read-only: the script installs into it, and a
# read-only bind would fail for reasons that have nothing to do with the script.
step "Copying the working tree in"
run 'rm -rf /opt/deckxcoin && cp -r /src /opt/deckxcoin && rm -rf /opt/deckxcoin/.git'
ok "/opt/deckxcoin"

step "Running deploy.sh for real"
run 'cd /opt/deckxcoin && bash chain/scripts/deploy.sh \
      --network regtest --gateway --gateway-port 8080 \
      --faucet --faucet-amount 5 --faucet-reserve 1 --no-firewall' \
  || die "deploy.sh failed"

step "The service is active, and stays active"
run 'systemctl is-active --quiet deckxd' || {
  run 'journalctl -u deckxd -n 60 --no-pager'; die "service is not active"
}
sleep 12
RESTARTS=$(run 'systemctl show deckxd -p NRestarts --value' | tr -d '\r')
# A daemon that exits and is restarted every five seconds reads as "active" at
# a glance. This is the check that catches it.
[ "$RESTARTS" = "0" ] || { run 'journalctl -u deckxd -n 80 --no-pager'; die "restart loop: $RESTARTS restarts"; }
ok "active, 0 restarts"

step "Unprivileged, from its own datadir"
OWNER=$(run 'ps -o user= -p $(systemctl show deckxd -p MainPID --value)' | tr -d ' \r')
[ "$OWNER" = "deckxd" ] || die "running as $OWNER, expected deckxd"
run 'test "$(stat -c %a /var/lib/deckxd)" = "700"' || die "datadir is not 0700"
run 'test "$(stat -c %a /var/lib/deckxd/faucet.key)" = "600"' || die "faucet key is not 0600"
ok "user deckxd · datadir 0700 · faucet.key 0600"

step "RPC answers on loopback"
run 'for i in $(seq 1 30); do curl -fsS --max-time 2 localhost:29332 -H "content-type: application/json" -d "{\"method\":\"getblockchaininfo\"}" >/dev/null 2>&1 && break; sleep 1; done'
run 'curl -fsS localhost:29332 -H "content-type: application/json" -d "{\"method\":\"getblockchaininfo\"}" | grep -q "\"supplyBalanced\":true"' \
  || die "the node did not report a balanced supply"
ok "balanced"

step "The gateway serves reads and refuses everything else"
run 'curl -fsS "localhost:8080/?method=getblockchaininfo" | grep -q height' || die "gateway read failed"
ok "reads"
for m in generate addnode submitblock sync getpeerinfo listbanned sendrawtransaction; do
  CODE=$(run "curl -s -o /dev/null -w '%{http_code}' -X POST localhost:8080 -H 'content-type: application/json' -d '{\"method\":\"$m\"}'" | tr -d '\r')
  [ "$CODE" = "403" ] || die "$m returned $CODE, expected 403"
  ok "$m refused"
done

step "Re-running changes nothing"
run 'cd /opt/deckxcoin && bash chain/scripts/deploy.sh --network regtest --gateway --faucet --no-firewall' >/dev/null \
  || die "second run failed"
run 'systemctl is-active --quiet deckxd' || die "service died on the second run"
ok "still active"

step "Uninstall removes the service and keeps the keys"
run 'cd /opt/deckxcoin && bash chain/scripts/deploy.sh --uninstall' >/dev/null
run 'test ! -f /etc/systemd/system/deckxd.service' || die "the unit file survived uninstall"
run 'test -d /var/lib/deckxd' || die "uninstall deleted the datadir — it must not"
ok "service gone, datadir kept"

printf '\n%sdeploy.sh works on real Linux.%s\n' "$BOLD" "$OFF"
printf '%s  The container is being removed. Nothing on this machine was changed.%s\n\n' "$DIM" "$OFF"
