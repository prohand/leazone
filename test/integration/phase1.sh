#!/usr/bin/env bash
# Phase 1 integration test: builds the image and checks, in Docker,
#  - the container runs as UID 1000 with a read-only root filesystem
#  - file capabilities work in non-root (privileged port bind) with and
#    without NET_ADMIN, and with no-new-privileges
#  - healthcheck, first start, forced MFA, CLI rescue commands
#  - image size < 40 MB
#
# Usage: test/integration/phase1.sh
# Env:   GO_IMAGE / NODE_IMAGE to use a registry mirror, KEEP=1 to keep containers.
set -euo pipefail
cd "$(dirname "$0")/../.."

IMG=leazone:phase1-test
NAME=leazone-phase1
PORT=844          # privileged port on purpose: proves NET_BIND_SERVICE works as UID 1000
WORK=$(mktemp -d)
pass=0; fail=0
ok()  { echo "  ✔ $*"; pass=$((pass+1)); }
ko()  { echo "  ✘ $*"; fail=$((fail+1)); }
cleanup() {
  [ "${KEEP:-0}" = 1 ] && return
  docker rm -f $NAME $NAME-nocap >/dev/null 2>&1 || true
  docker volume rm -f $NAME-data $NAME-logs >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

echo "== build"
args=()
[ -n "${GO_IMAGE:-}" ] && args+=(--build-arg GO_IMAGE="$GO_IMAGE")
[ -n "${NODE_IMAGE:-}" ] && args+=(--build-arg NODE_IMAGE="$NODE_IMAGE")
docker build --network host -q "${args[@]}" --build-arg VERSION=0.1.0-test -t $IMG . >/dev/null
size=$(docker image inspect $IMG -f '{{.Size}}')
mb=$((size/1024/1024))
[ "$mb" -lt 40 ] && ok "image size ${mb} MB < 40 MB" || ko "image size ${mb} MB >= 40 MB"

echo "admin password for tests 123" > "$WORK/admin_password"
chmod 644 "$WORK/admin_password"

run() { # name, extra docker args...
  local n=$1; shift
  docker run -d --name "$n" --network host --user 1000:1000 --read-only --tmpfs /tmp:mode=1777 \
    --security-opt no-new-privileges:true --cap-drop ALL "$@" \
    -e LEAZONE_HTTP_LISTEN=127.0.0.1:$PORT -e LEAZONE_CONTROL_SOCKET=/tmp/leazone.sock \
    -e LEAZONE_ADMIN_PASSWORD_FILE=/run/admin_password -v "$WORK/admin_password:/run/admin_password:ro" \
    -v $NAME-data:/data -v $NAME-logs:/logs $IMG >/dev/null
}

wait_healthy() {
  for _ in $(seq 1 60); do
    st=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$1" 2>/dev/null || true)
    [ "$st" = healthy ] && return 0
    [ "$(docker inspect -f '{{.State.Running}}' "$1")" = false ] && return 1
    # Do not wait for the 30 s HEALTHCHECK start period: run the same command.
    docker exec "$1" /leazone healthcheck >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}

echo "== non-root, read-only, no-new-privileges, without NET_ADMIN"
run $NAME --cap-add NET_BIND_SERVICE --cap-add NET_RAW
if wait_healthy $NAME; then ok "container healthy"; else ko "container not healthy"; docker logs $NAME; exit 1; fi
[ "$(docker inspect -f '{{.Config.User}}' $NAME)" = "1000:1000" ] && ok "runs as 1000:1000" || ko "user"
[ "$(docker inspect -f '{{.HostConfig.ReadonlyRootfs}}' $NAME)" = true ] && ok "read-only root filesystem" || ko "rootfs writable"
caps=$(docker exec $NAME /leazone caps)
[ "$caps" = "NET_BIND_SERVICE=yes NET_RAW=yes NET_ADMIN=no" ] && ok "capabilities: $caps" || ko "capabilities: $caps"
docker logs $NAME 2>&1 | grep -q "capabilities.*NET_ADMIN=no" && ok "startup log shows effective capabilities" || ko "caps log"

echo "== API"
B="https://127.0.0.1:$PORT"
curl -skf $B/health | grep -q '"ok"' && ok "/health on privileged port $PORT" || ko "/health"
hdr=$(curl -skI $B/)
echo "$hdr" | grep -qi "content-security-policy: default-src 'self'" && ok "CSP header" || ko "CSP header"
curl -sk $B/ | grep -qi '<div id="root"' && ok "web UI served" || ko "web UI not served"
st=$(curl -sk -X POST -H 'Content-Type: application/json' -H "Origin: $B" $B/api/v1/auth/login \
  -d '{"username":"admin","password":"admin password for tests 123"}')
echo "$st" | grep -q '"mfa_setup_required"' && ok "first login forces MFA setup" || ko "first login: $st"

echo "== brute force"
for _ in 1 2 3 4 5; do
  curl -sk -o /dev/null -X POST -H 'Content-Type: application/json' -H "Origin: $B" $B/api/v1/auth/login -d '{"username":"admin","password":"wrong wrong wrong"}'
done
code=$(curl -sk -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' -H "Origin: $B" $B/api/v1/auth/login \
  -d '{"username":"admin","password":"admin password for tests 123"}')
[ "$code" = 429 ] && ok "account locked after 5 failures (HTTP 429)" || ko "lockout: HTTP $code"

echo "== rescue commands (docker exec)"
out=$(docker exec $NAME /leazone admin reset-password admin)
echo "$out" | grep -q "Nouveau mot de passe" && ok "admin reset-password (also unlocks)" || ko "reset-password: $out"
newpw=$(echo "$out" | sed 's/.*: //')
st=$(curl -sk -X POST -H 'Content-Type: application/json' -H "Origin: $B" $B/api/v1/auth/login \
  -d "{\"username\":\"admin\",\"password\":\"$newpw\"}")
echo "$st" | grep -q '"mfa_setup_required"' && ok "login with the new password" || ko "login after reset: $st"
docker exec $NAME /leazone admin reset-mfa admin | grep -q "MFA réinitialisé" && ok "admin reset-mfa" || ko "reset-mfa"
ms=$(docker exec $NAME /leazone migrate status)
[[ "$ms" =~ schéma\ de\ la\ base\ :\ ([0-9]+),\ attendu\ par\ cette\ version\ :\ ([0-9]+) ]] && \
  [ "${BASH_REMATCH[1]}" = "${BASH_REMATCH[2]}" ] && ok "migrate status: schema up to date (${BASH_REMATCH[1]})" || ko "migrate status: $ms"

echo "== restart keeps data (no new admin password)"
docker restart $NAME >/dev/null
wait_healthy $NAME && ok "healthy after restart" || ko "restart"
[ "$(docker logs $NAME 2>&1 | grep -c 'initial admin account created')" = 1 ] && ok "admin created only once" || ko "admin created twice"
docker rm -f $NAME >/dev/null

echo "== with NET_ADMIN (VIP capable)"
run $NAME-nocap --cap-add NET_BIND_SERVICE --cap-add NET_RAW --cap-add NET_ADMIN
wait_healthy $NAME-nocap && ok "healthy" || ko "not healthy"
caps=$(docker exec $NAME-nocap /leazone caps)
[ "$caps" = "NET_BIND_SERVICE=yes NET_RAW=yes NET_ADMIN=yes" ] && ok "capabilities: $caps" || ko "capabilities: $caps"
docker rm -f $NAME-nocap >/dev/null

echo
echo "phase 1: $pass passed, $fail failed"
[ "$fail" = 0 ]
