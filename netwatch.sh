#!/usr/bin/env bash
# Control script for Netwatch.   ./netwatch.sh help
set -euo pipefail
NAME=netwatch
IMAGE=netwatch
VOL=netwatch-data
PORT="${PORT:-8080}"
cd "$(dirname "$0")"

need_docker() { command -v docker >/dev/null || { echo "Docker is not installed: https://docs.docker.com/engine/install/"; exit 1; }; }
running() { [ "$(docker inspect -f '{{.State.Running}}' $NAME 2>/dev/null || true)" = "true" ]; }

build() { docker build -t $IMAGE . ; }

start() {
  need_docker
  docker image inspect $IMAGE >/dev/null 2>&1 || build
  docker rm -f $NAME >/dev/null 2>&1 || true
  # --restart unless-stopped: comes back after every reboot (Docker starts at boot) until you run `stop`.
  # host network/pid + SYS_PTRACE + AppArmor off: needed to see sockets and the processes that own them.
  # NET_ADMIN: only used to add DROP rules to its own NETWATCH iptables chain.
  docker run -d --name $NAME --restart unless-stopped \
    --network host --pid host \
    --cap-add SYS_PTRACE --cap-add NET_ADMIN --security-opt apparmor=unconfined \
    -e PORT="$PORT" -e AUTOBLOCK="${AUTOBLOCK:-0}" \
    -v /etc/passwd:/etc/passwd:ro -v $VOL:/app/data \
    $IMAGE >/dev/null
  echo "Netwatch started: http://127.0.0.1:$PORT   (auto-block: ${AUTOBLOCK:-0})"
  echo "Open the dashboard with: ./netwatch.sh open   (the API needs an access token; './netwatch.sh token' prints it)"
  echo "It will start automatically after reboot. Stop it with: ./netwatch.sh stop"
}

stop() {
  need_docker
  docker stop $NAME >/dev/null 2>&1 && echo "Stopped. It will NOT restart on boot until you run ./netwatch.sh start" || echo "Not running."
  echo "Note: iptables block rules stay active. Remove them with: ./netwatch.sh unblock-all"
}

status() {
  need_docker
  if running; then echo "running  -> http://127.0.0.1:$PORT"; docker inspect -f 'restart policy: {{.HostConfig.RestartPolicy.Name}}' $NAME
  else echo "not running"; fi
  systemctl is-enabled docker 2>/dev/null | sed 's/^/docker service at boot: /' || true
}

unblock_all() {
  need_docker
  for t in iptables ip6tables; do
    docker run --rm --network host --cap-add NET_ADMIN $IMAGE sh -c \
      "$t -D OUTPUT -j NETWATCH 2>/dev/null; $t -F NETWATCH 2>/dev/null; $t -X NETWATCH 2>/dev/null; true"
  done
  docker run --rm -v $VOL:/d alpine sh -c 'rm -f /d/blocked.json' 2>/dev/null || true
  echo "All Netwatch block rules removed."
}

uninstall() {
  docker rm -f $NAME >/dev/null 2>&1 || true
  unblock_all
  docker rmi $IMAGE >/dev/null 2>&1 || true
  echo "Removed container, image and rules. Data volume kept; delete with: docker volume rm $VOL"
}

case "${1:-help}" in
  build) need_docker; build ;;
  start) start ;;
  stop) stop ;;
  restart) stop; start ;;
  status) status ;;
  logs) docker logs -f --tail 50 $NAME ;;
  open) T=$(docker exec $NAME cat /app/data/api-token 2>/dev/null || true)  # the dashboard needs this token; it is stored in your browser after the first visit
        URL="http://127.0.0.1:$PORT/#t=$T"; (xdg-open "$URL" 2>/dev/null || open "$URL" 2>/dev/null || echo "Open: $URL") ;;
  token) docker exec $NAME cat /app/data/api-token ;;
  alerts) docker exec $NAME cat /app/data/alerts.jsonl ;;
  unblock-all) unblock_all ;;
  uninstall) uninstall ;;
  *) cat <<USAGE
Usage: ./netwatch.sh <command>
  build        build the Docker image
  start        start (builds first run); auto-starts on every boot  [AUTOBLOCK=1 to auto-drop malicious IPs]
  stop         stop and disable boot auto-start
  restart      stop + start
  status       running? auto-start enabled?
  logs         follow logs
  open         open the dashboard in your browser
  alerts       print logged malicious-IP alerts
  unblock-all  remove every iptables rule Netwatch added
  uninstall    remove container, image and rules
USAGE
  ;;
esac
