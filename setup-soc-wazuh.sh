#!/usr/bin/env bash
# ============================================================================
#  Emne 3  -  WEEKS 12-13  WAZUH SOC on KALI
#  Runs the Wazuh manager + indexer + dashboard as Docker ON KALI (the cockpit).
#  The victim keeps only its slim dormant agent and connects UP to this SOC.
# ----------------------------------------------------------------------------
#  WHY THIS DESIGN: "Kali is the only cockpit." The SIEM lives on Kali, the
#  victim stays slim, and it mirrors real life - agent on the endpoint (victim),
#  manager + analysis on a separate host (Kali). Nothing heavy on the vulnerable
#  box, no re-staging, no bigger victim image.
#
#  RUN THIS ON KALI, NOT on the victim.  Needs internet to install Docker and
#  pull ~2 GB of images. Kali is expected to run TWO adapters (adapter 1 NAT for
#  internet + adapter 2 Host-Only to reach the victim), so there is NO network-
#  switching: NAT gives internet and Host-Only reaches the victim at the same
#  time. The victim stays Host-Only ONLY (never NAT); do not enable ip_forward
#  on Kali, so the victim keeps no internet path. The agent must point at Kali's
#  Host-Only (adapter 2) IP - this script prints all of Kali's IPs so you can
#  pick the one on the victim's subnet if the auto-guess is off.
#
#  Usage (on Kali):
#        sudo bash setup-soc-wazuh.sh
#
#  When it finishes it prints:
#    - the dashboard URL + login
#    - the EXACT one-liner to run on the VICTIM to point its agent here
#
#  >>> VERSION MATCH (read this) <<<
#  The manager version MUST be >= the agent version on the victim, or the agent
#  will not enrol. The victim's agent comes from Wazuh's "4.x" apt channel, so
#  it is whatever was latest when the victim image was built. The shipped v4
#  victim was CONFIRMED on 4.14.8 (Oct 8 2026), so WAZUH_TAG below is pinned to
#  v4.14.8 (manager == agent, the cleanest match). If a rebuilt victim ever pulls
#  a different agent, check it with:   dpkg -l wazuh-agent
#  and set WAZUH_TAG to the nearest wazuh-docker tag that is >= that version
#  (same minor is ideal), then re-run. Available tags: github.com/wazuh/wazuh-docker/tags
#
#  RAM: the indexer heap is capped low, but the stack still needs ~2-3 GB on
#  Kali. On an 8 GB laptop running Kali + the victim at once this is tight -
#  pair up or teacher-demo.
#
#  ENROLMENT: the agent reaches this SOC on TCP 1514 (events) and 1515
#  (enrolment). On the isolated host-only net, open enrolment is fine. If an
#  agent never shows up, that 1515 path is the first thing to check.
#
#  SAFE TO RE-RUN (idempotent).  Run as root:  sudo bash setup-soc-wazuh.sh
# ============================================================================

set -uo pipefail
WAZUH_TAG="v4.14.8"                      # matches victim's wazuh-agent 4.14.8 (confirmed Oct 8); MUST be >= the agent (see header)
WZ_DIR="/opt/wazuh-docker"
SN="${WZ_DIR}/single-node"
INDEXER_HEAP="512m"                      # low for laptop RAM; raise if you have headroom

LOG="/var/log/emne3-soc-wazuh-setup.log"
c_green="\e[32m"; c_red="\e[31m"; c_yellow="\e[33m"; c_blue="\e[36m"; c_reset="\e[0m"
say()  { echo -e "${c_yellow}[*]${c_reset} $*"; }
good() { echo -e "${c_green}[OK]${c_reset} $*"; }
bad()  { echo -e "${c_red}[!!]${c_reset} $*"; }
hdr()  { echo -e "\n${c_blue}==== $* ====${c_reset}"; }
require_root() { [[ $EUID -eq 0 ]] || { bad "Run as root: sudo bash $0"; exit 1; }; }

declare -A RESULT
run_task() { local n="$1"; shift; say "Task: $n";
  if "$@" >>"$LOG" 2>&1; then RESULT["$n"]="OK"; good "$n"; else RESULT["$n"]="FAILED"; bad "$n (see $LOG)"; fi; }

COMPOSE=""
pick_compose() {
  if docker compose version >/dev/null 2>&1; then COMPOSE="docker compose"
  elif command -v docker-compose >/dev/null 2>&1; then COMPOSE="docker-compose"
  else return 1; fi
}

# Best-guess host-only IP (what the victim's agent will point at). Kali usually
# has a NAT iface (10.0.2.x / 192.168.64.x) AND a host-only iface (192.168.x).
# We prefer a 192.168.* address that is not Docker's. All IPs are printed too,
# so you can pick the right one if the guess is off.
soc_ip() {
  local ip
  ip=$(ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 \
        | grep -vE '^(10\.0\.2\.|172\.(1[6-9]|2[0-9]|3[01])\.)' \
        | grep -E '^192\.168\.' | head -1)
  [[ -n "$ip" ]] || ip=$(hostname -I | awk '{print $1}')
  echo "$ip"
}

task_prereqs() {
  DEBIAN_FRONTEND=noninteractive apt-get update -y
  DEBIAN_FRONTEND=noninteractive apt-get install -y git docker.io docker-compose-v2 \
    || DEBIAN_FRONTEND=noninteractive apt-get install -y git docker.io docker-compose
  systemctl enable --now docker
  pick_compose || { echo "no docker compose"; return 1; }
  # OpenSearch (the Wazuh indexer) will not start without this
  sysctl -w vm.max_map_count=262144
  grep -q 'vm.max_map_count' /etc/sysctl.conf || echo 'vm.max_map_count=262144' >> /etc/sysctl.conf
}

task_fetch_stack() {
  if [[ -d "$WZ_DIR/.git" ]]; then
    git -C "$WZ_DIR" fetch --depth 1 origin "$WAZUH_TAG"
    git -C "$WZ_DIR" checkout -f "$WAZUH_TAG"
  else
    rm -rf "$WZ_DIR"
    git clone --depth 1 -b "$WAZUH_TAG" https://github.com/wazuh/wazuh-docker.git "$WZ_DIR"
  fi
  [[ -d "$SN" ]] || { echo "single-node dir missing"; return 1; }
}

task_tune_heap() {
  cat > "${SN}/docker-compose.override.yml" <<YML
services:
  wazuh.indexer:
    environment:
      - "OPENSEARCH_JAVA_OPTS=-Xms${INDEXER_HEAP} -Xmx${INDEXER_HEAP}"
YML
}

task_generate_certs() {
  ( cd "$SN" && $COMPOSE -f generate-indexer-certs.yml run --rm generator )
}

task_deploy() {
  # Unlike the victim's dormant pre-stage, the SOC comes UP and stays up.
  ( cd "$SN" && $COMPOSE pull && $COMPOSE up -d )
}

task_readme() {
  local ip; ip=$(soc_ip)
  local pw; pw=$(grep -m1 'INDEXER_PASSWORD' "${SN}/docker-compose.yml" 2>/dev/null \
                 | sed 's/.*INDEXER_PASSWORD=//' | tr -d " \"'" )
  cat > "${SN}/SOC-README.txt" <<TXT
WAZUH SOC on KALI - weeks 12-13

Dashboard (in Kali's own Firefox):  https://localhost   (or https://${ip})
Login: admin / ${pw:-<INDEXER_PASSWORD in ${SN}/docker-compose.yml>}

On the VICTIM, point its agent at this SOC and start it:
  sudo sed -i 's|<address>.*</address>|<address>${ip}</address>|' /var/ossec/etc/ossec.conf
  sudo systemctl enable --now wazuh-agent

Then on the dashboard: Agents -> the victim should show "active".

Stop the SOC (frees all the RAM):   cd ${SN} && sudo docker compose down
Start it again:                     cd ${SN} && sudo docker compose up -d
TXT
}

self_check() {
  hdr "Self-check"
  local ip; ip=$(soc_ip)
  local pw; pw=$(grep -m1 'INDEXER_PASSWORD' "${SN}/docker-compose.yml" 2>/dev/null \
                 | sed 's/.*INDEXER_PASSWORD=//' | tr -d " \"'" )
  [[ -d "$SN" ]] && good "wazuh-docker single-node present (${WAZUH_TAG})" || bad "stack missing"
  [[ -f "${SN}/docker-compose.override.yml" ]] && good "indexer heap capped at ${INDEXER_HEAP}" || bad "heap override missing"
  ls "${SN}"/config/wazuh_indexer_ssl_certs/*.pem >/dev/null 2>&1 && good "certificates generated" || bad "certs not generated"

  local running; running=$(docker ps --format '{{.Names}}' 2>/dev/null | grep -c 'wazuh')
  [[ "${running:-0}" -ge 3 ]] && good "SOC running (${running} wazuh containers up)" \
                               || bad "expected >=3 wazuh containers running, found ${running:-0} (docker compose logs)"

  # ports the victim's agent needs (1514 events, 1515 enrolment) + dashboard 443
  for p in 1514 1515 443; do
    if ss -ltn 2>/dev/null | grep -q ":${p} "; then good "port ${p} listening"
    else bad "port ${p} not listening yet"; fi
  done

  local code; code=$(curl -sk -o /dev/null -w '%{http_code}' "https://127.0.0.1/" 2>/dev/null)
  [[ "$code" =~ ^(200|302|401)$ ]] && good "dashboard answering on 443 (HTTP ${code})" \
                                   || bad "dashboard not answering yet (HTTP ${code:-none}) - the indexer can take a few minutes on first boot"

  echo
  hdr "SOC IS UP - what to do next"
  echo "  Dashboard (Kali Firefox):  https://localhost   (or https://${ip})"
  echo "  Login: admin / ${pw:-see INDEXER_PASSWORD in ${SN}/docker-compose.yml}"
  echo
  echo "  On the VICTIM, connect its agent to this SOC:"
  echo "    sudo sed -i 's|<address>.*</address>|<address>${ip}</address>|' /var/ossec/etc/ossec.conf"
  echo "    sudo systemctl enable --now wazuh-agent"
  echo
  echo "  All my IPv4 addresses (use the host-only one if the guess above is wrong):"
  ip -4 -o addr show scope global 2>/dev/null | awk '{printf "    %-8s %s\n",$2,$4}'
  echo
  say "Summary:"
  for k in prereqs fetch_stack tune_heap generate_certs deploy readme; do
    printf "    %-16s %s\n" "$k" "${RESULT[$k]:-SKIPPED}"
  done
}

require_root
: >"$LOG"
say "Starting Wazuh SOC on Kali. Full log: $LOG"
say "This installs Docker + pulls ~2 GB on first run - needs internet (NAT)."
run_task "prereqs"        task_prereqs
run_task "fetch_stack"    task_fetch_stack
run_task "tune_heap"      task_tune_heap
run_task "generate_certs" task_generate_certs
run_task "deploy"         task_deploy
run_task "readme"         task_readme
self_check
echo; good "Wazuh SOC ready. Connect the victim's agent with the command above."
