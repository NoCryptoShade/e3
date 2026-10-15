#!/usr/bin/env bash
# ============================================================================
#  Emne 3  -  SURICATA DETECTION on the VICTIM
# ----------------------------------------------------------------------------
#  Run this ONCE on the VICTIM, after you have imported the VM. It gets the
#  network IDS (Suricata) working and loads the lab detection rules, so your
#  attacks from Kali light up as alerts. Needs NO internet - it only touches
#  files already on the box.
#
#  It does two things (safe to run again):
#    1. Finds the real network card on THIS machine and writes it straight into
#       suricata.yaml, so the same VM works on VirtualBox (enp0s3), VMware
#       (ens33) and QEMU/UTM (enp0s1) alike. Without this, an imported VM gets
#       stuck on "activating" / exits with no alerts because the card name in
#       the config does not exist here. If you later move the VM to a DIFFERENT
#       hypervisor, just run this script again.
#    2. Loads the eight lab rules (SID 1000001-1000008) that map the week 6-7
#       attacks (SSH brute force, hidden admin panel, portal login, webshell,
#       command injection, SMB, FTP, exposed .git) to readable alerts.
#
#  NOTE: the card is written at setup time, as root, NOT via a boot-time systemd
#  hook. Suricata 8's service runs with a read-only /etc sandbox (ProtectSystem),
#  so an ExecStartPre hook cannot rewrite the config - doing it here avoids that.
#
#  HOW TO GET THIS FILE ONTO THE VICTIM
#    - While the victim is on NAT for the scenario update, you can also grab it:
#          curl -fO https://nocryptoshade.github.io/e3/setup-suricata.sh
#    - Or copy it over from Kali (victim is host-only):
#          scp setup-suricata.sh labadmin@<victim-ip>:~
#
#  RUN IT (on the victim):
#          sudo bash setup-suricata.sh
#
#  AFTER IT RUNS
#    - View alerts in Evebox from Kali's Firefox:  https://<victim-ip>:5636/
#    - To see the same alerts next to your host events in Wazuh (week 13),
#      the victim's agent already tails /var/log/suricata/eve.json.
# ============================================================================
set -uo pipefail
c_green="\e[32m"; c_red="\e[31m"; c_yellow="\e[33m"; c_reset="\e[0m"
say(){ echo -e "${c_yellow}[*]${c_reset} $*"; }
good(){ echo -e "${c_green}[OK]${c_reset} $*"; }
bad(){ echo -e "${c_red}[!!]${c_reset} $*"; }
[[ $EUID -eq 0 ]] || { bad "Run as root: sudo bash $0"; exit 1; }

if ! command -v suricata >/dev/null 2>&1; then
  bad "Suricata is not installed on this box. It should ship with the lab VM."
  bad "If you built the victim yourself, install it first: sudo apt-get install -y suricata"
  exit 1
fi

# --- remove the old broken boot-time hook if a previous version installed it ---
# (an ExecStartPre that rewrote /etc fails under Suricata 8's read-only sandbox)
if [ -f /etc/systemd/system/suricata.service.d/10-lab-iface.conf ]; then
  say "Removing the old boot-time NIC hook (incompatible with Suricata 8 sandboxing)"
  rm -f /etc/systemd/system/suricata.service.d/10-lab-iface.conf
  rmdir /etc/systemd/system/suricata.service.d 2>/dev/null || true
  rm -f /usr/local/sbin/suricata-pick-iface.sh
  systemctl daemon-reload
fi

# --- detect the real network card on THIS machine ---------------------------
say "Detecting the network card"
IFACE=""
for i in /sys/class/net/*; do
  n=${i##*/}; [ "$n" = lo ] && continue
  case "$n" in docker*|br-*|veth*|virbr*|vmnet*) continue;; esac
  [ -e "$i/device" ] || continue
  IFACE=$n; break
done
if [ -z "$IFACE" ]; then
  bad "Could not find a real network card. Check 'ip -brief addr'."
  exit 1
fi
good "network card: $IFACE"

# --- write that card into suricata.yaml (as root, no sandbox) ----------------
# Use a temp file IN THE SAME directory as the target (no cross-device move),
# then overwrite the target's contents (keeps its owner/permissions).
say "Writing $IFACE into /etc/suricata/suricata.yaml"
tmp="$(mktemp /etc/suricata/.suricata.yaml.XXXXXX)" || { bad "cannot write in /etc/suricata"; exit 1; }
awk -v nic="$IFACE" '
  /^af-packet:/{b=1}
  b && /^[^[:space:]#]/ && !/^af-packet:/{b=0}
  b && !d && /^[[:space:]]*-[[:space:]]*interface:/{sub(/interface:.*/,"interface: " nic); d=1}
  {print}' /etc/suricata/suricata.yaml >"$tmp" \
  && cat "$tmp" >/etc/suricata/suricata.yaml
rm -f "$tmp"

say "Loading the lab detection rules"
install -d /var/lib/suricata/rules
cat >/var/lib/suricata/rules/local.rules <<'RULES'
# --- Emne 3 lab rules: map week 6-7 attacks to visible alerts ---------------
alert tcp any any -> $HOME_NET 22 (msg:"LAB SSH brute-force (many SYN to 22)"; flow:to_server; flags:S; threshold:type both, track by_src, count 10, seconds 30; classtype:attempted-recon; sid:1000001; rev:1;)
alert http any any -> $HOME_NET any (msg:"LAB hidden admin panel access"; flow:to_server; http.uri; content:"/admin"; nocase; classtype:web-application-activity; sid:1000002; rev:1;)
alert http any any -> $HOME_NET any (msg:"LAB portal login attempt (POST /portal)"; flow:to_server; http.method; content:"POST"; http.uri; content:"/portal/index.php"; classtype:web-application-activity; sid:1000003; rev:1;)
alert http any any -> $HOME_NET any (msg:"LAB possible webshell request in /portal/uploads"; flow:to_server; http.uri; content:"/portal/uploads/"; pcre:"/\.php/U"; classtype:web-application-attack; sid:1000004; rev:1;)
alert http any any -> $HOME_NET any (msg:"LAB command-injection markers in ping host param"; flow:to_server; http.uri; content:"ping.php"; content:"host="; pcre:"/host=[^&]*[\x3b&|\x60]/U"; classtype:web-application-attack; sid:1000005; rev:2;)
alert tcp any any -> $HOME_NET 445 (msg:"LAB SMB access attempt"; flow:to_server; classtype:attempted-recon; sid:1000006; rev:1;)
alert tcp any any -> $HOME_NET 21 (msg:"LAB FTP access attempt"; flow:to_server; classtype:attempted-recon; sid:1000007; rev:1;)
alert http any any -> $HOME_NET any (msg:"LAB exposed .git access"; flow:to_server; http.uri; content:"/.git/"; classtype:web-application-activity; sid:1000008; rev:1;)
RULES

say "Starting Suricata"
systemctl enable suricata >/dev/null 2>&1 || true
systemctl restart suricata
sleep 6
if systemctl is-active --quiet suricata; then
  good "Suricata is running and sniffing: ${IFACE}"
  echo "    Now run your attacks from Kali and watch Evebox at https://<victim-ip>:5636/"
else
  bad "Suricata still not active. Send the output of:"
  bad "    sudo journalctl -u suricata -n 30 --no-pager"
  exit 1
fi
