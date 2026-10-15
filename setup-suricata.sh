#!/usr/bin/env bash
# ============================================================================
#  Emne 3  -  SURICATA NIC + RULE FIX on the VICTIM   (authored by Dag Thomas)
# ----------------------------------------------------------------------------
#  Run this ONCE on the VICTIM after importing the VM, as root:
#        sudo bash setup-suricata.sh
#
#  What it does (safe to re-run, backs up everything it touches first):
#    1. Installs a tiny launcher that picks the real network card AT BOOT and
#       starts Suricata with --af-packet=<card> on the command line. This never
#       edits /etc, so it works under Suricata 8's read-only service sandbox
#       (ProtectSystem) - the thing that broke the old config-rewrite approach.
#       The same VM then works on VirtualBox (enp0s3), VMware (ens33) and
#       QEMU/UTM (enp0s1) with no change. It requires EXACTLY ONE hardware NIC;
#       if you have both host-only and NAT attached at once it will refuse to
#       start, so detach the extra adapter before running your detection tasks.
#    2. Fixes the command-injection rule (SID 1000005) and keeps it on one line.
#    3. Validates the full config with `suricata -T` before restarting, and
#       drops a rollback.sh next to its backup so you can undo everything.
#
#  AFTER IT RUNS
#    - View alerts in Evebox from Kali's Firefox:  https://<victim-ip>:5636/
#
#  NOTE: it writes its backup + rollback.sh under ./Documentation/Fix Suricata
#  NIC detection/ relative to wherever you run it, so run it from a folder you
#  can find again (e.g. your home directory).
# ============================================================================
set -euo pipefail
umask 022
helper=/usr/local/sbin/suricata-pick-iface.sh
dropin=/etc/systemd/system/suricata.service.d/10-lab-iface.conf
rules=/var/lib/suricata/rules/local.rules
backup="$PWD/Documentation/Fix Suricata NIC detection/backup-$(date +%Y%m%d-%H%M%S)-$$"
mkdir -p -- "$backup/before"
chmod 700 -- "$backup"
for file in "$helper" "$dropin" "$rules"; do
    if [[ -e "$file" ]]; then
        cp -a --parents -- "$file" "$backup/before"
    else
        printf '%s\n' "$file" >> "$backup/absent-files"
    fi
done
printf 'Backups: %s\nRollback: sudo bash %q\n' "$backup" "$backup/rollback.sh"
trap 'echo "Stopped on error. Use the rollback command printed above." >&2' ERR

cat > "$backup/rollback.sh" <<'ROLLBACK'
#!/usr/bin/env bash
set -euo pipefail
backup=$(cd -- "$(dirname -- "$0")" && pwd)
for file in /usr/local/sbin/suricata-pick-iface.sh \
            /etc/systemd/system/suricata.service.d/10-lab-iface.conf \
            /var/lib/suricata/rules/local.rules; do
    if [[ -e "$backup/before$file" ]]; then
        cp -a -- "$backup/before$file" "$file"
    elif [[ -e "$file" ]]; then
        mkdir -p -- "$backup/after$(dirname -- "$file")"
        mv -- "$file" "$backup/after$file"
    fi
done
systemctl daemon-reload
systemctl restart suricata
systemctl is-active suricata
ROLLBACK

# 1) Install the NIC launcher.
cat > "$backup/suricata-pick-iface.sh" <<'PICK'
#!/usr/bin/env bash
set -euo pipefail
interfaces=()
for path in /sys/class/net/*; do
    name=${path##*/}
    case "$name" in
        lo|docker*|br-*|veth*|virbr*|vmnet*) continue ;;
    esac
    [[ -e "$path/device" ]] || continue
    interfaces+=("$name")
done
if (( ${#interfaces[@]} != 1 )); then
    printf 'Expected one hardware NIC; found %s.\n' "${#interfaces[@]}" >&2
    exit 1
fi
iface=${interfaces[0]}
printf 'Suricata: selected interface %s\n' "$iface"

# Add local.rules only when the YAML does not already load it.
rules=$(realpath -m -- /var/lib/suricata/rules/local.rules)
dump=$(/usr/bin/suricata --dump-config -c /etc/suricata/suricata.yaml)
rule_dir=$(awk '/^default-rule-path = / {sub(/^[^=]*= /, ""); print; exit}' <<< "$dump")
extra_rules=(-s "$rules")
while IFS= read -r pattern; do
    if [[ "$pattern" != /* ]]; then
        [[ -n "$rule_dir" ]] || { echo 'Missing default-rule-path.' >&2; exit 1; }
        pattern="$rule_dir/$pattern"
    fi
    pattern=$(realpath -m -- "$pattern")
    if [[ "$rules" == $pattern ]]; then
        extra_rules=()
        break
    fi
done < <(awk '/^rule-files\.[0-9]+ = / {sub(/^[^=]*= /, ""); print}' <<< "$dump")

common=(-c /etc/suricata/suricata.yaml
        --set "af-packet.0.interface=$iface" "${extra_rules[@]}")
if [[ ${1:-} == --test ]]; then
    exec /usr/bin/suricata -T --init-errors-fatal "${common[@]}"
fi
exec /usr/bin/suricata -D --af-packet="$iface" "${common[@]}" \
    --pidfile /var/run/suricata/suricata.pid
PICK
bash -n "$backup/suricata-pick-iface.sh"

# 2) Replace only SID 1000005, keeping the rule on one line.
if [[ -f "$rules" ]]; then
    awk '!/sid:[[:space:]]*1000005[[:space:]]*;/' "$rules" > "$backup/local.rules.new"
else
    : > "$backup/local.rules.new"
fi
cat >> "$backup/local.rules.new" <<'RULE'
alert http any any -> $HOME_NET any (msg:"LAB command-injection"; flow:to_server; http.uri; content:"ping.php"; content:"host="; pcre:"/host=[^&]*[\x3b&|\x60]/"; classtype:web-application-attack; sid:1000005; rev:2;)
RULE
printf 'Testing local rules; this may take a few minutes...\n'
timeout --kill-after=30s 10m /usr/bin/suricata -T --init-errors-fatal \
    -c /etc/suricata/suricata.yaml -S "$backup/local.rules.new"

install -d /usr/local/sbin /etc/systemd/system/suricata.service.d /var/lib/suricata/rules
install -m 0755 "$backup/suricata-pick-iface.sh" "$helper"
cat > "$dropin" <<'UNIT'
[Service]
ExecStartPre=
ExecStart=
ExecStart=/usr/local/sbin/suricata-pick-iface.sh
TimeoutStartSec=10min
UNIT
cat "$backup/local.rules.new" > "$rules"

# 3) Validate the full configuration, then restart and verify.
printf 'Testing full configuration; this may take a few minutes...\n'
timeout --kill-after=30s 10m "$helper" --test
systemctl daemon-reload
printf 'Restarting Suricata; allowing up to 10 minutes for startup...\n'
systemctl restart suricata
sleep 5
systemctl is-active suricata
journalctl -u suricata -n 12 --no-pager
