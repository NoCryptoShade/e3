#!/bin/bash
# fiks12.sh - reparerer nivaa 12 naar sudo-fila mangler. Beholder fremgang.
B="$HOME/bandit"
[ -f "$B/apne.sh" ] || { echo "Finner ikke ~/bandit paa denne maskinen."; exit 1; }
PW=$(tr -dc a-zA-Z0-9 </dev/urandom | head -c16)
T=$(mktemp -d); mkdir -p "$T/niva12"; echo niva12 > "$T/niva12/.ok"
printf 'NIVAA 12 - FERDIG\n\nGratulerer! Du loeste hele kjeden.\nFullfoeringsflagg (skriv paa tavla):  GA{bandit_mester}\n' > "$T/niva12/README.txt"
tar -czf - -C "$T" niva12 | openssl enc -aes-256-cbc -pbkdf2 -md sha256 -salt -k "$PW" -out "$B/.laast/niva12.enc"
printf '%s\n' "$PW" | bash "$B/apne.sh" >/dev/null 2>&1
rm -rf "$T"
if [ -d "$B/niva12" ]; then
  echo "========================================"
  echo " Nivaa 12 aapnet. Du er ferdig!"
  grep -o 'GA{[^}]*}' "$B/niva12/README.txt"
  echo "========================================"
else
  echo "Staar du paa nivaa 11? Sjekk med: ls ~/bandit"
fi
