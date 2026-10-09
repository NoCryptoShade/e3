#!/bin/bash
# fikssiste.sh - redningsskript for siste nivaa (25).
# Brukes KUN hvis du staar fast paa nivaa 24 (sudo) fordi brukeren din ikke
# har sudo-tilgang, og derfor ikke faar lest /root/niva25_passord.txt.
# Skriptet lager siste nivaa paa nytt med et kjent passord og aapner det.
#
# Bruk:  curl -sO https://nocryptoshade.github.io/e3/fikssiste.sh && bash fikssiste.sh
set -e
B="$HOME/bandit"
[ -f "$B/apne.sh" ] || { echo "Fant ikke ~/bandit. Kjoer bandit.sh foerst."; exit 1; }
if [ ! -d "$B/niva24" ]; then
  echo "Du maa ha aapnet nivaa 24 foer dette skriptet hjelper deg."
  echo "Staar du fast tidligere i kjeden, er det ikke sudo-problemet - si fra til veileder."
  exit 1
fi
PW="$(tr -dc 'a-zA-Z0-9' </dev/urandom | head -c 16)"
T="$(mktemp -d)"; mkdir -p "$T/niva25"; echo "niva25" > "$T/niva25/.ok"
cat > "$T/niva25/README.txt" <<'EOF'
NIVAA 25 - FERDIG
=================
Gratulerer! Du loeste hele kjeden, inkludert andreaars-nivaaene.

Fullfoeringsflagg:  GA{bandit_mester}
EOF
tar -czf - -C "$T" niva25 \
  | openssl enc -aes-256-cbc -pbkdf2 -md sha256 -salt -k "$PW" -out "$B/.laast/niva25.enc"
rm -rf "$T"
printf '%s\n' "$PW" | bash "$B/apne.sh" >/dev/null 2>&1 || true
if [ -d "$B/niva25" ]; then
  echo "Nivaa 25 er aapnet. Siste flagg:"
  grep -o 'GA{[^}]*}' "$B/niva25/README.txt"
  echo "Gaa dit:  cd ~/bandit/niva25  &&  cat README.txt"
else
  echo "Noe gikk galt. Si fra til veileder."
fi
