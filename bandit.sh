#!/bin/bash
# bandit.sh  -  bygger en lokal Bandit-stil flaggjakt paa en Kali.
# Ti nivaa (0-9). Hvert nivaa laerer en Linux-ferdighet. Passordet du finner
# paa et nivaa laaser opp det neste (ekte kryptering med openssl).
# Passordene er TILFELDIGE per maskin, saa ingen kan rope ut svaret.
#
# Kjoeres av HVER student paa egen maskin, som vanlig bruker.
# Trenger ikke internett, ikke victim-VM. Alt ligger i ~/bandit/.
#
# Bruk:   bash bandit.sh
# Spill:  cd ~/bandit/niva0 ; cat README.txt   ... og bruk  bash ~/bandit/apne.sh
set -e
B="$HOME/bandit"
rm -rf "$B"
mkdir -p "$B/.laast"
STAG="$(mktemp -d)"
CAND="$(mktemp)"
trap 'rm -rf "$STAG" "$CAND"' EXIT

# --- lag tilfeldige passord (P1..P12) ---
pw() { tr -dc 'a-zA-Z0-9' </dev/urandom | head -c 16; }
declare -a P
for i in 1 2 3 4 5 6 7 8 9 10 12; do P[$i]="$(pw)"; done

# --- nivaa 11: SVAKT passord valgt tilfeldig fra rockyou-topp (eller reserve) ---
# Bruker ekte rockyou-topp 500 hvis den finnes paa maskinen (Kali).
ROCKYOU=""
for r in /usr/share/wordlists/rockyou.txt /usr/share/wordlists/rockyou.txt.gz; do
  [ -f "$r" ] && ROCKYOU="$r" && break
done
if [ -n "$ROCKYOU" ]; then
  case "$ROCKYOU" in
    *.gz) zcat "$ROCKYOU" ;;
    *)    cat  "$ROCKYOU" ;;
  esac | grep -aE '^[A-Za-z0-9]{4,16}$' | head -500 > "$CAND"
fi
# reserve hvis rockyou mangler eller ga for faa brukbare linjer
if [ "$(wc -l < "$CAND")" -lt 50 ]; then
cat > "$CAND" <<'ORD'
123456
12345
123456789
password
iloveyou
princess
1234567
rockyou
12345678
abc123
nicole
daniel
babygirl
monkey
lovely
jessica
654321
michael
ashley
qwerty
111111
iloveu
michelle
tigger
sunshine
chocolate
password1
soccer
anthony
friends
butterfly
purple
angel
jordan
liverpool
justin
loveme
123123
football
secret
andrea
carlos
jennifer
joshua
bubbles
1234567890
superman
hannah
amanda
loveyou
pretty
basketball
andrew
angels
tweety
flower
playboy
hello
elizabeth
hottie
tinkerbell
charlie
samantha
barbie
chelsea
lovers
teamo
jasmine
brandon
666666
shadow
melissa
eminem
matthew
robert
danielle
forever
family
jonathan
computer
whatever
dragon
vanessa
cookie
naruto
summer
sweety
spongebob
joseph
junior
softball
taylor
yellow
daniela
lauren
mickey
princesa
alexandra
alexis
jesus
estrella
miguel
william
thomas
gabriel
sophie
peanut
bailey
cheese
snoopy
qwertyuiop
hunter
martin
startrek
passw0rd
gokstad
sandefjord
stavanger
ORD
fi

P[11]="$(shuf -n1 "$CAND")"

mkdir -p "$STAG"/niva{0,1,2,3,4,5,6,7,8,9,10,11,12}
# marker saa apne.sh kan se at dekryptering lyktes
for i in 0 1 2 3 4 5 6 7 8 9 10 11 12; do echo "niva$i" > "$STAG/niva$i/.ok"; done

# =====================================================================
# niva0  (aapent):  cat        -> P1
# =====================================================================
cat > "$STAG/niva0/README.txt" <<EOF
BANDIT-JAKT - nivaa 0
=====================
Velkommen. Det er tretten nivaa (0 til 12). Nivaa 0 til 8 er for alle.
Nivaa 9 til 12 er ekstra andreaars-nivaa, for de raske.
Paa hvert nivaa finner du et passord. Passordet laaser opp neste nivaa.
Slik gaar du videre:

  1. Finn passordet paa nivaaet du staar paa.
  2. Kjoer:   bash ~/bandit/apne.sh
  3. Skriv inn passordet. Da aapnes neste nivaa i ~/bandit/nivaN/.

Hvert nivaa laerer deg en Linux-ferdighet. README paa nivaaet sier hvilken.

Du klarte nivaa 0 ved aa lese denne fila med cat.
Passord til nivaa 1:  ${P[1]}
EOF

# =====================================================================
# niva1:  ls -a (skjult fil)   -> P2
# =====================================================================
cat > "$STAG/niva1/README.txt" <<'EOF'
NIVAA 1 - skjulte filer
=======================
Passordet til neste nivaa ligger i en SKJULT fil i denne mappen.
Filer som starter med punktum vises ikke med vanlig ls. Bruk  ls -a
Les deretter den skjulte fila.
EOF
echo "Passord til nivaa 2:  ${P[2]}" > "$STAG/niva1/.passord"

# =====================================================================
# niva2:  grep (logg)          -> P3
# =====================================================================
cat > "$STAG/niva2/README.txt" <<'EOF'
NIVAA 2 - let i loggen med grep
===============================
Passordet staar paa EN linje i system.log, merket med PASSORD=.
Fila har over 2000 linjer. Bla ikke - bruk  grep "PASSORD=" system.log
EOF
{
  for i in $(seq 1 1500); do echo "okt 08 10:$((RANDOM%60)):$((RANDOM%60)) srv tjeneste[$RANDOM]: rutine ok"; done
  echo "okt 08 02:17:44 srv auth: PASSORD=${P[3]}"
  for i in $(seq 1 600); do echo "okt 08 11:$((RANDOM%60)):$((RANDOM%60)) srv tjeneste[$RANDOM]: rutine ok"; done
} > "$STAG/niva2/system.log"

# =====================================================================
# niva3:  find (.conf)         -> P4
# =====================================================================
cat > "$STAG/niva3/README.txt" <<'EOF'
NIVAA 3 - finn fila med find
============================
Under mappen data/ ligger mange filer. Nesten alle er stoey.
Noeyaktig EN fil slutter paa .conf. Passordet staar i den.
Bruk  find data -name "*.conf"  og les fila den finner.
EOF
mkdir -p "$STAG/niva3/data/a/b" "$STAG/niva3/data/c"
for d in data data/a data/a/b data/c; do
  for n in 1 2 3 4 5; do echo "stoey" > "$STAG/niva3/$d/fil_$RANDOM.txt"; done
done
echo "Passord til nivaa 4:  ${P[4]}" > "$STAG/niva3/data/a/b/drift.conf"

# =====================================================================
# niva4:  tail (slutten)       -> P5
# =====================================================================
cat > "$STAG/niva4/README.txt" <<'EOF'
NIVAA 4 - siste linje med tail
==============================
Passordet staar paa den ALLER SISTE linjen i lang.txt (600 linjer).
Bruk  tail lang.txt
EOF
{ for i in $(seq 1 599); do echo "linje $i - ikke her"; done; echo "Passord til nivaa 5:  ${P[5]}"; } > "$STAG/niva4/lang.txt"

# =====================================================================
# niva5:  base64 -d            -> P6
# =====================================================================
cat > "$STAG/niva5/README.txt" <<'EOF'
NIVAA 5 - avkod base64
======================
kodet.txt er ikke kryptert, bare kodet med base64. Hvem som helst kan avkode.
Bruk  base64 -d kodet.txt
EOF
echo "Passord til nivaa 6:  ${P[6]}" | base64 > "$STAG/niva5/kodet.txt"

# =====================================================================
# niva6:  chmod (rettigheter)  -> P7
# =====================================================================
cat > "$STAG/niva6/README.txt" <<'EOF'
NIVAA 6 - rettigheter med chmod
===============================
Du har ikke lesetilgang til laast.txt ennaa. Se rettighetene med  ls -l
Du eier fila, saa du kan gi deg selv lesetilgang:  chmod +r laast.txt
Les den deretter.
EOF
echo "Passord til nivaa 7:  ${P[7]}" > "$STAG/niva6/laast.txt"
# Merk: vi laaser IKKE fila her. En 000-fil kan ikke leses av tar for en vanlig
# bruker, saa den ville falt ut av pakken. apne.sh setter 000 etter utpakking.

# =====================================================================
# niva7:  zcat (pakket logg)   -> P8
# =====================================================================
cat > "$STAG/niva7/README.txt" <<'EOF'
NIVAA 7 - pakket fil med zcat
=============================
Logg-arkivet arkiv.log.gz er pakket (gzip). Du trenger ikke pakke det ut paa disk.
Les det direkte med  zcat arkiv.log.gz   (eller  zgrep PASSORD arkiv.log.gz )
EOF
{ for i in $(seq 1 300); do echo "arkivlinje $i"; done; echo "PASSORD=${P[8]}"; } | gzip > "$STAG/niva7/arkiv.log.gz"

# =====================================================================
# niva8:  sort | uniq -u       -> P9
# =====================================================================
cat > "$STAG/niva8/README.txt" <<'EOF'
NIVAA 8 - den unike linjen (sort og uniq)
=========================================
I linjer.txt staar hver linje to ganger - bortsett fra EN som staar bare en gang.
Den ene unike linjen er passordet.
Bruk  sort linjer.txt | uniq -u
EOF
{
  for i in $(seq 1 200); do echo "duplikatlinje-$i"; echo "duplikatlinje-$i"; done
  echo "PASSORD=${P[9]}"
} > "$STAG/niva8/linjer.txt.tmp"
# bland linjene saa den unike ikke bare ligger sist
shuf "$STAG/niva8/linjer.txt.tmp" > "$STAG/niva8/linjer.txt"
rm "$STAG/niva8/linjer.txt.tmp"

# =====================================================================
# niva9:  ps (prosess)         -> P10     ANDREAARS
# Passordet ligger IKKE i en fil, men i en prosess som startes ved oppsett.
# =====================================================================
cat > "$STAG/niva9/README.txt" <<'EOF'
NIVAA 9 - prosesser med ps  (andreaars)
=======================================
Fra her er det andreaars-nivaa. Samme verktoey, litt tyngre bruk.

Passordet til neste nivaa ligger IKKE i en fil. Det ligger i en PROSESS som
kjoerer akkurat naa. ps aux lister alle prosesser med hele kommandolinjen.
Finn prosessen som heter bandit-agent:
   ps aux | grep bandit-agent
Passordet staar som en del av kommandolinjen.
EOF

# =====================================================================
# niva10: john (knekk hash)    -> P11 (svakt passord i ordliste)   ANDREAARS
# =====================================================================
cat > "$STAG/niva10/README.txt" <<'EOF'
NIVAA 10 - knekk hashen med john  (andreaars)
=============================================
I hash.txt ligger et passord lagret som en hash (sha512crypt). Du kan ikke lese
det direkte. Men passordet er svakt og staar et sted i ordliste.txt. Knekk det:
   john --wordlist=ordliste.txt hash.txt
   john --show hash.txt
Det knekte passordet aapner neste nivaa.
EOF
# tilfeldig salt (ikke fast), saa hashen ser ulik ut paa hver maskin
HASH="$(openssl passwd -6 "${P[11]}")"
echo "drift:${HASH}" > "$STAG/niva10/hash.txt"
# ordlista studenten knekker mot = kandidatlista (inneholder det valgte passordet)
cp "$CAND" "$STAG/niva10/ordliste.txt"

# =====================================================================
# niva11: sudo (root sin fil)  -> P12     ANDREAARS
# Passordet legges i /root ved oppsett hvis sudo er tilgjengelig.
# =====================================================================
cat > "$STAG/niva11/README.txt" <<'EOF'
NIVAA 11 - bare root, med sudo  (andreaars)
===========================================
Det siste passordet ligger i /root/niva12_passord.txt. Bare root kan lese den.
Hvis brukeren din har sudo, leser du den med:
   sudo cat /root/niva12_passord.txt
(Hvis sudo spoer om et passord du ikke har, si fra til veileder. Da stopper
kjeden her paa denne maskinen, og du har uansett fullfoert det meste.)
EOF

# =====================================================================
# niva12: ferdig
# =====================================================================
cat > "$STAG/niva12/README.txt" <<'EOF'
NIVAA 12 - FERDIG
=================
Gratulerer! Du loeste hele kjeden, inkludert andreaars-nivaaene:
cat, ls -a, grep, find, tail, base64, chmod, zcat, sort|uniq, ps, john og sudo.

Fullfoeringsflagg (skriv det paa tavla):  GA{bandit_mester}
EOF

# =====================================================================
# niva0 aapent, niva1..9 krypteres hver med passordet som aapner det
# =====================================================================
cp -r "$STAG/niva0" "$B/niva0"
for N in 1 2 3 4 5 6 7 8 9 10 11 12; do
  tar -czf - -C "$STAG" "niva$N" \
    | openssl enc -aes-256-cbc -pbkdf2 -md sha256 -salt -k "${P[$N]}" \
      -out "$B/.laast/niva$N.enc"
done

# --- andreaars nivaa 9: start ps-prosessen som baerer passordet (P10) ---
pkill -f "bandit-agent" 2>/dev/null || true
setsid bash -c "exec -a 'bandit-agent ${P[10]}' sleep 999999" >/dev/null 2>&1 &
disown 2>/dev/null || true

# --- andreaars nivaa 11: legg P12 i root sin fil hvis sudo er tilgjengelig ---
if sudo -n true 2>/dev/null; then
  echo "Passord til nivaa 12:  ${P[12]}" | sudo tee /root/niva12_passord.txt >/dev/null
  sudo chmod 600 /root/niva12_passord.txt
  SUDO_MERK="andreaars nivaa 11 (sudo) er klart"
else
  SUDO_MERK="MERK: sudo uten passord ikke tilgjengelig - nivaa 11 (sudo) kan ikke fullfoeres paa denne maskinen"
fi

# =====================================================================
# apne.sh  -  laaser opp neste nivaa
# =====================================================================
cat > "$B/apne.sh" <<'GATE'
#!/bin/bash
# apne.sh - laaser opp neste nivaa med passordet du fant.
BASE="$(cd "$(dirname "$0")" && pwd)"
# finn hoeyeste aapnede nivaa
cur=-1
for d in "$BASE"/niva*; do
  [ -d "$d" ] || continue
  n="${d##*/niva}"; [ "$n" -gt "$cur" ] 2>/dev/null && cur="$n"
done
next=$((cur+1))
enc="$BASE/.laast/niva$next.enc"
if [ ! -f "$enc" ]; then
  echo "Du har aapnet alle nivaaene. Bra jobba!"; exit 0
fi
echo "Du skal aapne nivaa $next."
read -r -p "Passord: " pw
tmp="$(mktemp -d)"
if openssl enc -d -aes-256-cbc -pbkdf2 -md sha256 -k "$pw" -in "$enc" 2>/dev/null \
     | tar -xzf - -C "$tmp" 2>/dev/null && [ "$(cat "$tmp/niva$next/.ok" 2>/dev/null)" = "niva$next" ]; then
  rm -rf "$BASE/niva$next"
  mv "$tmp/niva$next" "$BASE/niva$next"
  rm -rf "$tmp"
  # nivaa 6: laas laast.txt saa studenten maa bruke chmod for aa lese den
  [ -f "$BASE/niva$next/laast.txt" ] && chmod 000 "$BASE/niva$next/laast.txt" 2>/dev/null
  echo
  echo "Riktig! Nivaa $next er aapnet."
  echo "Gaa dit:   cd ~/bandit/niva$next   og les README.txt"
else
  rm -rf "$tmp"
  echo
  echo "Feil passord. Proev igjen naar du har funnet det riktige."
  exit 1
fi
GATE
chmod +x "$B/apne.sh"

echo
echo "Bandit-jakt klar. Alt ligger i:  $B"
echo "Start slik:"
echo "   cd ~/bandit/niva0"
echo "   cat README.txt"
echo "Naar du har et passord:   bash ~/bandit/apne.sh"
echo "$SUDO_MERK"
