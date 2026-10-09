#!/bin/bash
# bandit.sh  -  bygger en lokal Bandit-stil CTF paa en Kali.
# 26 nivaa (0-25). Hvert nivaa har ET fast flagg (GA{...}) du samler paa,
# OG et eget tilfeldig passord som laaser opp neste nivaa (ekte kryptering
# med openssl). Passordene er TILFELDIGE per maskin, saa ingen kan rope ut
# svaret. Hvert nivaa krever minst to kommandoer for aa finne svaret.
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

NIVA_MAX=25

# --- faste flagg (like paa alle maskiner, til aa samle paa) ---
declare -A FLAG
FLAG[0]="GA{forste_steg}"
FLAG[1]="GA{skjult_og_kodet}"
FLAG[2]="GA{grep_sa_avkod}"
FLAG[3]="GA{find_fant_det}"
FLAG[4]="GA{rett_linje}"
FLAG[5]="GA{bakvendt}"
FLAG[6]="GA{apnet_selv}"
FLAG[7]="GA{pakket_og_sokt}"
FLAG[8]="GA{den_unike}"
FLAG[9]="GA{forskjellen}"
FLAG[10]="GA{rotert}"
FLAG[11]="GA{hex_tilbake}"
FLAG[12]="GA{strenger}"
FLAG[13]="GA{i_minnet}"
FLAG[14]="GA{etterlatt_spor}"
FLAG[15]="GA{stakk_seg_ut}"
FLAG[16]="GA{ikke_base64}"
FLAG[17]="GA{hash_knekt}"
FLAG[18]="GA{zip_apnet}"
FLAG[19]="GA{riktig_type}"
FLAG[20]="GA{dekryptert}"
FLAG[21]="GA{bak_bildet}"
FLAG[22]="GA{grav_dypt}"
FLAG[23]="GA{rett_kolonne}"
FLAG[24]="GA{root_tilgang}"
FLAG[25]="GA{bandit_mester}"

# --- tilfeldige passord P1..P25 ---
pw() { tr -dc 'a-zA-Z0-9' </dev/urandom | head -c 16; }
declare -a P
for i in $(seq 1 "$NIVA_MAX"); do P[$i]="$(pw)"; done

# --- svak-passord-liste (rockyou-topp hvis finnes, ellers reserve) ---
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
if [ "$(wc -l < "$CAND")" -lt 50 ]; then
cat > "$CAND" <<'ORD'
123456
password
iloveyou
princess
rockyou
abc123
nicole
daniel
babygirl
monkey
jessica
michael
ashley
qwerty
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
football
secret
andrea
carlos
jennifer
joshua
bubbles
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
jasmine
brandon
shadow
melissa
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
spongebob
joseph
junior
softball
taylor
yellow
daniela
lauren
mickey
alexandra
alexis
jesus
miguel
william
thomas
sophie
peanut
bailey
cheese
snoopy
hunter
martin
startrek
passw0rd
gokstad
sandefjord
stavanger
ORD
fi

# --- svake ord til knekk-nivaaene (garantert i ordlista), alle forskjellige ---
# Disse er KEYS som knekkes, ikke passordene videre. Passordene videre (P18,P20)
# er tilfeldige og ligger kryptert i flagg.enc paa nivaaet.
CRACK17="$(shuf -n1 "$CAND")"                                          # niva17 -> sha512crypt
while :; do CRACK19="$(shuf -n1 "$CAND")"; [ "$CRACK19" != "$CRACK17" ] && break; done  # niva19 -> md5
while :; do ZIPPW="$(shuf -n1 "$CAND")"; [ "$ZIPPW" != "$CRACK17" ] && [ "$ZIPPW" != "$CRACK19" ] && break; done  # niva18 -> zip

# b64 uten linjeskift (portabelt)
b64() { base64 | tr -d '\n'; }
b32() { base32 | tr -d '\n'; }

mkdir -p "$STAG"
for i in $(seq 0 "$NIVA_MAX"); do mkdir -p "$STAG/niva$i"; echo "niva$i" > "$STAG/niva$i/.ok"; done

# reveal-linjer: flagg + passord til neste nivaa
reveal() {  # $1 = nivaa N -> skriver to linjer
  echo "Flagg: ${FLAG[$1]}"
  echo "Passord til nivaa $(( $1 + 1 )):  ${P[$(( $1 + 1 ))]}"
}

# =====================================================================
# niva0  (aapent):  cat + cat
# =====================================================================
cat > "$STAG/niva0/README.txt" <<'EOF'
BANDIT-CTF - nivaa 0
====================
Velkommen. Det er 26 nivaa (0 til 25). Nivaa 0 til 11 er for alle.
Nivaa 12 til 24 er ekstra andreaars-nivaa for de raske. Nivaa 25 er maal.

Paa hvert nivaa finner du to ting:
  - ET FLAGG paa formen  GA{...}   (samle dem, de er like for alle)
  - ET PASSORD til neste nivaa     (tilfeldig paa din maskin)

Slik gaar du videre:
  1. Loes nivaaet (hvert nivaa trenger minst to kommandoer).
  2. Kjoer:   bash ~/bandit/apne.sh
  3. Skriv inn passordet. Da aapnes neste nivaa i ~/bandit/nivaN/.

README paa hvert nivaa sier HVA du skal finne og gir deg et lite hint.
Selve kommandoene maa du finne ut av selv - det er de samme du oevde paa i
oppvarmingen. Kommer du helt fast, spoer veileder.

Flagget og passordet til nivaa 1 ligger i en annen fil i denne mappa.
Se deg om, og les den.
EOF
{ echo "Hei og velkommen til CTF-en."; echo "Les rolig, ta en kommando om gangen."; echo; reveal 0; } > "$STAG/niva0/velkomst.txt"

# =====================================================================
# niva1:  ls -a + base64 -d
# =====================================================================
cat > "$STAG/niva1/README.txt" <<'EOF'
NIVAA 1 - skjult og kodet
=========================
Svaret ligger gjemt, og det er i tillegg kodet (ikke kryptert).
Hint: en fil her vises ikke i en vanlig listing. Og det du finner i den,
maa avkodes foer det gir mening.
EOF
reveal 1 | b64 > "$STAG/niva1/.skjult"

# =====================================================================
# niva2:  grep + base64 -d
# =====================================================================
cat > "$STAG/niva2/README.txt" <<'EOF'
NIVAA 2 - grep saa avkod
========================
system.log har over 2000 linjer. EN linje er merket KODET= og baerer svaret,
men ikke i klartekst.
Hint: finn den ene linja uten aa bla, og avkod det den inneholder.
EOF
{
  for i in $(seq 1 1500); do echo "okt 08 10:$((RANDOM%60)):$((RANDOM%60)) srv tjeneste[$RANDOM]: rutine ok"; done
  echo "okt 08 02:17:44 srv auth: KODET=$(reveal 2 | b64)"
  for i in $(seq 1 600); do echo "okt 08 11:$((RANDOM%60)):$((RANDOM%60)) srv tjeneste[$RANDOM]: rutine ok"; done
} > "$STAG/niva2/system.log"

# =====================================================================
# niva3:  find + cat
# =====================================================================
cat > "$STAG/niva3/README.txt" <<'EOF'
NIVAA 3 - finn og les
=====================
Under data/ ligger mange filer, men bare EN er interessant.
Hint: den har en annen filtype enn stoeyen rundt (.conf). Let deg fram til den,
og les den.
EOF
mkdir -p "$STAG/niva3/data/a/b" "$STAG/niva3/data/c/d"
for d in data data/a data/a/b data/c data/c/d; do
  for n in 1 2 3 4 5; do echo "stoey" > "$STAG/niva3/$d/fil_$RANDOM.txt"; done
done
reveal 3 > "$STAG/niva3/data/a/b/drift.conf"

# =====================================================================
# niva4:  head + tail (to bestemte linjer)
# =====================================================================
cat > "$STAG/niva4/README.txt" <<'EOF'
NIVAA 4 - rett linje
====================
lang.txt har 800 linjer. Flagget staar paa linje 300, passordet paa linje 650.
Hint: du trenger ikke hele fila. Hent ut noeyaktig de to linjene (tenk head
og tail sammen).
EOF
{
  for i in $(seq 1 299); do echo "linje $i - ikke her"; done
  echo "Flagg: ${FLAG[4]}"
  for i in $(seq 301 649); do echo "linje $i - ikke her"; done
  echo "Passord til nivaa 5:  ${P[5]}"
  for i in $(seq 651 800); do echo "linje $i - ikke her"; done
} > "$STAG/niva4/lang.txt"

# =====================================================================
# niva5:  rev + base64 -d
# =====================================================================
cat > "$STAG/niva5/README.txt" <<'EOF'
NIVAA 5 - bakvendt
==================
kodet.txt er behandlet paa to maater. Du maa angre begge, i riktig rekkefoelge.
Hint: teksten ser ut som koding, men den leses ikke venstre mot hoyre. Snu
foerst, avkod saa.
EOF
reveal 5 | b64 | rev > "$STAG/niva5/kodet.txt"

# =====================================================================
# niva6:  chmod + cat   (laases i apne.sh etter utpakking)
# =====================================================================
cat > "$STAG/niva6/README.txt" <<'EOF'
NIVAA 6 - aapne selv
====================
laast.txt inneholder svaret, men du faar "Permission denied".
Hint: se paa rettighetene. Du eier fila, saa du har lov til aa endre dem.
EOF
reveal 6 > "$STAG/niva6/laast.txt"

# =====================================================================
# niva7:  zcat + grep
# =====================================================================
cat > "$STAG/niva7/README.txt" <<'EOF'
NIVAA 7 - pakket og soekt
=========================
arkiv.log.gz er pakket (gzip). Svaret ligger inni, blant 300 linjer.
Hint: du kan lese en .gz uten aa pakke den ut paa disk, og soeke rett i den.
EOF
{ for i in $(seq 1 300); do echo "arkivlinje $i rutine ok"; done; reveal 7; } | gzip > "$STAG/niva7/arkiv.log.gz"

# =====================================================================
# niva8:  sort | uniq -u + base64 -d
# =====================================================================
cat > "$STAG/niva8/README.txt" <<'EOF'
NIVAA 8 - den unike
===================
I linjer.txt staar hver linje to ganger - bortsett fra EN. Den ene baerer svaret,
men det er kodet.
Hint: faa fram linja som er alene, og avkod den.
EOF
{
  for i in $(seq 1 200); do echo "duplikatlinje-$i"; echo "duplikatlinje-$i"; done
  reveal 8 | b64
} | shuf > "$STAG/niva8/linjer.txt"

# =====================================================================
# niva9:  diff + base64 -d
# =====================================================================
cat > "$STAG/niva9/README.txt" <<'EOF'
NIVAA 9 - forskjellen
=====================
a.txt og b.txt er nesten like. Noeyaktig EN linje skiller dem, og den er kodet.
Hint: sammenlign de to filene, og avkod forskjellen.
EOF
for i in $(seq 1 400); do echo "felles linje $i"; done > "$STAG/niva9/a.txt"
cp "$STAG/niva9/a.txt" "$STAG/niva9/b.txt"
# bytt ut linje 200 i b.txt med base64 av reveal
DIFFB64="$(reveal 9 | b64)"
awk -v r="$DIFFB64" 'NR==200{print r; next} {print}' "$STAG/niva9/a.txt" > "$STAG/niva9/b.txt"

# =====================================================================
# niva10:  tr (ROT13)
# =====================================================================
cat > "$STAG/niva10/README.txt" <<'EOF'
NIVAA 10 - rotert
=================
rot13.txt ser ut som vroevl. Det er vanlig tekst, men hver bokstav er flyttet
et fast antall plasser.
Hint: det er den klassiske rotasjonen paa 13 plasser. Samme operasjon ruller
den tilbake.
EOF
reveal 10 | tr 'A-Za-z' 'N-ZA-Mn-za-m' > "$STAG/niva10/rot13.txt"

# =====================================================================
# niva11:  xxd + base64 -d
# =====================================================================
cat > "$STAG/niva11/README.txt" <<'EOF'
NIVAA 11 - hex tilbake
======================
hex.txt er bare tegnene 0-9 og a-f. Det er data skrevet som hex.
Hint: gjoer hexen om til tekst. Da sitter du igjen med noe som fortsatt maa
avkodes et hakk til.
EOF
reveal 11 | b64 | xxd -p > "$STAG/niva11/hex.txt"

# =====================================================================
# niva12:  strings + grep   (ANDREAARS)
# =====================================================================
cat > "$STAG/niva12/README.txt" <<'EOF'
NIVAA 12 - strenger i stoey  (andreaars)
========================================
Fra her er det andreaars-nivaa. stoey.bin ser ut som soepel, men det ligger
lesbar tekst inni.
Hint: det finnes et verktoey som plukker ut lesbare strenger fra en binaerfil.
EOF
{ head -c 1500 /dev/urandom; echo; reveal 12; head -c 1500 /dev/urandom; echo; } > "$STAG/niva12/stoey.bin"

# =====================================================================
# niva13:  ps + grep   (ANDREAARS) - svaret ligger i en prosess
# =====================================================================
cat > "$STAG/niva13/README.txt" <<'EOF'
NIVAA 13 - i minnet  (andreaars)
================================
Svaret ligger IKKE i en fil. Det ligger i noe som kjoerer akkurat naa.
Hint: en prosess ved navn bandit-agent baerer flagg= og passord= i
kommandolinja. List prosessene i full bredde (ellers avkortes linja), og
ignorer tallet 999999 bakerst.
EOF

# =====================================================================
# niva14:  ls -a + grep   (ANDREAARS) - spor i en historikkfil
# =====================================================================
cat > "$STAG/niva14/README.txt" <<'EOF'
NIVAA 14 - etterlatt spor  (andreaars)
======================================
En bruker har vaert her og lagt igjen spor.
Hint: historikken ligger i en skjult fil. Finn den, og grav ut linjene som
betyr noe.
EOF
{
  echo "cd /var/www"
  echo "ls -la"
  echo "sudo systemctl status nginx"
  echo "vim config.php"
  echo "echo 'Flagg: ${FLAG[14]}'"
  echo "echo 'Passord til nivaa 15:  ${P[15]}'"
  echo "history -c"
} > "$STAG/niva14/.kommandohistorikk"

# =====================================================================
# niva15:  find -size + cat   (ANDREAARS) - fila som stikker seg ut
# =====================================================================
cat > "$STAG/niva15/README.txt" <<'EOF'
NIVAA 15 - stakk seg ut  (andreaars)
====================================
I lager/ ligger mange smaa filer og EN som ikke ligner de andre.
Hint: den skiller seg ut paa stoerrelse (den er stor). Let etter den, og les den.
EOF
mkdir -p "$STAG/niva15/lager/arkiv" "$STAG/niva15/lager/temp"
for d in lager lager/arkiv lager/temp; do
  for n in 1 2 3 4 5 6; do echo "liten loggfil uten noe spennende" > "$STAG/niva15/$d/logg_$RANDOM.txt"; done
done
{ reveal 15; head -c 11000 /dev/zero | tr '\0' 'x'; } > "$STAG/niva15/lager/arkiv/stor_dump.txt"

# =====================================================================
# niva16:  base32   (ANDREAARS)
# =====================================================================
cat > "$STAG/niva16/README.txt" <<'EOF'
NIVAA 16 - ikke base64  (andreaars)
===================================
kodet.txt ser ut som base64, men proever du aa avkode det slik blir det feil.
Hint: tegnsettet er bare store bokstaver og tallene 2-7. Det peker mot en
beslektet, men annen, koding.
EOF
reveal 16 | b32 > "$STAG/niva16/kodet.txt"

# =====================================================================
# niva17:  john sha512crypt   (ANDREAARS)
# =====================================================================
cat > "$STAG/niva17/README.txt" <<'EOF'
NIVAA 17 - knekk hashen  (andreaars)
====================================
hash.txt er et passord lagret som sha512crypt. Det er svakt og staar i
ordliste.txt. Flagget og passordet til neste nivaa ligger kryptert i flagg.enc,
laast med det samme ordet.
Hint: knekk hashen mot ordlista, og bruk ordet til aa dekryptere flagg.enc
(openssl, aes-256-cbc).
EOF
HASH17="$(openssl passwd -6 "$CRACK17")"
echo "drift:${HASH17}" > "$STAG/niva17/hash.txt"
cp "$CAND" "$STAG/niva17/ordliste.txt"
reveal 17 | openssl enc -aes-256-cbc -pbkdf2 -md sha256 -salt -k "$CRACK17" -out "$STAG/niva17/flagg.enc"

# =====================================================================
# niva18:  zip2john + john + unzip   (ANDREAARS)
# =====================================================================
cat > "$STAG/niva18/README.txt" <<EOF
NIVAA 18 - knekk zip-en  (andreaars)
====================================
hemmelig.zip er passordbeskyttet, og passordet er svakt (staar i ordliste.txt).
Hint: en zip har sin egen hash du kan trekke ut og knekke mot ordlista. Naar du
har passordet, pakker du ut og leser fila som laa inni. Der er flagget og
passordet til neste nivaa.
EOF
ZTMP="$(mktemp -d)"
reveal 18 > "$ZTMP/inni.txt"
( cd "$ZTMP" && zip -q -P "$ZIPPW" hemmelig.zip inni.txt )
cp "$ZTMP/hemmelig.zip" "$STAG/niva18/hemmelig.zip"
cp "$CAND" "$STAG/niva18/ordliste.txt"
rm -rf "$ZTMP"

# =====================================================================
# niva19:  gjenkjenn hashtype + john (raw-md5)   (ANDREAARS)
# =====================================================================
cat > "$STAG/niva19/README.txt" <<'EOF'
NIVAA 19 - riktig type  (andreaars)
===================================
hash.txt inneholder EN hash. Hvilken type avsloerer lengden og tegnene.
Flagget og passordet til neste nivaa ligger kryptert i flagg.enc, laast med
det knekte ordet.
Hint: 32 tegn hex peker en vei. Si fra til knekke-verktoeyet hvilket format
det er, og bruk ordet til aa dekryptere flagg.enc. hashid kan foreslaa typen.
EOF
MD5_19="$(printf '%s' "$CRACK19" | openssl dgst -md5 -r | cut -d' ' -f1)"
echo "$MD5_19" > "$STAG/niva19/hash.txt"
cp "$CAND" "$STAG/niva19/ordliste.txt"
reveal 19 | openssl enc -aes-256-cbc -pbkdf2 -md sha256 -salt -k "$CRACK19" -out "$STAG/niva19/flagg.enc"

# =====================================================================
# niva20:  base64 -d + openssl enc -d   (ANDREAARS)
# =====================================================================
cat > "$STAG/niva20/README.txt" <<'EOF'
NIVAA 20 - dekryptert  (andreaars)
==================================
blob.enc er kryptert med openssl (aes-256-cbc). Noekkelen ligger kodet i hint.txt.
Hint: avkod hint.txt foerst for aa faa noekkelen. Bruk den saa som -k naar du
dekrypterer blob.enc med openssl enc -d (samme cipher, med -pbkdf2 og -md sha256).
EOF
KEY20="$(pw)"
printf '%s' "$KEY20" | b64 > "$STAG/niva20/hint.txt"
reveal 20 | openssl enc -aes-256-cbc -pbkdf2 -md sha256 -salt -k "$KEY20" -out "$STAG/niva20/blob.enc"

# =====================================================================
# niva21:  strings/tail -c   (ANDREAARS) - data bak et bilde
# =====================================================================
cat > "$STAG/niva21/README.txt" <<'EOF'
NIVAA 21 - bak bildet  (andreaars)
==================================
bilde.png ser ut som et bilde, men noen har limt tekst BAK bildedataene.
Hint: den lesbare teksten ligger paa slutten av fila. Plukk den ut (tenk
strenger i fila, eller de siste bytene).
EOF
# minimal PNG-signatur + litt bilde-stoey, saa reveal limt bak
printf '\x89PNG\r\n\x1a\n' > "$STAG/niva21/bilde.png"
head -c 800 /dev/urandom >> "$STAG/niva21/bilde.png"
printf '\n' >> "$STAG/niva21/bilde.png"
reveal 21 >> "$STAG/niva21/bilde.png"

# =====================================================================
# niva22:  grep -r + cut   (ANDREAARS)
# =====================================================================
cat > "$STAG/niva22/README.txt" <<'EOF'
NIVAA 22 - grav dypt  (andreaars)
=================================
Et helt mappetre med filer. Flagget staar i en av dem, passordet i en annen.
Hint: soek rekursivt etter flagget. Passordet staar i en kolon-delt linje
(feltet merket "rolle:") - klipp ut rett felt. Faar du filnavnet limt foran
treffet, roter det kolonne-tellingen.
EOF
mkdir -p "$STAG/niva22/prosjekt/src/util" "$STAG/niva22/prosjekt/doc" "$STAG/niva22/prosjekt/conf"
for d in prosjekt prosjekt/src prosjekt/src/util prosjekt/doc prosjekt/conf; do
  for n in 1 2 3; do echo "vanlig innhold uten noe spennende" > "$STAG/niva22/$d/notat_$RANDOM.txt"; done
done
echo "Flagg: ${FLAG[22]}" > "$STAG/niva22/prosjekt/src/util/hjelp.txt"
echo "rolle:drift:gruppe:${P[23]}:slutt" > "$STAG/niva22/prosjekt/conf/tilgang.cfg"

# =====================================================================
# niva23:  cut/awk paa passwd-lignende fil   (ANDREAARS)
# =====================================================================
cat > "$STAG/niva23/README.txt" <<'EOF'
NIVAA 23 - rett kolonne  (andreaars)
====================================
brukere.txt er paa /etc/passwd-format (felt delt med kolon). Alt du trenger
staar paa linja til brukeren "drift".
Hint: flagget ligger i ett felt, passordet i et annet. Klipp ut rett kolonne
(tenk felt 5 og 7).
EOF
{
  echo "root:x:0:0:root:/root:/bin/bash"
  echo "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"
  echo "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin"
  echo "drift:x:1001:1001:${FLAG[23]}:/home/drift:${P[24]}"
  echo "backup:x:34:34:backup:/var/backups:/usr/sbin/nologin"
} > "$STAG/niva23/brukere.txt"

# =====================================================================
# niva24:  sudo (root sin fil)   (ANDREAARS)
# =====================================================================
cat > "$STAG/niva24/README.txt" <<'EOF'
NIVAA 24 - root-tilgang  (andreaars)
====================================
Det siste passordet ligger i /root/niva25_passord.txt. Bare root kan lese den.
Hint: har brukeren din sudo, kan du lese root sine filer.
(Hvis sudo spoer om et passord du ikke har, si fra til veileder.)
EOF

# =====================================================================
# niva25: FERDIG
# =====================================================================
cat > "$STAG/niva25/README.txt" <<EOF
NIVAA 25 - FERDIG
=================
Gratulerer! Du loeste hele kjeden, inkludert andreaars-nivaaene:
cat, ls -a, grep, find, tail, base64, rev, tr, xxd, chmod, zcat, sort|uniq,
diff, strings, ps, base32, john, zip2john, openssl og sudo.

Fullfoeringsflagg:  ${FLAG[25]}
EOF

# =====================================================================
# niva0 aapent, niva1..25 krypteres hver med passordet som aapner det
# =====================================================================
cp -r "$STAG/niva0" "$B/niva0"
for N in $(seq 1 "$NIVA_MAX"); do
  tar -czf - -C "$STAG" "niva$N" \
    | openssl enc -aes-256-cbc -pbkdf2 -md sha256 -salt -k "${P[$N]}" \
      -out "$B/.laast/niva$N.enc"
done

# --- niva13: start ps-prosessen som baerer flagg + passord (P14) ---
pkill -f "bandit-agent" 2>/dev/null || true
setsid bash -c "exec -a 'bandit-agent flagg=${FLAG[13]} passord=${P[14]}' sleep 999999" >/dev/null 2>&1 &
disown 2>/dev/null || true

# --- niva24: legg flagg + P25 i root sin fil ---
SUDO_MERK=""
if sudo -n true 2>/dev/null; then
  reveal 24 | sudo -n tee /root/niva25_passord.txt >/dev/null 2>&1 \
    && sudo -n chmod 600 /root/niva25_passord.txt 2>/dev/null \
    && SUDO_MERK="andreaars nivaa 24 (sudo) er klart"
else
  echo
  echo ">> Setter opp andreaars-nivaa 24 (sudo). Skriv sudo-passordet ditt hvis du blir bedt om det."
  if reveal 24 | sudo tee /root/niva25_passord.txt >/dev/null 2>&1; then
    sudo chmod 600 /root/niva25_passord.txt 2>/dev/null
    SUDO_MERK="andreaars nivaa 24 (sudo) er klart"
  fi
fi
[ -z "$SUDO_MERK" ] && SUDO_MERK="MERK: fikk ikke satt opp nivaa 24 (ingen sudo). Kjoer fikssiste.sh naar du naar dit: curl -sO https://nocryptoshade.github.io/e3/fikssiste.sh && bash fikssiste.sh"

# =====================================================================
# apne.sh  -  laaser opp neste nivaa
# =====================================================================
cat > "$B/apne.sh" <<'GATE'
#!/bin/bash
# apne.sh - laaser opp neste nivaa med passordet du fant.
BASE="$(cd "$(dirname "$0")" && pwd)"
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
echo "Bandit-CTF klar. Alt ligger i:  $B"
echo "Start slik:"
echo "   cd ~/bandit/niva0"
echo "   cat README.txt"
echo "Naar du har et passord:   bash ~/bandit/apne.sh"
echo "$SUDO_MERK"
