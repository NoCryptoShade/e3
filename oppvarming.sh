#!/bin/bash
# oppvarming.sh  -  liten oevingsmappe for aa repetere Linux-kommandoene
# foer CTF-en. Ingenting er laast eller gjemt - alt er synlig. Hensikten er
# bare aa faa fingrene paa hver kommando en gang.
#
# Kjoeres av hver student paa egen maskin, som vanlig bruker.
#   bash oppvarming.sh
#   cd ~/oppvarming
set -e
O="$HOME/oppvarming"
rm -rf "$O"
mkdir -p "$O/mappe/undermappe"

# cat
echo "Hei! Dette er en helt vanlig tekstfil. cat skriver den ut." > "$O/velkommen.txt"

# ls -a  (skjult fil)
echo "Jeg er en skjult fil. Du ser meg bare med  ls -a" > "$O/.notat"

# grep  (en logg med en linje som skiller seg ut)
{
  for i in $(seq 1 20); do echo "okt 08 10:$((10+i)):00 srv tjeneste: alt ok"; done
  echo "okt 08 10:31:00 srv tjeneste: FEIL - noe gikk galt her"
  for i in $(seq 1 10); do echo "okt 08 10:4$i:00 srv tjeneste: alt ok"; done
} > "$O/sys.log"

# find  (en fil nede i en undermappe)
echo "Du fant meg med find!" > "$O/mappe/undermappe/skjult_fil.txt"

# tail / head  (lang fil)
for i in $(seq 1 100); do echo "linje nummer $i"; done > "$O/lang.txt"

# base64
echo "Dette var kodet med base64." | base64 > "$O/kode.txt"

# chmod  (fil uten lesetilgang - du eier den selv)
echo "Naa fikk du lest meg etter at du ga deg selv tilgang." > "$O/stengt.txt"
chmod 000 "$O/stengt.txt"

# zcat  (pakket fil)
echo "Jeg laa pakket i en .gz-fil, men zcat leser meg direkte." | gzip > "$O/gammel.log.gz"

# sort | uniq  (mange like linjer, noen faa unike)
{
  for i in 1 2 3; do echo "eple"; echo "banan"; echo "paere"; done
  echo "ananas"
} > "$O/frukt.txt"

cat > "$O/START.txt" <<'EOF'
OPPVARMING
==========
Her inne er det ingenting gjemt og ingenting laast for aa lure deg. Dette er
bare en liten oevingsmappe der du faar proeve hver kommando en gang, saa de
sitter i fingrene foer CTF-en.

Foelg oppgavearket, en kommando om gangen. Laereren gaar gjennom paa storskjerm,
du proever paa din egen maskin.
EOF

echo "Oppvarming klar i: $O"
echo "Start med:  cd ~/oppvarming  &&  cat START.txt"
