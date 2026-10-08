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

Hele oppgaven ligger i OPPGAVE.txt. Les den slik:
   cat OPPGAVE.txt
Ta en kommando om gangen. Laereren gaar gjennom paa storskjerm.
EOF

cat > "$O/OPPGAVE.txt" <<'EOF'
=====================================================================
 OPPVARMING - de ni kommandoene du trenger i CTF-en
=====================================================================
Ta en kommando om gangen. Les hva den gjoer, skriv den av, se hva som skjer.


0. FINN DEG TIL RETTE
   Hvor er jeg, og hva ligger her?
      pwd
      ls


1. cat - LES EN FIL
   cat skriver ut hele innholdet i en fil.
      cat velkommen.txt


2. ls -a - SE DE SKJULTE FILENE
   Filer som starter med punktum er skjult for vanlig ls. -a viser alt.
      ls
      ls -a
      cat .notat


3. grep - FINN EN LINJE I MENGDEN
   grep skriver ut bare linjene som inneholder teksten du leter etter.
      grep "FEIL" sys.log


4. find - LET ETTER EN FIL
   find leter gjennom mapper og undermapper. -name soeker paa navn.
      find mappe -name "*.txt"


5. tail og head - SLUTT ELLER START
   tail viser de siste linjene, head de foerste.
      tail lang.txt
      head lang.txt


6. base64 - AVKOD
   base64 er en maate aa skrive om data paa. Ikke kryptering - alle kan avkode.
      cat kode.txt
      base64 -d kode.txt


7. chmod - GI DEG SELV TILGANG
   En fil har rettigheter for hvem som kan lese den. ls -l viser dem,
   chmod endrer dem. Du eier fila, saa du har lov til aa gi deg selv tilgang.
      ls -l stengt.txt
      cat stengt.txt
      chmod +r stengt.txt
      cat stengt.txt


8. zcat - LES EN PAKKET FIL
   zcat leser en .gz-fil direkte, uten aa pakke den ut paa disk.
      zcat gammel.log.gz


9. sort og uniq - RYDD I LINJER
   sort stokker linjene i rekkefoelge saa like havner ved siden av hverandre.
   uniq -c teller, uniq -u viser bare de som finnes en gang.
      sort frukt.txt
      sort frukt.txt | uniq -c
      sort frukt.txt | uniq -u


=====================================================================
 Det var verktoeykassa: cat, ls -a, grep, find, tail, base64, chmod,
 zcat og sort|uniq. Det er noeyaktig det du trenger i CTF-en.
=====================================================================
EOF

echo "Oppvarming klar i: $O"
echo "Start med:  cd ~/oppvarming  &&  cat OPPGAVE.txt"
