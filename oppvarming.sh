#!/bin/bash
# oppvarming.sh  -  liten øvingsmappe for å repetere Linux-kommandoene
# før CTF-en. Ingenting er låst eller gjemt - alt er synlig. Hensikten er
# bare å få fingrene på hver kommando en gang.
#
# Kjøres av hver student på egen maskin, som vanlig bruker.
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

# rev  (tekst skrevet baklengs - ren ASCII, siden rev reverserer byte for byte)
echo "Gratulerer, du leste en baklengs linje med rev." | rev > "$O/reversert.txt"

# tr / ROT13  (hver bokstav flyttet 13 plasser - ren ASCII)
echo "Denne linja var rotert 13 plasser med ROT13." | tr 'A-Za-z' 'N-ZA-Mn-za-m' > "$O/rot13.txt"

# xxd  (ren hex)
echo "Dette lå gjemt som ren hex. xxd -r -p gir deg teksten." | xxd -p > "$O/hex.txt"

# chmod  (fil uten lesetilgang - du eier den selv)
echo "Nå fikk du lest meg etter at du ga deg selv tilgang." > "$O/stengt.txt"
chmod 000 "$O/stengt.txt"

# zcat  (pakket fil)
echo "Jeg lå pakket i en .gz-fil, men zcat leser meg direkte." | gzip > "$O/gammel.log.gz"

# sort | uniq  (mange like linjer, noen få unike)
{
  for i in 1 2 3; do echo "eple"; echo "banan"; echo "pære"; done
  echo "ananas"
} > "$O/frukt.txt"

# diff  (to nesten like filer, en linje skiller)
{ echo "linje en"; echo "linje to"; echo "linje tre"; echo "linje fire"; } > "$O/diff_a.txt"
{ echo "linje en"; echo "linje to"; echo "HER er forskjellen - det er denne diff viser deg"; echo "linje fire"; } > "$O/diff_b.txt"

cat > "$O/START.txt" <<'EOF'
OPPVARMING
==========
Her inne er det ingenting gjemt og ingenting låst for å lure deg. Dette er
bare en liten øvingsmappe der du får prøve hver kommando en gang, så de
sitter i fingrene før CTF-en.

Hele oppgaven ligger i OPPGAVE.txt. Les den slik:
   cat OPPGAVE.txt
Ta en kommando om gangen. Læreren går gjennom på storskjerm.
EOF

cat > "$O/OPPGAVE.txt" <<'EOF'
=====================================================================
 OPPVARMING - kommandoene du trenger i CTF-en
=====================================================================
Ta en kommando om gangen. Les hva den gjør, skriv den av, se hva som skjer.


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
   find leter gjennom mapper og undermapper. -name søker på navn.
      find mappe -name "*.txt"


5. tail og head - SLUTT ELLER START
   tail viser de siste linjene, head de første.
      tail lang.txt
      head lang.txt


6. base64 - AVKOD
   base64 er en måte å skrive om data på. Ikke kryptering - alle kan avkode.
      cat kode.txt
      base64 -d kode.txt


7. rev - LES BAKLENGS
   rev snur hver linje. En baklengs linje blir lesbar igjen.
      cat reversert.txt
      rev reversert.txt


8. tr - ROT13
   tr bytter ut tegn. ROT13 flytter hver bokstav 13 plasser. Kjører du
   ROT13 to ganger er du tilbake til start, så samme kommando avkoder.
      cat rot13.txt
      cat rot13.txt | tr 'A-Za-z' 'N-ZA-Mn-za-m'


9. xxd - HEX
   xxd -p viser data som ren hex. xxd -r -p gjør hex om til tekst igjen.
      cat hex.txt
      xxd -r -p hex.txt


10. chmod - GI DEG SELV TILGANG
   En fil har rettigheter for hvem som kan lese den. ls -l viser dem,
   chmod endrer dem. Du eier fila, så du har lov til å gi deg selv tilgang.
      ls -l stengt.txt
      cat stengt.txt
      chmod +r stengt.txt
      cat stengt.txt


11. zcat - LES EN PAKKET FIL
   zcat leser en .gz-fil direkte, uten å pakke den ut på disk.
      zcat gammel.log.gz


12. sort og uniq - RYDD I LINJER
   sort stokker linjene i rekkefølge så like havner ved siden av hverandre.
   uniq -c teller, uniq -u viser bare de som finnes en gang.
      sort frukt.txt
      sort frukt.txt | uniq -c
      sort frukt.txt | uniq -u


13. diff - FINN FORSKJELLEN
   diff sammenligner to filer og viser bare linjene som er ulike.
      diff diff_a.txt diff_b.txt


=====================================================================
 Det var verktøykassa: cat, ls -a, grep, find, tail, base64, rev, tr,
 xxd, chmod, zcat, sort|uniq og diff. Det er dette du trenger i CTF-en.
=====================================================================
EOF

echo "Oppvarming klar i: $O"
echo "Start med:  cd ~/oppvarming  &&  cat OPPGAVE.txt"
