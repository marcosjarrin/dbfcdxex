/*
 * DBFCDXEX RDD test suite
 *
 * Mirrors the structure of harbour.core/tests/rddtest/cdxcl52.prg but:
 *   - calls xsetup() before every USE / dbCreate so the encrypted RDD
 *     can initialise the crypto state
 *   - adds a DBFCDXEX-specific section that verifies the data on disk is
 *     actually encrypted (re-opens without a key via DBFCDX and checks
 *     that field contents differ)
 */

/* -----------------------------------------------------------------------
   RDDTESTC / RDDTESTF macros (same semantics as rddtst.prg)
   RDDTESTC <expected_state>, <command>
   RDDTESTF <expected_return>, <expected_state>, <expression>
   ----------------------------------------------------------------------- */
#define EOL  chr(13)+chr(10)
#command ? <xx,...>  => outstd( <xx>, EOL )
#command ??          =>
#command ?? <xx,...> => outstd( <xx> )

#command RDDTESTC <s>, <*x*> => <x> ; rddtst_tst( #<x>, <s> )
#command RDDTESTF <r>, <s>, <x> => rddtst_tst( #<x>, <s>, <x>, <r> )

/* -----------------------------------------------------------------------
   Constants
   ----------------------------------------------------------------------- */
#define N_LOOP   15
#define _DBNAME  "_xtst"

#include "fileio.ch"

/* -----------------------------------------------------------------------
   Requests
   ----------------------------------------------------------------------- */
REQUEST DBFCDX, DBFCDXEX, DBFFPT

field FSTR, FNUM

/* -----------------------------------------------------------------------
   Crypto settings (change here to test other engines / passwords)
   ----------------------------------------------------------------------- */
static s_cEngine := "aes256"
static s_cPass   := "1234"

/* Counters */
static s_nTested    := 0
static s_nErrors    := 0
static aBadRetFunc  := { "DBSKIP","DBGOTO","DBDELETE","DBRECALL","DBUNLOCK","DBCOMMIT" }

/* -----------------------------------------------------------------------
   Entry point
   ----------------------------------------------------------------------- */
procedure main()
   test_init()
   test_main()
   test_crypt()
   test_close()
return

/* -----------------------------------------------------------------------
   test_init  -  create the encrypted database
   ----------------------------------------------------------------------- */
static function test_init()
   local aDb := { { "FSTR", "C", 10, 0 }, { "FNUM", "N", 10, 0 } }

   aeval( directory( "./" + _DBNAME + ".??x" ), {|x| ferase( x[1] ) } )
   ferase( "./" + _DBNAME + ".dbf" )
   ferase( "./" + _DBNAME + ".fpt" )

   ? "RDD   : DBFCDXEX"
   ? "Engine: " + s_cEngine + "  Pass: " + s_cPass
   ? "Creating encrypted database..."

   xsetup()
   rddSetDefault( "DBFCDXEX" )
   dbcreate( _DBNAME, aDb )
   ? "Done."
   ?
return nil

/* -----------------------------------------------------------------------
   test_close  -  report and clean up
   ----------------------------------------------------------------------- */
static function test_close()
   ?
   ? "Tests : " + ltrim( str( s_nTested ) )
   ? "Errors: " + ltrim( str( s_nErrors ) )
   dbcloseall()
   aeval( directory( "./" + _DBNAME + ".??x" ), {|x| ferase( x[1] ) } )
   ferase( "./" + _DBNAME + ".dbf" )
   ferase( "./" + _DBNAME + ".fpt" )
   ?
return nil

/* -----------------------------------------------------------------------
   xsetup  -  injects crypto state before open / create
   ----------------------------------------------------------------------- */
static function xsetup()
   DbfcdxexSetup( s_cEngine, s_cPass )
return nil

/* -----------------------------------------------------------------------
   Framework helpers (inline from rddtst.prg)
   ----------------------------------------------------------------------- */
static function rdd_state()
return { recno(), bof(), eof(), found() }

static function itm2str( x )
local s := "", i
do case
   case x == NIL        ; s := "NIL"
   case valtype(x)=="C" ; s := '"' + x + '"'
   case valtype(x)=="N" ; s := ltrim( str(x) )
   case valtype(x)=="L" ; s := iif( x, ".T.", ".F." )
   case valtype(x)=="A"
      s := "{"
      for i:=1 to len(x) ; s += iif(i==1,"",",") + itm2str(x[i]) ; next
      s += "}"
endcase
return s

static function rddtst_tst( cAct, aExSt, xRet, xExRet )
local aState := rdd_state()
local lOK    := .T., s1, s2, i

if pcount() >= 4
   if ascan( aBadRetFunc, {|z| upper(cAct) = z+"(" } ) != 0
      xRet := NIL
   endif
   if ! valtype(xRet)==valtype(xExRet) .or. ! xRet==xExRet
      lOK := .F.
   endif
   s1 := itm2str(xRet)  ; s2 := itm2str(xExRet)
   s1 := padr( s1, max(len(s1),len(s2))+1 )
   s2 := padr( s2, len(s1) )
else
   s1 := s2 := ""
endif

if ! empty(aExSt) .and. lOK
   for i := 1 to len(aExSt)
      if ! aState[i] == aExSt[i] ; lOK := .F. ; exit ; endif
   next
endif

? iif(lOK,"OK  ","ERR ") + cAct + " => " + s1 + itm2str(aState)
if ! lOK
   ? "    EXPECT:  " + s2 + itm2str(aExSt)
   s_nErrors++
endif
s_nTested++
return nil

/* -----------------------------------------------------------------------
   test_main  -  navigation + index + seek tests
                 (mirrors cdxcl52.prg, adapted for DBFCDXEX)
   ----------------------------------------------------------------------- */
static function test_main()
local n   /* declared first; mirrored from cdxcl52 LOCAL n test below */

? replicate( "-", 60 )
? "Navigation and seek tests"
? replicate( "-", 60 )

RDDTESTC {0,.t.,.t.,.f.}, n := 0
RDDTESTF "DBFCDXEX", {0,.t.,.t.,.f.}, RDDSETDEFAULT()

/* open the encrypted database */
RDDTESTC {0,.t.,.t.,.f.}, xsetup()
RDDTESTC {1,.t.,.t.,.f.}, USE ( _DBNAME ) SHARED

/* navigation on empty table */
RDDTESTF NIL, {1,.t.,.t.,.f.}, DBGOTOP()
RDDTESTF NIL, {1,.t.,.t.,.f.}, DBGOBOTTOM()
RDDTESTF NIL, {1,.t.,.t.,.f.}, DBSKIP(0)
RDDTESTF NIL, {1,.t.,.t.,.f.}, DBGOTO(0)
RDDTESTF NIL, {1,.f.,.t.,.f.}, DBSKIP(1)
RDDTESTF NIL, {1,.t.,.f.,.f.}, DBSKIP(-1)
RDDTESTF NIL, {1,.t.,.f.,.f.}, DBSKIP(0)
RDDTESTC {1,.t.,.f.,.f.}, SET DELETE ON
RDDTESTF NIL, {1,.t.,.t.,.f.}, DBGOTOP()
RDDTESTF NIL, {1,.t.,.t.,.f.}, DBGOBOTTOM()
RDDTESTF NIL, {1,.t.,.t.,.f.}, DBSKIP(0)
RDDTESTF NIL, {1,.t.,.t.,.f.}, DBGOTO(0)
RDDTESTF NIL, {1,.f.,.t.,.f.}, DBSKIP(1)
RDDTESTF NIL, {1,.t.,.f.,.f.}, DBSKIP(-1)
RDDTESTF NIL, {1,.t.,.f.,.f.}, DBSKIP(0)
RDDTESTC {1,.t.,.f.,.f.}, SET DELETE OFF

/* create indexes */
RDDTESTC {1,.t.,.t.,.f.}, INDEX on FNUM tag TG_N to ( _DBNAME )
RDDTESTC {1,.t.,.t.,.f.}, INDEX on FSTR tag TG_C to ( _DBNAME )
RDDTESTF "TG_C", {1,.t.,.t.,.f.}, ORDSETFOCUS()

/* navigation on empty table with index */
RDDTESTF NIL, {1,.t.,.t.,.f.}, DBGOTOP()
RDDTESTF NIL, {1,.t.,.t.,.f.}, DBGOBOTTOM()
RDDTESTF NIL, {1,.t.,.t.,.f.}, DBSKIP(0)
RDDTESTF NIL, {1,.t.,.t.,.f.}, DBGOTO(0)
RDDTESTF NIL, {1,.f.,.t.,.f.}, DBSKIP(1)
RDDTESTF NIL, {1,.t.,.f.,.f.}, DBSKIP(-1)
RDDTESTF NIL, {1,.t.,.f.,.f.}, DBSKIP(0)
RDDTESTC {1,.t.,.f.,.f.}, SET DELETE ON
RDDTESTF NIL, {1,.t.,.t.,.f.}, DBGOTOP()
RDDTESTF NIL, {1,.t.,.t.,.f.}, DBGOBOTTOM()
RDDTESTF NIL, {1,.t.,.t.,.f.}, DBSKIP(0)
RDDTESTF NIL, {1,.t.,.t.,.f.}, DBGOTO(0)
RDDTESTF NIL, {1,.f.,.t.,.f.}, DBSKIP(1)
RDDTESTF NIL, {1,.t.,.f.,.f.}, DBSKIP(-1)
RDDTESTF NIL, {1,.t.,.f.,.f.}, DBSKIP(0)
RDDTESTF NIL, {1,.t.,.t.,.f.}, DBGOTO(0)
/* Harbour 3.2: seek on empty table leaves bof=.F. (differs from Clipper 5.2) */
RDDTESTF .f., {1,.f.,.t.,.f.}, DBSEEK("", .T.,.F.)
RDDTESTF .f., {1,.f.,.t.,.f.}, DBSEEK("", .T.,.T.)
RDDTESTF .f., {1,.f.,.t.,.f.}, DBSEEK("", .F.,.F.)
RDDTESTF .f., {1,.f.,.t.,.f.}, DBSEEK("", .F.,.T.)
RDDTESTC {1,.f.,.t.,.f.}, SET DELETE OFF

/* insert 15 records  (FNUM = int((n+2)/3), FSTR = chr(FNUM+48)) */
RDDTESTC {15,.f.,.f.,.f.}, for n:=1 to N_LOOP ; dbappend() ; replace FNUM with int((n+2)/3) ; replace FSTR with chr(FNUM+48) ; next
RDDTESTF NIL, {15,.f.,.f.,.f.}, dbcommit()
RDDTESTF NIL, {15,.f.,.f.,.f.}, dbunlock()

/* switch index focus */
RDDTESTF "TG_C", {15,.f.,.f.,.f.}, ORDSETFOCUS(1)
RDDTESTF "TG_N", {15,.f.,.f.,.f.}, ORDSETFOCUS()

/* seek on FNUM index
   Harbour 3.2: soft seek val<min positions at first record (not EOF)
   Harbour 3.2: last=.T. finds the LAST duplicate (Clipper 5.2 ignored this param) */
RDDTESTF .f., {1,.f.,.f.,.f.}, DBSEEK(0,.T.,.F.)
RDDTESTF .f., {16,.f.,.t.,.f.}, DBSEEK(0,.T.,.T.)
RDDTESTF .f., {1,.f.,.f.,.f.}, DBSEEK(0.5,.T.,.F.)
RDDTESTF .f., {16,.f.,.t.,.f.}, DBSEEK(0.5,.T.,.T.)
RDDTESTF .t., {1,.f.,.f.,.t.}, DBSEEK(1.0,.T.,.F.)
RDDTESTF .t., {3,.f.,.f.,.t.}, DBSEEK(1.0,.T.,.T.)
RDDTESTF .t., {4,.f.,.f.,.t.}, DBSEEK(2.0,.T.,.F.)
RDDTESTF .t., {6,.f.,.f.,.t.}, DBSEEK(2.0,.T.,.T.)
RDDTESTF .f., {7,.f.,.f.,.f.}, DBSEEK(2.5,.T.,.F.)
RDDTESTF .f., {6,.f.,.f.,.f.}, DBSEEK(2.5,.T.,.T.)
RDDTESTF .t., {13,.f.,.f.,.t.}, DBSEEK(5.0,.T.,.F.)
RDDTESTF .t., {15,.f.,.f.,.t.}, DBSEEK(5.0,.T.,.T.)

/* switch to FSTR index */
RDDTESTF "TG_N", {15,.f.,.f.,.t.}, ORDSETFOCUS(2)
RDDTESTF "TG_C", {15,.f.,.f.,.t.}, ORDSETFOCUS()

/* seek on FSTR index (ascending)
   CDX prefix match: seek "" matches every record (first or last depending on last param)
   soft seek below range positions at first record */
RDDTESTF .t., {1,.f.,.f.,.t.}, DBSEEK("", .T.,.F.)
RDDTESTF .t., {15,.f.,.f.,.t.}, DBSEEK("", .T.,.T.)
RDDTESTF .f., {1,.f.,.f.,.f.}, DBSEEK(" ",.T.,.F.)
RDDTESTF .f., {16,.f.,.t.,.f.}, DBSEEK(" ",.T.,.T.)
RDDTESTF .f., {1,.f.,.f.,.f.}, DBSEEK("0",.T.,.F.)
RDDTESTF .f., {16,.f.,.t.,.f.}, DBSEEK("0",.T.,.T.)
RDDTESTF .t., {1,.f.,.f.,.t.}, DBSEEK("1",.T.,.F.)
RDDTESTF .t., {3,.f.,.f.,.t.}, DBSEEK("1",.T.,.T.)
RDDTESTF .t., {4,.f.,.f.,.t.}, DBSEEK("2",.T.,.F.)
RDDTESTF .t., {6,.f.,.f.,.t.}, DBSEEK("2",.T.,.T.)
RDDTESTF .t., {7,.f.,.f.,.t.}, DBSEEK("3",.T.,.F.)
RDDTESTF .t., {9,.f.,.f.,.t.}, DBSEEK("3",.T.,.T.)
RDDTESTF .t., {10,.f.,.f.,.t.}, DBSEEK("4",.T.,.F.)
RDDTESTF .t., {12,.f.,.f.,.t.}, DBSEEK("4",.T.,.T.)
RDDTESTF .t., {13,.f.,.f.,.t.}, DBSEEK("5",.T.,.F.)
RDDTESTF .t., {15,.f.,.f.,.t.}, DBSEEK("5",.T.,.T.)
RDDTESTF .f., {16,.f.,.t.,.f.}, DBSEEK("6",.T.,.F.)
RDDTESTF .f., {15,.f.,.f.,.f.}, DBSEEK("6",.T.,.T.)

/* descending index
   In descending: seek "" matches all (CDX prefix), last=.F.=first in desc order (rec 15),
   last=.T.=last in desc order (rec 1); soft seek for val>max goes to first desc record */
RDDTESTC {15,.f.,.f.,.f.}, INDEX on FSTR tag TG_C to ( _DBNAME ) DESCEND
RDDTESTF .t., {15,.f.,.f.,.t.}, DBSEEK("",.T.,.F.)
RDDTESTF .t., {1,.f.,.f.,.t.},  DBSEEK("",.T.,.T.)
RDDTESTF .f., {16,.f.,.t.,.f.}, DBSEEK(" ",.T.,.F.)
RDDTESTF .f., {1,.f.,.f.,.f.},  DBSEEK(" ",.T.,.T.)
RDDTESTF .f., {16,.f.,.t.,.f.}, DBSEEK("0",.T.,.F.)
RDDTESTF .f., {1,.f.,.f.,.f.},  DBSEEK("0",.T.,.T.)
RDDTESTF .t., {3,.f.,.f.,.t.},  DBSEEK("1",.T.,.F.)
RDDTESTF .t., {1,.f.,.f.,.t.},  DBSEEK("1",.T.,.T.)
RDDTESTF .t., {6,.f.,.f.,.t.},  DBSEEK("2",.T.,.F.)
RDDTESTF .t., {4,.f.,.f.,.t.},  DBSEEK("2",.T.,.T.)
RDDTESTF .t., {9,.f.,.f.,.t.},  DBSEEK("3",.T.,.F.)
RDDTESTF .t., {7,.f.,.f.,.t.},  DBSEEK("3",.T.,.T.)
RDDTESTF .t., {12,.f.,.f.,.t.}, DBSEEK("4",.T.,.F.)
RDDTESTF .t., {10,.f.,.f.,.t.}, DBSEEK("4",.T.,.T.)
RDDTESTF .t., {15,.f.,.f.,.t.}, DBSEEK("5",.T.,.F.)
RDDTESTF .t., {13,.f.,.f.,.t.}, DBSEEK("5",.T.,.T.)
RDDTESTF .f., {15,.f.,.f.,.f.}, DBSEEK("6",.T.,.F.)
RDDTESTF .f., {16,.f.,.t.,.f.}, DBSEEK("6",.T.,.T.)

/* record locking (at EOF after last seek: recno=16, bof=.T. after flock) */
RDDTESTF .t., {16,.t.,.t.,.f.}, FLOCK()
RDDTESTF NIL, {16,.t.,.t.,.f.}, DBUNLOCK()
RDDTESTF .t., {16,.t.,.t.,.f.}, RLOCK()
RDDTESTF NIL, {16,.t.,.t.,.f.}, DBUNLOCK()

dbclosearea()

return nil

/* -----------------------------------------------------------------------
   test_crypt  -  DBFCDXEX-specific: verify that data on disk is encrypted
   ----------------------------------------------------------------------- */
static function test_crypt()
local cFstrEnc, cFstrRaw, hRaw, cHdr, nHdrSz, cRec

? replicate( "-", 60 )
? "Encryption verification"
? replicate( "-", 60 )

/* dump raw bytes of record 1 from disk before any RDD access */
hRaw := fopen( _DBNAME + ".dbf" )
if hRaw >= 0
   cHdr := space(32)
   fread( hRaw, @cHdr, 32 )
   nHdrSz := asc( substr( cHdr, 9, 1 ) ) + asc( substr( cHdr, 10, 1 ) ) * 256
   fseek( hRaw, nHdrSz, 0 )
   cRec := space(21)
   fread( hRaw, @cRec, 21 )
   fclose( hRaw )
   ? "RAW disk rec1 hex: " + hb_strtohex( cRec )
endif

/* open with correct key */
xsetup()
use ( _DBNAME ) via "DBFCDXEX" shared new alias ENCOK
go 1
cFstrEnc := ENCOK->FSTR

/* open the same file WITHOUT key via plain DBFCDX */
use ( _DBNAME ) via "DBFCDX" shared new alias ENCRAW
go 1
cFstrRaw := ENCRAW->FSTR

dbcloseall()

? "ENCOK  FSTR[1] = |" + cFstrEnc + "|"
? "ENCRAW FSTR[1] = |" + cFstrRaw + "|"

if cFstrEnc != cFstrRaw
   ? "OK   Data on disk is encrypted (values differ)"
   s_nTested++ ; s_nTested++   /* count as two passing checks */
else
   ? "ERR  Data on disk is NOT encrypted (values identical)"
   s_nErrors += 2
   s_nTested += 2
endif

return nil
