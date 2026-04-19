/*
 * sample07.prg  -  Wrong password: security verification
 *
 * Demonstrates that:
 *   1. Opening an encrypted table with the CORRECT password gives clear data.
 *   2. Opening the same table with a WRONG password produces garbled output.
 *
 * This is the expected security property: DBFCDXEX uses AES-256-CTR with no
 * authentication tag (unauthenticated encryption).  A wrong password does NOT
 * raise an error -- it silently returns garbage.  Applications must check
 * CDXEX_IsTableEncrypted() before USE and ensure the password is correct.
 *
 * NOTE: the CDX index is NOT rebuilt in this sample.  Seeking on an
 * encrypted CDX opened with the wrong key produces undefined results.
 *
 * Build:   go_07.bat
 */

REQUEST DBFCDXEX, DBFCDX, DBFFPT
REQUEST FIELDGET, FIELDPUT

#define DB_FILE       "clientes.dbf"
#define DB_ENGINE     "aes256"
#define DB_PASS_OK    "Secreto123"
#define DB_PASS_WRONG "WrongPass99"

STATIC FUNCTION aStruct()
   RETURN { { "ID",      "N",  4, 0 }, ;
            { "NOMBRE",  "C", 30, 0 }, ;
            { "IMPORTE", "N",  9, 2 } }

STATIC PROCEDURE PrintTable( cLabel )
   LOCAL n := 0
   ? cLabel
   GO TOP
   DO WHILE ! EOF()
      n++
      ? "  Rec", n, "| ID:", FIELDGET(1), ;
               "| NOMBRE:", ALLTRIM( FIELDGET(2) ), ;
               "| IMPORTE:", FIELDGET(3)
      SKIP
   ENDDO

PROCEDURE Main()

   ? "=== Sample 07: Wrong password -- security verification ==="
   ?

   /* Create a plain table and encrypt it */
   IF FILE( DB_FILE ) ; FERASE( DB_FILE ) ; ENDIF
   dbCreate( DB_FILE, aStruct(), "DBFCDX" )
   USE ( DB_FILE ) VIA "DBFCDX" EXCLUSIVE NEW
   dbAppend() ; FIELDPUT( 1, 1 ) ; FIELDPUT( 2, "Ana Garcia"    ) ; FIELDPUT( 3, 1500.00 )
   dbAppend() ; FIELDPUT( 1, 2 ) ; FIELDPUT( 2, "Pere Martinez" ) ; FIELDPUT( 3, 2300.50 )
   dbAppend() ; FIELDPUT( 1, 3 ) ; FIELDPUT( 2, "Laia Puig"     ) ; FIELDPUT( 3,  875.25 )
   USE

   DbfcdxexSetup( DB_ENGINE, DB_PASS_OK )
   USE ( DB_FILE ) VIA "DBFCDXEX" EXCLUSIVE NEW
   CDXEX_EncryptTable()
   USE

   /* --- CORRECT password --- */
   DbfcdxexSetup( DB_ENGINE, DB_PASS_OK )
   USE ( DB_FILE ) VIA "DBFCDXEX" SHARED NEW
   PrintTable( "CORRECT password (" + DB_PASS_OK + "):" )
   USE
   ?

   /* --- WRONG password --- */
   DbfcdxexSetup( DB_ENGINE, DB_PASS_WRONG )
   USE ( DB_FILE ) VIA "DBFCDXEX" SHARED NEW
   PrintTable( "WRONG password (" + DB_PASS_WRONG + ")  -- garbled output:" )
   USE
   ?

   ? "Conclusion: without the correct password, data is unreadable."
   ? "No exception is raised -- the application must validate the key."

   IF FILE( DB_FILE ) ; FERASE( DB_FILE ) ; ENDIF

   inkey(0)

RETURN
