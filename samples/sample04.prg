/*
 * sample04.prg  -  Diagnostics: CDXEX_Info() and CDXEX_IsTableEncrypted()
 *
 * Demonstrates:
 *   - CDXEX_IsTableEncrypted() reads byte 28 of the DBF header from the
 *     current work area -- requires an active USE (any RDD works).
 *   - CDXEX_Info() returns a diagnostic string from the active DBFCDXEX area.
 *   - Calling CDXEX_Info() without an active DBFCDXEX area returns a safe message.
 *
 * Build:   go_04.bat
 */

REQUEST DBFCDXEX, DBFCDX, DBFFPT
REQUEST FIELDGET, FIELDPUT

#define DB_FILE   "clientes.dbf"
#define DB_ENGINE "aes256"
#define DB_PASS   "Secreto123"

STATIC FUNCTION aStruct()
   RETURN { { "ID",      "N",  4, 0 }, ;
            { "NOMBRE",  "C", 30, 0 }, ;
            { "IMPORTE", "N",  9, 2 } }

PROCEDURE Main()

   LOCAL cFile := DB_FILE

   ? "=== Sample 04: Diagnostics ==="
   ?

   /* Create a plain table */
   IF FILE( cFile ) ; FERASE( cFile ) ; ENDIF
   dbCreate( cFile, aStruct(), "DBFCDX" )
   USE ( cFile ) VIA "DBFCDX" EXCLUSIVE NEW
   dbAppend() ; FIELDPUT( 1, 1 ) ; FIELDPUT( 2, "Ana Garcia" ) ; FIELDPUT( 3, 1500.00 )
   USE

   /* CDXEX_IsTableEncrypted() requires an open work area -- open DBFCDX first */
   USE ( cFile ) VIA "DBFCDX" SHARED NEW
   ? "--- State: plain table, DBFCDX area open ---"
   ? "IsTableEncrypted:", CDXEX_IsTableEncrypted()   /* .F. */
   ? "Info (DBFCDX)    :", CDXEX_Info()              /* "No DBFCDXEX area selected" */
   USE
   ?


   /* Encrypt the table */
   DbfcdxexSetup( DB_ENGINE, DB_PASS )
   USE ( cFile ) VIA "DBFCDXEX" EXCLUSIVE NEW
   CDXEX_EncryptTable()
   USE

   /* Open as DBFCDXEX -- full Info available */
   DbfcdxexSetup( DB_ENGINE, DB_PASS )
   USE ( cFile ) VIA "DBFCDXEX" SHARED NEW
   ? "--- State: encrypted table, DBFCDXEX area open ---"
   ? "IsTableEncrypted:", CDXEX_IsTableEncrypted()
   ? "Info (DBFCDXEX)  :", CDXEX_Info()
   USE
   ?

   /* Open encrypted table as plain DBFCDX -- IsTableEncrypted warns */
   USE ( cFile ) VIA "DBFCDX" SHARED NEW
   ? "--- State: encrypted table opened as plain DBFCDX (wrong!) ---"
   IF CDXEX_IsTableEncrypted()
      ? "WARNING: table is encrypted but opened as DBFCDX -- data is garbled."
   ENDIF
   ? "Info (no CDXEX)  :", CDXEX_Info()
   USE

   IF FILE( cFile ) ; FERASE( cFile ) ; ENDIF

   inkey(0)

RETURN
