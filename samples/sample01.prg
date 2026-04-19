/*
 * sample01.prg  -  Encrypt a plain DBF table
 *
 * Workflow:
 *   1. Create a plain table (DBFCDX, no encryption)
 *   2. Setup engine + password
 *   3. Open via DBFCDXEX and call CDXEX_EncryptTable()
 *   4. Verify the on-disk marker with CDXEX_IsTableEncrypted()
 *
 * Build:   go_01.bat
 * Next:    sample02 (read the encrypted table transparently)
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

STATIC PROCEDURE CreatePlainDB()
   IF FILE( DB_FILE ) ; FERASE( DB_FILE ) ; ENDIF
   dbCreate( DB_FILE, aStruct(), "DBFCDX" )
   USE ( DB_FILE ) VIA "DBFCDX" EXCLUSIVE NEW
   dbAppend() ; FIELDPUT( 1, 1 ) ; FIELDPUT( 2, "Ana Garcia"    ) ; FIELDPUT( 3, 1500.00 )
   dbAppend() ; FIELDPUT( 1, 2 ) ; FIELDPUT( 2, "Pere Martinez" ) ; FIELDPUT( 3, 2300.50 )
   dbAppend() ; FIELDPUT( 1, 3 ) ; FIELDPUT( 2, "Laia Puig"     ) ; FIELDPUT( 3,  875.25 )
   USE

PROCEDURE Main()

   ? "=== Sample 01: Encrypt a plain DBF table ==="
   ?

   /* Step 1: create plain table and check marker (requires an open area) */
   CreatePlainDB()
   ? "Plain table created:", DB_FILE
   USE ( DB_FILE ) VIA "DBFCDX" SHARED NEW
   ? "IsEncrypted (before):", CDXEX_IsTableEncrypted()   /* .F. -- plain table */
   USE

   /* Step 2 + 3: open via DBFCDXEX and encrypt */
   DbfcdxexSetup( DB_ENGINE, DB_PASS )
   USE ( DB_FILE ) VIA "DBFCDXEX" EXCLUSIVE NEW

   ? "Info (before encrypt):", CDXEX_Info()

   IF CDXEX_IsTableEncrypted()
      ? "Already encrypted -- nothing to do."
   ELSE
      IF CDXEX_EncryptTable()
         ? "Table encrypted successfully."
      ELSE
         ? "ERROR: encryption failed."
      ENDIF
   ENDIF

   ? "Info (after  encrypt):", CDXEX_Info()
   ? "IsEncrypted (inside DBFCDXEX) :", CDXEX_IsTableEncrypted()   /* .T. */
   USE

   /* Step 4: re-open as plain DBFCDX to verify the on-disk marker */
   USE ( DB_FILE ) VIA "DBFCDX" SHARED NEW
   ? "IsEncrypted (via DBFCDX after):", CDXEX_IsTableEncrypted()   /* .T. */
   USE
   ?
   ? "Run sample02 to read the encrypted table."

   inkey(0)

RETURN
