/*
 * sample03.prg  -  Decrypt an encrypted table back to plain DBF
 *
 * Workflow:
 *   1. Open the encrypted table via DBFCDXEX
 *   2. Call CDXEX_DecryptTable() -- decrypts in-place, removes CDX, clears marker
 *   3. Re-open as plain DBFCDX (no password needed) and verify all records
 *
 * Build:   go_03.bat
 * Next:    sample04 (diagnostics / CDXEX_Info)
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

STATIC PROCEDURE EnsureEncrypted()
   IF ! FILE( DB_FILE )
      dbCreate( DB_FILE, aStruct(), "DBFCDX" )
      USE ( DB_FILE ) VIA "DBFCDX" EXCLUSIVE NEW
      dbAppend() ; FIELDPUT( 1, 1 ) ; FIELDPUT( 2, "Ana Garcia"    ) ; FIELDPUT( 3, 1500.00 )
      dbAppend() ; FIELDPUT( 1, 2 ) ; FIELDPUT( 2, "Pere Martinez" ) ; FIELDPUT( 3, 2300.50 )
      dbAppend() ; FIELDPUT( 1, 3 ) ; FIELDPUT( 2, "Laia Puig"     ) ; FIELDPUT( 3,  875.25 )
      USE
   ENDIF
   IF ! CDXEX_IsTableEncrypted( DB_FILE )
      DbfcdxexSetup( DB_ENGINE, DB_PASS )
      USE ( DB_FILE ) VIA "DBFCDXEX" EXCLUSIVE NEW
      CDXEX_EncryptTable()
      USE
   ENDIF

PROCEDURE Main()

   ? "=== Sample 03: Decrypt table back to plain DBF ==="
   ?

   EnsureEncrypted()

   ? "IsEncrypted (before):", CDXEX_IsTableEncrypted( DB_FILE )

   /* Step 1 + 2: open via DBFCDXEX and decrypt */
   DbfcdxexSetup( DB_ENGINE, DB_PASS )
   USE ( DB_FILE ) VIA "DBFCDXEX" EXCLUSIVE NEW

   ? "Info (before decrypt):", CDXEX_Info()

   IF ! CDXEX_IsTableEncrypted()
      ? "Table is already plaintext."
   ELSE
      IF CDXEX_DecryptTable()
         ? "Table decrypted successfully."
      ELSE
         ? "ERROR: decryption failed."
      ENDIF
   ENDIF

   ? "Info (after  decrypt):", CDXEX_Info()
   USE

   ? "IsEncrypted (after) :", CDXEX_IsTableEncrypted( DB_FILE )
   ?

   /* Step 3: open as plain DBFCDX -- no password needed */
   USE ( DB_FILE ) VIA "DBFCDX" SHARED NEW
   ? "Plain DBFCDX access -- all records:"
   GO TOP
   DO WHILE ! EOF()
      ? "  ID:", FIELDGET(1), "  NOMBRE:", ALLTRIM( FIELDGET(2) ), "  IMPORTE:", FIELDGET(3)
      SKIP
   ENDDO
   USE

   IF FILE( DB_FILE ) ; FERASE( DB_FILE ) ; ENDIF

   inkey(0)

RETURN
