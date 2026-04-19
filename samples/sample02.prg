/*
 * sample02.prg  -  Transparent read/write on an encrypted table
 *
 * Workflow:
 *   1. Expects clientes.dbf already encrypted (run sample01 first,
 *      or the sample encrypts it automatically)
 *   2. Rebuild the CDX index (EncryptTable removes it)
 *   3. Read all records -- decryption is transparent
 *   4. Append a new record -- encryption is transparent
 *   5. Seek via index to verify CDX works on encrypted data
 *
 * Build:   go_02.bat
 * Next:    sample03 (decrypt the table back to plain)
 */

REQUEST DBFCDXEX, DBFCDX, DBFFPT
REQUEST FIELDGET, FIELDPUT

#define DB_FILE   "clientes.dbf"
#define DB_CDX    "clientes"
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

   ? "=== Sample 02: Transparent read/write on encrypted table ==="
   ?

   EnsureEncrypted()

   /* Step 1: rebuild CDX (EncryptTable removes it) */
   DbfcdxexSetup( DB_ENGINE, DB_PASS )
   USE ( DB_FILE ) VIA "DBFCDXEX" EXCLUSIVE NEW
   INDEX ON FIELDGET( 2 ) TO ( DB_CDX )
   USE

   /* Step 2: open shared and read all records */
   DbfcdxexSetup( DB_ENGINE, DB_PASS )
   USE ( DB_FILE ) VIA "DBFCDXEX" SHARED NEW
   SET ORDER TO 1

   ? CDXEX_Info()
   ? "All records (decrypted transparently):"
   GO TOP
   DO WHILE ! EOF()
      ? "  ID:", FIELDGET(1), "  NOMBRE:", ALLTRIM( FIELDGET(2) ), "  IMPORTE:", FIELDGET(3)
      SKIP
   ENDDO
   USE

   /* Step 3: append a record and verify via SEEK */
   DbfcdxexSetup( DB_ENGINE, DB_PASS )
   USE ( DB_FILE ) VIA "DBFCDXEX" EXCLUSIVE NEW
   SET ORDER TO 1
   dbAppend()
   FIELDPUT( 1, 4 )
   FIELDPUT( 2, "Joan Soler" )
   FIELDPUT( 3, 3100.00 )
   dbCommit()

   ? "After append -- SEEK 'Joan Soler':"
   DBSEEK( "Joan Soler" )
   IF FOUND()
      ? "  Found:", FIELDGET(1), ALLTRIM( FIELDGET(2) ), FIELDGET(3)
   ELSE
      ? "  NOT found."
   ENDIF
   USE

   ?
   ? "Run sample03 to decrypt the table back to plain."

   inkey(0)

RETURN
