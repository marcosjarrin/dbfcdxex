/*
 * sample06.prg  -  Engine selection: dummy / rot13 / aes256
 *
 * DBFCDXEX supports pluggable encryption engines.  This sample creates
 * the same table three times -- once with each engine -- and verifies that
 * data can be read back correctly after encryption.
 *
 *   Engine   Description
 *   -------  -----------------------------------------------------------
 *   dummy    XOR with first key byte; fast, not secure (testing only)
 *   rot13    ROT-13 for A-Z / a-z; self-inverse, not secure (demo only)
 *   aes256   AES-256-CTR via Windows BCrypt; production-grade security
 *
 * Build:   go_06.bat
 */

REQUEST DBFCDXEX, DBFCDX, DBFFPT
REQUEST FIELDGET, FIELDPUT

#define DB_PASS   "test"

PROCEDURE Main()

   LOCAL cFile   := "test_eng.dbf"
   LOCAL cEngine
   LOCAL aEngines := { "dummy", "rot13", "aes256" }

   ? "=== Sample 06: Engine selection ==="
   ?

   FOR EACH cEngine IN aEngines

      ? replicate( "-", 50 )
      ? "Engine:", cEngine

      /* Create a plain table */
      IF FILE( cFile ) ; FERASE( cFile ) ; ENDIF
      dbCreate( cFile, { { "NAME", "C", 20, 0 } }, "DBFCDX" )
      USE ( cFile ) VIA "DBFCDX" EXCLUSIVE NEW
      dbAppend() ; FIELDPUT( 1, "Hello World" )
      USE

      /* Encrypt with this engine */
      DbfcdxexSetup( cEngine, DB_PASS )
      USE ( cFile ) VIA "DBFCDXEX" EXCLUSIVE NEW
      CDXEX_EncryptTable()
      ? "  After encrypt:", CDXEX_Info()
      USE

      /* Read back -- setup must be called again before each USE */
      DbfcdxexSetup( cEngine, DB_PASS )
      USE ( cFile ) VIA "DBFCDXEX" SHARED NEW
      GO TOP
      ? "  Read back    :", ALLTRIM( FIELDGET(1) )   /* must show "Hello World" */
      USE

      IF FILE( cFile ) ; FERASE( cFile ) ; ENDIF

   NEXT

   ?

   inkey(0)

RETURN
