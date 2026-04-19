/*
 * sample05.prg  -  ADS-equivalent pattern ported to DBFCDXEX
 *
 * Shows a 1:1 mapping from ADS (Advantage Database Server) encryption API
 * to the DBFCDXEX API.  Useful for projects migrating from ADS.
 *
 *   ADS original                        DBFCDXEX equivalent
 *   --------------------------------    -----------------------------------
 *   AdsSetPassword("Secreto123")        DbfcdxexSetup("aes256","Secreto123")
 *   USE file VIA "ADS" EXCLUSIVE        USE file VIA "DBFCDXEX" EXCLUSIVE
 *   AdsIsTableEncrypted()               CDXEX_IsTableEncrypted()
 *   AdsEncryptTable()                   CDXEX_EncryptTable()
 *   AdsDecryptTable()                   CDXEX_DecryptTable()
 *
 * Build:   go_05.bat
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

   ? "=== Sample 05: ADS-equivalent pattern ==="
   ?

   /* Create a fresh plain table */
   IF FILE( DB_FILE ) ; FERASE( DB_FILE ) ; ENDIF
   dbCreate( DB_FILE, aStruct(), "DBFCDX" )
   USE ( DB_FILE ) VIA "DBFCDX" EXCLUSIVE NEW
   dbAppend() ; FIELDPUT( 1, 1 ) ; FIELDPUT( 2, "Ana Garcia"    ) ; FIELDPUT( 3, 1500.00 )
   dbAppend() ; FIELDPUT( 1, 2 ) ; FIELDPUT( 2, "Pere Martinez" ) ; FIELDPUT( 3, 2300.50 )
   dbAppend() ; FIELDPUT( 1, 3 ) ; FIELDPUT( 2, "Laia Puig"     ) ; FIELDPUT( 3,  875.25 )
   USE

   /*
    * ADS original:
    *   AdsSetServerType(1)
    *   AdsSetPassword("Secreto123")
    *   USE "clientes.dbf" VIA "ADS" EXCLUSIVE
    *   IF !AdsIsTableEncrypted()
    *      IF AdsEncryptTable()
    *         ? "Tabla cifrada con exito"
    *      ENDIF
    *   ENDIF
    */

   DbfcdxexSetup( DB_ENGINE, DB_PASS )
   USE ( DB_FILE ) VIA "DBFCDXEX" EXCLUSIVE NEW
   IF ! CDXEX_IsTableEncrypted()
      IF CDXEX_EncryptTable()
         ? "Tabla cifrada con exito."
      ELSE
         ? "Error al cifrar."
      ENDIF
   ENDIF
   ? CDXEX_Info()
   USE

   ? "IsEncrypted:", CDXEX_IsTableEncrypted( DB_FILE )

   IF FILE( DB_FILE ) ; FERASE( DB_FILE ) ; ENDIF

   inkey(0)

RETURN
