/*
 * DBFCDXEX RDD - DBFCDX with pluggable encryption/decryption
 *
 * Copyright 2026 Carles Aubia <carles9000@gmail.com> 
 * Copyright 2026 Claude Code (IA) 
 *
 * Architecture:
 *   - Includes dbfcdx1.c with HB_CDXEX defined, activating CDX page hooks
 *   - Overrides structSize / newArea / open / create / close in the RDD table
 *   - DBF record + FPT memo encryption is delegated to the Harbour SIX layer
 *     (bCryptType = DB_CRYPT_SIX) using the first 8 bytes of the derived key
 *   - CDX index pages are encrypted via CDXEX_PAGE_ENCRYPT/DECRYPT macros
 *
 * Usage (Harbour):
 *   DbfcdxexSetup( 'aes256', 'mypassword' )
 *   USE myfile VIA 'DBFCDXEX'
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file LICENSE.txt.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA (or visit https://www.gnu.org/licenses/).
 *
 * As a special exception, the Harbour Project gives permission for
 * additional uses of the text contained in its release of Harbour.
 *
 * The exception is that, if you link the Harbour libraries with other
 * files to produce an executable, this does not by itself cause the
 * resulting executable to be covered by the GNU General Public License.
 * Your use of that executable is in no way restricted on account of
 * linking the Harbour library code into it.
 *
 * This exception does not however invalidate any other reasons why
 * the executable file might be covered by the GNU General Public License.
 *
 * This exception applies only to the code released by the Harbour
 * Project under the name Harbour.  If you copy code from other
 * Harbour Project or Free Software Foundation releases into a copy of
 * Harbour, as the General Public License permits, the exception does
 * not apply to the code that you add in this way.  To avoid misleading
 * anyone as to the status of such modified files, you must delete
 * this exception notice from them.
 *
 * If you write modifications of your own for Harbour, it is your choice
 * whether to permit this exception to apply to your modifications.
 * If you do not wish that, delete this exception notice.
 *
 */

/* ======================================================================
   PART 1 - Types and hook infrastructure (must precede dbfcdx1.c include)
   ====================================================================== */

#include "hbapi.h"
#define HB_CDX_DBGCODE   /* must precede hbrddcdx.h so CDXINDEX has RdLck/WrLck */
#include "hbrddcdx.h"   /* CDXAREA, CDXINDEX; transitively: hbrdddbf.h ->
                           hbapirdd.h -> dbinfo.ch (DB_CRYPT_SIX)          */
#include "hbapifs.h"    /* HB_FOFFSET, hb_fileReadAt/WriteAt/Flush, hb_fileDelete */
#include "hbapierr.h"   /* hb_errRT_BASE                                    */

/* Pluggable crypto engine interface.
 * fn_derive  : derives a 32-byte key from the password
 * fn_encrypt : encrypts buffer in-place; nOffset is the file position (for IV)
 * fn_decrypt : decrypts buffer in-place (same signature, symmetric ciphers
 *              may share the same function body)                            */
typedef struct _HB_CDXEX_ENGINE
{
   const char * szName;
   void ( * fn_derive  )( const char * szPassword, HB_BYTE * aKey );
   void ( * fn_encrypt )( const HB_BYTE * aKey, HB_BYTE * pBuf,
                          HB_SIZE nSize, HB_FOFFSET nOffset );
   void ( * fn_decrypt )( const HB_BYTE * aKey, HB_BYTE * pBuf,
                          HB_SIZE nSize, HB_FOFFSET nOffset );
} HB_CDXEX_ENGINE;

/* Extended work area: CDXAREA (which extends DBFAREA) + crypto state.
 * CDXAREA MUST be the first member so all existing CDXAREA/DBFAREA
 * pointer casts remain valid.                                              */
typedef struct _CDXEXAREA
{
   CDXAREA                   cdxarea;
   const HB_CDXEX_ENGINE *   pEngine;
   HB_BYTE                   aKey[ 32 ];
   HB_BOOL                   fCryptoActive;   /* key loaded and ready         */
   HB_BOOL                   fOnDiskEncrypted;/* byte-28 marker is set on disk*/
} CDXEXAREA, * LPCDXEXAREA;

/* Header marker — byte 28 of the DBF header used to flag on-disk encryption */
#define HB_CDXEX_HDR_CRYPT_OFS   28
#define HB_CDXEX_HDR_CRYPT_MAGIC 0xCE

/* Forward declarations */
static void hb_cdxexApplyEncrypt( LPCDXEXAREA pExArea, HB_BYTE * pBuf,
                                  HB_SIZE nSize, HB_ULONG ulPage );
static void hb_cdxexApplyDecrypt( LPCDXEXAREA pExArea, HB_BYTE * pBuf,
                                  HB_SIZE nSize, HB_ULONG ulPage );
static HB_BOOL hb_cdxexHdrMarker( DBFAREAP pDbf, HB_BOOL bSet );
static HB_ERRCODE hb_cdxexWriteDBHeader( AREAP pArea );

/* Macros expanded inside dbfcdx1.c when HB_CDXEX is defined.             */
#define CDXEX_PAGE_ENCRYPT( pIdx, pBuf, nSz, ulPg ) \
   hb_cdxexApplyEncrypt( ( LPCDXEXAREA ) ( pIdx )->pArea, \
                         ( pBuf ), ( nSz ), ( ulPg ) )
#define CDXEX_PAGE_DECRYPT( pIdx, pBuf, nSz, ulPg ) \
   hb_cdxexApplyDecrypt( ( LPCDXEXAREA ) ( pIdx )->pArea, \
                         ( pBuf ), ( nSz ), ( ulPg ) )

#define HB_CDXEX   /* activates hooks + name + suppresses registration     */

/* ======================================================================
   PART 2 - Base DBFCDX code (with HB_CDXEX hooks active)
   ====================================================================== */

#include "dbfcdx1.c"

/* ======================================================================
   PART 3 - Crypto engine: dummy (XOR, proof-of-concept only)
   ====================================================================== */

static void s_dummyDerive( const char * szPassword, HB_BYTE * aKey )
{
   /* seed = XOR-sum of all password bytes, then spread over 32 bytes      */
   HB_BYTE   acc = 0x5A;
   HB_SIZE   i;

   for( i = 0; szPassword[ i ]; i++ )
      acc ^= ( HB_BYTE ) szPassword[ i ];
   if( acc == 0 )
      acc = 0x5A;

   for( i = 0; i < 32; i++ )
      aKey[ i ] = ( HB_BYTE ) ( acc ^ ( HB_BYTE ) i );
}

static void s_dummyXor( const HB_BYTE * aKey, HB_BYTE * pBuf,
                        HB_SIZE nSize, HB_FOFFSET nOffset )
{
   HB_SIZE i;
   HB_SYMBOL_UNUSED( nOffset );
   for( i = 0; i < nSize; i++ )
      pBuf[ i ] ^= aKey[ i & 31 ];
}

static const HB_CDXEX_ENGINE s_engineDummy =
{
   "dummy",
   s_dummyDerive,
   s_dummyXor,   /* encrypt */
   s_dummyXor    /* decrypt (XOR is its own inverse) */
};

/* ======================================================================
   PART 3b - Crypto engine: AES-256-CTR  (Windows BCrypt, single-threaded)
   ====================================================================== */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#pragma comment( lib, "bcrypt.lib" )

/* Per-process BCrypt providers, opened lazily on first use */
static BCRYPT_ALG_HANDLE s_hBcAes = NULL;   /* AES / ECB  */
static BCRYPT_ALG_HANDLE s_hBcSha = NULL;   /* SHA-256    */

static void hb_bcryptEnsureAlg( void )
{
   if( s_hBcAes )
      return;
   if( BCryptOpenAlgorithmProvider( &s_hBcAes,
                                    BCRYPT_AES_ALGORITHM, NULL, 0 ) == 0 )
      BCryptSetProperty( s_hBcAes, BCRYPT_CHAINING_MODE,
                         ( PUCHAR ) BCRYPT_CHAIN_MODE_ECB,
                         sizeof( BCRYPT_CHAIN_MODE_ECB ), 0 );
   BCryptOpenAlgorithmProvider( &s_hBcSha,
                                BCRYPT_SHA256_ALGORITHM, NULL, 0 );
}

/* Cached AES key to avoid re-importing the same 32-byte key on every page */
static HB_BYTE           s_aesLastKey[ 32 ] = { 0 };
static BCRYPT_KEY_HANDLE s_hBcKey           = NULL;
static PBYTE             s_pBcKeyObj        = NULL;

static void hb_bcryptEnsureKey( const HB_BYTE * aKey )
{
   DWORD cbKeyObj = 0, cbResult = 0;

   hb_bcryptEnsureAlg();
   if( ! s_hBcAes )
      return;

   if( s_hBcKey && memcmp( s_aesLastKey, aKey, 32 ) == 0 )
      return;   /* same key — reuse cached handle */

   if( s_hBcKey )  { BCryptDestroyKey( s_hBcKey ); s_hBcKey = NULL; }
   if( s_pBcKeyObj ) { hb_xfree( s_pBcKeyObj ); s_pBcKeyObj = NULL; }

   BCryptGetProperty( s_hBcAes, BCRYPT_OBJECT_LENGTH,
                      ( PBYTE ) &cbKeyObj, sizeof( cbKeyObj ),
                      &cbResult, 0 );
   s_pBcKeyObj = ( PBYTE ) hb_xgrab( cbKeyObj );

   if( BCryptGenerateSymmetricKey( s_hBcAes, &s_hBcKey,
                                   s_pBcKeyObj, cbKeyObj,
                                   ( PUCHAR ) aKey, 32, 0 ) == 0 )
      memcpy( s_aesLastKey, aKey, 32 );
}

/*
 * AES-256-CTR encrypt/decrypt (symmetric: same function for both).
 * Counter layout (128 bits, big-endian):
 *   [  0.. 7]  block index within the page  (64-bit)
 *   [ 8..15]  page offset / nonce           (64-bit)
 * This guarantees a unique counter for every 16-byte block in the file.
 */
static void s_aesCtr( const HB_BYTE * aKey, HB_BYTE * pBuf,
                      HB_SIZE nSize, HB_FOFFSET nOffset )
{
   HB_BYTE        ctr[ 16 ], ks[ 16 ];
   HB_ULONGLONG   ulOfs   = ( HB_ULONGLONG ) ( HB_LONGLONG ) nOffset;
   HB_ULONGLONG   nBlock  = 0;
   HB_SIZE        i;
   DWORD          cbResult;

   hb_bcryptEnsureKey( aKey );
   if( ! s_hBcKey )
      return;   /* BCrypt unavailable — data unchanged (should never happen) */

   /* Set the page nonce in the lower 8 bytes of the counter block */
   ctr[  8 ] = ( HB_BYTE ) ( ulOfs >> 56 );
   ctr[  9 ] = ( HB_BYTE ) ( ulOfs >> 48 );
   ctr[ 10 ] = ( HB_BYTE ) ( ulOfs >> 40 );
   ctr[ 11 ] = ( HB_BYTE ) ( ulOfs >> 32 );
   ctr[ 12 ] = ( HB_BYTE ) ( ulOfs >> 24 );
   ctr[ 13 ] = ( HB_BYTE ) ( ulOfs >> 16 );
   ctr[ 14 ] = ( HB_BYTE ) ( ulOfs >>  8 );
   ctr[ 15 ] = ( HB_BYTE ) ( ulOfs        );

   for( i = 0; i < nSize; i += 16 )
   {
      HB_SIZE j, nChunk;

      /* Block index in upper 8 bytes */
      ctr[ 0 ] = ( HB_BYTE ) ( nBlock >> 56 );
      ctr[ 1 ] = ( HB_BYTE ) ( nBlock >> 48 );
      ctr[ 2 ] = ( HB_BYTE ) ( nBlock >> 40 );
      ctr[ 3 ] = ( HB_BYTE ) ( nBlock >> 32 );
      ctr[ 4 ] = ( HB_BYTE ) ( nBlock >> 24 );
      ctr[ 5 ] = ( HB_BYTE ) ( nBlock >> 16 );
      ctr[ 6 ] = ( HB_BYTE ) ( nBlock >>  8 );
      ctr[ 7 ] = ( HB_BYTE ) ( nBlock        );
      nBlock++;

      BCryptEncrypt( s_hBcKey, ctr, 16, NULL, NULL, 0,
                     ks, 16, &cbResult, 0 );

      nChunk = nSize - i < 16 ? nSize - i : 16;
      for( j = 0; j < nChunk; j++ )
         pBuf[ i + j ] ^= ks[ j ];
   }
}

/* Key derivation: SHA-256(password) → 32-byte AES key */
static void s_aesDerive( const char * szPassword, HB_BYTE * aKey )
{
   BCRYPT_HASH_HANDLE hHash = NULL;
   HB_BYTE            hashObj[ 512 ];   /* SHA-256 obj is ~60 bytes on Windows */

   hb_bcryptEnsureAlg();

   if( s_hBcSha &&
       BCryptCreateHash( s_hBcSha, &hHash, hashObj, sizeof( hashObj ),
                         NULL, 0, 0 ) == 0 )
   {
      BCryptHashData( hHash, ( PUCHAR ) szPassword,
                      ( ULONG ) strlen( szPassword ), 0 );
      BCryptFinishHash( hHash, aKey, 32, 0 );
      BCryptDestroyHash( hHash );
   }
   else
   {
      /* Fallback: XOR-spread (BCrypt unavailable) */
      HB_BYTE acc = 0x5A;
      HB_SIZE i;
      for( i = 0; szPassword[ i ]; i++ )
         acc ^= ( HB_BYTE ) szPassword[ i ];
      if( acc == 0 ) acc = 0x5A;
      for( i = 0; i < 32; i++ )
         aKey[ i ] = ( HB_BYTE ) ( acc ^ ( HB_BYTE ) i );
   }
}

static const HB_CDXEX_ENGINE s_engineAes =
{
   "aes256",
   s_aesDerive,
   s_aesCtr,   /* encrypt */
   s_aesCtr    /* decrypt (CTR is its own inverse) */
};

/* ======================================================================
   PART 3c - Crypto engine: rot13 (proof-of-concept, letters only)
   Demonstrates that any byte-level transform can be plugged in.
   ROT13 is self-inverse: encrypt == decrypt.
   ====================================================================== */

static void s_rot13Derive( const char * szPassword, HB_BYTE * aKey )
{
   /* Key not used by ROT13; store password bytes as a marker only */
   HB_SIZE len = strlen( szPassword );
   HB_SIZE i;
   for( i = 0; i < 32; i++ )
      aKey[ i ] = ( HB_BYTE ) szPassword[ i % ( len ? len : 1 ) ];
}

static void s_rot13Crypt( const HB_BYTE * aKey, HB_BYTE * pBuf,
                          HB_SIZE nSize, HB_FOFFSET nOffset )
{
   HB_SIZE i;
   HB_SYMBOL_UNUSED( aKey );
   HB_SYMBOL_UNUSED( nOffset );
   for( i = 0; i < nSize; i++ )
   {
      HB_BYTE b = pBuf[ i ];
      if(      b >= 'A' && b <= 'Z' ) pBuf[ i ] = ( HB_BYTE ) ( 'A' + ( b - 'A' + 13 ) % 26 );
      else if( b >= 'a' && b <= 'z' ) pBuf[ i ] = ( HB_BYTE ) ( 'a' + ( b - 'a' + 13 ) % 26 );
   }
}

static const HB_CDXEX_ENGINE s_engineRot13 =
{
   "rot13",
   s_rot13Derive,
   s_rot13Crypt,   /* encrypt */
   s_rot13Crypt    /* decrypt (ROT13 is its own inverse) */
};

/* Engine registry - NULL-terminated, extend here for future engines      */
static const HB_CDXEX_ENGINE * const s_engines[] =
{
   &s_engineDummy,
   &s_engineAes,
   &s_engineRot13,
   NULL
};

static const HB_CDXEX_ENGINE * hb_cdxexFindEngine( const char * szName )
{
   int i;

   for( i = 0; s_engines[ i ]; i++ )
   {
      if( hb_stricmp( s_engines[ i ]->szName, szName ) == 0 )
         return s_engines[ i ];
   }
   return NULL;
}

/* ======================================================================
   PART 4 - CDX page hook implementations (called from macros in Part 1)
   ====================================================================== */

static void hb_cdxexApplyEncrypt( LPCDXEXAREA pExArea, HB_BYTE * pBuf,
                                  HB_SIZE nSize, HB_ULONG ulPage )
{
   if( pExArea->fCryptoActive && pExArea->fOnDiskEncrypted && pExArea->pEngine )
      pExArea->pEngine->fn_encrypt( pExArea->aKey, pBuf, nSize,
                                    ( HB_FOFFSET ) ulPage );
}

static void hb_cdxexApplyDecrypt( LPCDXEXAREA pExArea, HB_BYTE * pBuf,
                                  HB_SIZE nSize, HB_ULONG ulPage )
{
   if( pExArea->fCryptoActive && pExArea->fOnDiskEncrypted && pExArea->pEngine )
      pExArea->pEngine->fn_decrypt( pExArea->aKey, pBuf, nSize,
                                    ( HB_FOFFSET ) ulPage );
}

/* ======================================================================
   PART 4b - DBF record and FPT memo encryption
   ======================================================================
   Invariant: pRecord in DBFAREA always holds ENCRYPTED bytes (same as
   on disk).  getValue decrypts → SUPER → re-encrypts.  putValue does
   the same in reverse.  append encrypts the blank buffer so the
   invariant holds from the moment a new record is created.

   Nonce spaces (prevent (key,nonce) reuse across file types):
     CDX pages : ulPage           (small, < file_size/page_size)
     DBF recs  : 0x0001_0000_0000 + ulRecNo
     FPT memos : 0x0002_0000_0000 + (ulRecNo << 16) + uiField
   ==================================================================== */

#define HB_CDXEX_DBF_BASE   ( ( HB_FOFFSET ) HB_LL( 0x100000000 ) )
#define HB_CDXEX_MEMO_BASE  ( ( HB_FOFFSET ) HB_LL( 0x200000000 ) )

/* Encrypt or decrypt pRecord in-place.  Uses ulRecNo as per-record nonce. */
static void hb_cdxexCryptRecord( LPCDXEXAREA pEx, HB_BOOL bEncrypt )
{
   AREAP    pArea = ( AREAP ) pEx;
   DBFAREAP pDbf  = &pEx->cdxarea.dbfarea;

   if( ! pEx->fCryptoActive || ! pEx->fOnDiskEncrypted || ! pEx->pEngine )
      return;
   if( pArea->fEof || pDbf->ulRecNo == 0 )
      return;

   if( bEncrypt )
      pEx->pEngine->fn_encrypt( pEx->aKey, pDbf->pRecord,
                                pDbf->uiRecordLen,
                                HB_CDXEX_DBF_BASE + ( HB_FOFFSET ) pDbf->ulRecNo );
   else
      pEx->pEngine->fn_decrypt( pEx->aKey, pDbf->pRecord,
                                pDbf->uiRecordLen,
                                HB_CDXEX_DBF_BASE + ( HB_FOFFSET ) pDbf->ulRecNo );

}

/* ======================================================================
   PART 5 - Global pending setup (consumed once per USE/CREATE)
   ====================================================================== */

static char s_szPendingEngine[ 32 ] = "";
static char s_szPendingPass[ 256 ]  = "";

/* ======================================================================
   PART 6 - DBFCDXEX RDD overrides
   ====================================================================== */

static RDDFUNCS   cdxexSuper;
static HB_USHORT  s_cdxexRddId = 0;

/* Redefine SUPERTABLE so SUPER_xxx macros in our functions use cdxexSuper */
#undef  SUPERTABLE
#define SUPERTABLE  ( &cdxexSuper )

/* append: SUPER creates a blank record; encrypt it to maintain Invariant D
 * (pRecord is always in encrypted state in memory).                      */
static HB_ERRCODE hb_cdxexAppend( AREAP pArea, HB_BOOL bUnLockAll )
{
   LPCDXEXAREA pEx     = ( LPCDXEXAREA ) pArea;
   HB_ERRCODE  errCode;

   errCode = SUPER_APPEND( pArea, bUnLockAll );

   if( errCode == HB_SUCCESS && pEx->fCryptoActive && pEx->fOnDiskEncrypted )
      hb_cdxexCryptRecord( pEx, HB_TRUE );
   return errCode;
}

/* getValue: decrypt → SUPER (reads plaintext) → re-encrypt.
 * For memo fields: also decrypt the FPT string SUPER returned.
 *
 * hb_dbfGoTo sets fValidBuffer=FALSE without reading from disk (lazy read).
 * hb_dbfGetValue then reads on demand inside SUPER_GETVALUE, AFTER our
 * decrypt has already run on the stale blank buffer.  Fix: force the lazy
 * disk read via SUPER_DELETED before our decrypt, so pRecord has the
 * encrypted on-disk content when we XOR it.                               */
static HB_ERRCODE hb_cdxexGetValue( AREAP pArea, HB_USHORT uiIndex,
                                    PHB_ITEM pItem )
{
   LPCDXEXAREA pEx  = ( LPCDXEXAREA ) pArea;
   DBFAREAP    pDbf = &pEx->cdxarea.dbfarea;
   HB_ERRCODE  errCode;
   HB_BOOL     bMemo;

   if( ! pEx->fCryptoActive || ! pEx->fOnDiskEncrypted || pArea->fEof || pDbf->ulRecNo == 0 )
      return SUPER_GETVALUE( pArea, uiIndex, pItem );

   bMemo = ( uiIndex >= 1 && uiIndex <= pArea->uiFieldCount &&
             ( pArea->lpFields[ uiIndex - 1 ].uiType == HB_FT_MEMO ||
               pArea->lpFields[ uiIndex - 1 ].uiType == HB_FT_ANY ) );

   /* Force lazy disk read if fValidBuffer is FALSE (e.g. after GOTO) */
   if( ! pDbf->fValidBuffer )
   {
      HB_BOOL bDel = HB_FALSE;
      SUPER_DELETED( pArea, &bDel );
   }

   hb_cdxexCryptRecord( pEx, HB_FALSE );
   errCode = SUPER_GETVALUE( pArea, uiIndex, pItem );
   hb_cdxexCryptRecord( pEx, HB_TRUE );

   if( errCode == HB_SUCCESS && bMemo && HB_IS_STRING( pItem ) )
   {
      HB_SIZE    nLen   = hb_itemGetCLen( pItem );
      HB_BYTE *  pBuf   = ( HB_BYTE * ) hb_xgrab( nLen + 1 );
      HB_FOFFSET nNonce = HB_CDXEX_MEMO_BASE +
                          ( HB_FOFFSET ) ( ( HB_ULONGLONG ) pDbf->ulRecNo << 16 ) +
                          ( HB_FOFFSET ) uiIndex;

      memcpy( pBuf, hb_itemGetCPtr( pItem ), nLen );
      pBuf[ nLen ] = 0;
      pEx->pEngine->fn_decrypt( pEx->aKey, pBuf, nLen, nNonce );
      hb_itemPutCL( pItem, ( const char * ) pBuf, nLen );
      hb_xfree( pBuf );
   }
   return errCode;
}

/* putValue: encrypt memo content before storing; for all fields
 * decrypt → SUPER → re-encrypt to keep pRecord in encrypted state.  */
static HB_ERRCODE hb_cdxexPutValue( AREAP pArea, HB_USHORT uiIndex,
                                    PHB_ITEM pItem )
{
   LPCDXEXAREA pEx  = ( LPCDXEXAREA ) pArea;
   DBFAREAP    pDbf = &pEx->cdxarea.dbfarea;
   HB_ERRCODE  errCode;
   PHB_ITEM    pEncItem = NULL;
   HB_BOOL     bMemo;

   if( ! pEx->fCryptoActive || ! pEx->fOnDiskEncrypted || pArea->fEof || pDbf->ulRecNo == 0 )
      return SUPER_PUTVALUE( pArea, uiIndex, pItem );

   bMemo = ( uiIndex >= 1 && uiIndex <= pArea->uiFieldCount &&
             ( pArea->lpFields[ uiIndex - 1 ].uiType == HB_FT_MEMO ||
               pArea->lpFields[ uiIndex - 1 ].uiType == HB_FT_ANY ) );

   if( bMemo && HB_IS_STRING( pItem ) )
   {
      HB_SIZE    nLen   = hb_itemGetCLen( pItem );
      HB_BYTE *  pBuf   = ( HB_BYTE * ) hb_xgrab( nLen + 1 );
      HB_FOFFSET nNonce = HB_CDXEX_MEMO_BASE +
                          ( HB_FOFFSET ) ( ( HB_ULONGLONG ) pDbf->ulRecNo << 16 ) +
                          ( HB_FOFFSET ) uiIndex;

      memcpy( pBuf, hb_itemGetCPtr( pItem ), nLen );
      pBuf[ nLen ] = 0;
      pEx->pEngine->fn_encrypt( pEx->aKey, pBuf, nLen, nNonce );
      pEncItem = hb_itemNew( NULL );
      hb_itemPutCL( pEncItem, ( const char * ) pBuf, nLen );
      hb_xfree( pBuf );
   }

   /* Force lazy disk read if fValidBuffer is FALSE (e.g. after GOTO) */
   if( ! pDbf->fValidBuffer )
   {
      HB_BOOL bDel = HB_FALSE;
      SUPER_DELETED( pArea, &bDel );
   }

   hb_cdxexCryptRecord( pEx, HB_FALSE );
   errCode = SUPER_PUTVALUE( pArea, uiIndex, pEncItem ? pEncItem : pItem );
   hb_cdxexCryptRecord( pEx, HB_TRUE );

   if( pEncItem )
      hb_itemRelease( pEncItem );

   return errCode;
}

/* structSize: return size of our extended work area */
static HB_ERRCODE hb_cdxexStructSize( AREAP pArea, HB_USHORT * uiSize )
{
   HB_SYMBOL_UNUSED( pArea );
   *uiSize = sizeof( CDXEXAREA );
   return HB_SUCCESS;
}

/* newArea: initialise the extended fields after the parent initialises   */
static HB_ERRCODE hb_cdxexNewArea( AREAP pArea )
{
   HB_ERRCODE  errCode = SUPER_NEW( pArea );

   if( errCode == HB_SUCCESS )
   {
      LPCDXEXAREA pEx = ( LPCDXEXAREA ) pArea;
      pEx->pEngine          = NULL;
      memset( pEx->aKey, 0, sizeof( pEx->aKey ) );
      pEx->fCryptoActive    = HB_FALSE;
      pEx->fOnDiskEncrypted = HB_FALSE;
   }
   return errCode;
}

/* Consume s_szPendingEngine/Pass and initialise pExArea crypto fields    */
static void hb_cdxexActivateCrypto( LPCDXEXAREA pEx )
{
   const HB_CDXEX_ENGINE * pEng;

   if( s_szPendingEngine[ 0 ] == '\0' )
      return;

   pEng = hb_cdxexFindEngine( s_szPendingEngine );
   if( pEng )
   {
      pEx->pEngine = pEng;
      pEng->fn_derive( s_szPendingPass, pEx->aKey );
      pEx->fCryptoActive = HB_TRUE;
   }
   s_szPendingEngine[ 0 ] = '\0';
   s_szPendingPass[ 0 ]   = '\0';
}

/* open: activate crypto then delegate; set fOnDiskEncrypted by reading byte 28 */
static HB_ERRCODE hb_cdxexOpen( AREAP pArea, LPDBOPENINFO pOpenInfo )
{
   LPCDXEXAREA pEx = ( LPCDXEXAREA ) pArea;
   HB_ERRCODE  errCode;
   HB_BYTE     b;

   hb_cdxexActivateCrypto( pEx );
   errCode = SUPER_OPEN( pArea, pOpenInfo );
   if( errCode == HB_SUCCESS && pEx->fCryptoActive )
   {
      DBFAREAP pDbf = &pEx->cdxarea.dbfarea;
      if( pDbf->pDataFile &&
          hb_fileReadAt( pDbf->pDataFile, &b, 1,
                         ( HB_FOFFSET ) HB_CDXEX_HDR_CRYPT_OFS ) == 1 )
         pEx->fOnDiskEncrypted = ( b == HB_CDXEX_HDR_CRYPT_MAGIC );
   }
   return errCode;
}

/* create: activate crypto; set fOnDiskEncrypted before SUPER_CREATE so that
 * hb_cdxexWriteDBHeader (called from within SUPER_CREATE) will stamp byte 28 */
static HB_ERRCODE hb_cdxexCreate( AREAP pArea, LPDBOPENINFO pOpenInfo )
{
   LPCDXEXAREA pEx = ( LPCDXEXAREA ) pArea;

   hb_cdxexActivateCrypto( pEx );
   if( pEx->fCryptoActive )
      pEx->fOnDiskEncrypted = HB_TRUE;
   return SUPER_CREATE( pArea, pOpenInfo );
}

/* writeDBHeader: after the parent writes the DBF header (which may reset
 * byte 28), re-stamp the encryption marker if live crypto is active.     */
static HB_ERRCODE hb_cdxexWriteDBHeader( AREAP pArea )
{
   LPCDXEXAREA pEx     = ( LPCDXEXAREA ) pArea;
   HB_ERRCODE  errCode = SUPER_WRITEDBHEADER( pArea );

   if( errCode == HB_SUCCESS && pEx->fCryptoActive && pEx->fOnDiskEncrypted )
      hb_cdxexHdrMarker( &pEx->cdxarea.dbfarea, HB_TRUE );
   return errCode;
}

/* close: zero crypto state after parent close                            */
static HB_ERRCODE hb_cdxexClose( AREAP pArea )
{
   LPCDXEXAREA pEx     = ( LPCDXEXAREA ) pArea;
   HB_ERRCODE  errCode = SUPER_CLOSE( pArea );

   pEx->pEngine          = NULL;
   memset( pEx->aKey, 0, sizeof( pEx->aKey ) );
   pEx->fCryptoActive    = HB_FALSE;
   pEx->fOnDiskEncrypted = HB_FALSE;

   return errCode;
}

/* ======================================================================
   PART 7 - RDDFUNCS table for DBFCDXEX
   Non-NULL entries override; NULL entries inherit from cdxexSuper (DBFCDX).
   ====================================================================== */

static const RDDFUNCS cdxexTable =
{
   /* Movement and positioning */
   ( DBENTRYP_BP )    NULL,  /* bof            */
   ( DBENTRYP_BP )    NULL,  /* eof            */
   ( DBENTRYP_BP )    NULL,  /* found          */
   ( DBENTRYP_V )     NULL,  /* goBottom       */
   ( DBENTRYP_UL )    NULL,  /* go             */
   ( DBENTRYP_I )     NULL,  /* goToId         */
   ( DBENTRYP_V )     NULL,  /* goTop          */
   ( DBENTRYP_BIB )   NULL,  /* seek           */
   ( DBENTRYP_L )     NULL,  /* skip           */
   ( DBENTRYP_L )     NULL,  /* skipFilter     */
   ( DBENTRYP_L )     NULL,  /* skipRaw        */

   /* Data management */
   ( DBENTRYP_VF )    NULL,                    /* addField       */
   ( DBENTRYP_B )     hb_cdxexAppend,          /* append         */
   ( DBENTRYP_I )     NULL,                    /* createFields   */
   ( DBENTRYP_V )     NULL,                    /* deleteRec      */
   ( DBENTRYP_BP )    NULL,                    /* deleted        */
   ( DBENTRYP_SP )    NULL,                    /* fieldCount     */
   ( DBENTRYP_VF )    NULL,                    /* fieldDisplay   */
   ( DBENTRYP_SSI )   NULL,                    /* fieldInfo      */
   ( DBENTRYP_SCP )   NULL,                    /* fieldName      */
   ( DBENTRYP_V )     NULL,                    /* flush          */
   ( DBENTRYP_PP )    NULL,                    /* getRec         */
   ( DBENTRYP_SI )    hb_cdxexGetValue,        /* getValue       */
   ( DBENTRYP_SVL )   NULL,  /* getVarLen      */
   ( DBENTRYP_V )     NULL,  /* goCold         */
   ( DBENTRYP_V )     NULL,  /* goHot          */
   ( DBENTRYP_P )     NULL,  /* putRec         */
   ( DBENTRYP_SI )    hb_cdxexPutValue,        /* putValue       */
   ( DBENTRYP_V )     NULL,  /* recall         */
   ( DBENTRYP_ULP )   NULL,  /* recCount       */
   ( DBENTRYP_ISI )   NULL,  /* recInfo        */
   ( DBENTRYP_ULP )   NULL,  /* recNo          */
   ( DBENTRYP_I )     NULL,  /* recId          */
   ( DBENTRYP_S )     NULL,  /* setFieldExtent */

   /* WorkArea/Database management */
   ( DBENTRYP_CP )    NULL,               /* alias      */
   ( DBENTRYP_V )     hb_cdxexClose,      /* close      */
   ( DBENTRYP_VO )    hb_cdxexCreate,     /* create     */
   ( DBENTRYP_SI )    NULL,               /* info       */
   ( DBENTRYP_V )     hb_cdxexNewArea,    /* newarea    */
   ( DBENTRYP_VO )    hb_cdxexOpen,       /* open       */
   ( DBENTRYP_V )     NULL,               /* release    */
   ( DBENTRYP_SP )    hb_cdxexStructSize, /* structSize */
   ( DBENTRYP_CP )    NULL,               /* sysName    */
   ( DBENTRYP_VEI )   NULL,               /* dbEval     */
   ( DBENTRYP_V )     NULL,               /* pack       */
   ( DBENTRYP_LSP )   NULL,               /* packRec    */
   ( DBENTRYP_VS )    NULL,               /* sort       */
   ( DBENTRYP_VT )    NULL,               /* trans      */
   ( DBENTRYP_VT )    NULL,               /* transRec   */
   ( DBENTRYP_V )     NULL,               /* zap        */

   /* Relational Methods */
   ( DBENTRYP_VR )    NULL,  /* childEnd      */
   ( DBENTRYP_VR )    NULL,  /* childStart    */
   ( DBENTRYP_VR )    NULL,  /* childSync     */
   ( DBENTRYP_V )     NULL,  /* syncChildren  */
   ( DBENTRYP_V )     NULL,  /* clearRel      */
   ( DBENTRYP_V )     NULL,  /* forceRel      */
   ( DBENTRYP_SSP )   NULL,  /* relArea       */
   ( DBENTRYP_VR )    NULL,  /* relEval       */
   ( DBENTRYP_SI )    NULL,  /* relText       */
   ( DBENTRYP_VR )    NULL,  /* setRel        */

   /* Order Management */
   ( DBENTRYP_VOI )   NULL,  /* orderListAdd     */
   ( DBENTRYP_V )     NULL,  /* orderListClear   */
   ( DBENTRYP_VOI )   NULL,  /* orderListDelete  */
   ( DBENTRYP_VOI )   NULL,  /* orderListFocus   */
   ( DBENTRYP_V )     NULL,  /* orderListRebuild */
   ( DBENTRYP_VOO )   NULL,  /* orderCondition   */
   ( DBENTRYP_VOC )   NULL,  /* orderCreate      */
   ( DBENTRYP_VOI )   NULL,  /* orderDestroy     */
   ( DBENTRYP_SVOI )  NULL,  /* orderInfo        */

   /* Filters and Scope */
   ( DBENTRYP_V )     NULL,  /* clearFilter */
   ( DBENTRYP_V )     NULL,  /* clearLocate */
   ( DBENTRYP_V )     NULL,  /* clearScope  */
   ( DBENTRYP_VPLP )  NULL,  /* countScope  */
   ( DBENTRYP_I )     NULL,  /* filterText  */
   ( DBENTRYP_SI )    NULL,  /* scopeInfo   */
   ( DBENTRYP_VFI )   NULL,  /* setFilter   */
   ( DBENTRYP_VLO )   NULL,  /* setLocate   */
   ( DBENTRYP_VOS )   NULL,  /* setScope    */
   ( DBENTRYP_VPL )   NULL,  /* skipScope   */
   ( DBENTRYP_B )     NULL,  /* locate      */

   /* Miscellaneous */
   ( DBENTRYP_CC )    NULL,  /* compile   */
   ( DBENTRYP_I )     NULL,  /* error     */
   ( DBENTRYP_I )     NULL,  /* evalBlock */

   /* Network operations */
   ( DBENTRYP_VSP )   NULL,  /* rawLock */
   ( DBENTRYP_VL )    NULL,  /* lock    */
   ( DBENTRYP_I )     NULL,  /* unlock  */

   /* Memofile functions */
   ( DBENTRYP_V )     NULL,  /* closeMemFile  */
   ( DBENTRYP_VO )    NULL,  /* createMemFile */
   ( DBENTRYP_SCCS )  NULL,  /* getValueFile  */
   ( DBENTRYP_VO )    NULL,  /* openMemFile   */
   ( DBENTRYP_SCCS )  NULL,  /* putValueFile  */

   /* Database file header handling */
   ( DBENTRYP_V )     NULL,                       /* readDBHeader  */
   ( DBENTRYP_V )     hb_cdxexWriteDBHeader,      /* writeDBHeader */

   /* Non-WorkArea functions */
   ( DBENTRYP_R )     NULL,  /* init    */
   ( DBENTRYP_R )     NULL,  /* exit    */
   ( DBENTRYP_RVVL )  NULL,  /* drop    */
   ( DBENTRYP_RVVL )  NULL,  /* exists  */
   ( DBENTRYP_RVVVL ) NULL,  /* rename  */
   ( DBENTRYP_RSLV )  NULL,  /* rddInfo */

   /* Special */
   ( DBENTRYP_SVP )   NULL   /* whoCares */
};

/* ======================================================================
   PART 8 - RDD registration
   ====================================================================== */

HB_FUNC_STATIC( DBFCDXEX_GETFUNCTABLE )
{
   RDDFUNCS *  pTable        = ( RDDFUNCS * ) hb_parptr( 2 );
   HB_USHORT * puiCount      = ( HB_USHORT * ) hb_parptr( 1 );
   HB_USHORT   uiRddId       = ( HB_USHORT ) hb_parni( 4 );
   HB_USHORT * puiSuperRddId = ( HB_USHORT * ) hb_parptr( 5 );

   if( pTable )
   {
      HB_ERRCODE errCode;

      if( puiCount )
         *puiCount = RDDFUNCSCOUNT;

      /* Inherit from DBFCDX: our overrides in cdxexTable win; everything
       * else (GoBottom, Seek, OrderCreate, etc.) is taken from DBFCDX.   */
      errCode = hb_rddInheritEx( pTable, &cdxexTable, &cdxexSuper,
                                 "DBFCDX", puiSuperRddId );
      if( errCode == HB_SUCCESS )
         s_cdxexRddId = uiRddId;

      hb_retni( errCode );
   }
   else
      hb_retni( HB_FAILURE );
}

static void hb_cdxexRddInit( void * cargo )
{
   HB_SYMBOL_UNUSED( cargo );

   /* Ensure the dependency chain is registered before DBFCDXEX           */
   if( hb_rddRegister( "DBF",      RDT_FULL ) <= 1 )
   {
      hb_rddRegister( "DBFFPT",   RDT_FULL );
      if( hb_rddRegister( "DBFCDX",  RDT_FULL ) <= 1 )
      {
         if( hb_rddRegister( "DBFCDXEX", RDT_FULL ) <= 1 )
            return;
      }
   }
   hb_errInternal( HB_EI_RDDINVALID, NULL, NULL, NULL );
}

/* Public entry point - REQUEST DBFCDXEX in .prg pulls this symbol in     */
HB_FUNC( DBFCDXEX ) {}

HB_INIT_SYMBOLS_BEGIN( _hb_dbfcdxex_InitSymbols_ )
{ "DBFCDXEX",              { HB_FS_PUBLIC | HB_FS_LOCAL },
                           { HB_FUNCNAME( DBFCDXEX )              }, NULL },
{ "DBFCDXEX_GETFUNCTABLE", { HB_FS_PUBLIC | HB_FS_LOCAL },
                           { HB_FUNCNAME( DBFCDXEX_GETFUNCTABLE ) }, NULL }
HB_INIT_SYMBOLS_END( _hb_dbfcdxex_InitSymbols_ )

HB_CALL_ON_STARTUP_BEGIN( _hb_dbfcdxex_rdd_init_ )
   hb_vmAtInit( hb_cdxexRddInit, NULL );
HB_CALL_ON_STARTUP_END( _hb_dbfcdxex_rdd_init_ )

#if defined( HB_PRAGMA_STARTUP )
   #pragma startup _hb_dbfcdxex_InitSymbols_
   #pragma startup _hb_dbfcdxex_rdd_init_
#elif defined( HB_DATASEG_STARTUP )
   #define HB_DATASEG_BODY    HB_DATASEG_FUNC( _hb_dbfcdxex_InitSymbols_ ) \
                              HB_DATASEG_FUNC( _hb_dbfcdxex_rdd_init_ )
   #include "hbiniseg.h"
#endif

/* ======================================================================
   PART 9 - Harbour-visible API
   ====================================================================== */

/*
 * DbfcdxexSetup( cEngine, cPassword ) -> NIL
 *
 * Must be called immediately before USE ... VIA 'DBFCDXEX' or
 * dbCreate(..., 'DBFCDXEX').  The pending state is consumed (cleared)
 * by the first subsequent open/create on a DBFCDXEX area.
 *
 * To clear a pending setup (e.g. on error before USE), call with no args.
 */
HB_FUNC( DBFCDXEXSETUP )
{
   const char * szEngine = hb_parc( 1 );
   const char * szPass   = hb_parc( 2 );

   if( szEngine && *szEngine )
   {
      hb_strncpy( s_szPendingEngine, szEngine,
                  sizeof( s_szPendingEngine ) - 1 );
      hb_strncpy( s_szPendingPass, szPass ? szPass : "",
                  sizeof( s_szPendingPass ) - 1 );
   }
   else
   {
      s_szPendingEngine[ 0 ] = '\0';
      s_szPendingPass[ 0 ]   = '\0';
   }
}

/* ======================================================================
   PART 10 - Table management API (similar to AdsEncryptTable / AdsIsTableEncrypted)

   Marker: byte 28 (0-indexed) in the DBF header is unused by DBFCDX.
   We write 0xCE there to flag on-disk DBFCDXEX encryption.  Both the
   encrypt and decrypt functions write/clear this byte atomically.

   CDX indexes: EncryptTable and DecryptTable CLOSE and DELETE all open
   CDX files.  The caller must rebuild indexes after either operation.
   ====================================================================== */

/* Helper: is the current work area a live DBFCDXEX area? */
static HB_BOOL hb_cdxexCurArea( LPCDXEXAREA * ppEx )
{
   AREAP pArea = ( AREAP ) hb_rddGetCurrentWorkAreaPointer();
   if( pArea && pArea->rddID == s_cdxexRddId )
   {
      *ppEx = ( LPCDXEXAREA ) pArea;
      return HB_TRUE;
   }
   return HB_FALSE;
}

/* Helper: read/write the single marker byte in the DBF header */
static HB_BOOL hb_cdxexHdrMarker( DBFAREAP pDbf, HB_BOOL bSet )
{
   HB_BYTE b = bSet ? HB_CDXEX_HDR_CRYPT_MAGIC : 0;
   return hb_fileWriteAt( pDbf->pDataFile, &b, 1,
                          ( HB_FOFFSET ) HB_CDXEX_HDR_CRYPT_OFS ) == 1;
}

/* Helper: close all CDX index files attached to this area and delete them
 * from disk.  Must be called before an in-place encrypt/decrypt pass so
 * that index pages are not left in a mixed (partial) crypto state.       */
static void hb_cdxexDropIndexes( AREAP pArea )
{
   LPCDXAREA  pCdx = ( LPCDXAREA ) pArea;
   LPCDXINDEX pIdx;
   char **    aNames = NULL;
   int        nCount = 0, i;

   for( pIdx = pCdx->lpIndexes; pIdx; pIdx = pIdx->pNext )
      nCount++;

   if( nCount > 0 )
   {
      aNames = ( char ** ) hb_xgrab( nCount * sizeof( char * ) );
      for( i = 0, pIdx = pCdx->lpIndexes; pIdx; pIdx = pIdx->pNext, i++ )
         aNames[ i ] = hb_strdup( pIdx->szFileName );

      SELF_ORDLSTCLEAR( pArea );

      for( i = 0; i < nCount; i++ )
      {
         if( aNames[ i ] )
         {
            hb_fileDelete( aNames[ i ] );
            hb_xfree( aNames[ i ] );
         }
      }
      hb_xfree( aNames );
   }
}

/*
 * CDXEX_IsTableEncrypted( [cFile] ) → .T. / .F.
 *
 * If cFile is given, opens the file directly and reads byte 28 — no open
 * work area required.  Without cFile, reads from the current work area.
 */
HB_FUNC( CDXEX_ISTABLEENCRYPTED )
{
   const char * szFile  = hb_parc( 1 );
   HB_BYTE      hdr[ 32 ];
   HB_BOOL      bResult = HB_FALSE;

   if( szFile && *szFile )
   {
      HB_FHANDLE hFH = hb_fsOpen( szFile, FO_READ | FO_DENYNONE );
      if( hFH != FS_ERROR )
      {
         if( hb_fsReadAt( hFH, hdr, 32, 0 ) == 32 )
            bResult = ( hdr[ HB_CDXEX_HDR_CRYPT_OFS ] == HB_CDXEX_HDR_CRYPT_MAGIC );
         hb_fsClose( hFH );
      }
   }
   else
   {
      AREAP    pArea = ( AREAP ) hb_rddGetCurrentWorkAreaPointer();
      DBFAREAP pDbf;
      if( pArea )
      {
         pDbf = ( DBFAREAP ) pArea;
         if( pDbf->pDataFile &&
             hb_fileReadAt( pDbf->pDataFile, hdr, 32, 0 ) == 32 )
            bResult = ( hdr[ HB_CDXEX_HDR_CRYPT_OFS ] == HB_CDXEX_HDR_CRYPT_MAGIC );
      }
   }
   hb_retl( bResult );
}

/*
 * CDXEX_EncryptTable() → .T. on success
 *
 * Encrypts all DBF records of the currently selected table IN PLACE.
 * Requirements:
 *   - Table must be open EXCLUSIVE via DBFCDXEX
 *   - DbfcdxexSetup() must have been called before the USE
 *   - Table must NOT already be encrypted
 *
 * Side effects:
 *   - All open CDX index files are CLOSED and DELETED from disk
 *   - Caller must rebuild indexes after this call
 *   - FPT memo blocks are NOT encrypted (future enhancement)
 */
HB_FUNC( CDXEX_ENCRYPTTABLE )
{
   LPCDXEXAREA  pEx;
   DBFAREAP     pDbf;
   HB_BYTE      hdr[ 32 ], * pBuf;
   HB_ULONG     i;
   HB_FOFFSET   nOfs;
   HB_BOOL      bOk = HB_FALSE;

   if( ! hb_cdxexCurArea( &pEx ) )
   {
      hb_errRT_BASE( EG_OPEN, 2001,
         "Work area is not open via DBFCDXEX", "CDXEX_EncryptTable", 0 );
      hb_retl( HB_FALSE );
      return;
   }
   pDbf = &pEx->cdxarea.dbfarea;

   if( ! pEx->fCryptoActive )
   {
      hb_errRT_BASE( EG_OPEN, 2002,
         "Call DbfcdxexSetup() before USE to set the encryption key",
         "CDXEX_EncryptTable", 0 );
      hb_retl( HB_FALSE );
      return;
   }
   if( pDbf->fShared )
   {
      hb_errRT_BASE( EG_OPEN, 2003,
         "Table must be open EXCLUSIVE", "CDXEX_EncryptTable", 0 );
      hb_retl( HB_FALSE );
      return;
   }

   /* abort if already encrypted */
   if( hb_fileReadAt( pDbf->pDataFile, hdr, 32, 0 ) == 32 &&
       hdr[ HB_CDXEX_HDR_CRYPT_OFS ] == HB_CDXEX_HDR_CRYPT_MAGIC )
   {
      hb_retl( HB_FALSE );
      return;
   }

   /* close + delete CDX files (they must be rebuilt after encrypt) */
   hb_cdxexDropIndexes( ( AREAP ) pEx );

   /* flush any pending RDD write before touching the file directly */
   SELF_FLUSH( ( AREAP ) pEx );

   /* encrypt each record in place using direct file I/O */
   pBuf = ( HB_BYTE * ) hb_xgrab( pDbf->uiRecordLen );
   bOk  = HB_TRUE;

   for( i = 1; i <= pDbf->ulRecCount && bOk; i++ )
   {
      nOfs = ( HB_FOFFSET ) pDbf->uiHeaderLen +
             ( HB_FOFFSET ) ( i - 1 ) * ( HB_FOFFSET ) pDbf->uiRecordLen;

      if( hb_fileReadAt( pDbf->pDataFile, pBuf,
                         pDbf->uiRecordLen, nOfs ) != pDbf->uiRecordLen )
      { bOk = HB_FALSE; break; }

      pEx->pEngine->fn_encrypt( pEx->aKey, pBuf, pDbf->uiRecordLen,
                                HB_CDXEX_DBF_BASE + ( HB_FOFFSET ) i );

      if( hb_fileWriteAt( pDbf->pDataFile, pBuf,
                          pDbf->uiRecordLen, nOfs ) != pDbf->uiRecordLen )
      { bOk = HB_FALSE; break; }
   }
   hb_xfree( pBuf );

   if( bOk )
   {
      hb_cdxexHdrMarker( pDbf, HB_TRUE );
      hb_fileFlush( pDbf->pDataFile, HB_TRUE );
      pDbf->fValidBuffer    = HB_FALSE;
      pEx->fOnDiskEncrypted = HB_TRUE;
   }
   hb_retl( bOk );
}

/*
 * CDXEX_DecryptTable() → .T. on success
 *
 * Decrypts all DBF records of the currently selected table IN PLACE.
 * Requirements: same as CDXEX_EncryptTable — open EXCLUSIVE via DBFCDXEX.
 *
 * After success:
 *   - Data on disk is plaintext
 *   - All CDX files are CLOSED and DELETED (caller must reindex)
 *   - The work area crypto is deactivated (reads/writes are plain)
 *   - To continue working with the table, close and reopen via DBFCDX
 */
HB_FUNC( CDXEX_DECRYPTTABLE )
{
   LPCDXEXAREA  pEx;
   DBFAREAP     pDbf;
   HB_BYTE      hdr[ 32 ], * pBuf;
   HB_ULONG     i;
   HB_FOFFSET   nOfs;
   HB_BOOL      bOk = HB_FALSE;

   if( ! hb_cdxexCurArea( &pEx ) )
   {
      hb_errRT_BASE( EG_OPEN, 2001,
         "Work area is not open via DBFCDXEX", "CDXEX_DecryptTable", 0 );
      hb_retl( HB_FALSE );
      return;
   }
   pDbf = &pEx->cdxarea.dbfarea;

   if( ! pEx->fCryptoActive )
   {
      hb_errRT_BASE( EG_OPEN, 2002,
         "Call DbfcdxexSetup() before USE to set the decryption key",
         "CDXEX_DecryptTable", 0 );
      hb_retl( HB_FALSE );
      return;
   }
   if( pDbf->fShared )
   {
      hb_errRT_BASE( EG_OPEN, 2003,
         "Table must be open EXCLUSIVE", "CDXEX_DecryptTable", 0 );
      hb_retl( HB_FALSE );
      return;
   }

   /* abort if not encrypted */
   if( hb_fileReadAt( pDbf->pDataFile, hdr, 32, 0 ) != 32 ||
       hdr[ HB_CDXEX_HDR_CRYPT_OFS ] != HB_CDXEX_HDR_CRYPT_MAGIC )
   {
      hb_retl( HB_FALSE );
      return;
   }

   hb_cdxexDropIndexes( ( AREAP ) pEx );
   SELF_FLUSH( ( AREAP ) pEx );

   pBuf = ( HB_BYTE * ) hb_xgrab( pDbf->uiRecordLen );
   bOk  = HB_TRUE;

   for( i = 1; i <= pDbf->ulRecCount && bOk; i++ )
   {
      nOfs = ( HB_FOFFSET ) pDbf->uiHeaderLen +
             ( HB_FOFFSET ) ( i - 1 ) * ( HB_FOFFSET ) pDbf->uiRecordLen;

      if( hb_fileReadAt( pDbf->pDataFile, pBuf,
                         pDbf->uiRecordLen, nOfs ) != pDbf->uiRecordLen )
      { bOk = HB_FALSE; break; }

      pEx->pEngine->fn_decrypt( pEx->aKey, pBuf, pDbf->uiRecordLen,
                                HB_CDXEX_DBF_BASE + ( HB_FOFFSET ) i );

      if( hb_fileWriteAt( pDbf->pDataFile, pBuf,
                          pDbf->uiRecordLen, nOfs ) != pDbf->uiRecordLen )
      { bOk = HB_FALSE; break; }
   }
   hb_xfree( pBuf );

   if( bOk )
   {
      hb_cdxexHdrMarker( pDbf, HB_FALSE );
      hb_fileFlush( pDbf->pDataFile, HB_TRUE );
      pDbf->fValidBuffer    = HB_FALSE;
      pEx->fCryptoActive    = HB_FALSE;
      pEx->fOnDiskEncrypted = HB_FALSE;
   }
   hb_retl( bOk );
}

/*
 * CDXEX_Info() → cString
 *
 * Returns a one-line summary of the current work area's encryption state.
 * Useful for debugging and diagnostics.
 */
HB_FUNC( CDXEX_INFO )
{
   LPCDXEXAREA  pEx;
   DBFAREAP     pDbf;
   HB_BYTE      hdr[ 32 ];
   HB_BOOL      bMarked = HB_FALSE;
   char         buf[ 256 ];

   if( ! hb_cdxexCurArea( &pEx ) )
   {
      AREAP pArea = ( AREAP ) hb_rddGetCurrentWorkAreaPointer();
      {
         LPRDDNODE pNode = pArea ? hb_rddGetNode( pArea->rddID ) : NULL;
         hb_snprintf( buf, sizeof( buf ), "RDD: %s | No DBFCDXEX area selected",
                      pNode ? pNode->szName : "(none)" );
      }
      hb_retc( buf );
      return;
   }
   pDbf = &pEx->cdxarea.dbfarea;

   if( pDbf->pDataFile &&
       hb_fileReadAt( pDbf->pDataFile, hdr, 32, 0 ) == 32 )
      bMarked = ( hdr[ HB_CDXEX_HDR_CRYPT_OFS ] == HB_CDXEX_HDR_CRYPT_MAGIC );

   hb_snprintf( buf, sizeof( buf ),
                "DBFCDXEX | Engine: %-8s | KeyActive: %s | OnDisk: %s | Records: %lu | Mode: %s",
                pEx->pEngine ? pEx->pEngine->szName : "(none)",
                pEx->fCryptoActive ? "YES" : "NO",
                bMarked ? "ENCRYPTED" : "PLAIN",
                ( unsigned long ) pDbf->ulRecCount,
                pDbf->fShared ? "SHARED" : "EXCLUSIVE" );
   hb_retc( buf );
}
