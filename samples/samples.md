# 🧪 DBFCDXEX Samples 

All samples share the same database structure and password so you can follow
the progression from start to finish.  Each sample is self-contained: it
creates the data it needs, so you can run any one independently.

| Constant   | Value        |
|------------|--------------|
| Engine     | `aes256`     |
| Password   | `Secreto123` |
| Table      | `clientes.dbf` |
| Fields     | ID (N,4), NOMBRE (C,30), IMPORTE (N,9,2) |

---

## 👉 sample01 - Encrypt a plain DBF table

**Build & run:** `go_01.bat`

What it does:
1. Creates a plain `clientes.dbf` with 3 records using the standard DBFCDX driver.
2. Calls `DbfcdxexSetup()` to choose the engine and password.
3. Opens the table via DBFCDXEX and calls `CDXEX_EncryptTable()` to encrypt all
   records in-place.
4. Shows `CDXEX_Info()` before and after encryption.
5. Verifies the on-disk encryption marker with `CDXEX_IsTableEncrypted()`.

After this sample, `clientes.dbf` is encrypted on disk.
The CDX index is removed by `EncryptTable` (it must be rebuilt before seeking).

---

## 👉 sample02 - Transparent read / write on an encrypted table

**Build & run:** `go_02.bat`

What it does:
1. Ensures `clientes.dbf` is encrypted (encrypts it automatically if needed).
2. Opens via DBFCDXEX exclusive and rebuilds the CDX index with `INDEX ON`.
3. Opens via DBFCDXEX shared, reads all records — decryption is transparent
   to the application code.
4. Appends a fourth record ("Joan Soler") and commits — encryption is
   transparent on write too.
5. Uses `DBSEEK` to find the new record via the encrypted CDX, proving that
   index operations work correctly on encrypted data.

---

## 👉 sample03 - Decrypt a table back to plain DBF

**Build & run:** `go_03.bat`

What it does:
1. Ensures `clientes.dbf` is encrypted.
2. Opens via DBFCDXEX and calls `CDXEX_DecryptTable()`.
   - Decrypts all records in-place.
   - Removes the CDX index.
   - Clears the encryption marker in the DBF header.
3. Shows `CDXEX_Info()` before and after decryption.
4. Re-opens the table as plain DBFCDX (no password, no DBFCDXEX) and
   reads all records to confirm the data is back to plaintext.

After this sample the file is a normal DBF readable by any driver.

---

## 👉 sample04 - Diagnostics: CDXEX_Info() and CDXEX_IsTableEncrypted()

**Build & run:** `go_04.bat`

What it does:
Walks through four states and shows what the diagnostic functions return in
each one:

| State                                    | IsTableEncrypted | Info()                        |
|------------------------------------------|------------------|-------------------------------|
| Plain table, opened as DBFCDX            | `.F.`            | "No DBFCDXEX area selected"   |
| Encrypted table, opened as DBFCDXEX      | `.T.`            | full engine/key/records info  |
| Encrypted table, opened as plain DBFCDX  | `.T.`            | "No DBFCDXEX area selected"   |

> `CDXEX_IsTableEncrypted()` always requires an open work area.

Key points:
- `CDXEX_IsTableEncrypted()` reads byte 28 of the DBF header from the
  **currently open work area**.  It requires an active `USE` — any RDD works
  (DBFCDX, DBFCDXEX).  There is no filename-parameter version; always open
  the table first.
- Opening an encrypted table as plain DBFCDX is legal but data will appear
  garbled — always check `IsTableEncrypted()` before choosing the RDD.

---

## 👉 sample05 - ADS-equivalent pattern

**Build & run:** `go_05.bat`

What it does:
Shows a 1:1 port from the Advantage Database Server (ADS) encryption API
to the DBFCDXEX API.  Intended for teams migrating existing ADS code.

| ADS call                   | DBFCDXEX equivalent                          |
|----------------------------|----------------------------------------------|
| `AdsSetPassword("pwd")`    | `DbfcdxexSetup("aes256","pwd")`              |
| `USE file VIA "ADS"`       | `USE file VIA "DBFCDXEX"`                    |
| `AdsIsTableEncrypted()`    | `CDXEX_IsTableEncrypted()`                   |
| `AdsEncryptTable()`        | `CDXEX_EncryptTable()`                       |
| `AdsDecryptTable()`        | `CDXEX_DecryptTable()`                       |

The sample creates a fresh plain table, then follows the exact ADS pattern
to check-and-encrypt.

---

## 👉sample06 - Engine selection: dummy / rot13 / aes256

**Build & run:** `go_06.bat`

What it does:
Creates the same single-field table three times, once with each available
engine, and verifies the round-trip (encrypt → read back):

| Engine  | Description                                          | Use case          |
|---------|------------------------------------------------------|-------------------|
| `dummy` | XOR with first key byte                              | Testing only      |
| `rot13` | ROT-13 for A–Z / a–z (self-inverse)                  | Demo / learning   |
| `aes256`| AES-256-CTR via Windows BCrypt API                   | Production        |

All three engines share the same `DbfcdxexSetup()` / `CDXEX_EncryptTable()`
API — switching engine requires only changing the first argument of `DbfcdxexSetup`.

---

## 👉 sample07 - Wrong password: security verification  *(new)*

**Build & run:** `go_07.bat`

What it does:
Demonstrates the security property of the encryption:

1. Creates and encrypts `clientes.dbf` with the correct password (`Secreto123`).
2. Opens with the **correct** password → all records display clearly.
3. Opens with a **wrong** password (`WrongPass99`) → records display as garbage.

Important notes shown by the sample:
- DBFCDXEX uses **unauthenticated encryption** (AES-256-CTR without a MAC).
  A wrong password does **not** raise an error — it silently returns garbage.
- Applications must call `CDXEX_IsTableEncrypted()` before opening and must
  ensure the password is correct through their own application logic.
- Seeking via an encrypted CDX with the wrong key produces undefined results
  (the CDX is not opened in this sample for that reason).

---

## 👉 rddtest - Full RDD test suite (106 tests)

> This is one of the most important tests because it is the one used in Harbour itself to test the RDD and it was created by Przemyslaw Czerpak.

**Build & run:** `go_rddtest.bat`

What it does:
Runs the complete regression suite against the DBFCDXEX driver.  Mirrors
the structure of the Harbour core `cdxcl52.prg` test battery but adapted
for encrypted tables.

Test sections:
1. **Navigation** - GOTO, SKIP, BOF, EOF on empty and populated tables.
2. **Index operations** - ascending and descending CDX tags, ORDSETFOCUS.
3. **SEEK** - exact, soft-seek, last-duplicate on numeric and character keys.
4. **Delete / Recall** - DBDELETE, DBRECALL, SET DELETE ON/OFF.
5. **Encryption verification** - re-opens the same table as plain DBFCDX
   and confirms that raw field bytes differ from the decrypted values,
   proving data is actually encrypted on disk.

Expected output: `106 tests, 0 errors`.

