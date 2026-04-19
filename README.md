<h1 style="display: flex; align-items: center;">
  <img src="https://raw.githubusercontent.com/carles9000/carles9000.github.io/main/images/rdd.png" height="50" style="margin-right: 10px;">
  RDD DbfCdxEx
</h1>



**DBFCDXEX** is a drop-in Harbour RDD (Replaceable Database Driver) that extends
the standard **DBFCDX** driver with transparent, per-file AES-256 encryption.
Any existing application that uses `USE ... VIA "DBFCDX"` can switch to
`USE ... VIA "DBFCDXEX"` and get full encryption with zero changes to the
data-access code.

---

## 🖥️ Built with Claude Code
I designed and implemented this RDD as an AI-assisted systems programming experiment
, using **[Claude Code](https://claude.ai/code)** Anthropic’s official command-line interface for Claude, as the primary development tool.

The complete RDD (C source code, Harbour API, pluggable engine framework, examples, and a suite of 106 regression tests from Harbour itself) was developed in less than **24 hours** of hand-to-hand programming with Claude Code. The workflow was conversational, outlining the scenario and my roadmap: describe a requirement, review the generated C/PRG code, compile, run, observe the error, describe it again, and repeat. Claude Code handled the low-level internals of Harbour’s RDD (CDXAREA structures, page-level I/O points, header byte management), allowing me to focus on design decisions.

Experience shows that the code of complex and specialized systems - internal aspects of Harbour, integration with the Windows BCrypt API, encryption of CDX pages - is within reach of AI-assisted development when the user contributes their domain knowledge to guide the collaboration.

---

## ⚙️ How It Works

### Encryption architecture

DBFCDXEX hooks three layers of the DBFCDX I/O path:

| Layer  | Hook point                       | Nonce scheme                          |
|--------|----------------------------------|---------------------------------------|
| DBF    | `hb_cdxexWriteDBF / ReadDBF`     | `0x100000000 + recno`                 |
| CDX    | `CDXEX_PAGE_ENCRYPT/DECRYPT`     | `ulPage` (CDX page offset)            |
| FPT    | `hb_cdxexWriteFPT / ReadFPT`     | `0x200000000 + (recno<<16) + field`   |

Every record, index page, and memo block gets its own nonce, so identical
plaintext produces different ciphertext in different positions.

### Pluggable engine interface

Encryption is not hard-coded.  Each engine implements three callbacks:

```c
typedef struct
{
   const char * szName;
   void ( * fn_derive  )( const char * pwd, HB_BYTE key[32] );
   void ( * fn_encrypt )( const HB_BYTE key[32], HB_U64 nonce,
                          HB_BYTE * buf, HB_SIZE len );
   void ( * fn_decrypt )( const HB_BYTE key[32], HB_U64 nonce,
                          const HB_BYTE * in, HB_BYTE * out, HB_SIZE len );
} HB_CDXEX_ENGINE;
```

Three engines are included:

| Engine   | Algorithm                        | Use case              |
|----------|----------------------------------|-----------------------|
| `aes256` | AES-256-CTR via Windows BCrypt   | Production            |
| `dummy`  | XOR with first key byte          | Testing / debugging   |
| `rot13`  | ROT-13 on A–Z / a–z (self-inverse) | Learning / demo     |

Switching engines requires only changing the first argument of `DbfcdxexSetup()`.
To add a custom engine, implement the three callbacks and register the struct.

### Encryption marker

Byte 28 of the DBF header stores the value `0xCE` when the file is encrypted.
`CDXEX_IsTableEncrypted()` reads this byte (from an open work area or directly
from a file path) so applications can detect the state before choosing a driver.

---

## 🔧 Harbour API

```harbour
DbfcdxexSetup( "aes256", "MyPassword" )  // select engine + password (thread-local)
USE myfile VIA "DBFCDXEX" EXCLUSIVE NEW  // open encrypted table

CDXEX_EncryptTable()        // encrypt all records in-place
CDXEX_DecryptTable()        // decrypt all records in-place
CDXEX_IsTableEncrypted()    // .T. / .F. -- reads byte 28
CDXEX_Info()                // diagnostic string: engine, key state, record count
```

---

## 🧪 Samples

All samples are in the `samples/` folder.  Each one is self-contained and
creates its own data.  Build with `hbmk2` + MSVC64 (`go_NN.bat`), or build
all at once with `build_all.ps1`.

| Sample           | bat file          | What it demonstrates |
|------------------|-------------------|----------------------|
| `sample01`       | `go_01.bat`       | Encrypt a plain DBF table in-place with `CDXEX_EncryptTable()` |
| `sample02`       | `go_02.bat`       | Transparent read, write, and DBSEEK on an encrypted table |
| `sample03`       | `go_03.bat`       | Decrypt back to plain DBF with `CDXEX_DecryptTable()` |
| `sample04`       | `go_04.bat`       | Diagnostics: `CDXEX_Info()` and `CDXEX_IsTableEncrypted()` across all states |
| `sample05`       | `go_05.bat`       | ADS (Advantage Database Server) API migration guide |
| `sample06`       | `go_06.bat`       | Engine selection: dummy / rot13 / aes256 side-by-side |
| `sample07`       | `go_07.bat`       | Wrong-password security test: AES-CTR returns garbage, not an error |
| `rddtest`        | `go_rddtest.bat`  | Full regression suite -  106 tests, 0 errors |


### 🔔 rddtest in detail

**rddtest** is a special test found with the Harbour distribution that adapts Harbour's cdxcl52.prg test suite to run against DBFCDXEX. It covers navigation, index operations, SEEK (exact/soft-seek/last duplicate), DELETE/RECALL, and a section dedicated to encryption verification that reopens the table as unencrypted DBFCDX and confirms that the raw bytes differ from the decrypted values, proving that the data is indeed encrypted on disk.

**Result: 106 tests, 0 errors.**

---

## ❗ Building

Requirements:
- [Harbour](https://harbour.github.io/) (`c:\harbour`)
- Visual Studio 2022 Community (MSVC64)

---

## ⚠️ Disclaimer

DBFCDXEX is free software provided **as-is**, without warranty of any kind.

It passes a 106-test regression suite and has been validated against the
standard Harbour DBFCDX test battery.  However, encryption is a critical
security component.  **We take no responsibility for any data loss, data
corruption, security breach, or other damage** arising from the use of this
software in any context.

In particular:
- AES-256-CTR as implemented here is **unauthenticated** (no MAC/HMAC).
  A wrong password returns garbage data silently — it does not raise an error.
- Key management (password storage, rotation) is entirely the application's
  responsibility.
- This software has not been audited by a cryptographer or security professional.

Use at your own risk.

---

## 💬 "Yesterday, we were building worlds; today, we’re just supervising their creation." 

What started as a simple experiment to see where AI is at has ended up blurring my entire identity as a coder. Honestly, it’s a trip—seeing the lifework of legends like Bruno Cantero, Horacio Roldan, and Przemysław swallowed up and outdone by a system in just a few hours. It gives you this inevitable sense of vertigo.

 We aren't writing the script anymore; we’re just proofreading it. We’ve become "fact-checkers" for someone else's miracles. As we shift from being hands-on craftsmen to just captains of the machine, the question sticks with you: if the execution isn’t ours anymore, what’s left of our authorship? The change isn't "coming", it's already changed who we are.
 
--- 

<h1 style="display: flex; align-items: center;">
  <img src="https://raw.githubusercontent.com/carles9000/carles9000.github.io/main/images/harbour.png" height="90" style="margin-right: 10px;">
  Harbour Project, 2026 
</h1>
