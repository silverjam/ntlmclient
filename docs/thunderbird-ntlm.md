# Thunderbird / Mozilla NTLM Implementation

This document describes how Mozilla Thunderbird (and Firefox) implement the
NTLM authentication protocol. Thunderbird shares its NTLM code with Firefox
via the `mozilla-central` repository. The core implementation lives in:

- `security/manager/ssl/nsNTLMAuthModule.cpp` -- built-in ("generic") NTLM
- `security/manager/ssl/nsNTLMAuthModule.h` -- class declaration
- `security/manager/ssl/md4.h` / `md4.c` -- custom MD4 implementation
- `netwerk/protocol/http/nsHttpNTLMAuth.cpp` -- HTTP-level NTLM integration

The code comment states it is "based on documentation from:
http://davenport.sourceforge.net/ntlm.html" rather than the Microsoft
MS-NLMP specification directly.

Source: https://searchfox.org/mozilla-central/source/security/manager/ssl/nsNTLMAuthModule.cpp

---

## Architecture Overview

Mozilla has two NTLM implementations:

| Module ID | Description | When Used |
|---|---|---|
| `"sys-ntlm"` | Native OS NTLM (Windows SSPI, or system auth on other platforms) | Default when available; supports SSO with default credentials |
| `"ntlm"` | Built-in generic NTLM (`nsNTLMAuthModule`) | Fallback when native is unavailable or forced via pref |

Both implement the `nsIAuthModule` interface (`Init`, `GetNextToken`, `Wrap`,
`Unwrap`). The HTTP layer (`nsHttpNTLMAuth`) selects between them and handles
base64 encoding/decoding of NTLM tokens in HTTP headers.

The built-in module supports NTLMv2 (default), NTLM2 Session Security, and
plain NTLMv1 as a fallback. It does **not** implement session signing/sealing
(`Wrap`/`Unwrap` return `NS_ERROR_NOT_IMPLEMENTED`).

---

## Negotiate Flags

### Defined Constants

```c
#define NTLM_NegotiateUnicode             0x00000001  // NTLMSSP_NEGOTIATE_UNICODE
#define NTLM_NegotiateOEM                 0x00000002  // NTLMSSP_NEGOTIATE_OEM
#define NTLM_RequestTarget                0x00000004  // NTLMSSP_REQUEST_TARGET
#define NTLM_NegotiateSign                0x00000010  // NTLMSSP_NEGOTIATE_SIGN
#define NTLM_NegotiateSeal                0x00000020  // NTLMSSP_NEGOTIATE_SEAL
#define NTLM_NegotiateDatagramStyle       0x00000040  // NTLMSSP_NEGOTIATE_DATAGRAM
#define NTLM_NegotiateLanManagerKey       0x00000080  // NTLMSSP_NEGOTIATE_LM_KEY
#define NTLM_NegotiateNTLMKey             0x00000200  // NTLMSSP_NEGOTIATE_NTLM
#define NTLM_NegotiateDomainSupplied      0x00001000  // NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED
#define NTLM_NegotiateWorkstationSupplied 0x00002000  // NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED
#define NTLM_NegotiateLocalCall           0x00004000  // NTLMSSP_NEGOTIATE_LOCAL_CALL
#define NTLM_NegotiateAlwaysSign          0x00008000  // NTLMSSP_NEGOTIATE_ALWAYS_SIGN
#define NTLM_TargetTypeDomain             0x00010000  // NTLMSSP_TARGET_TYPE_DOMAIN
#define NTLM_TargetTypeServer             0x00020000  // NTLMSSP_TARGET_TYPE_SERVER
#define NTLM_TargetTypeShare              0x00040000  // NTLMSSP_TARGET_TYPE_SHARE
#define NTLM_NegotiateNTLM2Key           0x00080000  // NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
#define NTLM_NegotiateTargetInfo          0x00800000  // NTLMSSP_NEGOTIATE_TARGET_INFO
#define NTLM_Negotiate128                 0x20000000  // NTLMSSP_NEGOTIATE_128
#define NTLM_NegotiateKeyExchange         0x40000000  // NTLMSSP_NEGOTIATE_KEY_EXCH
#define NTLM_Negotiate56                  0x80000000  // NTLMSSP_NEGOTIATE_56
```

Note: `NTLM_NegotiateNTLM2Key` (0x00080000) uses the older Davenport naming
convention. In MS-NLMP this is `NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY`.

### Flags Sent in Type 1 Message

```c
#define NTLM_TYPE1_FLAGS \
  (NTLM_NegotiateUnicode | NTLM_NegotiateOEM | NTLM_RequestTarget | \
   NTLM_NegotiateNTLMKey | NTLM_NegotiateAlwaysSign | NTLM_NegotiateNTLM2Key)
// = 0x00088207
```

Notably absent from Type 1 flags:
- `NTLM_NegotiateTargetInfo` -- not requested, but servers typically send it anyway
- `NTLM_NegotiateSign` / `NTLM_NegotiateSeal` -- no session security
- `NTLM_Negotiate128` / `NTLM_Negotiate56` -- no key strength negotiation
- `NTLM_NegotiateKeyExchange` -- no session key exchange

---

## Message Structure Constants

```c
#define NTLM_TYPE1_HEADER_LEN  32   // Negotiate message fixed header
#define NTLM_TYPE2_HEADER_LEN  48   // Challenge message fixed header
#define NTLM_TYPE3_HEADER_LEN  64   // Authenticate message fixed header

#define LM_RESP_LEN      24   // LM response field (always 24 bytes on wire)
#define NTLM_CHAL_LEN     8   // Server/client challenge length
#define NTLM_HASH_LEN    16   // MD4 hash of password (NTOWF result)
#define NTLMv2_HASH_LEN  16   // HMAC-MD5 based NTLMv2 hash
#define NTLM_RESP_LEN    24   // NTLMv1 DES-based response (3x 8-byte blocks)
#define NTLMv2_RESP_LEN  16   // NTLMv2 HMAC-MD5 result
#define NTLMv2_BLOB1_LEN 28   // Fixed-size portion of NTLMv2 client blob

static const char NTLM_SIGNATURE[] = "NTLMSSP";  // 8 bytes with null terminator
```

---

## Type 1 Message (NEGOTIATE_MESSAGE) Generation

```c
static nsresult GenerateType1Msg(void** outBuf, uint32_t* outLen)
```

Produces a minimal 32-byte negotiate message:

| Offset | Size | Field | Value |
|--------|------|-------|-------|
| 0 | 8 | Signature | `"NTLMSSP\0"` |
| 8 | 4 | MessageType | `0x00000001` (LE) |
| 12 | 4 | NegotiateFlags | `NTLM_TYPE1_FLAGS` (LE) |
| 16 | 8 | DomainNameFields | Length=0, MaxLength=0, Offset=0 |
| 24 | 8 | WorkstationFields | Length=0, MaxLength=0, Offset=0 |

Domain and workstation are intentionally empty. The code comments: "it is
common for the domain and workstation fields to be empty. this is true of
Win2k clients... it doesn't hurt to save some bytes on the wire."

No VERSION structure is included.

---

## Type 2 Message (CHALLENGE_MESSAGE) Parsing

```c
struct Type2Msg {
    uint32_t       flags;
    uint8_t        challenge[NTLM_CHAL_LEN];  // 8 bytes
    const uint8_t* target;                      // pointer into inBuf
    uint32_t       targetLen;
    const uint8_t* targetInfo;                  // pointer into inBuf
    uint32_t       targetInfoLen;
};

static nsresult ParseType2Msg(const void* inBuf, uint32_t inLen, Type2Msg* msg)
```

Parsing procedure:
1. Verify `inLen >= 48` (NTLM_TYPE2_HEADER_LEN).
2. Verify signature `"NTLMSSP\0"` at offset 0.
3. Verify message type marker `0x00000002` at offset 8.
4. **Offset 12 -- Target Name Security Buffer:** Read length (uint16), skip
   maxLength (uint16), read offset (uint32). Uses `CheckedInt<uint32_t>` for
   overflow safety. If out of bounds, sets `targetLen=0, target=nullptr`
   (silent fallback, does not error).
5. **Offset 20 -- NegotiateFlags:** `ReadUint32`.
6. **Offset 24 -- ServerChallenge:** `memcpy` 8 bytes.
7. **Offset 32 -- Reserved:** Skip 8 bytes (two `ReadUint32` calls).
8. **Offset 40 -- Target Info Security Buffer:** Read length, skip maxLength,
   read offset. Overflow-checked. If out of bounds, **returns
   `NS_ERROR_UNEXPECTED`** (unlike target name, this IS a hard error).

The `targetInfo` pointer points directly into the input buffer -- no copy is
made.

---

## Type 3 Message (AUTHENTICATE_MESSAGE) Generation

```c
static nsresult GenerateType3Msg(
    const nsString& domain,
    const nsString& username,
    const nsString& password,
    const void* inBuf,
    uint32_t inLen,
    void** outBuf,
    uint32_t* outLen)
```

### Layout

| Offset | Size | Field |
|--------|------|-------|
| 0 | 8 | Signature `"NTLMSSP\0"` |
| 8 | 4 | MessageType `0x00000003` (LE) |
| 12 | 8 | LmChallengeResponseFields |
| 20 | 8 | NtChallengeResponseFields |
| 28 | 8 | DomainNameFields |
| 36 | 8 | UserNameFields |
| 44 | 8 | WorkstationFields |
| 52 | 8 | EncryptedRandomSessionKeyFields (always empty: length=0) |
| 60 | 4 | NegotiateFlags (`msg.flags & NTLM_TYPE1_FLAGS`) |

### Variable data after header (offset 64):

1. Domain string
2. Username string
3. Workstation string
4. LM response (24 bytes)
5. NTLM response (24 bytes for NTLMv1, or variable for NTLMv2)

### String encoding

Determined by `msg.flags & NTLM_NegotiateUnicode`:
- If unicode: UTF-16LE encoding (with byte-swapping on big-endian)
- If OEM: Converts from Unicode to native charset via `NS_CopyUnicodeToNative`

### Workstation name

Read from the preference `network.generic-ntlm-auth.workstation` rather than
the actual hostname, for privacy/security reasons (bug 1046421).

### Negotiated flags in Type 3

The flags written are: `msg.flags & NTLM_TYPE1_FLAGS` -- the server's flags
ANDed with the client's original Type 1 flags. This ensures only mutually
supported flags are indicated.

### Session key

The EncryptedRandomSessionKey field at offset 52 is **always empty** (length=0,
offset=0). No session key exchange is performed.

---

## Cryptographic Operations

### Password Hash (NTOWF / NTLM_Hash)

```c
static void NTLM_Hash(const nsString& password, unsigned char* hash)
```

Computes: `MD4(UTF-16LE(password))` → 16 bytes.

On little-endian platforms, the nsString (UTF-16) data is used directly. On
big-endian, bytes are swapped to LE first. Uses Mozilla's custom `md4sum()`
from `md4.h`.

### DES Key Expansion (7-byte → 8-byte with parity)

```c
static void des_makekey(const uint8_t* raw, uint8_t* key)
```

Standard NTLM DES key expansion: each 7 bits from the raw key become the
high 7 bits of each DES key byte. The LSB of each byte is set for odd parity
via `des_setkeyparity()`.

### DES Encryption

```c
static void des_encrypt(const uint8_t* key, const uint8_t* src, uint8_t* hash)
```

Uses NSS (`pk11pub.h`) for DES-ECB:
- `PK11_GetBestSlot(CKM_DES_ECB, nullptr)` to get a PKCS#11 slot
- `PK11_ImportSymKey` with `CKM_DES_ECB` and `CKA_ENCRYPT`
- `PK11_CreateContextBySymKey` → `PK11_CipherOp` to encrypt 8 bytes in ECB mode

### LM_Response (3x DES)

```c
static void LM_Response(const uint8_t* hash, const uint8_t* challenge,
                         uint8_t* response)
```

1. Zero-pad the 16-byte NTLM hash to 21 bytes.
2. Split into three 7-byte chunks.
3. Expand each to an 8-byte DES key via `des_makekey`.
4. DES-ECB encrypt the 8-byte challenge with each key.
5. Concatenate three 8-byte results → 24-byte response.

### HMAC-MD5

Used via `mozilla::HMAC` class with `SEC_OID_MD5` (NSS-backed). Used for:
- NTLMv2 hash computation
- NTLMv2 response computation
- LMv2 response computation

### MD5

Plain MD5 hashing via `nsICryptoHash` (contract `@mozilla.org/security/hash;1`)
with `nsICryptoHash::MD5`. Used for NTLM2 Session Security session hash.

### Random Number Generation

`PK11_GenerateRandom` (NSS CSPRNG) for client challenges and nonces.

### Crypto Library Summary

| Primitive | Implementation |
|---|---|
| MD4 | Custom `md4sum()` from `md4.h` (Mozilla's own, RFC 1320) |
| MD5 | `nsICryptoHash::MD5` (via `@mozilla.org/security/hash;1`) |
| HMAC-MD5 | `mozilla::HMAC` with `SEC_OID_MD5` (NSS) |
| DES-ECB | NSS via `pk11pub.h`, `CKM_DES_ECB` |
| CSPRNG | `PK11_GenerateRandom` (NSS) |

---

## Authentication Modes

The module supports three authentication modes, selected at Type 3 generation
time. The decision is:

```
if (!network.auth.force-generic-ntlm-v1)  →  NTLMv2 (default)
else if (server flags & NTLM_NegotiateNTLM2Key)  →  NTLM2 Session Security
else  →  Plain NTLMv1
```

### NTLMv2 (Default Path)

This is the default and preferred mode.

**Requirements:** `msg.targetInfoLen > 0` (target info from server's Type 2).

**NTLMv2 Hash computation:**
```
ntlmHash = MD4(UTF-16LE(password))
ntlmv2Hash = HMAC-MD5(ntlmHash, UTF-16LE(UPPER(username)) + UTF-16LE(UPPER(domain)))
```

Both username and domain are uppercased via `ToUpperCase()` before UTF-16LE
encoding.

**LMv2 Response (24 bytes):**
```
clientRandom = PK11_GenerateRandom(8)
lmv2Resp = HMAC-MD5(ntlmv2Hash, serverChallenge || clientRandom)  // 16 bytes
LM_Response = lmv2Resp || clientRandom                             // 24 bytes
```

**NTLMv2 Blob (blob1) construction (28 bytes fixed + targetInfo):**

| Offset | Size | Field | Value |
|--------|------|-------|-------|
| 0 | 1 | RespType | 1 |
| 1 | 1 | HiRespType | 1 |
| 2 | 6 | Reserved | 0 |
| 8 | 8 | TimeStamp | NT time (100ns since 1601-01-01), little-endian |
| 16 | 8 | ChallengeFromClient | `PK11_GenerateRandom(8)` |
| 24 | 4 | Reserved | 0 |

The timestamp is computed from `time()`: add 11644473600 seconds (epoch
difference), multiply by 10,000,000.

**NTLMv2 Response:**
```
ntlmv2Resp = HMAC-MD5(ntlmv2Hash, serverChallenge || blob1 || targetInfo)
NTLM_Response = ntlmv2Resp || blob1 || targetInfo
```

Total NTLM response length: `16 + 28 + targetInfoLen`.

### NTLM2 Session Security (Extended Session Security)

Fallback when NTLMv2 is disabled but the server supports Extended Session
Security (`NTLM_NegotiateNTLM2Key` flag).

**LM Response (24 bytes):**
```
lmResp[0..7] = PK11_GenerateRandom(8)    // client challenge
lmResp[8..23] = 0x00                      // zero-padded
```

**NTLM Response (24 bytes):**
```
sessionHash = MD5(serverChallenge || clientChallenge)   // full 16-byte MD5
ntlmHash = MD4(UTF-16LE(password))
NTLM_Response = LM_Response(ntlmHash, sessionHash[0..7])   // use first 8 bytes
```

The `LM_Response` function (3x DES) is applied to the first 8 bytes of the
MD5 session hash, not the original server challenge.

### Plain NTLMv1

Final fallback. No LM hash is ever computed.

**LM Response (24 bytes):**
```
ntlmHash = MD4(UTF-16LE(password))
LM_Response = DES3(ntlmHash, serverChallenge)    // same as NTLM response
```

The LM response field contains the NTLM response (hash sent twice). The code
follows Davenport's recommendation: "the correct way to not send the LM hash
is to send the NTLM hash twice in both the LM and NTLM response fields."

**NTLM Response (24 bytes):**
```
ntlmHash = MD4(UTF-16LE(password))
NTLM_Response = DES3(ntlmHash, serverChallenge)
```

---

## Target Info / AV_PAIR Handling

Target info AV_PAIRs are **not individually parsed**. The entire target info
blob from the Type 2 message is treated as opaque data:

1. The raw bytes are pointed to in the parsed Type 2 structure
   (`msg->targetInfo`, `msg->targetInfoLen`).
2. In NTLMv2 response computation, the entire blob is fed into the HMAC.
3. In the Type 3 message, the blob is copied verbatim into the response.

This means:
- No MIC (Message Integrity Code) computation
- No channel binding via AV_PAIRs (MsvAvFlags)
- No server timestamp extraction (the client generates its own)
- No SPN validation
- No individual AV_PAIR inspection

---

## nsIAuthModule Interface

```cpp
class nsNTLMAuthModule : public nsIAuthModule {
 public:
    NS_DECL_ISUPPORTS
    NS_DECL_NSIAUTHMODULE

    nsNTLMAuthModule() : mNTLMNegotiateSent(false) {}
    nsresult InitTest();
    static void SetSendLM(bool sendLM);

 private:
    nsString mDomain;
    nsString mUsername;
    nsString mPassword;
    bool mNTLMNegotiateSent;
};
```

### Init

```cpp
NS_IMETHODIMP nsNTLMAuthModule::Init(
    const nsACString& serviceName, uint32_t serviceFlags,
    const nsAString& domain, const nsAString& username,
    const nsAString& password)
```

- Asserts `serviceFlags` is `REQ_DEFAULT` or `REQ_PROXY_AUTH`.
- Stores domain, username, password as member variables.
- Sets `mNTLMNegotiateSent = false`.
- Reports telemetry via `mozilla::glean::security::ntlm_module_used`.

### GetNextToken (State Machine)

```cpp
NS_IMETHODIMP nsNTLMAuthModule::GetNextToken(
    const void* inToken, uint32_t inTokenLen,
    void** outToken, uint32_t* outTokenLen)
```

State machine:

| mNTLMNegotiateSent | inToken | Action |
|---|---|---|
| `false` | `null` | `GenerateType1Msg()` → set `mNTLMNegotiateSent = true` |
| `false` | non-null | Error: received reply before sending negotiate |
| `true` | non-null | `GenerateType3Msg(domain, user, pass, inToken, inLen)` |
| `true` | `null` | Error: negotiate was presumably rejected |

FIPS mode check: If `PK11_IsFIPS()` returns true, the module returns
`NS_ERROR_NOT_AVAILABLE` immediately. NTLM uses DES and MD4, which are not
FIPS-approved.

### Wrap / Unwrap

Both return `NS_ERROR_NOT_IMPLEMENTED`. No message signing or sealing support.

### Destructor

Securely zeroes the password: `ZapString(mPassword)`.

---

## HTTP Integration (nsHttpNTLMAuth)

`nsHttpNTLMAuth` implements `nsIHttpAuthenticator` and manages the HTTP-level
NTLM handshake.

### Module Selection (ChallengeReceived)

When the server sends `WWW-Authenticate: NTLM`:

1. If `network.auth.force-generic-ntlm` is true → use built-in `"ntlm"`.
2. If previous native NTLM attempt failed (`*sessionState` non-null) → use
   `"ntlm"`.
3. If `CanUseDefaultCredentials()` → try `"sys-ntlm"` with SSO (no prompt).
4. On Windows only: if default credentials not allowed → try `"sys-ntlm"` with
   prompt.
5. On Windows: if sys-ntlm unavailable and not forced generic → error out.
6. On non-Windows: fall back to built-in `"ntlm"` with prompt.

### Default Credential Authorization

`CanUseDefaultCredentials()` checks:
- **Proxy auth:** `network.automatic-ntlm-auth.allow-proxies` pref
- **Private browsing:** Blocked unless `network.auth.private-browsing-sso`
  is true, or permanent private browsing mode is active
- **Non-FQDN hosts:** Allowed if `network.automatic-ntlm-auth.allow-non-fqdn`
  is true and the host has no dots and is not an IP literal
- **Trusted URIs:** `network.automatic-ntlm-auth.trusted-uris` pattern match

### Token Flow (GenerateCredentials)

**Step 1 -- Initial challenge is `"NTLM"`:**
1. Build service name as `"HTTP@<host>"`.
2. Call `module->Init(serviceName, flags, domain, user, pass)`.
3. Call `module->GetNextToken(nullptr, 0, &outBuf, &outLen)` → Type 1.
4. Base64-encode → prepend `"NTLM "` → set as `Authorization` header.

**Step 2 -- Challenge is `"NTLM <base64>"`:**
1. Strip `"NTLM "` prefix, strip trailing `=` padding.
2. Base64-decode → Type 2 binary blob.
3. Call `module->GetNextToken(type2Buf, type2Len, &outBuf, &outLen)` → Type 3.
4. Base64-encode → prepend `"NTLM "` → set as `Authorization` header.

### Channel Binding (Windows Only)

On Windows with native NTLM over HTTPS, the server's TLS certificate (raw
DER) is passed as the input buffer to `GetNextToken()` on the first call.
The `nsAuthSSPI` module uses this to compute a Channel Binding Token (CBT/EPA)
for NTLMv2, preventing NTLM relay attacks.

### Connection Semantics

```cpp
NS_IMETHODIMP nsHttpNTLMAuth::GetAuthFlags(uint32_t* flags) {
    *flags = CONNECTION_BASED | IDENTITY_INCLUDES_DOMAIN | IDENTITY_ENCRYPTED;
    return NS_OK;
}
```

`CONNECTION_BASED` means the NTLM 3-leg handshake must occur on the **same
TCP connection**. The HTTP stack must:
- Keep the connection alive between handshake legs
- Not pipeline other requests during the handshake
- Bind auth state to the connection lifetime
- Retry on a new connection if the connection drops mid-handshake

```
Client                               Server
  |  GET /                              |
  |  ─────────────────────────────────→ |
  |  401 WWW-Authenticate: NTLM        |
  |  ←───────────────────────────────── |
  |                                     |
  |  GET /                              |
  |  Authorization: NTLM <Type1>       |
  |  ─────────────────────────────────→ |
  |  401 WWW-Authenticate: NTLM <T2>   |
  |  ←───────────────────────────────── |  (same TCP connection)
  |                                     |
  |  GET /                              |
  |  Authorization: NTLM <Type3>       |
  |  ─────────────────────────────────→ |
  |  200 OK                             |
  |  ←───────────────────────────────── |
```

### Async Support

`GenerateCredentialsAsync` returns `NS_ERROR_NOT_IMPLEMENTED`. NTLM
credential generation is always synchronous.

---

## Configuration Preferences

| Preference | Type | Default | Description |
|---|---|---|---|
| `network.auth.force-generic-ntlm` | bool | false | Force built-in NTLM instead of native OS NTLM |
| `network.auth.force-generic-ntlm-v1` | bool | false | Force NTLMv1 instead of NTLMv2 |
| `network.automatic-ntlm-auth.allow-proxies` | bool | false | Allow SSO for proxy authentication |
| `network.automatic-ntlm-auth.allow-non-fqdn` | bool | false | Allow SSO for single-label hostnames |
| `network.automatic-ntlm-auth.trusted-uris` | string | "" | Comma-separated URI patterns for SSO |
| `network.auth.private-browsing-sso` | bool | false | Allow SSO in private browsing mode |
| `network.generic-ntlm-auth.workstation` | string | "" | Workstation name sent in Type 3 (privacy) |

---

## Notable Deviations from MS-NLMP

1. **No LM hash computation.** The LM response field always contains either
   the NTLM response (NTLMv1), random client challenge (NTLM2/NTLMv2), or
   the LMv2 response. The LM one-way function (LMOWF) is never used.

2. **No session key exchange.** The EncryptedRandomSessionKey field in Type 3
   is always empty. `NTLM_NegotiateKeyExchange` is never requested.

3. **No message signing or sealing.** `NTLM_NegotiateSign` and
   `NTLM_NegotiateSeal` are not included in Type 1 flags. `Wrap()`/`Unwrap()`
   are unimplemented.

4. **No MIC (Message Integrity Code).** The Type 3 message does not contain
   a MIC field.

5. **Target info treated as opaque blob.** AV_PAIRs are not individually
   parsed. No server timestamp extraction, no channel binding via AV_PAIRs,
   no SPN validation.

6. **No VERSION structure.** Type 1 and Type 3 messages do not include the
   optional VERSION field.

7. **Workstation from preference, not hostname.** The workstation name in
   Type 3 is read from `network.generic-ntlm-auth.workstation` rather than
   the actual machine hostname (privacy consideration, bug 1046421).

8. **WriteSecBuf sets MaxLength = Length.** The security buffer's
   "allocated space" field is always set equal to the "length" field, rather
   than potentially being larger.

9. **FIPS mode disables NTLM entirely.** `PK11_IsFIPS()` → immediate
   `NS_ERROR_NOT_AVAILABLE`, because NTLM requires DES and MD4 which are
   not FIPS-approved algorithms.

10. **Based on Davenport documentation.** The implementation references
    http://davenport.sourceforge.net/ntlm.html rather than the Microsoft
    MS-NLMP specification. Flag naming follows older Davenport conventions
    (e.g., `NegotiateNTLM2Key` instead of
    `NEGOTIATE_EXTENDED_SESSIONSECURITY`).

11. **No `NTLM_NegotiateTargetInfo` in Type 1.** Despite NTLMv2 requiring
    target info from the server, this flag is not set in the negotiate
    message. Servers typically include target info regardless.

12. **Silent fallback on target name parse failure.** If the target name
    security buffer in Type 2 is out of bounds, the code sets `targetLen=0`
    and continues rather than erroring. Target info out of bounds *does*
    produce a hard error.
