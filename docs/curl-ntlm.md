# curl NTLM Implementation

This document describes how curl implements the NTLM authentication protocol.
The implementation is split across several files:

- `lib/vauth/ntlm.c` -- Built-in ("generic") NTLM message generation/parsing
- `lib/vauth/ntlm_sspi.c` -- Windows SSPI-based NTLM (delegates to OS)
- `lib/curl_ntlm_core.c` -- Core cryptographic operations (DES, hashing)
- `lib/curl_ntlm_core.h` -- Core crypto function declarations and helpers
- `lib/http_ntlm.c` -- HTTP-level NTLM integration (state machine, base64)
- `lib/vauth/vauth.h` -- `struct ntlmdata` definition and auth API declarations

The code comments reference the Davenport NTLM documentation
(https://davenport.sourceforge.net/ntlm.html) and
https://www.innovation.ch/java/ntlm.html as primary sources.

Source: https://github.com/curl/curl/tree/master/lib

---

## Architecture Overview

curl has two NTLM implementations, selected at compile time:

| Compile Flag | Implementation | Description |
|---|---|---|
| `USE_NTLM && !USE_WINDOWS_SSPI` | `vauth/ntlm.c` + `curl_ntlm_core.c` | Built-in generic NTLM using a pluggable crypto backend |
| `USE_WINDOWS_SSPI && USE_NTLM` | `vauth/ntlm_sspi.c` | Delegates to Windows SSPI (`InitializeSecurityContext`) |

Both implementations expose the same API surface through `vauth.h`:
- `Curl_auth_create_ntlm_type1_message()` -- Generate Type 1 (Negotiate)
- `Curl_auth_decode_ntlm_type2_message()` -- Parse Type 2 (Challenge)
- `Curl_auth_create_ntlm_type3_message()` -- Generate Type 3 (Authenticate)
- `Curl_auth_cleanup_ntlm()` -- Free NTLM state

The built-in implementation supports NTLMv2 (preferred when the server sets
`NTLMFLAG_NEGOTIATE_NTLM2_KEY`) and NTLMv1 as fallback. It does **not**
implement NTLM2 Session Security as a separate mode -- instead, the presence
of the NTLM2 flag triggers the full NTLMv2 path.

---

## NTLM Data Structure

```c
struct ntlmdata {
#ifdef USE_WINDOWS_SSPI
  CtxtHandle *sslContext;        // Schannel channel bindings (EPA)
  CredHandle *credentials;
  CtxtHandle *context;
  SEC_WINNT_AUTH_IDENTITY identity;
  SEC_WINNT_AUTH_IDENTITY *p_identity;
  size_t token_max;
  BYTE *output_token;
  BYTE *input_token;
  size_t input_token_len;
  TCHAR *spn;
#else
  unsigned int flags;            // Negotiated flags from Type 2
  unsigned char nonce[8];        // Server challenge from Type 2
  unsigned int target_info_len;  // Length of target info blob
  void *target_info;             // Target info AV_PAIRs (copied from Type 2)
#endif
};
```

The `ntlmdata` struct is stored per-connection via metadata keys
`"meta:auth:ntml:conn"` and `"meta:auth:ntml-proxy:conn"`.

---

## NTLM State Machine

The HTTP layer tracks NTLM state via the `curlntlm` enum:

```
NTLMSTATE_NONE → NTLMSTATE_TYPE1 → NTLMSTATE_TYPE2 → NTLMSTATE_TYPE3 → NTLMSTATE_LAST
```

| State | Meaning |
|---|---|
| `NTLMSTATE_NONE` | No NTLM auth in progress |
| `NTLMSTATE_TYPE1` | Need to send Type 1 (Negotiate) message |
| `NTLMSTATE_TYPE2` | Received Type 2 (Challenge), need to send Type 3 |
| `NTLMSTATE_TYPE3` | Type 3 (Authenticate) sent, waiting for server response |
| `NTLMSTATE_LAST` | Authentication complete, no more headers needed |

### State transitions in `Curl_input_ntlm()`:

- Server sends `WWW-Authenticate: NTLM` (no token) → `NTLMSTATE_TYPE1`
- Server sends `WWW-Authenticate: NTLM <base64>` → base64 decode, parse Type
  2, → `NTLMSTATE_TYPE2`
- If in `NTLMSTATE_LAST` and server sends bare `NTLM` → restart (re-auth)
- If in `NTLMSTATE_TYPE3` and server sends bare `NTLM` → handshake rejected
  → `CURLE_REMOTE_ACCESS_DENIED`

### Output in `Curl_output_ntlm()`:

- `NTLMSTATE_TYPE1` → create Type 1, base64 encode, set
  `Authorization: NTLM <base64>\r\n`
- `NTLMSTATE_TYPE2` → create Type 3, base64 encode, set
  `Authorization: NTLM <base64>\r\n`, transition to `NTLMSTATE_TYPE3`
- `NTLMSTATE_TYPE3` → auto-transition to `NTLMSTATE_LAST`
- `NTLMSTATE_LAST` → no header sent, `authp->done = TRUE`

---

## Negotiate Flags

### Defined Constants (from `vauth/ntlm.c`)

Most flags are only defined inside `#if DEBUG_ME` blocks and are used solely
for debug logging. The flags that are actually used in protocol logic:

```c
#define NTLMFLAG_NEGOTIATE_UNICODE       (1 << 0)   // 0x00000001
#define NTLMFLAG_NEGOTIATE_OEM           (1 << 1)   // 0x00000002
#define NTLMFLAG_REQUEST_TARGET          (1 << 2)   // 0x00000004
#define NTLMFLAG_NEGOTIATE_NTLM_KEY     (1 << 9)   // 0x00000200
#define NTLMFLAG_NEGOTIATE_ALWAYS_SIGN  (1 << 15)   // 0x00008000
#define NTLMFLAG_NEGOTIATE_NTLM2_KEY   (1 << 19)   // 0x00080000
#define NTLMFLAG_NEGOTIATE_TARGET_INFO  (1 << 23)   // 0x00800000
```

### Flags Sent in Type 1 Message

```c
NTLMFLAG_NEGOTIATE_OEM |
NTLMFLAG_REQUEST_TARGET |
NTLMFLAG_NEGOTIATE_NTLM_KEY |
NTLMFLAG_NEGOTIATE_NTLM2_KEY |
NTLMFLAG_NEGOTIATE_ALWAYS_SIGN
// = 0x00088206
```

Notable: **`NTLMFLAG_NEGOTIATE_UNICODE` is NOT sent in Type 1.** Only OEM is
offered. Unicode support is determined from the server's Type 2 flags.

Also absent: `NEGOTIATE_SIGN`, `NEGOTIATE_SEAL`, `NEGOTIATE_KEY_EXCHANGE`,
`NEGOTIATE_128`, `NEGOTIATE_56`, `NEGOTIATE_TARGET_INFO`.

---

## Type 1 Message (NEGOTIATE_MESSAGE) Generation

```c
CURLcode Curl_auth_create_ntlm_type1_message(
    struct Curl_easy *data,
    const char *userp,
    const char *passwdp,
    const char *service,
    const char *hostname,
    struct ntlmdata *ntlm,
    struct bufref *out)
```

Produces a minimal 32-byte negotiate message. The `userp`, `passwdp`,
`service`, and `hostname` parameters are **unused** (cast to `(void)`).

| Offset | Size | Field | Value |
|--------|------|-------|-------|
| 0 | 8 | Signature | `"NTLMSSP\0"` |
| 8 | 4 | MessageType | `0x00000001` (LE) |
| 12 | 4 | NegotiateFlags | `0x00088206` (LE) |
| 16 | 8 | DomainNameFields | Length=0, MaxLength=0, Offset=0 |
| 24 | 8 | WorkstationFields | Length=0, MaxLength=0, Offset=0 |

Domain and workstation are always empty (both `host` and `domain` are
initialized to `""` with length 0).

The message is constructed using `curl_maprintf()` with `%c` format
specifiers for individual bytes, using the `SHORTPAIR()` and `LONGQUARTET()`
macros for little-endian encoding.

`Curl_auth_cleanup_ntlm(ntlm)` is called at the start to reset any previous
state.

---

## Type 2 Message (CHALLENGE_MESSAGE) Parsing

```c
CURLcode Curl_auth_decode_ntlm_type2_message(
    struct Curl_easy *data,
    const struct bufref *type2ref,
    struct ntlmdata *ntlm)
```

### Validation

1. Minimum length: 32 bytes (not 48 -- more lenient than Mozilla).
2. Verify signature `"NTLMSSP\0"` at offset 0.
3. Verify type marker `0x02000000` at offset 8.

### Fields extracted

| Offset | Field | Storage |
|--------|-------|---------|
| 20 | NegotiateFlags | `ntlm->flags` (via `Curl_read32_le`) |
| 24 | ServerChallenge | `ntlm->nonce[8]` (memcpy) |

### Target Info extraction

Only parsed if `ntlm->flags & NTLMFLAG_NEGOTIATE_TARGET_INFO` is set.
Delegated to `ntlm_decode_type2_target()`:

1. Requires `type2len >= 48`.
2. Reads target info length (uint16 LE) from offset 40.
3. Reads target info offset (uint32 LE) from offset 44.
4. Validates: offset >= 48, offset + length <= type2len.
5. **Copies** (not points to) target info into `ntlm->target_info` via
   `curlx_memdup()`. Previous target_info is freed first.

If bounds check fails → `CURLE_BAD_CONTENT_ENCODING`.

Note: The **target name** security buffer at offset 12 is **not parsed at
all**. Only flags, challenge, and target info are extracted.

---

## Type 3 Message (AUTHENTICATE_MESSAGE) Generation

```c
CURLcode Curl_auth_create_ntlm_type3_message(
    struct Curl_easy *data,
    const char *userp,
    const char *passwdp,
    struct ntlmdata *ntlm,
    struct bufref *out)
```

### Domain/User Parsing

The `userp` string is parsed for `\` or `/` to split domain and user:
```c
user = strchr(userp, '\\');
if(!user) user = strchr(userp, '/');
if(user) { domain = userp; domlen = user - domain; user++; }
else user = userp;
```

### Workstation Name

Hard-coded to `"WORKSTATION"` (the string, not the actual hostname):
```c
static const char host[] = "WORKSTATION";
```

The comment says: "The fixed hostname we provide, in order to not leak our
real local host name. Copy the name used by Firefox."

### Authentication Mode Selection

```c
if(ntlm->flags & NTLMFLAG_NEGOTIATE_NTLM2_KEY) {
    // NTLMv2 path
} else {
    // NTLMv1 path
}
```

The decision is based solely on whether the server's Type 2 flags include
`NTLMFLAG_NEGOTIATE_NTLM2_KEY` (0x00080000, which is
`NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY` in MS-NLMP). There is no
separate preference to force NTLMv1 -- if the server offers the flag, NTLMv2
is used.

### NTLMv2 Path

1. Generate 8 random bytes (`entropy`) via `Curl_rand()`.
2. Compute NT hash: `Curl_ntlm_core_mk_nt_hash(password, ntbuffer)` →
   `MD4(UTF-16LE(password))` zero-padded to 21 bytes.
3. Compute NTLMv2 hash:
   `Curl_ntlm_core_mk_ntlmv2_hash(user, userlen, domain, domlen, ntbuffer, ntlmv2hash)`
   → `HMAC-MD5(ntHash[0:16], UTF-16LE(UPPER(user)) + UTF-16LE(domain))`
   Note: username is uppercased, **domain is NOT uppercased**.
4. Compute LMv2 response:
   `Curl_ntlm_core_mk_lmv2_resp(ntlmv2hash, entropy, nonce, lmresp)` → 24 bytes.
5. Compute NTLMv2 response:
   `Curl_ntlm_core_mk_ntlmv2_resp(ntlmv2hash, entropy, ntlm, &ntlmv2resp, &ntresplen)` → variable length.

### NTLMv1 Path

1. Compute NT hash: `Curl_ntlm_core_mk_nt_hash(password, ntbuffer)` →
   `MD4(UTF-16LE(password))` zero-padded to 21 bytes.
2. NTLM response: `Curl_ntlm_core_lm_resp(ntbuffer, nonce, ntresp)` → 24
   bytes (3x DES of challenge using NT hash).
3. Compute LM hash: `Curl_ntlm_core_mk_lm_hash(password, lmbuffer)` →
   DES-ECB encrypt `"KGS!@#$%"` with the password, zero-padded to 21 bytes.
4. LM response: `Curl_ntlm_core_lm_resp(lmbuffer, nonce, lmresp)` → 24
   bytes (3x DES of challenge using LM hash).

**Unlike Mozilla, curl DOES compute and send a real LM response in NTLMv1
mode.** The code has a comment noting a safer alternative:
```c
/* A safer but less compatible alternative is:
 *   Curl_ntlm_core_lm_resp(ntbuffer, &ntlm->nonce[0], lmresp);
 * See https://davenport.sourceforge.net/ntlm.html#ntlmVersion2 */
```

5. Clear the NTLM2 flag: `ntlm->flags &= ~NTLMFLAG_NEGOTIATE_NTLM2_KEY`

### Message Layout

| Offset | Size | Field |
|--------|------|-------|
| 0 | 8 | Signature `"NTLMSSP\0"` |
| 8 | 4 | MessageType `0x00000003` (LE) |
| 12 | 8 | LmChallengeResponseFields (length=24, offset=64) |
| 20 | 8 | NtChallengeResponseFields (length=variable, offset=88) |
| 28 | 8 | DomainNameFields |
| 36 | 8 | UserNameFields |
| 44 | 8 | WorkstationFields |
| 52 | 8 | SessionKeyFields (always length=0) |
| 60 | 4 | NegotiateFlags (`ntlm->flags`) |

Data after header (offset 64):
1. LM response (24 bytes)
2. NTLM response (24 bytes for NTLMv1, variable for NTLMv2)
3. Domain string
4. Username string
5. Workstation string (`"WORKSTATION"`)

Note: The data order is **different from Mozilla** -- curl places the
response blobs before the string fields. Mozilla places strings first.

### String Encoding

Determined by `ntlm->flags & NTLMFLAG_NEGOTIATE_UNICODE`:
- If unicode: UTF-16LE via `unicodecpy()` (doubles each byte, zeroes high
  byte -- ASCII only)
- If OEM: raw `memcpy()` (no charset conversion)

### Buffer Size

Uses a fixed `NTLM_BUFSIZE` (1024 bytes) stack buffer. If `size + userlen +
domlen + hostlen >= NTLM_BUFSIZE`, returns `CURLE_TOO_LARGE`.

### Session Key

The SessionKey security buffer at offset 52 is **always empty** (length=0,
offset=0). No session key exchange is performed.

---

## Cryptographic Operations

### Password Hashing -- NT Hash (NTOWF)

```c
CURLcode Curl_ntlm_core_mk_nt_hash(const char *password,
                                    unsigned char *ntbuffer /* 21 bytes */)
```

1. Convert password to UTF-16LE via `ascii_to_unicode_le()` (each ASCII byte
   becomes 2 bytes: `byte, 0x00`). Only handles ASCII -- no proper Unicode
   conversion.
2. `Curl_md4it(ntbuffer, pw, 2 * len)` -- MD4 hash → 16 bytes.
3. Zero-pad bytes 16-20 → 21 bytes total.

### Password Hashing -- LM Hash (LMOWF)

```c
CURLcode Curl_ntlm_core_mk_lm_hash(const char *password,
                                    unsigned char *lmbuffer /* 21 bytes */)
```

1. Uppercase the password, truncate/pad to 14 bytes.
2. Split into two 7-byte halves.
3. DES-ECB encrypt the magic constant `"KGS!@#$%"` with each half.
4. Concatenate → 16 bytes, zero-pad to 21 bytes.

**curl is one of the few implementations that still computes the LM hash.**

### DES Key Expansion (56-bit → 64-bit)

```c
static void extend_key_56_to_64(const unsigned char *key_56, char *key)
```

Standard NTLM 7-byte to 8-byte DES key expansion. Parity is then set by
either the crypto backend's `DES_set_odd_parity()` or curl's own
`curl_des_set_odd_parity()`.

### DES Encryption -- Multi-Backend Support

The `setup_des_key()` and `encrypt_des()` functions support six crypto
backends, selected via compile-time defines in this priority order:

| Priority | Define | Backend |
|---|---|---|
| 1 | `USE_OPENSSL` | OpenSSL `DES_ecb_encrypt` |
| 2 | `USE_WOLFSSL` | wolfSSL (via OpenSSL compat API) |
| 3 | `USE_GNUTLS` | Nettle `des_encrypt` |
| 4 | `USE_MBEDTLS` | mbedTLS `mbedtls_des_crypt_ecb` |
| 5 | `USE_OS400CRYPTO` | IBM i `_CIPHER` |
| 6 | `USE_WIN32_CRYPTO` | Windows CryptoAPI `CryptEncrypt` |

The priority order ensures OpenSSL takes precedence over Windows CryptoAPI
"due to issues with the latter supporting NTLM2Session responses in NTLM
type-3 messages."

### LM Response (3x DES)

```c
void Curl_ntlm_core_lm_resp(const unsigned char *keys,
                             const unsigned char *plaintext,
                             unsigned char *results)
```

Takes a 21-byte key (zero-padded hash), splits into three 7-byte segments,
expands each to 8-byte DES key, encrypts the 8-byte plaintext (challenge)
with each → 24-byte result.

### NTLMv2 Hash

```c
CURLcode Curl_ntlm_core_mk_ntlmv2_hash(const char *user, size_t userlen,
                                        const char *domain, size_t domlen,
                                        unsigned char *ntlmhash,
                                        unsigned char *ntlmv2hash)
```

```
ntlmv2hash = HMAC-MD5(ntlmhash[0:16], UTF-16LE(UPPER(user)) + UTF-16LE(domain))
```

The username is uppercased via `ascii_uppercase_to_unicode_le()`. The domain
is encoded as UTF-16LE but **not uppercased** (using `ascii_to_unicode_le()`).

### NTLMv2 Response

```c
CURLcode Curl_ntlm_core_mk_ntlmv2_resp(const unsigned char *ntlmv2hash,
                                        const unsigned char *challenge_client,
                                        const struct ntlmdata *ntlm,
                                        unsigned char **ntresp,
                                        unsigned int *ntresp_len)
```

**NTLMv2 response structure:**

| Offset | Size | Field | Value |
|--------|------|-------|-------|
| 0 | 16 | HMAC-MD5 | Computed over challenge + blob |
| 16 | 4 | Blob Signature | `0x01010000` |
| 20 | 4 | Reserved | `0x00000000` |
| 24 | 8 | Timestamp | NT filetime (100ns since 1601-01-01), LE |
| 32 | 8 | ClientChallenge | 8 random bytes |
| 40 | 4 | Unknown/Reserved | `0x00000000` |
| 44 | N | TargetInfo | Copied from Type 2 message |
| 44+N | 4 | Trailing zeroes | `0x00000000` |

**Total length:** `16 + (44 - 16 + target_info_len + 4)` = `28 + target_info_len + 4 + 16`

The HMAC is computed as:
```
hmac_input = server_challenge(8) || blob(28 + target_info_len + 4)
HMAC-MD5(ntlmv2hash, hmac_input) → 16 bytes at offset 0
```

The implementation cleverly reuses the output buffer: the server challenge is
temporarily placed at offset 8 (overwriting the blob signature area), the
HMAC is computed over `ptr + 8` for `NTLMv2_BLOB_LEN + 8` bytes, then the
16-byte HMAC result is written at offset 0 (overwriting the temporary
challenge copy).

**Timestamp handling:** The `time2filetime()` function converts `time_t` to
Windows FILETIME (100ns intervals since January 1, 1601). It handles both
32-bit and 64-bit `time_t`. For debug builds, the environment variable
`CURL_FORCETIME` forces timestamp to 0 (epoch of 1601) for reproducible
testing.

### LMv2 Response

```c
CURLcode Curl_ntlm_core_mk_lmv2_resp(const unsigned char *ntlmv2hash,
                                      const unsigned char *challenge_client,
                                      const unsigned char *challenge_server,
                                      unsigned char *lmresp)
```

```
data = server_challenge(8) || client_challenge(8)
hmac = HMAC-MD5(ntlmv2hash, data) → 16 bytes
lmresp = hmac(16) || client_challenge(8) → 24 bytes
```

### Random Number Generation

`Curl_rand(data, buffer, length)` -- curl's own random function, which
delegates to the configured crypto backend's CSPRNG.

### Crypto Primitives Summary

| Primitive | Implementation |
|---|---|
| MD4 | `Curl_md4it()` from `curl_md4.h` (backend-dependent) |
| MD5 | Part of HMAC-MD5 via `Curl_hmacit()` |
| HMAC-MD5 | `Curl_hmacit(&Curl_HMAC_MD5, ...)` from `curl_hmac.h` |
| DES-ECB | Backend-specific (OpenSSL/wolfSSL/Nettle/mbedTLS/CryptoAPI) |
| CSPRNG | `Curl_rand()` (backend-specific) |

---

## Windows SSPI Implementation (`ntlm_sspi.c`)

When `USE_WINDOWS_SSPI` is defined, curl delegates entirely to Windows:

### Type 1 Generation

1. `QuerySecurityPackageInfo("NTLM")` to get max token size.
2. `AcquireCredentialsHandle("NTLM", SECPKG_CRED_OUTBOUND, ...)`.
   - If `userp` is provided, populate `SEC_WINNT_AUTH_IDENTITY` →
     explicit credentials.
   - If `userp` is empty/null, `p_identity = NULL` → use current
     Windows user (SSO).
3. Build SPN: `Curl_auth_build_spn(service, host, NULL)`.
4. `InitializeSecurityContext(credentials, NULL, spn, ...)` → produces
   Type 1 token.

### Type 2 Parsing

Simply copies the raw Type 2 blob into `ntlm->input_token`. No parsing --
SSPI handles it internally.

### Type 3 Generation

1. Set up `SecBufferDesc` with the stored Type 2 as input.
2. **Channel Binding (EPA):** If `SECPKG_ATTR_ENDPOINT_BINDINGS` is available
   and `ntlm->sslContext` is set (Schannel TLS), query channel bindings and
   add as a second `SecBuffer` of type `SECBUFFER_CHANNEL_BINDINGS`. This
   prevents NTLM relay attacks over HTTPS.
3. `InitializeSecurityContext(credentials, context, spn, ..., type2_desc, ..., type3_desc)` → produces Type 3.

### Cleanup

- `DeleteSecurityContext`
- `FreeCredentialsHandle`
- `Curl_sspi_free_identity`
- Free input/output tokens and SPN

---

## HTTP Integration (`http_ntlm.c`)

### Parsing Server Challenge (`Curl_input_ntlm`)

```c
CURLcode Curl_input_ntlm(struct Curl_easy *data, bool proxy,
                          const char *header)
```

1. Check `header` starts with `"NTLM"`.
2. Skip `"NTLM"` and whitespace.
3. If there's token data after `"NTLM "`:
   - Base64 decode into binary.
   - Call `Curl_auth_decode_ntlm_type2_message()`.
   - Set state → `NTLMSTATE_TYPE2`.
4. If no token (bare `"NTLM"`):
   - If in `NTLMSTATE_LAST` → restart auth.
   - If in `NTLMSTATE_TYPE3` → handshake rejected, return
     `CURLE_REMOTE_ACCESS_DENIED`.
   - Otherwise → set state to `NTLMSTATE_TYPE1`.

### Generating Auth Headers (`Curl_output_ntlm`)

```c
CURLcode Curl_output_ntlm(struct Curl_easy *data, bool proxy)
```

Handles both server auth and proxy auth (via the `proxy` parameter).

1. Select user/password/service/hostname based on proxy vs. host.
2. Service defaults to `"HTTP"` unless overridden via
   `CURLOPT_PROXY_SERVICE_NAME` or `CURLOPT_SERVICE_NAME`.
3. On Windows SSPI, initializes SSPI if needed and passes `sslContext` for
   channel bindings.
4. Based on state:
   - `NTLMSTATE_TYPE1` → create Type 1, base64 encode, format as
     `[Proxy-]Authorization: NTLM <base64>\r\n`
   - `NTLMSTATE_TYPE2` → create Type 3, base64 encode, format header,
     set `authp->done = TRUE`, transition to `NTLMSTATE_TYPE3`
   - `NTLMSTATE_TYPE3` → auto-transition to `NTLMSTATE_LAST`
   - `NTLMSTATE_LAST` → free header, set `authp->done = TRUE`

---

## Target Info / AV_PAIR Handling

Target info AV_PAIRs are **not individually parsed**. The entire target info
blob is:

1. **Copied** from the Type 2 message (unlike Mozilla which keeps a pointer
   into the message buffer -- curl allocates a separate copy).
2. Fed raw into the NTLMv2 HMAC computation.
3. Copied verbatim into the NTLMv2 response blob.

No individual AV_PAIR inspection, no MIC computation, no timestamp
extraction, no channel binding via AV_PAIRs (channel binding is handled
separately via SSPI on Windows).

---

## String Handling

### Character Encoding

All `ascii_to_unicode_le()` and `ascii_uppercase_to_unicode_le()` functions
are **ASCII-only** -- they simply zero-extend each byte to 16 bits. No proper
UTF-8 to UTF-16 conversion is performed. This means passwords and usernames
with non-ASCII characters will not produce correct NTLM hashes.

```c
static void ascii_to_unicode_le(unsigned char *dest, const char *src,
                                size_t srclen)
{
  size_t i;
  for(i = 0; i < srclen; i++) {
    dest[2 * i] = (unsigned char)src[i];
    dest[(2 * i) + 1] = '\0';
  }
}
```

### Domain Parsing

Domains are extracted from the username using `\` or `/` as separator:
`DOMAIN\user` or `DOMAIN/user`. The domain is taken as-is (no uppercasing in
the NTLMv2 hash computation -- only the username is uppercased).

---

## Comparison: NTLMv2 vs NTLMv1 Feature Matrix

| Feature | NTLMv2 | NTLMv1 |
|---|---|---|
| Triggered by | `NTLMFLAG_NEGOTIATE_NTLM2_KEY` in Type 2 | Absence of flag |
| LM response | LMv2 (HMAC-MD5 based, 24 bytes) | Real LM hash response |
| NTLM response | NTLMv2 blob with timestamp + target info | 3x DES of challenge |
| Password hash | NT hash (MD4) + HMAC-MD5 | NT hash (MD4) + DES; LM hash (DES) |
| Server challenge protection | HMAC with client nonce + timestamp | Direct DES encryption |
| Target info required | Yes (from Type 2) | No |

---

## Notable Deviations from MS-NLMP

1. **Real LM hash in NTLMv1 mode.** Unlike Mozilla (which sends the NT
   response in both fields), curl computes and sends the actual LM hash
   response. This is less secure but more compatible with older servers.

2. **No NTLM2 Session Security as a separate mode.** The
   `NTLMFLAG_NEGOTIATE_NTLM2_KEY` flag triggers the full NTLMv2 path, not
   the intermediate "Extended Session Security" mode (where LM response
   contains the client challenge and the NTLM response uses
   `MD5(serverChallenge + clientChallenge)` as the effective challenge).
   The comment says: "Although this cannot be negotiated, it is used here if
   available, as servers featuring extended security are likely supporting
   also NTLMv2."

3. **No `NTLMFLAG_NEGOTIATE_UNICODE` in Type 1.** Only OEM is offered. The
   server decides via its Type 2 flags whether Unicode will be used.

4. **No session key exchange.** Session key field is always empty.

5. **No message signing or sealing.** `NEGOTIATE_SIGN` and `NEGOTIATE_SEAL`
   are not set.

6. **No MIC (Message Integrity Code).** Type 3 does not include a MIC.

7. **No VERSION structure.** Not included in Type 1 or Type 3.

8. **ASCII-only Unicode conversion.** The `ascii_to_unicode_le()` function
   only handles ASCII characters. Non-ASCII passwords will produce incorrect
   hashes.

9. **Target name not parsed.** The target name security buffer at Type 2
   offset 12 is completely ignored.

10. **Fixed workstation name.** Hard-coded to `"WORKSTATION"` for privacy
    (same approach as Firefox).

11. **Domain not uppercased in NTLMv2 hash.** The MS-NLMP spec says both
    username and domain should be uppercased in `NTOWFv2`. curl only
    uppercases the username; the domain is used as-is from the user input.

12. **Minimum Type 2 length is 32 bytes.** MS-NLMP specifies the Type 2
    minimum at 32 bytes (header only), but target info requires 48.  curl
    accepts 32-byte Type 2 messages and only reads target info if >= 48
    bytes.

13. **Data layout differs.** In Type 3, curl places LM/NTLM responses before
    the domain/user/workstation strings (offset 64 = LM response). Mozilla
    and MS-NLMP examples typically place strings first.

14. **Based on Davenport documentation.** Like Mozilla, curl references
    https://davenport.sourceforge.net/ntlm.html rather than the Microsoft
    MS-NLMP specification.

15. **NTLMv2 blob trailing zeroes.** The NTLMv2 blob includes 4 trailing
    zero bytes after the target info
    (`#define NTLMv2_BLOB_LEN (44 - 16 + ntlm->target_info_len + 4)`).
    Some implementations omit these.

16. **Six crypto backends.** The DES and hashing operations support OpenSSL,
    wolfSSL, GnuTLS/Nettle, mbedTLS, OS/400 crypto, and Windows CryptoAPI
    -- significantly more backend flexibility than any other NTLM
    implementation.
