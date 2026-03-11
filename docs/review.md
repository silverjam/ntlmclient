# NTLM Implementation Review

Comparison of `ntlmclient` (library) and a downstream consumer application
against the MS-NLMP specification, curl, and Thunderbird/Mozilla.

Date: 2026-03-11

---

## Overall Assessment

Our implementation is substantially more complete and correct than both curl
and Thunderbird/Mozilla.  Both reference implementations have significant gaps
that ours does not:

| Feature | ntlmclient | curl | Mozilla/Thunderbird |
|---|---|---|---|
| AV_PAIR parsing | Full TLV parsing | Opaque blob | Opaque blob |
| MIC computation | Yes | No | No |
| Channel binding (NTLM-layer) | Yes | SSPI-only | SSPI-only |
| UTF-16LE password hashing | Yes | ASCII-only | Yes |
| LM response suppression (MsvAvTimestamp) | Yes | No | No |
| NTLMv2 builder API | Yes (ergonomic) | N/A (C structs) | N/A |

---

## Findings

### 1. Domain NOT uppercased in NTLMv2 hash — No action needed

**Location**: `ntlmclient/src/lib.rs:1324-1341` (`ntlm_v2_password_func`)

MS-NLMP section 3.3.2 defines:

```
NTOWFv2(Passwd, User, UserDom) = HMAC_MD5(
    MD4(UNICODE(Passwd)),
    UNICODE(ConcatenationOf(Uppercase(User), UserDom))
)
```

The spec says `UserDom` (unchanged), NOT `Uppercase(UserDom)`.  Our code
matches the spec exactly: it uppercases the username but leaves the domain
as-is.

curl does the same.  Mozilla uppercases both, which is actually the
non-conformant behaviour.

**Verdict**: Correct.

### 2. ExportedSessionKey not derived when KEY_EXCH negotiated — No practical impact

**Location**: `ntlmclient/src/lib.rs:1807-1818` (documented in
`NtlmV2Builder::mic()`)

When `NTLMSSP_NEGOTIATE_KEY_EXCH` is negotiated together with `SIGN` or
`SEAL`, the spec says:

```
ExportedSessionKey   = NONCE(16)
EncryptedRandomSessionKey = RC4K(SessionBaseKey, ExportedSessionKey)
MIC = HMAC_MD5(ExportedSessionKey, nego || chal || auth)
```

Our MIC uses `SessionBaseKey` directly.

However: in practice the consuming application's negotiate and authenticate
messages do not set `KEY_EXCH`, `SIGN`, or `SEAL`.  The flags sent are only
`NEGOTIATE_UNICODE | REQUEST_TARGET | NEGOTIATE_NTLM
[| NEGOTIATE_WORKSTATION_SUPPLIED]`.  So the
`ExportedSessionKey == SessionBaseKey` identity holds, and the MIC is computed
correctly.

**Verdict**: No action needed for the current use case.  If `KEY_EXCH` /
`SIGN` / `SEAL` support is ever added (e.g. for NTLM session security /
signing), `ExportedSessionKey` derivation would need to be implemented.  The
library documentation already notes this.

### 3. Negotiate flags are minimal — Intentional, appropriate for HTTP-over-TLS

A typical consumer application using `ntlmclient` for HTTP-over-TLS NTLM auth
will set Type 1 flags like:

```
NEGOTIATE_UNICODE | REQUEST_TARGET | NEGOTIATE_NTLM
    [| NEGOTIATE_WORKSTATION_SUPPLIED]
```

Flags NOT included that curl and Mozilla typically send:

- `NEGOTIATE_ALWAYS_SIGN` — curl and Mozilla both set this.
- `NEGOTIATE_NTLM2_KEY` (Extended Session Security) — curl sets this.
- `NEGOTIATE_56BIT`, `NEGOTIATE_128BIT` — curl sets these.
- `NEGOTIATE_KEY_EXCHANGE` — Mozilla sets this.

**Impact**: The server negotiates based on what the client offers.  By not
offering these flags the server won't enable extended session security or
session signing.  For HTTP-level NTLM auth over TLS (our use case) this is
fine — the TLS layer provides integrity and confidentiality, so NTLM session
security is redundant.

Some servers *may* behave differently if they see these flags (e.g. might not
set `MsvAvFlags` or `MsvAvTimestamp` in the challenge), but in practice
SharePoint SE/2019 works fine without them, as our E2E tests confirm.

**Verdict**: No action needed.  The minimal flag set is appropriate for
HTTP-over-TLS and reduces implementation complexity.

### 4. MIC only computed when server explicitly requires it — Conservative, spec-compliant

A consumer application may choose to enable MIC only when `MsvAvFlags` has bit
`0x02` set (server *explicitly* requires it).  The spec says the client SHOULD
also produce a MIC when `MsvAvTimestamp` is present (even without the explicit
flag).  The `ntlmclient` library supports both checks:

- `server_requires_mic()` — strict: only `MsvAvFlags` bit `0x02`.
- `server_should_mic()` — soft: also triggers on `MsvAvTimestamp` presence.

Using only the strict check is a defensible choice: including an incorrect MIC
would cause auth failure, and the SHOULD is advisory.

**Verdict**: No action needed.  If a server is ever encountered that expects
MIC based only on timestamp presence, `server_should_mic()` can be used
instead.

### 5. `session_key` always populated in Type 3 message — Cosmetic

**Location**: `ntlmclient/src/lib.rs:1912`

The `session_key` is always stored in the authenticate message's
`EncryptedRandomSessionKey` security buffer.  Per the spec this field should
only be populated when `NEGOTIATE_KEY_EXCH` is negotiated.  Since our flags
don't include `KEY_EXCH`, the spec says this field should be empty.

The field is written as a security buffer.  If the server doesn't expect it
(no `KEY_EXCH`), it ignores it.  In practice this works fine.

**Verdict**: Optional improvement — could gate the
`EncryptedRandomSessionKey` on the `KEY_EXCH` flag.  No practical impact.

---

## Summary

| # | Finding | Severity | Action |
|---|---|---|---|
| 1 | Domain casing in NTLMv2 hash | Non-issue | Code matches the spec correctly |
| 2 | No ExportedSessionKey derivation | N/A for current use | Already documented; no action unless KEY_EXCH added |
| 3 | Minimal negotiate flags | Intentional | Appropriate for HTTP-over-TLS |
| 4 | MIC only on explicit server request | Conservative | Correct for our use case |
| 5 | session_key always in Type 3 | Cosmetic | Optional: gate on KEY_EXCH flag |

**No changes are required.**  The implementation is correct for its use case
(NTLMv2 HTTP auth over TLS against SharePoint), more complete than both curl
and Mozilla in the areas that matter (MIC, CBT, AV_PAIR handling, UTF-16LE),
and has thorough test coverage including E2E validation with pyspnego.
