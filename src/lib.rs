//! A simple NTLM client library for Rust.
//!
//! Sample usage:
//! ```
//! use base64::prelude::{BASE64_STANDARD, Engine};
//!
//! const EWS_URL: &str = "https://example.com/EWS/Exchange.asmx";
//!
//! async fn initialize_authed_client(username: &str, password: &str, domain: &str, local_hostname: &str) -> reqwest::Client {
//!     let nego_flags
//!         = ntlmclient::Flags::NEGOTIATE_UNICODE
//!         | ntlmclient::Flags::REQUEST_TARGET
//!         | ntlmclient::Flags::NEGOTIATE_NTLM
//!         | ntlmclient::Flags::NEGOTIATE_WORKSTATION_SUPPLIED
//!         ;
//!     let nego_msg = ntlmclient::Message::Negotiate(ntlmclient::NegotiateMessage {
//!         flags: nego_flags,
//!         supplied_domain: String::new(),
//!         supplied_workstation: local_hostname.to_owned(),
//!         os_version: Default::default(),
//!     });
//!     let nego_msg_bytes = nego_msg.to_bytes()
//!         .expect("failed to encode NTLM negotiation message");
//!     let nego_b64 = BASE64_STANDARD.encode(&nego_msg_bytes);
//!
//!     let client = reqwest::Client::builder()
//!         .cookie_store(true)
//!         .build()
//!         .expect("failed to build client");
//!     let resp = client.get(EWS_URL)
//!         .header("Authorization", format!("NTLM {}", nego_b64))
//!         .send().await
//!         .expect("failed to send challenge request to Exchange");
//!     let challenge_header = resp.headers().get("www-authenticate")
//!         .expect("response missing challenge header");
//!
//!     // we might have been redirected to a specialized authentication URL
//!     let auth_url = resp.url();
//!
//!     let challenge_b64 = challenge_header.to_str()
//!         .expect("challenge header not a string")
//!         .split(" ")
//!         .nth(1).expect("second chunk of challenge header missing");
//!     let challenge_bytes = BASE64_STANDARD.decode(challenge_b64)
//!         .expect("base64 decoding challenge message failed");
//!     let challenge = ntlmclient::Message::try_from(challenge_bytes.as_slice())
//!         .expect("decoding challenge message failed");
//!     let challenge_content = match challenge {
//!         ntlmclient::Message::Challenge(c) => c,
//!         other => panic!("wrong challenge message: {:?}", other),
//!     };
//!     let target_info_bytes: Vec<u8> = challenge_content.target_information
//!         .iter()
//!         .flat_map(|ie| ie.to_bytes())
//!         .collect();
//!
//!     // calculate the response
//!     let creds = ntlmclient::Credentials {
//!         username: username.to_owned(),
//!         password: password.to_owned(),
//!         domain: domain.to_owned(),
//!     };
//!     let challenge_response = ntlmclient::respond_challenge_ntlm_v2(
//!         challenge_content.challenge,
//!         &target_info_bytes,
//!         ntlmclient::get_ntlm_time(),
//!         &creds,
//!     );
//!
//!     // assemble the packet
//!     let auth_flags
//!         = ntlmclient::Flags::NEGOTIATE_UNICODE
//!         | ntlmclient::Flags::NEGOTIATE_NTLM
//!         ;
//!     let auth_msg = challenge_response.to_message(
//!         &creds,
//!         local_hostname,
//!         auth_flags,
//!     );
//!     let auth_msg_bytes = auth_msg.to_bytes()
//!         .expect("failed to encode NTLM authentication message");
//!     let auth_b64 = BASE64_STANDARD.encode(&auth_msg_bytes);
//!
//!     client.get(auth_url.clone())
//!         .header("Authorization", format!("NTLM {}", auth_b64))
//!         .send().await
//!         .expect("failed to send authentication request to Exchange")
//!         .error_for_status()
//!         .expect("error response to authentication message");
//!
//!     // try calling again, without the auth stuff (thanks to cookies)
//!     client.get(EWS_URL)
//!         .send().await
//!         .expect("failed to send refresher request to Exchange")
//!         .error_for_status()
//!         .expect("error response to refresher message");
//!
//!     client
//! }
//! ```

#[cfg(windows)]
mod encoding_windows;

#[cfg(not(windows))]
mod encoding_utf8;

use std::fmt;

use bitflags::bitflags;
use chrono::{NaiveDate, Utc};
use cipher::generic_array::typenum::U8;
use cipher::generic_array::GenericArray;
use cipher::{BlockEncrypt, KeyInit};
use des::Des;
use digest::Digest;
use hmac::{Hmac, Mac};
use md4::Md4;
use md5::Md5;
use rand::rng;
use rand::Rng;
use rc4::{Rc4, StreamCipher};
use sha2::Sha256;

#[cfg(windows)]
use crate::encoding_windows::{ansi_string_to_rust, rust_string_to_ansi};

#[cfg(not(windows))]
use crate::encoding_utf8::{ansi_string_to_rust, rust_string_to_ansi};

/// The magic value at the start of every NTLMSSP data packet.
const NTLMSSP_MAGIC: [u8; 8] = *b"NTLMSSP\0";

/// Standard NTLM credentials, consisting of username, password and domain.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Credentials {
    /// The username part of the credentials.
    pub username: String,

    /// The password part of the credentials.
    pub password: String,

    /// The domain part of the credentials.
    ///
    /// Often specified in combination with the username as `<DOMAIN>\<USERNAME>`. In credentials
    /// without a domain, the domain is an empty string.
    pub domain: String,
}

/// The response to an NTLM challenge.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ChallengeResponse {
    /// The classic LanManager (LM) response.
    pub lm_response: Vec<u8>,

    /// The NT LanManager (NTLM) response.
    pub ntlm_response: Vec<u8>,

    /// The session key, generally calculated from elements of the responses.
    pub session_key: Vec<u8>,
}

bitflags! {
    /// NTLM operation flags.
    #[derive(Clone, Copy, Debug, Default, Hash, Eq, Ord, PartialEq, PartialOrd)]
    pub struct Flags: u32 {
        const NEGOTIATE_UNICODE = 0x0000_0001;
        const NEGOTIATE_OEM = 0x0000_0002;
        const REQUEST_TARGET = 0x0000_0004;
        const UNKNOWN_8 = 0x0000_0008;
        const NEGOTIATE_SIGN = 0x0000_0010;
        const NEGOTIATE_SEAL = 0x0000_0020;
        const NEGOTIATE_DATAGRAM = 0x0000_0040;
        const NEGOTIATE_LANMAN_KEY = 0x0000_0080;
        const NEGOTIATE_NETWARE = 0x0000_0100;
        const NEGOTIATE_NTLM = 0x0000_0200;
        const UNKNOWN_400 = 0x0000_0400;
        const NEGOTIATE_ANONYMOUS = 0x0000_0800;
        const NEGOTIATE_DOMAIN_SUPPLIED = 0x0000_1000;
        const NEGOTIATE_WORKSTATION_SUPPLIED = 0x0000_2000;
        const NEGOTIATE_LOCAL_CALL = 0x0000_4000;
        const NEGOTIATE_ALWAYS_SIGN = 0x0000_8000;
        const TARGET_TYPE_DOMAIN = 0x0001_0000;
        const TARGET_TYPE_SERVER = 0x0002_0000;
        const TARGET_TYPE_SHARE = 0x0004_0000;
        const NEGOTIATE_NTLM2_KEY = 0x0008_0000;
        const REQUEST_INIT_RESPONSE = 0x0010_0000;
        const REQUEST_ACCEPT_RESPONSE = 0x0020_0000;
        const REQUEST_NON_NT_SESSION_KEY = 0x0040_0000;
        const NEGOTIATE_TARGET_INFO = 0x0080_0000;
        const UNKNOWN_1000000 = 0x0100_0000;
        const NEGOTIATE_VERSION = 0x0200_0000;
        const UNKNOWN_4000000 = 0x0400_0000;
        const UNKNOWN_8000000 = 0x0800_0000;
        const UNKNOWN_10000000 = 0x1000_0000;
        const NEGOTIATE_128BIT = 0x2000_0000;
        const NEGOTIATE_KEY_EXCHANGE = 0x4000_0000;
        const NEGOTIATE_56BIT = 0x8000_0000;
    }
}

/// An error that may occur while parsing existing NTLM packets.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ParsingError {
    /// The header is shorter than expected.
    ShortHeader {
        expected_min_len: usize,
        obtained_len: usize,
    },

    /// The magic value does not match the expected one.
    MagicMismatch {
        expected: [u8; 8],
        obtained: Vec<u8>,
    },

    /// An internal item has a different length than expected.
    ItemLengthMismatch { expected: usize, obtained: usize },

    /// An internal item is shorter than expected.
    ItemMinLengthMismatch {
        expected_at_least: usize,
        obtained: usize,
    },

    /// An internal item's length is not divisible by an expected divisor.
    ItemLengthNotDivisible {
        expected_divisor: usize,
        obtained_length: usize,
    },

    /// A byte string cannot be decoded using the current OEM encoding.
    InvalidOemEncoding { value: Vec<u8> },

    /// A string of 16-bit characters could not be decoded as UTF-8.
    InvalidUtf16 { value: Vec<u16> },

    /// An offset is too large for the isize type.
    OffsetTooLargeIsize,

    /// A length is too large for the isize type.
    LengthTooLargeIsize,

    /// A start value is out of the range of a slice.
    StartOutOfRange { start: isize, length: usize },

    /// An end value is out of the range of a slice.
    EndOutOfRange { end: isize, length: usize },

    /// Neither Unicode nor OEM encoding was selected.
    NeitherUnicodeNorOem,
}
impl fmt::Display for ParsingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ShortHeader { expected_min_len, obtained_len }
                => write!(f, "header too short (expected at least {} bytes, obtained {})", expected_min_len, obtained_len),
            Self::MagicMismatch { expected, obtained }
                => write!(f, "mismatched magic (expected {:?}, obtained {:?})", expected, obtained),
            Self::ItemLengthMismatch { expected, obtained }
                => write!(f, "insufficient length for an internal item (expected {:?}, obtained {:?})", expected, obtained),
            Self::ItemMinLengthMismatch { expected_at_least, obtained }
                => write!(f, "insufficient minimum length for an internal item (expected at least {:?}, obtained {:?})", expected_at_least, obtained),
            Self::ItemLengthNotDivisible { expected_divisor, obtained_length }
                => write!(f, "item length {} not divisible by {}", obtained_length, expected_divisor),
            Self::InvalidOemEncoding { value }
                => write!(f, "failed to decode value with the current OEM encoding: {:?}", value),
            Self::InvalidUtf16{ value }
                => write!(f, "failed to decode value as UTF-16: {:?}", value),
            Self::OffsetTooLargeIsize
                => write!(f, "the offset value is too large for the isize type"),
            Self::LengthTooLargeIsize
                => write!(f, "the length value is too large for the isize type"),
            Self::StartOutOfRange { start, length }
                => write!(f, "start ({}) out of range (slice has {} items)", start, length),
            Self::EndOutOfRange { end, length }
                => write!(f, "end ({}) out of range (slice has {} items)", end, length),
            Self::NeitherUnicodeNorOem
                => write!(f, "neither Unicode nor OEM encoding was selected"),
        }
    }
}
impl std::error::Error for ParsingError {}

/// An error that may occur while writing an NTLM packet.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum StoringError {
    /// The string cannot be encoded using the OEM encoding.
    NonOemEncodable { string: String },

    /// Neither Unicode nor OEM encoding was selected.
    NeitherUnicodeNorOem,
}
impl fmt::Display for StoringError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonOemEncodable { string } => {
                write!(f, "failed to encode {:?} using OEM encoding", string)
            }
            Self::NeitherUnicodeNorOem => {
                write!(f, "neither Unicode nor OEM encoding was selected")
            }
        }
    }
}
impl std::error::Error for StoringError {}

/// An NTLM message.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Message {
    Negotiate(NegotiateMessage),
    Challenge(ChallengeMessage),
    Authenticate(AuthenticateMessage),
    Other(u32, Vec<u8>),
}
impl Message {
    /// Returns the 32-bit message number identifying the type of this message.
    pub fn message_number(&self) -> u32 {
        match self {
            Self::Negotiate(_) => 0x0000_0001,
            Self::Challenge(_) => 0x0000_0002,
            Self::Authenticate(_) => 0x0000_0003,
            Self::Other(t, _data) => *t,
        }
    }
}

/// A structure representing the version of an operating system as well as the NTLM revision used.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OsVersion {
    pub major_version: u8,
    pub minor_version: u8,
    pub build_number: u16,
    pub reserved: [u8; 3],
    pub ntlm_revision: u8,
}
impl Default for OsVersion {
    fn default() -> Self {
        Self {
            major_version: 0,
            minor_version: 0,
            build_number: 0,
            reserved: [0, 0, 0],
            ntlm_revision: 0,
        }
    }
}

/// The contents of an NTLM Negotiate message.
///
/// The Negotiate message is the first message in an NTLM challenge-response process and is sent by
/// the client to the server; the server is expected to respond with a Challenge message.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NegotiateMessage {
    /// Stores which information has been specified and which NTLM behavior should be negotiated.
    pub flags: Flags,

    /// The domain against which the client wishes to authenticate.
    pub supplied_domain: String,

    /// The NT hostname of the client.
    pub supplied_workstation: String,

    /// Version information about the client's operating system.
    pub os_version: OsVersion,
}

/// The contents of an NTLM Challenge message.
///
/// The Challenge message is sent by the server in response to the client's Negotiate message; the
/// client is expected to respond with an Authenticate message.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ChallengeMessage {
    /// The host against which the client is authenticating.
    pub target_name: String,

    /// Stores which NTLM behavior has been accepted by the server from the client's request.
    pub flags: Flags,

    /// The challenge value.
    pub challenge: [u8; 8],

    /// The context value.
    pub context: (u32, u32),

    /// Information about the targets of the authentication.
    pub target_information: Vec<TargetInfoEntry>,

    /// Version information about the server's operating system.
    pub os_version: OsVersion,
}

/// The contents of an NTLM Authenticate message.
///
/// The Authenticate message is sent by the client in response to the server's Challenge message;
/// once it is accepted by the server, the authentication has succeeded.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AuthenticateMessage {
    pub lm_response: Vec<u8>,
    pub ntlm_response: Vec<u8>,
    pub domain_name: String,
    pub user_name: String,
    pub workstation_name: String,
    pub session_key: Vec<u8>,
    pub flags: Flags,
    pub os_version: OsVersion,
    /// Optional 16-byte MIC, occupying bytes 72..88 of the serialized message when present.
    pub mic: Option<[u8; 16]>,
}

/// An NTLM security buffer, pointing to a string contained later in the message.
#[derive(Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SecurityBuffer {
    pub length: u16,
    pub capacity: u16,
    pub offset: u32,
}

/// The type of additional target information included in the Challenge message.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TargetInfoType {
    Terminator,
    NtServer,
    NtDomain,
    DnsDomain,
    DnsServer,
    DnsForest,
    Flags,
    Timestamp,
    SingleHost,
    TargetName,
    ChannelBindings,
    Unknown(u16),
}
impl From<TargetInfoType> for u16 {
    fn from(t: TargetInfoType) -> Self {
        match t {
            TargetInfoType::Terminator => 0x0000,
            TargetInfoType::NtServer => 0x0001,
            TargetInfoType::NtDomain => 0x0002,
            TargetInfoType::DnsServer => 0x0003,
            TargetInfoType::DnsDomain => 0x0004,
            TargetInfoType::DnsForest => 0x0005,
            TargetInfoType::Flags => 0x0006,
            TargetInfoType::Timestamp => 0x0007,
            TargetInfoType::SingleHost => 0x0008,
            TargetInfoType::TargetName => 0x0009,
            TargetInfoType::ChannelBindings => 0x000A,
            TargetInfoType::Unknown(w) => w,
        }
    }
}
impl From<u16> for TargetInfoType {
    fn from(w: u16) -> Self {
        match w {
            0x0000 => TargetInfoType::Terminator,
            0x0001 => TargetInfoType::NtServer,
            0x0002 => TargetInfoType::NtDomain,
            0x0003 => TargetInfoType::DnsServer,
            0x0004 => TargetInfoType::DnsDomain,
            0x0005 => TargetInfoType::DnsForest,
            0x0006 => TargetInfoType::Flags,
            0x0007 => TargetInfoType::Timestamp,
            0x0008 => TargetInfoType::SingleHost,
            0x0009 => TargetInfoType::TargetName,
            0x000A => TargetInfoType::ChannelBindings,
            other => TargetInfoType::Unknown(other),
        }
    }
}

/// An entry of additional target information included in the Challenge message.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TargetInfoEntry {
    pub entry_type: TargetInfoType,
    pub data: Vec<u8>,
}

// serialization and deserialization code

/// Appends a security buffer to the end of a message.
///
/// The security buffer is appended to `message_bytes` while the data itself is appended to
/// `data_block`. It is assumed that once `message_bytes` has been filled with all the required
/// information, the contents of `data_block` are appended to it. `sec_buffer_offset` takes care of
/// the next free offset in the message at which data of a security buffer can be appended.
fn append_sec_buffer(
    message_bytes: &mut Vec<u8>,
    data_block: &mut Vec<u8>,
    sec_buffer_offset: &mut u32,
    data: &[u8],
) {
    // data_block will be placed at the end of the packet; fill it with the actual data
    data_block.extend_from_slice(data);

    // create an NTLM security buffer which will point to the data
    let mut sb = SecurityBuffer::for_slice(data);
    sb.offset = *sec_buffer_offset;

    // add this security buffer to the message
    message_bytes.extend_from_slice(&sb.to_bytes());

    // update the offset for the next security buffer
    *sec_buffer_offset += u32::from(sb.length);
}

/// Appends a security buffer to the end of a message, where the data is a string.
///
/// Functions similarly to [`append_sec_buffer`], but encodes the string in the expected format
/// first.
fn append_sec_buffer_string(
    packet_bytes: &mut Vec<u8>,
    data_block: &mut Vec<u8>,
    sec_buffer_offset: &mut u32,
    flags: Flags,
    data: &str,
) -> Result<(), StoringError> {
    let bs = if flags.contains(Flags::NEGOTIATE_UNICODE) {
        data.encode_utf16().flat_map(|w| w.to_le_bytes()).collect()
    } else if flags.contains(Flags::NEGOTIATE_OEM) {
        rust_string_to_ansi(data).ok_or_else(|| StoringError::NonOemEncodable {
            string: data.to_owned(),
        })?
    } else {
        return Err(StoringError::NeitherUnicodeNorOem);
    };

    append_sec_buffer(packet_bytes, data_block, sec_buffer_offset, &bs);

    Ok(())
}

/// Converts UTF-16 values stored as bytes in little-endian format into a string.
fn utf16_le_bytes_to_string(bytes: &[u8]) -> Result<String, ParsingError> {
    if bytes.len() % 2 != 0 {
        return Err(ParsingError::ItemLengthNotDivisible {
            expected_divisor: 2,
            obtained_length: bytes.len(),
        });
    }
    let u16s: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|chk| u16::from_le_bytes(chk.try_into().unwrap()))
        .collect();
    String::from_utf16(&u16s).or(Err(ParsingError::InvalidUtf16 { value: u16s }))
}

/// Converts an ANSI string into a Rust string.
fn oem_bytes_to_string(bytes: &[u8]) -> Result<String, ParsingError> {
    ansi_string_to_rust(bytes).ok_or_else(|| ParsingError::InvalidOemEncoding {
        value: Vec::from(bytes),
    })
}

/// Converts a string into a Rust string, using ANSI or UTF-16 encoding depending on the `flags`.
fn ntlm_bytes_to_string(flags: Flags, bytes: &[u8]) -> Result<String, ParsingError> {
    if flags.contains(Flags::NEGOTIATE_UNICODE) {
        utf16_le_bytes_to_string(bytes)
    } else if flags.contains(Flags::NEGOTIATE_OEM) {
        oem_bytes_to_string(bytes)
    } else {
        Err(ParsingError::NeitherUnicodeNorOem)
    }
}

impl Message {
    /// Serializes the NTLM message into bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, StoringError> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&NTLMSSP_MAGIC);
        buf.extend_from_slice(&self.message_number().to_le_bytes());
        match self {
            Message::Negotiate(t1m) => {
                buf.extend_from_slice(&t1m.to_bytes()?);
            }
            Message::Challenge(t2m) => {
                buf.extend_from_slice(&t2m.to_bytes()?);
            }
            Message::Authenticate(t3m) => {
                buf.extend_from_slice(&t3m.to_bytes()?);
            }
            Message::Other(_msg_num, data) => {
                buf.extend_from_slice(data);
            }
        }
        Ok(buf)
    }
}
impl TryFrom<&[u8]> for Message {
    type Error = ParsingError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() < 12 {
            // assume magic mismatch
            return Err(ParsingError::ShortHeader {
                expected_min_len: 12,
                obtained_len: value.len(),
            });
        }
        let obtained_magic: [u8; 8] = value[0..8].try_into().unwrap();
        if obtained_magic != NTLMSSP_MAGIC {
            return Err(ParsingError::MagicMismatch {
                expected: NTLMSSP_MAGIC,
                obtained: Vec::from(obtained_magic),
            });
        }
        let message_type = u32::from_le_bytes(value[8..12].try_into().unwrap());
        match message_type {
            0x0000_0001 => {
                NegotiateMessage::try_from(&value[12..]).map(|t1m| Message::Negotiate(t1m))
            }
            0x0000_0002 => {
                ChallengeMessage::try_from(&value[12..]).map(|t2m| Message::Challenge(t2m))
            }
            0x0000_0003 => {
                AuthenticateMessage::try_from(&value[12..]).map(|t3m| Message::Authenticate(t3m))
            }
            other_type => Ok(Message::Other(other_type, Vec::from(&value[12..]))),
        }
    }
}

impl OsVersion {
    /// Serializes the OS version structure into bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut ret = Vec::with_capacity(8);
        ret.push(self.major_version);
        ret.push(self.minor_version);
        ret.extend_from_slice(&self.build_number.to_le_bytes());
        ret.extend_from_slice(&self.reserved);
        ret.push(self.ntlm_revision);
        ret
    }
}
impl TryFrom<&[u8]> for OsVersion {
    type Error = ParsingError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != 8 {
            return Err(ParsingError::ItemLengthMismatch {
                expected: 8,
                obtained: value.len(),
            });
        }

        let major_version = value[0];
        let minor_version = value[1];
        let build_number = u16::from_le_bytes(value[2..4].try_into().unwrap());
        let reserved = value[4..7].try_into().unwrap();
        let ntlm_revision = value[7];

        Ok(OsVersion {
            major_version,
            minor_version,
            build_number,
            reserved,
            ntlm_revision,
        })
    }
}

impl NegotiateMessage {
    /// Serializes the Negotiate message body into bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, StoringError> {
        let mut sec_buffer_offset: u32
            = 8 // magic
            + 4 // message type
            + 4 // flags
            + 8 // supplied domain secbuffer
            + 8 // supplied workstation secbuffer
            + 8 // version
            ;

        let mut ret = Vec::new();
        let mut data_block = Vec::new();

        ret.extend_from_slice(&self.flags.bits().to_le_bytes());
        append_sec_buffer_string(
            &mut ret,
            &mut data_block,
            &mut sec_buffer_offset,
            self.flags,
            &self.supplied_domain,
        )?;
        append_sec_buffer_string(
            &mut ret,
            &mut data_block,
            &mut sec_buffer_offset,
            self.flags,
            &self.supplied_workstation,
        )?;
        ret.extend_from_slice(&self.os_version.to_bytes());
        ret.append(&mut data_block);
        Ok(ret)
    }
}
impl TryFrom<&[u8]> for NegotiateMessage {
    type Error = ParsingError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        // magic and message type have already been sliced away

        if value.len() < 32 {
            return Err(ParsingError::ItemMinLengthMismatch {
                expected_at_least: 32,
                obtained: value.len(),
            });
        }
        let flags_u32 = u32::from_le_bytes(value[0..4].try_into().unwrap());
        let flags = Flags::from_bits(flags_u32).unwrap();

        let supplied_domain_secbuf = SecurityBuffer::try_from(&value[4..12]).unwrap();
        let supplied_workstation_secbuf = SecurityBuffer::try_from(&value[12..20]).unwrap();
        let os_version = if flags.contains(Flags::NEGOTIATE_VERSION) {
            OsVersion::try_from(&value[20..28]).unwrap()
        } else {
            OsVersion::default()
        };

        // offsets in secbufs are in relation to the start of the message
        // however, magic and message type have already been sliced away
        // adjust offsets accordingly
        let supplied_domain_bytes = supplied_domain_secbuf.apply_to_slice(&value, -(8 + 4))?;
        let supplied_workstation_bytes =
            supplied_workstation_secbuf.apply_to_slice(&value, -(8 + 4))?;

        let supplied_domain = ntlm_bytes_to_string(flags, supplied_domain_bytes)?;
        let supplied_workstation = ntlm_bytes_to_string(flags, supplied_workstation_bytes)?;

        Ok(Self {
            flags,
            supplied_domain,
            supplied_workstation,
            os_version,
        })
    }
}

impl ChallengeMessage {
    /// Serializes the Challenge message body into bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, StoringError> {
        let mut sec_buffer_offset: u32
            = 8 // magic
            + 4 // message type
            + 8 // target name secbuffer
            + 4 // flags
            + 8 // challenge
            + 8 // context
            + 8 // target information secbuffer
            + 8 // version
            ;

        let mut ret = Vec::new();
        let mut data_block = Vec::new();

        append_sec_buffer_string(
            &mut ret,
            &mut data_block,
            &mut sec_buffer_offset,
            self.flags,
            &self.target_name,
        )?;
        ret.extend_from_slice(&self.flags.bits().to_le_bytes());
        ret.extend_from_slice(&self.challenge);
        data_block.extend_from_slice(&self.context.0.to_le_bytes());
        data_block.extend_from_slice(&self.context.1.to_le_bytes());
        {
            let target_info_bytes: Vec<u8> = self
                .target_information
                .iter()
                .flat_map(|ti| ti.to_bytes())
                .collect();
            append_sec_buffer(
                &mut ret,
                &mut data_block,
                &mut sec_buffer_offset,
                &target_info_bytes,
            );
        }
        ret.extend_from_slice(&self.os_version.to_bytes());
        ret.append(&mut data_block);
        Ok(ret)
    }
}
impl TryFrom<&[u8]> for ChallengeMessage {
    type Error = ParsingError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        // magic and message type have already been sliced away

        if value.len() < 44 {
            return Err(ParsingError::ItemMinLengthMismatch {
                expected_at_least: 44,
                obtained: value.len(),
            });
        }
        let target_name_secbuf = SecurityBuffer::try_from(&value[0..8]).unwrap();
        let flags_u32 = u32::from_le_bytes(value[8..12].try_into().unwrap());
        let flags = Flags::from_bits(flags_u32).unwrap();
        let challenge = value[12..20].try_into().unwrap();
        let context = {
            let context_0 = u32::from_le_bytes(value[20..24].try_into().unwrap());
            let context_1 = u32::from_le_bytes(value[24..28].try_into().unwrap());
            (context_0, context_1)
        };
        let target_info_secbuf = SecurityBuffer::try_from(&value[28..36]).unwrap();
        let os_version = if flags.contains(Flags::NEGOTIATE_VERSION) {
            OsVersion::try_from(&value[36..44]).unwrap()
        } else {
            OsVersion::default()
        };

        // offsets in secbufs are in relation to the start of the message
        // however, magic and message type have already been sliced away
        // adjust offsets accordingly
        let target_name_bytes = target_name_secbuf.apply_to_slice(&value, -(8 + 4))?;
        let mut target_info_bytes = target_info_secbuf.apply_to_slice(&value, -(8 + 4))?;

        let target_name = ntlm_bytes_to_string(flags, target_name_bytes)?;

        let mut target_information = Vec::new();
        while target_info_bytes.len() > 0 {
            let (tie, next) = TargetInfoEntry::try_from_bytes(&target_info_bytes)?;
            target_information.push(tie);
            target_info_bytes = next;
        }

        Ok(Self {
            target_name,
            flags,
            challenge,
            context,
            target_information,
            os_version,
        })
    }
}

impl AuthenticateMessage {
    /// The byte offset of the MIC field within the full NTLM message (including magic + type).
    ///
    /// This is 8 (magic) + 4 (type) + 48 (6 security buffers) + 4 (flags) + 8 (version) = 72.
    pub const MIC_OFFSET: usize = 72;

    /// The length of the MIC field in bytes.
    pub const MIC_LENGTH: usize = 16;

    /// Serializes the Authenticate message body into bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, StoringError> {
        let mut sec_buffer_offset: u32
            = 8 // magic
            + 4 // message type
            + 8 // LM response secbuffer
            + 8 // NTLM response secbuffer
            + 8 // domain name secbuffer
            + 8 // user name secbuffer
            + 8 // workstation name secbuffer
            + 8 // session key secbuffer
            + 4 // flags
            + 8 // version
            ;

        if self.mic.is_some() {
            sec_buffer_offset += Self::MIC_LENGTH as u32;
        }

        let mut ret = Vec::new();
        let mut data_block = Vec::new();

        append_sec_buffer(
            &mut ret,
            &mut data_block,
            &mut sec_buffer_offset,
            &self.lm_response,
        );
        append_sec_buffer(
            &mut ret,
            &mut data_block,
            &mut sec_buffer_offset,
            &self.ntlm_response,
        );
        append_sec_buffer_string(
            &mut ret,
            &mut data_block,
            &mut sec_buffer_offset,
            self.flags,
            &self.domain_name,
        )?;
        append_sec_buffer_string(
            &mut ret,
            &mut data_block,
            &mut sec_buffer_offset,
            self.flags,
            &self.user_name,
        )?;
        append_sec_buffer_string(
            &mut ret,
            &mut data_block,
            &mut sec_buffer_offset,
            self.flags,
            &self.workstation_name,
        )?;
        append_sec_buffer(
            &mut ret,
            &mut data_block,
            &mut sec_buffer_offset,
            &self.session_key,
        );
        ret.extend_from_slice(&self.flags.bits().to_le_bytes());
        ret.extend_from_slice(&self.os_version.to_bytes());

        if let Some(mic) = &self.mic {
            ret.extend_from_slice(mic);
        }

        ret.append(&mut data_block);
        Ok(ret)
    }
}
impl TryFrom<&[u8]> for AuthenticateMessage {
    type Error = ParsingError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        // magic and message type have already been sliced away

        if value.len() < 60 {
            return Err(ParsingError::ItemMinLengthMismatch {
                expected_at_least: 60,
                obtained: value.len(),
            });
        }
        let lm_response_secbuf = SecurityBuffer::try_from(&value[0..8]).unwrap();
        let ntlm_response_secbuf = SecurityBuffer::try_from(&value[8..16]).unwrap();
        let domain_name_secbuf = SecurityBuffer::try_from(&value[16..24]).unwrap();
        let user_name_secbuf = SecurityBuffer::try_from(&value[24..32]).unwrap();
        let workstation_name_secbuf = SecurityBuffer::try_from(&value[32..40]).unwrap();
        let session_key_secbuf = SecurityBuffer::try_from(&value[40..48]).unwrap();
        let flags_u32 = u32::from_le_bytes(value[48..52].try_into().unwrap());
        let flags = Flags::from_bits(flags_u32).unwrap();
        let os_version = if flags.contains(Flags::NEGOTIATE_VERSION) {
            OsVersion::try_from(&value[52..60]).unwrap()
        } else {
            OsVersion::default()
        };

        // offsets in secbufs are in relation to the start of the message
        // however, magic and message type have already been sliced away
        // adjust offsets accordingly
        let lm_response_bytes = lm_response_secbuf.apply_to_slice(&value, -(8 + 4))?;
        let ntlm_response_bytes = ntlm_response_secbuf.apply_to_slice(&value, -(8 + 4))?;
        let domain_name_bytes = domain_name_secbuf.apply_to_slice(&value, -(8 + 4))?;
        let user_name_bytes = user_name_secbuf.apply_to_slice(&value, -(8 + 4))?;
        let workstation_name_bytes = workstation_name_secbuf.apply_to_slice(&value, -(8 + 4))?;
        let session_key_bytes = session_key_secbuf.apply_to_slice(&value, -(8 + 4))?;

        let lm_response = Vec::from(lm_response_bytes);
        let ntlm_response = Vec::from(ntlm_response_bytes);
        let domain_name = ntlm_bytes_to_string(flags, domain_name_bytes)?;
        let user_name = ntlm_bytes_to_string(flags, user_name_bytes)?;
        let workstation_name = ntlm_bytes_to_string(flags, workstation_name_bytes)?;
        let session_key = Vec::from(session_key_bytes);

        // MIC is present if all security buffer offsets are >= 88 (header + MIC)
        let min_data_offset = [
            &lm_response_secbuf,
            &ntlm_response_secbuf,
            &domain_name_secbuf,
            &user_name_secbuf,
            &workstation_name_secbuf,
            &session_key_secbuf,
        ]
        .iter()
        .filter(|sb| sb.length > 0)
        .map(|sb| sb.offset)
        .min();

        let mic = if min_data_offset.unwrap_or(0) >= 88 && value.len() >= 76 {
            let mic_bytes: [u8; 16] = value[60..76].try_into().unwrap();
            if mic_bytes == [0u8; 16] {
                None
            } else {
                Some(mic_bytes)
            }
        } else {
            None
        };

        Ok(Self {
            lm_response,
            ntlm_response,
            domain_name,
            user_name,
            workstation_name,
            session_key,
            flags,
            os_version,
            mic,
        })
    }
}

impl SecurityBuffer {
    /// Generates a security buffer for the given slice of bytes.
    ///
    /// The length and capacity are set to the length of the slice, while the offset is set to 0.
    pub fn for_slice(slice: &[u8]) -> Self {
        let len_u16: u16 = slice
            .len()
            .try_into()
            .expect("buffer too long for u16 length");
        Self {
            length: len_u16,
            capacity: len_u16,
            offset: 0,
        }
    }

    /// Serializes the security buffer into bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut ret = Vec::with_capacity(8);
        ret.extend_from_slice(&self.length.to_le_bytes());
        ret.extend_from_slice(&self.capacity.to_le_bytes());
        ret.extend_from_slice(&self.offset.to_le_bytes());
        ret
    }

    /// Applies the security buffer to a slice, extracting the data itself.
    ///
    /// The data is assumed to be located in `slice` beginning at `self.offset`. In case leading
    /// fields have been removed from `slice`, the offset may be further adjusted through `adjust`.
    pub fn apply_to_slice<'a>(
        &self,
        slice: &'a [u8],
        adjust: isize,
    ) -> Result<&'a [u8], ParsingError> {
        if self.length == 0 {
            // short-circuit
            return Ok(&slice[0..0]);
        }

        let offset_isize: isize = self
            .offset
            .try_into()
            .or(Err(ParsingError::OffsetTooLargeIsize))?;
        let length_isize: isize = self
            .length
            .try_into()
            .or(Err(ParsingError::LengthTooLargeIsize))?;

        if offset_isize + adjust < 0 {
            return Err(ParsingError::StartOutOfRange {
                start: offset_isize + adjust,
                length: slice.len(),
            });
        }
        if offset_isize + length_isize + adjust < 0 {
            return Err(ParsingError::EndOutOfRange {
                end: offset_isize + length_isize + adjust,
                length: slice.len(),
            });
        }

        let start: usize = (offset_isize + adjust).try_into().unwrap();
        let end: usize = (offset_isize + length_isize + adjust).try_into().unwrap();

        if start >= slice.len() {
            return Err(ParsingError::StartOutOfRange {
                start: offset_isize + adjust,
                length: slice.len(),
            });
        }
        if end > slice.len() {
            return Err(ParsingError::EndOutOfRange {
                end: offset_isize + length_isize + adjust,
                length: slice.len(),
            });
        }

        Ok(&slice[start..end])
    }
}
impl TryFrom<&[u8]> for SecurityBuffer {
    type Error = ParsingError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != 8 {
            return Err(ParsingError::ItemLengthMismatch {
                expected: 8,
                obtained: value.len(),
            });
        }

        let length = u16::from_le_bytes(value[0..2].try_into().unwrap());
        let capacity = u16::from_le_bytes(value[2..4].try_into().unwrap());
        let offset = u32::from_le_bytes(value[4..8].try_into().unwrap());

        Ok(Self {
            length,
            capacity,
            offset,
        })
    }
}

impl TargetInfoEntry {
    /// Serializes the target info entry into bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut ret = Vec::new();

        // always Unicode, even if flags claim OEM
        let entry_type_u16: u16 = self.entry_type.into();
        let bytes_len: u16 = self
            .data
            .len()
            .try_into()
            .expect("length of bytes does not fit into u16");

        ret.extend_from_slice(&entry_type_u16.to_le_bytes());
        ret.extend_from_slice(&bytes_len.to_le_bytes());
        ret.extend_from_slice(&self.data);
        ret
    }

    /// Attempts to deserialize a target info entry from the given byte slice. If successful,
    /// returns the deserialized target info entry as well as any bytes remaining in the slice (that
    /// are not part of the freshly deserialized target info entry).
    pub fn try_from_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), ParsingError> {
        if bytes.len() < 4 {
            return Err(ParsingError::ItemMinLengthMismatch {
                expected_at_least: 4,
                obtained: bytes.len(),
            });
        }

        let entry_type_u16 = u16::from_le_bytes(bytes[0..2].try_into().unwrap());
        let entry_type: TargetInfoType = entry_type_u16.into();
        let length_u16 = u16::from_le_bytes(bytes[2..4].try_into().unwrap());
        let length: usize = length_u16.into();

        if length + 4 > bytes.len() {
            return Err(ParsingError::ItemMinLengthMismatch {
                expected_at_least: length + 4,
                obtained: bytes.len(),
            });
        }
        if length % 2 != 0 {
            return Err(ParsingError::ItemLengthNotDivisible {
                expected_divisor: 2,
                obtained_length: bytes.len(),
            });
        }

        let data = Vec::from(&bytes[4..4 + length]);

        let entry = Self { entry_type, data };
        let rest = &bytes[4 + length..];
        Ok((entry, rest))
    }

    /// Attempts to convert the data within this target info entry into a string.
    pub fn to_string(&self) -> Result<String, ParsingError> {
        utf16_le_bytes_to_string(&self.data)
    }

    /// Creates a target info entry from an entry type and a string.
    pub fn from_string(entry_type: TargetInfoType, string: &str) -> Self {
        // always Unicode, even if flags claim OEM
        let data: Vec<u8> = string
            .encode_utf16()
            .flat_map(|b| b.to_le_bytes())
            .collect();
        Self { entry_type, data }
    }
}

impl ChallengeResponse {
    /// Converts this response to a challenge into a full-blown Authenticate NTLM message.
    pub fn to_message(&self, creds: &Credentials, workstation_name: &str, flags: Flags) -> Message {
        Message::Authenticate(AuthenticateMessage {
            lm_response: self.lm_response.clone(),
            ntlm_response: self.ntlm_response.clone(),
            domain_name: creds.domain.clone(),
            user_name: creds.username.clone(),
            workstation_name: workstation_name.to_owned(),
            session_key: self.session_key.clone(),
            flags,
            os_version: Default::default(),
            mic: None,
        })
    }
}

// response calculation functions

/// Obtains the current NTLM timestamp.
pub fn get_ntlm_time() -> i64 {
    let windows_epoch = NaiveDate::from_ymd_opt(1601, 1, 1)
        .expect("1601-01-01 is not a valid date?!")
        .and_hms_opt(0, 0, 0)
        .expect("1601-01-01T00:00:00 is not a valid date-time?!")
        .and_utc();
    let now = Utc::now();
    // the requested format is "tenths of a microsecond", so multiply by 10_000_000 and read seconds
    let delta = (now - windows_epoch) * 10_000_000;
    delta.num_seconds()
}

/// Performs the NTLMv1 DES encryption to calculate the response value to the challenge.
pub fn des_long(key: [u8; 16], data: [u8; 8]) -> [u8; 24] {
    let key0: [u8; 7] = key[0..7].try_into().unwrap();
    let key1: [u8; 7] = key[7..14].try_into().unwrap();
    let key2: [u8; 7] = [key[14], key[15], 0, 0, 0, 0, 0];

    let des0 = Des::new_from_slice(&key0).unwrap();
    let des1 = Des::new_from_slice(&key1).unwrap();
    let des2 = Des::new_from_slice(&key2).unwrap();

    let mut res0: GenericArray<u8, U8> = data.try_into().unwrap();
    let mut res1 = res0.clone();
    let mut res2 = res0.clone();

    des0.encrypt_block(&mut res0);
    des1.encrypt_block(&mut res1);
    des2.encrypt_block(&mut res2);

    let mut ret = [0u8; 24];
    let (slice0, ret2) = ret.split_at_mut(8);
    let (slice1, slice2) = ret2.split_at_mut(8);
    slice0.copy_from_slice(res0.as_slice());
    slice1.copy_from_slice(res1.as_slice());
    slice2.copy_from_slice(res2.as_slice());

    ret
}

/// Derives the encryption key from a password according to the LMv1 scheme.
///
/// The LMv1 scheme consists of the following:
///
/// ```plain
///            ┌────────────┐  ┌───────────────┐  ┌─────────────┐
/// password ──┤ convert to ├──┤ encode using  ├──┤ truncate or ├──┐
///            │ uppercase  │  │ ANSI codepage │  │ pad to 14 B │  │
///            └────────────┘  └───────────────┘  └─────────────┘  │
///           ┌────────────────────────────────────────────────────┘
///           │┌───────┐
///           └┤ split │           "KGS!@#$%"
///            └─┬───┬─┘               │ input
///         0..7 │   │ 7..14    key ┌──┴──┐ output
///              │   └──────────────┤ DES ├────────────┐
///              │                  └─────┘            │ 0..8
///              │                                  ┌──┴───┐
///              │                 "KGS!@#$%"       │ join ├──── key
///              │                     │ input      └──┬───┘
///              │              key ┌──┴──┐ output     │ 8..16
///              └──────────────────┤ DES ├────────────┘
///                                 └─────┘
/// ```
pub fn lm_v1_password_func(password: &str) -> [u8; 16] {
    let des_plaintext_fixed: GenericArray<u8, U8> = GenericArray::from(*b"KGS!@#$%");

    let uppercase_password = password.to_uppercase();
    let mut password_bytes = match rust_string_to_ansi(&uppercase_password) {
        Some(bs) => bs,
        None => return [0; 16],
    };
    while password_bytes.len() < 14 {
        password_bytes.push(0x00);
    }

    let mut output = [0; 16];
    let (half0, half1) = output.split_at_mut(8);

    {
        {
            let des_state = Des::new_from_slice(&password_bytes[0..7]).unwrap();
            let mut buf = des_plaintext_fixed.clone();
            des_state.encrypt_block(&mut buf);
            half0.copy_from_slice(buf.as_slice());
        }
        {
            let des_state = Des::new_from_slice(&password_bytes[7..14]).unwrap();
            let mut buf = des_plaintext_fixed.clone();
            des_state.encrypt_block(&mut buf);
            half1.copy_from_slice(buf.as_slice());
        }
    }

    output
}

/// Derives the encryption key from a password according to the NTLMv1 scheme.
///
/// The NTLMv1 scheme encodes the password as UTF-16 in little-endian byte order (without the Byte
/// Order Mark) and hashes it using MD4.
pub fn ntlm_v1_password_func(password: &str) -> [u8; 16] {
    let password_bytes: Vec<u8> = password
        .encode_utf16()
        .flat_map(|p| p.to_le_bytes())
        .collect();
    let mut md4_state = <Md4 as Digest>::new();
    md4_state.update(&password_bytes);
    md4_state.finalize().as_slice().try_into().unwrap()
}

/// Derives the encryption key from a password according to the NTLMv2 scheme.
///
/// The NTLMv2 scheme is a HMAC-MD5 scheme whose key is the encryption key derived from the password
/// using the NTLMv1 scheme and whose plaintext is a concatenation of uppercase username and
/// unchanged-case domain, each encoded as UTF-16 in little-endian byte order without the Byte Order
/// Mark.
pub fn ntlm_v2_password_func(creds: &Credentials) -> [u8; 16] {
    // the HMAC key func is the same as the NTLMv1 password func
    let hmac_key = ntlm_v1_password_func(&creds.password);
    let mut hmac_md5: Hmac<Md5> = <Hmac<Md5> as Mac>::new_from_slice(&hmac_key).unwrap();

    let upper_user_bytes: Vec<u8> = creds
        .username
        .to_uppercase()
        .encode_utf16()
        .flat_map(|p| p.to_le_bytes())
        .collect();
    hmac_md5.update(&upper_user_bytes);
    let dom_bytes: Vec<u8> = creds
        .domain
        .encode_utf16()
        .flat_map(|p| p.to_le_bytes())
        .collect();
    hmac_md5.update(&dom_bytes);

    let mut ret = [0; 16];
    ret.copy_from_slice(hmac_md5.finalize().into_bytes().as_slice());
    ret
}

/// Calculates an NTLMv1 response to the given server challenge.
///
/// An LMv1 response is also included.
pub fn respond_challenge_ntlm_v1(
    server_challenge: [u8; 8],
    creds: &Credentials,
) -> ChallengeResponse {
    let ntlm_key = ntlm_v1_password_func(&creds.password);
    let ntlm_response = Vec::from(des_long(ntlm_key, server_challenge));

    let lm_key = lm_v1_password_func(&creds.password);
    let lm_response = Vec::from(des_long(lm_key, server_challenge));

    let session_key = {
        let mut md4 = <Md4 as Digest>::new();
        md4.update(&ntlm_key);
        Vec::from(md4.finalize().as_slice())
    };

    ChallengeResponse {
        lm_response,
        ntlm_response,
        session_key,
    }
}

/// Calculates an NTLMv1 response to the given server challenge.
///
/// No LM response is included; instead, the NTLMv1 response is copied.
pub fn respond_challenge_ntlm_v1_no_lm(
    server_challenge: [u8; 8],
    creds: &Credentials,
) -> ChallengeResponse {
    let ntlm_key = ntlm_v1_password_func(&creds.password);
    let ntlm_response = Vec::from(des_long(ntlm_key, server_challenge));

    let lm_response = ntlm_response.clone();

    let session_key = {
        let mut md4 = <Md4 as Digest>::new();
        md4.update(&ntlm_key);
        Vec::from(md4.finalize().as_slice())
    };

    ChallengeResponse {
        lm_response,
        ntlm_response,
        session_key,
    }
}

/// Calculates an extended NTLMv1 response to the given server challenge.
///
/// The NTLM response is in the extended format; the LM response field contains the randomly
/// generated client challenge which has also influenced the calculation of the NTLM response.
pub fn respond_challenge_ntlm_v1_extended(
    server_challenge: [u8; 8],
    creds: &Credentials,
) -> ChallengeResponse {
    let mut client_challenge: [u8; 8] = [0; 8];
    rng().fill(&mut client_challenge);

    let ntlm_key = ntlm_v1_password_func(&creds.password);

    let desl_plaintext: [u8; 8] = {
        let mut md5 = <Md5 as Digest>::new();
        md5.update(server_challenge);
        md5.update(client_challenge);
        let digest = md5.finalize();

        let mut dk = [0u8; 8];
        dk.copy_from_slice(&digest.as_slice()[0..8]);
        dk
    };

    let ntlm_response = Vec::from(des_long(ntlm_key, desl_plaintext));
    let mut lm_response = Vec::with_capacity(24);
    lm_response.extend_from_slice(&client_challenge);
    while lm_response.len() < 24 {
        lm_response.push(0);
    }

    let session_key = {
        let mut md4 = <Md4 as Digest>::new();
        md4.update(&ntlm_key);
        Vec::from(md4.finalize().as_slice())
    };

    ChallengeResponse {
        lm_response,
        ntlm_response,
        session_key,
    }
}

/// Calculates an NTLMv2 response to the given server challenge, including target info and time
/// value to protect against replay attacks.
pub fn respond_challenge_ntlm_v2(
    server_challenge: [u8; 8],
    target_info: &[u8],
    time: i64,
    creds: &Credentials,
) -> ChallengeResponse {
    let mut client_challenge: [u8; 8] = [0; 8];
    rng().fill(&mut client_challenge);

    let mut temp = Vec::new();
    temp.push(0x01); // Responserversion
    temp.push(0x01); // HiResponserversion
    for _ in 0..6 {
        temp.push(0x00);
    }
    temp.extend_from_slice(&time.to_le_bytes());
    temp.extend_from_slice(&client_challenge);
    for _ in 0..4 {
        temp.push(0x00);
    }
    temp.extend_from_slice(&target_info);
    for _ in 0..4 {
        temp.push(0x00);
    }

    let ntlm_key = ntlm_v2_password_func(&creds);

    let nt_proof_string = {
        let mut hmac_md5: Hmac<Md5> = <Hmac<Md5> as Mac>::new_from_slice(&ntlm_key).unwrap();
        hmac_md5.update(&server_challenge);
        hmac_md5.update(&temp);

        let mut ps = [0u8; 16];
        ps.copy_from_slice(hmac_md5.finalize().into_bytes().as_slice());
        ps
    };

    let mut ntlm_response = Vec::with_capacity(16 + temp.len());
    ntlm_response.extend_from_slice(&nt_proof_string);
    ntlm_response.extend_from_slice(&temp);

    let mut lm_response = Vec::with_capacity(16 + 8);
    {
        let mut hmac_md5: Hmac<Md5> = <Hmac<Md5> as Mac>::new_from_slice(&ntlm_key).unwrap();
        hmac_md5.update(&server_challenge);
        hmac_md5.update(&client_challenge);
        lm_response.extend_from_slice(hmac_md5.finalize().into_bytes().as_slice());
    }
    lm_response.extend_from_slice(&client_challenge);

    let session_key = {
        let mut hmac_md5: Hmac<Md5> = <Hmac<Md5> as Mac>::new_from_slice(&ntlm_key).unwrap();
        hmac_md5.update(&nt_proof_string);
        Vec::from(hmac_md5.finalize().into_bytes().as_slice())
    };

    ChallengeResponse {
        lm_response,
        ntlm_response,
        session_key,
    }
}

// Channel Binding Token (CBT) / Extended Protection for Authentication (EPA)

/// The `MsvAvFlags` bit indicating that the client has computed a MIC and included it in the
/// Type 3 message.
pub const AV_FLAGS_MIC_PROVIDED: u32 = 0x0000_0002;

/// Computes the 16-byte NTLM channel binding hash from a server's DER-encoded TLS certificate.
///
/// Implements `tls-server-end-point` channel binding (RFC 5929) via the GSS channel
/// bindings struct (RFC 4121 §4.1.1.2), producing the `MsvAvChannelBindings` value.
pub fn compute_channel_bindings_hash(server_cert_der: &[u8]) -> [u8; 16] {
    let cert_hash = <Sha256 as Digest>::digest(server_cert_der);

    let mut application_data = b"tls-server-end-point:".to_vec();
    application_data.extend_from_slice(&cert_hash);

    // GSS channel bindings: 4 zero fields (initiator/acceptor addr type + length) + app data
    let mut gss_bindings = Vec::with_capacity(20 + application_data.len());
    for _ in 0..4 {
        gss_bindings.extend_from_slice(&0u32.to_le_bytes());
    }
    gss_bindings.extend_from_slice(&(application_data.len() as u32).to_le_bytes());
    gss_bindings.extend_from_slice(&application_data);

    <Md5 as Digest>::digest(&gss_bindings).into()
}

/// Injects `MsvAvChannelBindings` and/or `MsvAvFlags` into a target info entry list,
/// replacing any pre-existing values. Always re-adds the terminator.
///
/// - `cbt_hash`: if `Some`, replaces any existing `ChannelBindings` entry.
/// - `flags_value`: if `Some`, replaces any existing `Flags` entry with this value.
///   If `None`, preserves the original `Flags` entry (if any).
pub fn inject_av_pairs(
    target_info: &[TargetInfoEntry],
    cbt_hash: Option<[u8; 16]>,
    flags_value: Option<u32>,
) -> Vec<TargetInfoEntry> {
    let mut result: Vec<TargetInfoEntry> = Vec::with_capacity(target_info.len() + 3);

    for entry in target_info {
        match entry.entry_type {
            TargetInfoType::Terminator => {}
            TargetInfoType::ChannelBindings => {}
            TargetInfoType::Flags if flags_value.is_some() => {}
            _ => result.push(entry.clone()),
        }
    }

    if let Some(fv) = flags_value {
        result.push(TargetInfoEntry {
            entry_type: TargetInfoType::Flags,
            data: fv.to_le_bytes().to_vec(),
        });
    }

    if let Some(hash) = cbt_hash {
        result.push(TargetInfoEntry {
            entry_type: TargetInfoType::ChannelBindings,
            data: hash.to_vec(),
        });
    }

    result.push(TargetInfoEntry {
        entry_type: TargetInfoType::Terminator,
        data: Vec::new(),
    });

    result
}

/// Parses raw target_info bytes into a list of [`TargetInfoEntry`] values.
pub fn parse_target_info(mut bytes: &[u8]) -> Result<Vec<TargetInfoEntry>, ParsingError> {
    let mut entries = Vec::new();
    while !bytes.is_empty() {
        let (entry, rest) = TargetInfoEntry::try_from_bytes(bytes)?;
        entries.push(entry);
        bytes = rest;
    }
    Ok(entries)
}

/// Serializes a list of [`TargetInfoEntry`] values into raw bytes.
pub fn serialize_target_info(entries: &[TargetInfoEntry]) -> Vec<u8> {
    entries.iter().flat_map(|e| e.to_bytes()).collect()
}

/// Reads the `MsvAvFlags` value from a target info entry list, if present.
pub fn get_av_flags(target_info: &[TargetInfoEntry]) -> Option<u32> {
    for entry in target_info {
        if entry.entry_type == TargetInfoType::Flags && entry.data.len() == 4 {
            return Some(u32::from_le_bytes(entry.data[0..4].try_into().unwrap()));
        }
    }
    None
}

/// Returns `true` if the target info entries contain an `MsvAvTimestamp` entry.
pub fn has_av_timestamp(target_info: &[TargetInfoEntry]) -> bool {
    target_info
        .iter()
        .any(|e| e.entry_type == TargetInfoType::Timestamp)
}

/// Returns `true` when `MsvAvFlags` contains the `MIC_PROVIDED` bit (`0x0000_0002`).
///
/// This is the strict check. For the softer check that also triggers on `MsvAvTimestamp`
/// presence, see [`server_suggests_mic`].
pub fn server_requires_mic(target_info: &[TargetInfoEntry]) -> bool {
    get_av_flags(target_info).unwrap_or(0) & AV_FLAGS_MIC_PROVIDED != 0
}

/// Returns `true` when `MsvAvFlags` has the `MIC_PROVIDED` bit set, **or** when
/// `MsvAvTimestamp` is present (MS-NLMP §3.1.5.1.2 SHOULD).
pub fn server_suggests_mic(target_info: &[TargetInfoEntry]) -> bool {
    server_requires_mic(target_info) || has_av_timestamp(target_info)
}

// NTLMv2 Builder API

/// An error that may occur while building an NTLMv2 response.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum BuildError {
    /// The server requires a MIC but the negotiate and/or challenge message bytes were not
    /// provided via [`NtlmV2Builder::mic`].
    MicRequiredButMessagesNotProvided,

    /// An error occurred while serializing the authenticate message.
    Storing(StoringError),

    /// An error occurred while parsing the target info bytes.
    Parsing(ParsingError),
}
impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MicRequiredButMessagesNotProvided => write!(
                f,
                "server requires MIC but negotiate/challenge message bytes were not provided"
            ),
            Self::Storing(e) => write!(f, "storing error: {}", e),
            Self::Parsing(e) => write!(f, "parsing error: {}", e),
        }
    }
}
impl std::error::Error for BuildError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::MicRequiredButMessagesNotProvided => None,
            Self::Storing(e) => Some(e),
            Self::Parsing(e) => Some(e),
        }
    }
}
impl From<StoringError> for BuildError {
    fn from(e: StoringError) -> Self {
        Self::Storing(e)
    }
}
impl From<ParsingError> for BuildError {
    fn from(e: ParsingError) -> Self {
        Self::Parsing(e)
    }
}

/// A builder for NTLMv2 authenticate messages with optional CBT and MIC support.
///
/// ```ignore
/// let type3_bytes = NtlmV2Builder::new(challenge, &target_info, time, &creds)
///     .channel_binding(server_cert_der)
///     .mic(&negotiate_msg_bytes, &challenge_msg_bytes)
///     .build()?;
/// ```
pub struct NtlmV2Builder<'a> {
    challenge: [u8; 8],
    target_info: &'a [u8],
    time: i64,
    credentials: &'a Credentials,
    server_cert_der: Option<&'a [u8]>,
    negotiate_msg_bytes: Option<&'a [u8]>,
    challenge_msg_bytes: Option<&'a [u8]>,
    workstation: &'a str,
    flags: Flags,
    client_challenge: Option<[u8; 8]>,
    exported_session_key: Option<[u8; 16]>,
}

impl<'a> NtlmV2Builder<'a> {
    /// Creates a new builder with the required parameters.
    pub fn new(
        challenge: [u8; 8],
        target_info: &'a [u8],
        time: i64,
        credentials: &'a Credentials,
    ) -> Self {
        Self {
            challenge,
            target_info,
            time,
            credentials,
            server_cert_der: None,
            negotiate_msg_bytes: None,
            challenge_msg_bytes: None,
            workstation: "",
            flags: Flags::NEGOTIATE_UNICODE | Flags::NEGOTIATE_NTLM,
            client_challenge: None,
            exported_session_key: None,
        }
    }

    /// Enables Channel Binding Token (CBT) using the server's DER-encoded TLS certificate.
    pub fn channel_binding(mut self, server_cert_der: &'a [u8]) -> Self {
        self.server_cert_der = Some(server_cert_der);
        self
    }

    /// Provides the raw Type 1 and Type 2 message bytes for MIC computation.
    ///
    /// When provided, a MIC is included in the Type 3 message. Required if the server's
    /// `MsvAvFlags` has the `MIC_PROVIDED` bit set.
    pub fn mic(mut self, negotiate_msg_bytes: &'a [u8], challenge_msg_bytes: &'a [u8]) -> Self {
        self.negotiate_msg_bytes = Some(negotiate_msg_bytes);
        self.challenge_msg_bytes = Some(challenge_msg_bytes);
        self
    }

    /// Sets the workstation name included in the Type 3 message (default: empty string).
    pub fn workstation(mut self, workstation: &'a str) -> Self {
        self.workstation = workstation;
        self
    }

    /// Overrides the negotiate flags included in the Type 3 message.
    ///
    /// Default: `NEGOTIATE_UNICODE | NEGOTIATE_NTLM`.
    pub fn flags(mut self, flags: Flags) -> Self {
        self.flags = flags;
        self
    }

    /// Sets a fixed client challenge for testing. If not set, a random challenge is generated.
    pub fn client_challenge(mut self, challenge: [u8; 8]) -> Self {
        self.client_challenge = Some(challenge);
        self
    }

    /// Sets a fixed ExportedSessionKey for testing. Only meaningful when KEY_EXCH is active.
    pub fn exported_session_key(mut self, key: [u8; 16]) -> Self {
        self.exported_session_key = Some(key);
        self
    }

    /// Builds the NTLMv2 response without MIC, returning just the [`ChallengeResponse`].
    ///
    /// Applies CBT (if configured) to the target info but does NOT compute a MIC.
    /// If `MsvAvTimestamp` is present, the `lm_response` is set to `Z(24)` per MS-NLMP §3.1.5.1.2.
    pub fn build_response(&self) -> Result<ChallengeResponse, BuildError> {
        let parsed = parse_target_info(self.target_info)?;
        let target_info_bytes = self.prepare_target_info_from(&parsed, false)?;
        let mut response = self.compute_response(&target_info_bytes);

        if has_av_timestamp(&parsed) {
            response.lm_response = vec![0u8; 24];
        }

        Ok(response)
    }

    /// Builds the complete Type 3 authenticate message as serialized bytes.
    ///
    /// This is the primary method for most use cases. It handles CBT injection,
    /// MIC auto-detection, NTLMv2 response computation, KEY_EXCH derivation,
    /// and MIC patching.
    pub fn build(&self) -> Result<Vec<u8>, BuildError> {
        let parsed_target_info = parse_target_info(self.target_info)?;
        let have_mic_bytes =
            self.negotiate_msg_bytes.is_some() && self.challenge_msg_bytes.is_some();

        if server_requires_mic(&parsed_target_info) && !have_mic_bytes {
            return Err(BuildError::MicRequiredButMessagesNotProvided);
        }

        let include_mic = have_mic_bytes;
        let target_info_bytes = self.prepare_target_info_from(&parsed_target_info, include_mic)?;
        let response = self.compute_response(&target_info_bytes);

        let lm_response = if has_av_timestamp(&parsed_target_info) {
            vec![0u8; 24]
        } else {
            response.lm_response
        };

        // KEY_EXCH: derive ExportedSessionKey when KEY_EXCH + (SIGN or SEAL) are set
        let key_exch_active = self.flags.contains(Flags::NEGOTIATE_KEY_EXCHANGE)
            && self
                .flags
                .intersects(Flags::NEGOTIATE_SIGN | Flags::NEGOTIATE_SEAL);

        let (exported_session_key, encrypted_random_session_key) = if key_exch_active {
            let esk = self.exported_session_key.unwrap_or_else(|| {
                let mut nonce = [0u8; 16];
                rng().fill(&mut nonce);
                nonce
            });
            let mut encrypted = esk;
            let key = rc4::Key::<rc4::consts::U16>::from_slice(&response.session_key);
            let mut rc4: Rc4<rc4::consts::U16> = <Rc4<rc4::consts::U16> as KeyInit>::new(key);
            rc4.apply_keystream(&mut encrypted);
            (esk.to_vec(), encrypted.to_vec())
        } else {
            (response.session_key.clone(), vec![])
        };

        let auth_msg = AuthenticateMessage {
            lm_response,
            ntlm_response: response.ntlm_response,
            domain_name: self.credentials.domain.clone(),
            user_name: self.credentials.username.clone(),
            workstation_name: self.workstation.to_owned(),
            session_key: encrypted_random_session_key,
            flags: self.flags,
            os_version: Default::default(),
            mic: if include_mic { Some([0u8; 16]) } else { None },
        };

        let message = Message::Authenticate(auth_msg);
        let mut msg_bytes = message.to_bytes()?;

        if include_mic {
            let negotiate_bytes = self.negotiate_msg_bytes.unwrap();
            let challenge_bytes = self.challenge_msg_bytes.unwrap();

            let mut hmac_md5: Hmac<Md5> =
                <Hmac<Md5> as Mac>::new_from_slice(&exported_session_key).unwrap();
            hmac_md5.update(negotiate_bytes);
            hmac_md5.update(challenge_bytes);
            hmac_md5.update(&msg_bytes);

            let mic: [u8; 16] = hmac_md5.finalize().into_bytes().into();
            msg_bytes[AuthenticateMessage::MIC_OFFSET
                ..AuthenticateMessage::MIC_OFFSET + AuthenticateMessage::MIC_LENGTH]
                .copy_from_slice(&mic);
        }

        Ok(msg_bytes)
    }

    /// Prepares the target info bytes, injecting CBT and MIC flags as needed.
    fn prepare_target_info_from(
        &self,
        entries: &[TargetInfoEntry],
        include_mic: bool,
    ) -> Result<Vec<u8>, BuildError> {
        if self.server_cert_der.is_none() && !include_mic {
            return Ok(self.target_info.to_vec());
        }

        let cbt_hash = self.server_cert_der.map(compute_channel_bindings_hash);
        let mut flags_value = get_av_flags(entries).unwrap_or(0);
        if include_mic {
            flags_value |= AV_FLAGS_MIC_PROVIDED;
        }

        let modified = inject_av_pairs(entries, cbt_hash, Some(flags_value));
        Ok(serialize_target_info(&modified))
    }

    fn compute_response(&self, target_info: &[u8]) -> ChallengeResponse {
        let client_challenge = self.client_challenge.unwrap_or_else(|| {
            let mut cc = [0u8; 8];
            rng().fill(&mut cc);
            cc
        });

        let mut temp = Vec::new();
        temp.push(0x01); // Responserversion
        temp.push(0x01); // HiResponserversion
        for _ in 0..6 {
            temp.push(0x00);
        }
        temp.extend_from_slice(&self.time.to_le_bytes());
        temp.extend_from_slice(&client_challenge);
        for _ in 0..4 {
            temp.push(0x00);
        }
        temp.extend_from_slice(target_info);
        for _ in 0..4 {
            temp.push(0x00);
        }

        let ntlm_key = ntlm_v2_password_func(self.credentials);

        let nt_proof_string = {
            let mut hmac_md5: Hmac<Md5> = <Hmac<Md5> as Mac>::new_from_slice(&ntlm_key).unwrap();
            hmac_md5.update(&self.challenge);
            hmac_md5.update(&temp);

            let mut ps = [0u8; 16];
            ps.copy_from_slice(hmac_md5.finalize().into_bytes().as_slice());
            ps
        };

        let mut ntlm_response = Vec::with_capacity(16 + temp.len());
        ntlm_response.extend_from_slice(&nt_proof_string);
        ntlm_response.extend_from_slice(&temp);

        let mut lm_response = Vec::with_capacity(16 + 8);
        {
            let mut hmac_md5: Hmac<Md5> = <Hmac<Md5> as Mac>::new_from_slice(&ntlm_key).unwrap();
            hmac_md5.update(&self.challenge);
            hmac_md5.update(&client_challenge);
            lm_response.extend_from_slice(hmac_md5.finalize().into_bytes().as_slice());
        }
        lm_response.extend_from_slice(&client_challenge);

        let session_key = {
            let mut hmac_md5: Hmac<Md5> = <Hmac<Md5> as Mac>::new_from_slice(&ntlm_key).unwrap();
            hmac_md5.update(&nt_proof_string);
            Vec::from(hmac_md5.finalize().into_bytes().as_slice())
        };

        ChallengeResponse {
            lm_response,
            ntlm_response,
            session_key,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_channel_bindings_hash() {
        // Deterministic: same input always yields same output
        let h1 = compute_channel_bindings_hash(b"cert-a");
        let h2 = compute_channel_bindings_hash(b"cert-a");
        assert_eq!(h1, h2);

        // Different inputs yield different outputs
        let h3 = compute_channel_bindings_hash(b"cert-b");
        assert_ne!(h1, h3);
    }

    #[test]
    fn test_inject_cbt_into_existing_entries() {
        let entries = vec![
            TargetInfoEntry::from_string(TargetInfoType::NtDomain, "TEST"),
            TargetInfoEntry::from_string(TargetInfoType::DnsDomain, "test.local"),
            TargetInfoEntry {
                entry_type: TargetInfoType::Terminator,
                data: Vec::new(),
            },
        ];

        let cbt_hash = [0xAA; 16];
        let result = inject_av_pairs(&entries, Some(cbt_hash), Some(0));

        assert_eq!(result.len(), 5);
        assert_eq!(result[0].entry_type, TargetInfoType::NtDomain);
        assert_eq!(result[1].entry_type, TargetInfoType::DnsDomain);
        assert_eq!(result[2].entry_type, TargetInfoType::Flags);
        assert_eq!(result[2].data, 0u32.to_le_bytes());
        assert_eq!(result[3].entry_type, TargetInfoType::ChannelBindings);
        assert_eq!(result[3].data, vec![0xAA; 16]);
        assert_eq!(result[4].entry_type, TargetInfoType::Terminator);
    }

    #[test]
    fn test_inject_replaces_existing_flags_and_cbt() {
        let entries = vec![
            TargetInfoEntry::from_string(TargetInfoType::NtDomain, "TEST"),
            TargetInfoEntry {
                entry_type: TargetInfoType::Flags,
                data: 0x1234u32.to_le_bytes().to_vec(),
            },
            TargetInfoEntry {
                entry_type: TargetInfoType::ChannelBindings,
                data: vec![0xFF; 16],
            },
            TargetInfoEntry {
                entry_type: TargetInfoType::Terminator,
                data: Vec::new(),
            },
        ];

        let cbt_hash = [0xBB; 16];
        let result = inject_av_pairs(&entries, Some(cbt_hash), Some(AV_FLAGS_MIC_PROVIDED));

        assert_eq!(result.len(), 4);
        assert_eq!(result[0].entry_type, TargetInfoType::NtDomain);
        assert_eq!(result[1].entry_type, TargetInfoType::Flags);
        assert_eq!(
            u32::from_le_bytes(result[1].data[..].try_into().unwrap()),
            AV_FLAGS_MIC_PROVIDED
        );
        assert_eq!(result[2].entry_type, TargetInfoType::ChannelBindings);
        assert_eq!(result[2].data, vec![0xBB; 16]);
        assert_eq!(result[3].entry_type, TargetInfoType::Terminator);
    }

    #[test]
    fn test_inject_empty_target_info() {
        // Empty target info (no entries at all)
        let entries: Vec<TargetInfoEntry> = Vec::new();
        let cbt_hash = [0xCC; 16];
        let result = inject_av_pairs(&entries, Some(cbt_hash), Some(0));

        assert_eq!(result.len(), 3);
        assert_eq!(result[0].entry_type, TargetInfoType::Flags);
        assert_eq!(result[1].entry_type, TargetInfoType::ChannelBindings);
        assert_eq!(result[2].entry_type, TargetInfoType::Terminator);
    }

    #[test]
    fn test_server_requires_mic_with_flags() {
        let entries = vec![
            TargetInfoEntry {
                entry_type: TargetInfoType::Flags,
                data: AV_FLAGS_MIC_PROVIDED.to_le_bytes().to_vec(),
            },
            TargetInfoEntry {
                entry_type: TargetInfoType::Terminator,
                data: Vec::new(),
            },
        ];
        assert!(server_requires_mic(&entries));
    }

    #[test]
    fn test_server_requires_mic_not_triggered_by_timestamp_alone() {
        let entries = vec![
            TargetInfoEntry {
                entry_type: TargetInfoType::Timestamp,
                data: 0i64.to_le_bytes().to_vec(),
            },
            TargetInfoEntry {
                entry_type: TargetInfoType::Terminator,
                data: Vec::new(),
            },
        ];
        assert!(!server_requires_mic(&entries));
        assert!(server_suggests_mic(&entries));
    }

    #[test]
    fn test_server_does_not_require_mic() {
        let entries = vec![
            TargetInfoEntry::from_string(TargetInfoType::NtDomain, "TEST"),
            TargetInfoEntry {
                entry_type: TargetInfoType::Terminator,
                data: Vec::new(),
            },
        ];
        assert!(!server_requires_mic(&entries));
    }

    #[test]
    fn test_type3_without_mic_no_extra_bytes() {
        let auth = AuthenticateMessage {
            lm_response: vec![0; 24],
            ntlm_response: vec![0; 24],
            domain_name: String::new(),
            user_name: String::new(),
            workstation_name: String::new(),
            session_key: Vec::new(),
            flags: Flags::NEGOTIATE_UNICODE | Flags::NEGOTIATE_NTLM,
            os_version: Default::default(),
            mic: None,
        };

        let msg = Message::Authenticate(auth);
        let bytes = msg.to_bytes().unwrap();

        let lm_secbuf = SecurityBuffer::try_from(&bytes[12..20]).unwrap();
        assert_eq!(lm_secbuf.offset, 72);
    }

    #[test]
    fn test_type3_with_mic_reserves_16_bytes() {
        let auth = AuthenticateMessage {
            lm_response: vec![0; 24],
            ntlm_response: vec![0; 24],
            domain_name: String::new(),
            user_name: String::new(),
            workstation_name: String::new(),
            session_key: Vec::new(),
            flags: Flags::NEGOTIATE_UNICODE | Flags::NEGOTIATE_NTLM,
            os_version: Default::default(),
            mic: Some([0x42; 16]),
        };

        let msg = Message::Authenticate(auth.clone());
        let bytes = msg.to_bytes().unwrap();

        let lm_secbuf = SecurityBuffer::try_from(&bytes[12..20]).unwrap();
        assert_eq!(lm_secbuf.offset, 88);

        assert_eq!(
            &bytes[AuthenticateMessage::MIC_OFFSET
                ..AuthenticateMessage::MIC_OFFSET + AuthenticateMessage::MIC_LENGTH],
            &[0x42; 16]
        );
    }

    #[test]
    fn test_type3_round_trip_with_mic() {
        let auth = AuthenticateMessage {
            lm_response: vec![1, 2, 3],
            ntlm_response: vec![4, 5, 6],
            domain_name: String::new(),
            user_name: String::new(),
            workstation_name: String::new(),
            session_key: vec![7, 8],
            flags: Flags::NEGOTIATE_UNICODE | Flags::NEGOTIATE_NTLM,
            os_version: Default::default(),
            mic: Some([0xAB; 16]),
        };

        let msg = Message::Authenticate(auth.clone());
        let bytes = msg.to_bytes().unwrap();
        let parsed = Message::try_from(bytes.as_slice()).unwrap();

        match parsed {
            Message::Authenticate(parsed_auth) => {
                assert_eq!(parsed_auth.lm_response, auth.lm_response);
                assert_eq!(parsed_auth.ntlm_response, auth.ntlm_response);
                assert_eq!(parsed_auth.session_key, auth.session_key);
                assert_eq!(parsed_auth.mic, Some([0xAB; 16]));
            }
            _ => panic!("expected Authenticate message"),
        }
    }

    #[test]
    fn test_type3_round_trip_without_mic() {
        let auth = AuthenticateMessage {
            lm_response: vec![1, 2, 3],
            ntlm_response: vec![4, 5, 6],
            domain_name: String::new(),
            user_name: String::new(),
            workstation_name: String::new(),
            session_key: vec![7, 8],
            flags: Flags::NEGOTIATE_UNICODE | Flags::NEGOTIATE_NTLM,
            os_version: Default::default(),
            mic: None,
        };

        let msg = Message::Authenticate(auth.clone());
        let bytes = msg.to_bytes().unwrap();
        let parsed = Message::try_from(bytes.as_slice()).unwrap();

        match parsed {
            Message::Authenticate(parsed_auth) => {
                assert_eq!(parsed_auth.lm_response, auth.lm_response);
                assert_eq!(parsed_auth.ntlm_response, auth.ntlm_response);
                assert_eq!(parsed_auth.session_key, auth.session_key);
                assert_eq!(parsed_auth.mic, None);
            }
            _ => panic!("expected Authenticate message"),
        }
    }

    #[test]
    fn test_builder_basic() {
        let creds = Credentials {
            username: "User".to_owned(),
            password: "Password".to_owned(),
            domain: "Domain".to_owned(),
        };

        let challenge = [0x01; 8];
        let target_info_entries = vec![
            TargetInfoEntry::from_string(TargetInfoType::NtDomain, "TEST"),
            TargetInfoEntry {
                entry_type: TargetInfoType::Terminator,
                data: Vec::new(),
            },
        ];
        let target_info = serialize_target_info(&target_info_entries);

        let result = NtlmV2Builder::new(challenge, &target_info, 0, &creds)
            .client_challenge([0x02; 8])
            .build();

        assert!(result.is_ok());
        let bytes = result.unwrap();
        // Should parse as a valid Type 3 message
        let msg = Message::try_from(bytes.as_slice()).unwrap();
        match msg {
            Message::Authenticate(auth) => {
                assert_eq!(auth.domain_name, "Domain");
                assert_eq!(auth.user_name, "User");
                assert_eq!(auth.mic, None); // no MIC since no timestamp/flags in target_info
            }
            _ => panic!("expected Authenticate message"),
        }
    }

    #[test]
    fn test_builder_with_cbt() {
        let creds = Credentials {
            username: "User".to_owned(),
            password: "Password".to_owned(),
            domain: "Domain".to_owned(),
        };

        let challenge = [0x01; 8];
        let target_info_entries = vec![
            TargetInfoEntry::from_string(TargetInfoType::NtDomain, "TEST"),
            TargetInfoEntry {
                entry_type: TargetInfoType::Terminator,
                data: Vec::new(),
            },
        ];
        let target_info = serialize_target_info(&target_info_entries);
        let cert_der = b"test-certificate";

        let bytes = NtlmV2Builder::new(challenge, &target_info, 0, &creds)
            .channel_binding(cert_der)
            .client_challenge([0x02; 8])
            .build()
            .unwrap();

        let msg = Message::try_from(bytes.as_slice()).unwrap();
        match msg {
            Message::Authenticate(auth) => {
                // Extract target info from NTLMv2 response blob
                let temp = &auth.ntlm_response[16..];
                let ti_offset = 28; // version(2) + reserved(6) + time(8) + challenge(8) + reserved(4)
                let ti_end = temp.len() - 4;
                let ti_bytes = &temp[ti_offset..ti_end];

                let entries = parse_target_info(ti_bytes).unwrap();
                let has_cbt = entries
                    .iter()
                    .any(|e| e.entry_type == TargetInfoType::ChannelBindings);
                let has_flags = entries
                    .iter()
                    .any(|e| e.entry_type == TargetInfoType::Flags);
                assert!(has_cbt);
                assert!(has_flags);

                let expected_cbt = compute_channel_bindings_hash(cert_der);
                let cbt_entry = entries
                    .iter()
                    .find(|e| e.entry_type == TargetInfoType::ChannelBindings)
                    .unwrap();
                assert_eq!(cbt_entry.data, expected_cbt);
            }
            _ => panic!("expected Authenticate message"),
        }
    }

    #[test]
    fn test_builder_with_mic() {
        let creds = Credentials {
            username: "User".to_owned(),
            password: "Password".to_owned(),
            domain: "Domain".to_owned(),
        };

        let challenge = [0x01; 8];
        let target_info_entries = vec![
            TargetInfoEntry::from_string(TargetInfoType::NtDomain, "TEST"),
            TargetInfoEntry {
                entry_type: TargetInfoType::Timestamp,
                data: 0i64.to_le_bytes().to_vec(),
            },
            TargetInfoEntry {
                entry_type: TargetInfoType::Terminator,
                data: Vec::new(),
            },
        ];
        let target_info = serialize_target_info(&target_info_entries);

        let nego_msg = Message::Negotiate(NegotiateMessage {
            flags: Flags::NEGOTIATE_UNICODE | Flags::NEGOTIATE_NTLM,
            supplied_domain: String::new(),
            supplied_workstation: String::new(),
            os_version: Default::default(),
        });
        let nego_bytes = nego_msg.to_bytes().unwrap();

        let chal_msg = Message::Challenge(ChallengeMessage {
            target_name: "TEST".to_owned(),
            flags: Flags::NEGOTIATE_UNICODE | Flags::NEGOTIATE_NTLM,
            challenge: [0x01; 8],
            context: (0, 0),
            target_information: target_info_entries.clone(),
            os_version: Default::default(),
        });
        let chal_bytes = chal_msg.to_bytes().unwrap();

        let bytes = NtlmV2Builder::new(challenge, &target_info, 0, &creds)
            .mic(&nego_bytes, &chal_bytes)
            .client_challenge([0x02; 8])
            .build()
            .unwrap();

        let mic_bytes = &bytes[AuthenticateMessage::MIC_OFFSET
            ..AuthenticateMessage::MIC_OFFSET + AuthenticateMessage::MIC_LENGTH];
        assert_ne!(mic_bytes, &[0u8; 16]);

        let msg = Message::try_from(bytes.as_slice()).unwrap();
        match msg {
            Message::Authenticate(auth) => {
                assert!(auth.mic.is_some());
            }
            _ => panic!("expected Authenticate message"),
        }
    }

    #[test]
    fn test_builder_mic_required_but_not_provided() {
        let creds = Credentials {
            username: "User".to_owned(),
            password: "Password".to_owned(),
            domain: "Domain".to_owned(),
        };

        let challenge = [0x01; 8];
        let target_info_entries = vec![
            TargetInfoEntry {
                entry_type: TargetInfoType::Flags,
                data: AV_FLAGS_MIC_PROVIDED.to_le_bytes().to_vec(),
            },
            TargetInfoEntry {
                entry_type: TargetInfoType::Terminator,
                data: Vec::new(),
            },
        ];
        let target_info = serialize_target_info(&target_info_entries);

        let result = NtlmV2Builder::new(challenge, &target_info, 0, &creds)
            .client_challenge([0x02; 8])
            .build();

        assert!(matches!(
            result,
            Err(BuildError::MicRequiredButMessagesNotProvided)
        ));
    }

    #[test]
    fn test_builder_timestamp_only_does_not_require_mic() {
        let creds = Credentials {
            username: "User".to_owned(),
            password: "Password".to_owned(),
            domain: "Domain".to_owned(),
        };

        let challenge = [0x01; 8];
        let target_info_entries = vec![
            TargetInfoEntry::from_string(TargetInfoType::NtDomain, "TEST"),
            TargetInfoEntry {
                entry_type: TargetInfoType::Timestamp,
                data: 0i64.to_le_bytes().to_vec(),
            },
            TargetInfoEntry {
                entry_type: TargetInfoType::Terminator,
                data: Vec::new(),
            },
        ];
        let target_info = serialize_target_info(&target_info_entries);

        let result = NtlmV2Builder::new(challenge, &target_info, 0, &creds)
            .client_challenge([0x02; 8])
            .build();

        assert!(result.is_ok());
        let msg = Message::try_from(result.unwrap().as_slice()).unwrap();
        match msg {
            Message::Authenticate(auth) => assert_eq!(auth.mic, None),
            _ => panic!("expected Authenticate"),
        }
    }

    #[test]
    fn test_target_info_parse_serialize_round_trip() {
        let entries = vec![
            TargetInfoEntry::from_string(TargetInfoType::NtDomain, "TESTDOMAIN"),
            TargetInfoEntry::from_string(TargetInfoType::DnsDomain, "testdomain.local"),
            TargetInfoEntry::from_string(TargetInfoType::DnsServer, "server.testdomain.local"),
            TargetInfoEntry {
                entry_type: TargetInfoType::Timestamp,
                data: 132456789i64.to_le_bytes().to_vec(),
            },
            TargetInfoEntry {
                entry_type: TargetInfoType::Terminator,
                data: Vec::new(),
            },
        ];

        let bytes = serialize_target_info(&entries);
        let parsed = parse_target_info(&bytes).unwrap();
        assert_eq!(entries, parsed);
    }

    #[test]
    fn test_builder_with_cbt_and_mic() {
        let creds = Credentials {
            username: "User".to_owned(),
            password: "Password".to_owned(),
            domain: "Domain".to_owned(),
        };

        let challenge = [0x01; 8];
        let target_info_entries = vec![
            TargetInfoEntry::from_string(TargetInfoType::NtDomain, "TEST"),
            TargetInfoEntry::from_string(TargetInfoType::DnsDomain, "test.local"),
            TargetInfoEntry {
                entry_type: TargetInfoType::Timestamp,
                data: get_ntlm_time().to_le_bytes().to_vec(),
            },
            TargetInfoEntry {
                entry_type: TargetInfoType::Terminator,
                data: Vec::new(),
            },
        ];
        let target_info = serialize_target_info(&target_info_entries);
        let cert_der = b"test-server-certificate-der-bytes";

        let nego_msg = Message::Negotiate(NegotiateMessage {
            flags: Flags::NEGOTIATE_UNICODE | Flags::NEGOTIATE_NTLM,
            supplied_domain: String::new(),
            supplied_workstation: String::new(),
            os_version: Default::default(),
        });
        let nego_bytes = nego_msg.to_bytes().unwrap();

        let chal_msg = Message::Challenge(ChallengeMessage {
            target_name: "TEST".to_owned(),
            flags: Flags::NEGOTIATE_UNICODE | Flags::NEGOTIATE_NTLM,
            challenge,
            context: (0, 0),
            target_information: target_info_entries.clone(),
            os_version: Default::default(),
        });
        let chal_bytes = chal_msg.to_bytes().unwrap();

        let bytes = NtlmV2Builder::new(challenge, &target_info, get_ntlm_time(), &creds)
            .channel_binding(cert_der)
            .mic(&nego_bytes, &chal_bytes)
            .client_challenge([0x03; 8])
            .build()
            .unwrap();

        let msg = Message::try_from(bytes.as_slice()).unwrap();
        match msg {
            Message::Authenticate(auth) => {
                assert!(auth.mic.is_some());

                let temp = &auth.ntlm_response[16..];
                let ti_offset = 28;
                let ti_end = temp.len() - 4;
                let ti_bytes = &temp[ti_offset..ti_end];
                let entries = parse_target_info(ti_bytes).unwrap();

                let has_cbt = entries
                    .iter()
                    .any(|e| e.entry_type == TargetInfoType::ChannelBindings);
                assert!(has_cbt);

                let flags_entry = entries
                    .iter()
                    .find(|e| e.entry_type == TargetInfoType::Flags)
                    .expect("Flags entry missing");
                let flags_val = u32::from_le_bytes(flags_entry.data[..].try_into().unwrap());
                assert_ne!(flags_val & AV_FLAGS_MIC_PROVIDED, 0);
            }
            _ => panic!("expected Authenticate message"),
        }
    }

    #[test]
    fn test_mic_verification() {
        let creds = Credentials {
            username: "User".to_owned(),
            password: "Password".to_owned(),
            domain: "Domain".to_owned(),
        };

        let challenge = [0x01; 8];
        let target_info_entries = vec![
            TargetInfoEntry::from_string(TargetInfoType::NtDomain, "TEST"),
            TargetInfoEntry {
                entry_type: TargetInfoType::Timestamp,
                data: 0i64.to_le_bytes().to_vec(),
            },
            TargetInfoEntry {
                entry_type: TargetInfoType::Terminator,
                data: Vec::new(),
            },
        ];
        let target_info = serialize_target_info(&target_info_entries);

        let nego_msg = Message::Negotiate(NegotiateMessage {
            flags: Flags::NEGOTIATE_UNICODE | Flags::NEGOTIATE_NTLM,
            supplied_domain: String::new(),
            supplied_workstation: String::new(),
            os_version: Default::default(),
        });
        let nego_bytes = nego_msg.to_bytes().unwrap();

        let chal_msg = Message::Challenge(ChallengeMessage {
            target_name: "TEST".to_owned(),
            flags: Flags::NEGOTIATE_UNICODE | Flags::NEGOTIATE_NTLM,
            challenge,
            context: (0, 0),
            target_information: target_info_entries.clone(),
            os_version: Default::default(),
        });
        let chal_bytes = chal_msg.to_bytes().unwrap();

        let msg_bytes = NtlmV2Builder::new(challenge, &target_info, 0, &creds)
            .mic(&nego_bytes, &chal_bytes)
            .client_challenge([0x02; 8])
            .build()
            .unwrap();

        let original_mic: [u8; 16] = msg_bytes[AuthenticateMessage::MIC_OFFSET
            ..AuthenticateMessage::MIC_OFFSET + AuthenticateMessage::MIC_LENGTH]
            .try_into()
            .unwrap();
        assert_ne!(original_mic, [0u8; 16]);

        // Derive SessionBaseKey independently (simulating server-side)
        let parsed = Message::try_from(msg_bytes.as_slice()).unwrap();
        let auth = match &parsed {
            Message::Authenticate(auth) => auth,
            _ => panic!("expected Authenticate message"),
        };
        assert!(auth.session_key.is_empty());

        let ntlm_key = ntlm_v2_password_func(&creds);
        let nt_proof_string = &auth.ntlm_response[..16];
        let mut hmac_sk: Hmac<Md5> = <Hmac<Md5> as Mac>::new_from_slice(&ntlm_key).unwrap();
        hmac_sk.update(nt_proof_string);
        let session_key: Vec<u8> = Vec::from(hmac_sk.finalize().into_bytes().as_slice());

        // Zero the MIC and recompute
        let mut verify_bytes = msg_bytes.clone();
        verify_bytes[AuthenticateMessage::MIC_OFFSET
            ..AuthenticateMessage::MIC_OFFSET + AuthenticateMessage::MIC_LENGTH]
            .fill(0);

        let mut hmac_md5: Hmac<Md5> = <Hmac<Md5> as Mac>::new_from_slice(&session_key).unwrap();
        hmac_md5.update(&nego_bytes);
        hmac_md5.update(&chal_bytes);
        hmac_md5.update(&verify_bytes);
        let recomputed_mic: [u8; 16] = hmac_md5.finalize().into_bytes().into();

        assert_eq!(
            original_mic, recomputed_mic,
            "MIC verification failed: recomputed MIC doesn't match"
        );
    }

    #[test]
    fn test_lm_response_z24_when_timestamp_present() {
        let creds = Credentials {
            username: "user".to_owned(),
            password: "pass".to_owned(),
            domain: "DOMAIN".to_owned(),
        };
        let challenge = [0x01; 8];
        let target_info_entries = vec![
            TargetInfoEntry::from_string(TargetInfoType::NtDomain, "TEST"),
            TargetInfoEntry {
                entry_type: TargetInfoType::Timestamp,
                data: 132456789012345678i64.to_le_bytes().to_vec(),
            },
            TargetInfoEntry {
                entry_type: TargetInfoType::Terminator,
                data: Vec::new(),
            },
        ];
        let target_info = serialize_target_info(&target_info_entries);

        let nego_msg = Message::Negotiate(NegotiateMessage {
            flags: Flags::NEGOTIATE_UNICODE | Flags::NEGOTIATE_NTLM,
            supplied_domain: String::new(),
            supplied_workstation: String::new(),
            os_version: Default::default(),
        });
        let nego_bytes = nego_msg.to_bytes().unwrap();

        let chal_msg = Message::Challenge(ChallengeMessage {
            target_name: "TEST".to_owned(),
            flags: Flags::NEGOTIATE_UNICODE | Flags::NEGOTIATE_NTLM,
            challenge,
            context: (0, 0),
            target_information: target_info_entries.clone(),
            os_version: Default::default(),
        });
        let chal_bytes = chal_msg.to_bytes().unwrap();

        let msg_bytes = NtlmV2Builder::new(challenge, &target_info, 0, &creds)
            .mic(&nego_bytes, &chal_bytes)
            .client_challenge([0x02; 8])
            .build()
            .unwrap();

        let parsed = Message::try_from(msg_bytes.as_slice()).unwrap();
        let auth = match &parsed {
            Message::Authenticate(a) => a,
            _ => panic!("expected Authenticate"),
        };
        assert_eq!(auth.lm_response, vec![0u8; 24]);

        // Also verify via build_response()
        let response = NtlmV2Builder::new(challenge, &target_info, 0, &creds)
            .client_challenge([0x02; 8])
            .build_response()
            .unwrap();
        assert_eq!(response.lm_response, vec![0u8; 24]);
    }

    #[test]
    fn test_lm_response_normal_when_no_timestamp() {
        let creds = Credentials {
            username: "user".to_owned(),
            password: "pass".to_owned(),
            domain: "DOMAIN".to_owned(),
        };
        let challenge = [0x01; 8];
        let client_challenge = [0x02; 8];
        let target_info_entries = vec![
            TargetInfoEntry::from_string(TargetInfoType::NtDomain, "TEST"),
            TargetInfoEntry {
                entry_type: TargetInfoType::Terminator,
                data: Vec::new(),
            },
        ];
        let target_info = serialize_target_info(&target_info_entries);

        let response = NtlmV2Builder::new(challenge, &target_info, 0, &creds)
            .client_challenge(client_challenge)
            .build_response()
            .unwrap();

        assert_eq!(response.lm_response.len(), 24);
        assert_eq!(&response.lm_response[16..24], &client_challenge);
        assert_ne!(response.lm_response, vec![0u8; 24]);
    }

    #[test]
    fn test_key_exch_encrypted_random_session_key() {
        let creds = Credentials {
            username: "User".to_owned(),
            password: "Password".to_owned(),
            domain: "Domain".to_owned(),
        };
        let challenge = [0x01; 8];
        let target_info_entries = vec![
            TargetInfoEntry::from_string(TargetInfoType::NtDomain, "TEST"),
            TargetInfoEntry {
                entry_type: TargetInfoType::Terminator,
                data: Vec::new(),
            },
        ];
        let target_info = serialize_target_info(&target_info_entries);

        let fixed_esk = [0xAA; 16];

        let flags = Flags::NEGOTIATE_UNICODE
            | Flags::NEGOTIATE_NTLM
            | Flags::NEGOTIATE_KEY_EXCHANGE
            | Flags::NEGOTIATE_SIGN;

        let msg_bytes = NtlmV2Builder::new(challenge, &target_info, 0, &creds)
            .flags(flags)
            .client_challenge([0x02; 8])
            .exported_session_key(fixed_esk)
            .build()
            .unwrap();

        let parsed = Message::try_from(msg_bytes.as_slice()).unwrap();
        let auth = match &parsed {
            Message::Authenticate(auth) => auth,
            _ => panic!("expected Authenticate message"),
        };

        assert_eq!(auth.session_key.len(), 16);

        // Derive SessionBaseKey and verify round-trip
        let ntlm_key = ntlm_v2_password_func(&creds);
        let nt_proof_string = &auth.ntlm_response[..16];
        let mut hmac_sk: Hmac<Md5> = <Hmac<Md5> as Mac>::new_from_slice(&ntlm_key).unwrap();
        hmac_sk.update(nt_proof_string);
        let session_base_key: Vec<u8> = Vec::from(hmac_sk.finalize().into_bytes().as_slice());

        let mut decrypted_esk = auth.session_key.clone();
        let key = rc4::Key::<rc4::consts::U16>::from_slice(&session_base_key);
        let mut rc4: Rc4<rc4::consts::U16> = <Rc4<rc4::consts::U16> as cipher::KeyInit>::new(key);
        rc4.apply_keystream(&mut decrypted_esk);

        assert_eq!(decrypted_esk, fixed_esk.to_vec());
    }

    #[test]
    fn test_key_exch_inactive_without_sign_or_seal() {
        // KEY_EXCH requires SIGN or SEAL to activate; without them, session_key is empty
        let creds = Credentials {
            username: "User".to_owned(),
            password: "Password".to_owned(),
            domain: "Domain".to_owned(),
        };
        let challenge = [0x01; 8];
        let target_info_entries = vec![
            TargetInfoEntry::from_string(TargetInfoType::NtDomain, "TEST"),
            TargetInfoEntry {
                entry_type: TargetInfoType::Terminator,
                data: Vec::new(),
            },
        ];
        let target_info = serialize_target_info(&target_info_entries);

        // Case 1: KEY_EXCH set but no SIGN/SEAL
        let flags =
            Flags::NEGOTIATE_UNICODE | Flags::NEGOTIATE_NTLM | Flags::NEGOTIATE_KEY_EXCHANGE;
        let bytes = NtlmV2Builder::new(challenge, &target_info, 0, &creds)
            .flags(flags)
            .client_challenge([0x02; 8])
            .build()
            .unwrap();
        let auth = match Message::try_from(bytes.as_slice()).unwrap() {
            Message::Authenticate(a) => a,
            _ => panic!("expected Authenticate"),
        };
        assert!(auth.session_key.is_empty());

        // Case 2: no KEY_EXCH at all
        let bytes = NtlmV2Builder::new(challenge, &target_info, 0, &creds)
            .client_challenge([0x02; 8])
            .build()
            .unwrap();
        let auth = match Message::try_from(bytes.as_slice()).unwrap() {
            Message::Authenticate(a) => a,
            _ => panic!("expected Authenticate"),
        };
        assert!(auth.session_key.is_empty());
    }

    #[test]
    fn test_key_exch_mic_uses_exported_session_key() {
        let creds = Credentials {
            username: "User".to_owned(),
            password: "Password".to_owned(),
            domain: "Domain".to_owned(),
        };
        let challenge = [0x01; 8];
        let target_info_entries = vec![
            TargetInfoEntry::from_string(TargetInfoType::NtDomain, "TEST"),
            TargetInfoEntry {
                entry_type: TargetInfoType::Timestamp,
                data: 0i64.to_le_bytes().to_vec(),
            },
            TargetInfoEntry {
                entry_type: TargetInfoType::Terminator,
                data: Vec::new(),
            },
        ];
        let target_info = serialize_target_info(&target_info_entries);

        let fixed_esk = [0xBB; 16];

        let flags = Flags::NEGOTIATE_UNICODE
            | Flags::NEGOTIATE_NTLM
            | Flags::NEGOTIATE_KEY_EXCHANGE
            | Flags::NEGOTIATE_SEAL;

        let nego_msg = Message::Negotiate(NegotiateMessage {
            flags,
            supplied_domain: String::new(),
            supplied_workstation: String::new(),
            os_version: Default::default(),
        });
        let nego_bytes = nego_msg.to_bytes().unwrap();

        let chal_msg = Message::Challenge(ChallengeMessage {
            target_name: "TEST".to_owned(),
            flags,
            challenge,
            context: (0, 0),
            target_information: target_info_entries.clone(),
            os_version: Default::default(),
        });
        let chal_bytes = chal_msg.to_bytes().unwrap();

        let msg_bytes = NtlmV2Builder::new(challenge, &target_info, 0, &creds)
            .flags(flags)
            .mic(&nego_bytes, &chal_bytes)
            .client_challenge([0x02; 8])
            .exported_session_key(fixed_esk)
            .build()
            .unwrap();

        let original_mic: [u8; 16] = msg_bytes[AuthenticateMessage::MIC_OFFSET
            ..AuthenticateMessage::MIC_OFFSET + AuthenticateMessage::MIC_LENGTH]
            .try_into()
            .unwrap();
        assert_ne!(original_mic, [0u8; 16]);

        // Verify with ExportedSessionKey
        let mut verify_bytes = msg_bytes.clone();
        verify_bytes[AuthenticateMessage::MIC_OFFSET
            ..AuthenticateMessage::MIC_OFFSET + AuthenticateMessage::MIC_LENGTH]
            .fill(0);

        let mut hmac_md5: Hmac<Md5> = <Hmac<Md5> as Mac>::new_from_slice(&fixed_esk).unwrap();
        hmac_md5.update(&nego_bytes);
        hmac_md5.update(&chal_bytes);
        hmac_md5.update(&verify_bytes);
        let recomputed_mic: [u8; 16] = hmac_md5.finalize().into_bytes().into();

        assert_eq!(original_mic, recomputed_mic);

        // Verify that SessionBaseKey (wrong key) does NOT match
        let parsed = Message::try_from(msg_bytes.as_slice()).unwrap();
        let auth = match &parsed {
            Message::Authenticate(auth) => auth,
            _ => panic!("expected Authenticate message"),
        };

        let ntlm_key = ntlm_v2_password_func(&creds);
        let nt_proof_string = &auth.ntlm_response[..16];
        let mut hmac_sk: Hmac<Md5> = <Hmac<Md5> as Mac>::new_from_slice(&ntlm_key).unwrap();
        hmac_sk.update(nt_proof_string);
        let session_base_key: Vec<u8> = Vec::from(hmac_sk.finalize().into_bytes().as_slice());

        let mut hmac_wrong: Hmac<Md5> =
            <Hmac<Md5> as Mac>::new_from_slice(&session_base_key).unwrap();
        hmac_wrong.update(&nego_bytes);
        hmac_wrong.update(&chal_bytes);
        hmac_wrong.update(&verify_bytes);
        let wrong_mic: [u8; 16] = hmac_wrong.finalize().into_bytes().into();

        assert_ne!(original_mic, wrong_mic);
    }

    #[test]
    fn test_key_exch_server_side_verification() {
        let creds = Credentials {
            username: "TestUser".to_owned(),
            password: "SecretPassword123".to_owned(),
            domain: "TESTDOMAIN".to_owned(),
        };
        let challenge = [0x55; 8];
        let target_info_entries = vec![
            TargetInfoEntry::from_string(TargetInfoType::NtDomain, "TESTDOMAIN"),
            TargetInfoEntry::from_string(TargetInfoType::DnsDomain, "testdomain.local"),
            TargetInfoEntry {
                entry_type: TargetInfoType::Timestamp,
                data: 132500000000000000i64.to_le_bytes().to_vec(),
            },
            TargetInfoEntry {
                entry_type: TargetInfoType::Terminator,
                data: Vec::new(),
            },
        ];
        let target_info = serialize_target_info(&target_info_entries);

        let flags = Flags::NEGOTIATE_UNICODE
            | Flags::NEGOTIATE_NTLM
            | Flags::NEGOTIATE_KEY_EXCHANGE
            | Flags::NEGOTIATE_SIGN
            | Flags::NEGOTIATE_SEAL
            | Flags::NEGOTIATE_128BIT
            | Flags::NEGOTIATE_ALWAYS_SIGN;

        let nego_msg = Message::Negotiate(NegotiateMessage {
            flags,
            supplied_domain: String::new(),
            supplied_workstation: String::new(),
            os_version: Default::default(),
        });
        let nego_bytes = nego_msg.to_bytes().unwrap();

        let chal_msg = Message::Challenge(ChallengeMessage {
            target_name: "TESTDOMAIN".to_owned(),
            flags,
            challenge,
            context: (0, 0),
            target_information: target_info_entries.clone(),
            os_version: Default::default(),
        });
        let chal_bytes = chal_msg.to_bytes().unwrap();

        let msg_bytes = NtlmV2Builder::new(challenge, &target_info, 132500000000000000, &creds)
            .flags(flags)
            .mic(&nego_bytes, &chal_bytes)
            .client_challenge([0x33; 8])
            .build()
            .unwrap();

        // Server-side: derive SessionBaseKey, decrypt ExportedSessionKey, verify MIC
        let parsed = Message::try_from(msg_bytes.as_slice()).unwrap();
        let auth = match &parsed {
            Message::Authenticate(auth) => auth,
            _ => panic!("expected Authenticate message"),
        };

        let ntlm_key = ntlm_v2_password_func(&creds);
        let nt_proof_string = &auth.ntlm_response[..16];
        let mut hmac_sk: Hmac<Md5> = <Hmac<Md5> as Mac>::new_from_slice(&ntlm_key).unwrap();
        hmac_sk.update(nt_proof_string);
        let session_base_key: Vec<u8> = Vec::from(hmac_sk.finalize().into_bytes().as_slice());

        assert_eq!(auth.session_key.len(), 16);
        let mut exported_session_key = auth.session_key.clone();
        let key = rc4::Key::<rc4::consts::U16>::from_slice(&session_base_key);
        let mut rc4: Rc4<rc4::consts::U16> = <Rc4<rc4::consts::U16> as cipher::KeyInit>::new(key);
        rc4.apply_keystream(&mut exported_session_key);

        let original_mic: [u8; 16] = msg_bytes[AuthenticateMessage::MIC_OFFSET
            ..AuthenticateMessage::MIC_OFFSET + AuthenticateMessage::MIC_LENGTH]
            .try_into()
            .unwrap();

        let mut verify_bytes = msg_bytes.clone();
        verify_bytes[AuthenticateMessage::MIC_OFFSET
            ..AuthenticateMessage::MIC_OFFSET + AuthenticateMessage::MIC_LENGTH]
            .fill(0);

        let mut hmac_md5: Hmac<Md5> =
            <Hmac<Md5> as Mac>::new_from_slice(&exported_session_key).unwrap();
        hmac_md5.update(&nego_bytes);
        hmac_md5.update(&chal_bytes);
        hmac_md5.update(&verify_bytes);
        let recomputed_mic: [u8; 16] = hmac_md5.finalize().into_bytes().into();

        assert_eq!(original_mic, recomputed_mic);
    }
}
