use chrono::{DateTime, Utc};
use serde::{de, Deserialize, Serialize};
use std::{
    fmt::{self, Write},
    ops,
    str::FromStr,
};
use subtle::ConstantTimeEq;

#[derive(Debug, Eq, PartialEq, Copy, Clone, Serialize, Deserialize)]
#[repr(u8)]
pub enum Operation {
    #[serde(rename = "download")]
    Download = 1,
    #[serde(rename = "upload")]
    Upload = 2,
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct ParseOperationError;

impl fmt::Display for ParseOperationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "operation should be 'download' or 'upload'")
    }
}

impl FromStr for Operation {
    type Err = ParseOperationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "upload" => Ok(Self::Upload),
            "download" => Ok(Self::Download),
            _ => Err(ParseOperationError),
        }
    }
}

#[repr(u8)]
enum AuthType {
    BatchApi = 1,
    Download = 2,
}

/// None means out of range.
fn decode_nibble(c: u8) -> Option<u8> {
    if c.is_ascii_digit() {
        Some(c - b'0')
    } else if (b'a'..=b'f').contains(&c) {
        Some(c - b'a' + 10)
    } else if (b'A'..=b'F').contains(&c) {
        Some(c - b'A' + 10)
    } else {
        None
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct HexByte(pub u8);

impl<'de> Deserialize<'de> for HexByte {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let str = <&str>::deserialize(deserializer)?;
        let &[b1, b2] = str.as_bytes() else {
            return Err(de::Error::invalid_length(
                str.len(),
                &"two hexadecimal characters",
            ));
        };
        let (Some(b1), Some(b2)) = (decode_nibble(b1), decode_nibble(b2)) else {
            return Err(de::Error::invalid_value(
                de::Unexpected::Str(str),
                &"two hexadecimal characters",
            ));
        };
        Ok(HexByte((b1 << 4) | b2))
    }
}

impl fmt::Display for HexByte {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let &HexByte(b) = self;
        HexFmt(&[b]).fmt(f)
    }
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum ParseHexError {
    UnevenNibbles,
    InvalidCharacter,
    TooShort,
    TooLong,
}

impl fmt::Display for ParseHexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnevenNibbles => {
                write!(f, "uneven amount of nibbles (chars in range [a-zA-Z0-9])")
            }
            Self::InvalidCharacter => write!(f, "non-hex character encountered"),
            Self::TooShort => write!(f, "unexpected end of hex sequence"),
            Self::TooLong => write!(f, "longer hex sequence than expected"),
        }
    }
}

#[derive(Debug)]
pub enum ReadHexError {
    Io(std::io::Error),
    Format(ParseHexError),
}

impl fmt::Display for ReadHexError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Io(e) => e.fmt(f),
            Self::Format(e) => e.fmt(f),
        }
    }
}

fn parse_hex_exact(value: &str, buf: &mut [u8]) -> Result<(), ParseHexError> {
    if value.bytes().len() % 2 == 1 {
        return Err(ParseHexError::UnevenNibbles);
    }
    if value.bytes().len() < 2 * buf.len() {
        return Err(ParseHexError::TooShort);
    }
    if value.bytes().len() > 2 * buf.len() {
        return Err(ParseHexError::TooLong);
    }
    for (i, c) in value.bytes().enumerate() {
        if let Some(b) = decode_nibble(c) {
            if i % 2 == 0 {
                buf[i / 2] = b << 4;
            } else {
                buf[i / 2] |= b;
            }
        } else {
            return Err(ParseHexError::InvalidCharacter);
        }
    }
    Ok(())
}

pub struct SafeByteArray<const N: usize> {
    inner: [u8; N],
}

impl<const N: usize> SafeByteArray<N> {
    pub fn new() -> Self {
        Self { inner: [0; N] }
    }
}

impl<const N: usize> Default for SafeByteArray<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> AsRef<[u8]> for SafeByteArray<N> {
    fn as_ref(&self) -> &[u8] {
        &self.inner
    }
}

impl<const N: usize> AsMut<[u8]> for SafeByteArray<N> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.inner
    }
}

impl<const N: usize> Drop for SafeByteArray<N> {
    fn drop(&mut self) {
        self.inner.fill(0)
    }
}

impl<const N: usize> FromStr for SafeByteArray<N> {
    type Err = ParseHexError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let mut sba = Self { inner: [0u8; N] };
        parse_hex_exact(value, &mut sba.inner)?;
        Ok(sba)
    }
}

pub type Oid = Digest<32>;

#[derive(Debug, Copy, Clone)]
pub enum SpecificClaims {
    BatchApi(Operation),
    Download(Oid),
}

#[derive(Debug, Copy, Clone)]
pub struct Claims<'a> {
    pub specific_claims: SpecificClaims,
    pub repo_path: &'a str,
    pub expires_at: DateTime<Utc>,
}

/// Returns None if the claims are invalid. Repo path length may be no more than 100 bytes.
pub fn generate_tag(claims: Claims, key: impl AsRef<[u8]>) -> Option<Digest<32>> {
    if claims.repo_path.len() > 100 {
        return None;
    }

    let mut hmac = hmac_sha256::HMAC::new(key);
    match claims.specific_claims {
        SpecificClaims::BatchApi(operation) => {
            hmac.update([AuthType::BatchApi as u8]);
            hmac.update([operation as u8]);
        }
        SpecificClaims::Download(oid) => {
            hmac.update([AuthType::Download as u8]);
            hmac.update(oid.as_bytes());
        }
    }
    hmac.update([claims.repo_path.len() as u8]);
    hmac.update(claims.repo_path.as_bytes());
    hmac.update(claims.expires_at.timestamp().to_be_bytes());
    Some(hmac.finalize().into())
}

pub struct HexFmt<B: AsRef<[u8]>>(pub B);

impl<B: AsRef<[u8]>> fmt::Display for HexFmt<B> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let HexFmt(buf) = self;
        for b in buf.as_ref() {
            let (high, low) = (b >> 4, b & 0xF);
            let highc = if high < 10 {
                high + b'0'
            } else {
                high - 10 + b'a'
            };
            let lowc = if low < 10 {
                low + b'0'
            } else {
                low - 10 + b'a'
            };
            f.write_char(highc as char)?;
            f.write_char(lowc as char)?;
        }
        Ok(())
    }
}

pub struct EscJsonFmt<'a>(pub &'a str);

impl<'a> fmt::Display for EscJsonFmt<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let EscJsonFmt(buf) = self;
        for c in buf.chars() {
            match c {
                '"' => f.write_str("\\\"")?,   // quote
                '\\' => f.write_str("\\\\")?,  // backslash
                '\x08' => f.write_str("\\b")?, // backspace
                '\x0C' => f.write_str("\\f")?, // form feed
                '\n' => f.write_str("\\n")?,   // line feed
                '\r' => f.write_str("\\r")?,   // carriage return
                '\t' => f.write_str("\\t")?,   // horizontal tab
                _ => f.write_char(c)?,
            };
        }
        Ok(())
    }
}

#[derive(Debug, Copy, Clone)]
pub struct Digest<const N: usize> {
    inner: [u8; N],
}

impl<const N: usize> ops::Index<usize> for Digest<N> {
    type Output = u8;

    fn index(&self, index: usize) -> &Self::Output {
        &self.inner[index]
    }
}

impl<const N: usize> Digest<N> {
    pub fn as_bytes(&self) -> &[u8; N] {
        &self.inner
    }
}

impl<const N: usize> fmt::Display for Digest<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        HexFmt(&self.inner).fmt(f)
    }
}

impl<const N: usize> Digest<N> {
    pub fn new(data: [u8; N]) -> Self {
        Self { inner: data }
    }
}

impl<const N: usize> From<[u8; N]> for Digest<N> {
    fn from(value: [u8; N]) -> Self {
        Self::new(value)
    }
}

impl<const N: usize> From<Digest<N>> for [u8; N] {
    fn from(val: Digest<N>) -> Self {
        val.inner
    }
}

impl<const N: usize> FromStr for Digest<N> {
    type Err = ParseHexError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let mut buf = [0u8; N];
        parse_hex_exact(value, &mut buf)?;
        Ok(buf.into())
    }
}

impl<const N: usize> ConstantTimeEq for Digest<N> {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.inner.ct_eq(&other.inner)
    }
}

impl<const N: usize> PartialEq for Digest<N> {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl<const N: usize> Eq for Digest<N> {}

impl<'de, const N: usize> Deserialize<'de> for Digest<N> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let hex = <&str>::deserialize(deserializer)?;
        Digest::from_str(hex).map_err(de::Error::custom)
    }
}

impl<const N: usize> Serialize for Digest<N> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&format!("{self}"))
    }
}

pub type Key = SafeByteArray<64>;

pub fn load_key(path: &str) -> Result<Key, ReadHexError> {
    let key_str = std::fs::read_to_string(path).map_err(ReadHexError::Io)?;
    key_str.trim().parse().map_err(ReadHexError::Format)
}
