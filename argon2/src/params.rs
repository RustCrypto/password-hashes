//! Argon2 password hash parameters.

use crate::{Error, Result, SYNC_POINTS};
use base64ct::{Base64Unpadded as B64, Encoding};
use core::str::FromStr;

#[cfg(feature = "password-hash")]
use password_hash::{ParamsString, PasswordHash};

/// Argon2 password hash parameters.
///
/// These are parameters which can be encoded into a PHC hash string.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Params {
    /// Memory size, expressed in kibibytes, between 1 and (2^32)-1.
    ///
    /// Value is an integer in decimal (1 to 10 digits).
    m_cost: u32,

    /// Number of iterations, between 1 and (2^32)-1.
    ///
    /// Value is an integer in decimal (1 to 10 digits).
    t_cost: u32,

    /// Degree of parallelism, between 1 and 255.
    ///
    /// Value is an integer in decimal (1 to 3 digits).
    p_cost: u32,

    /// Key identifier.
    keyid: KeyId,

    /// Associated data.
    data: AssociatedData,

    /// Size of the output (in bytes).
    output_len: Option<usize>,
}

impl Params {
    /// Default memory cost.
    pub const DEFAULT_M_COST: u32 = 4096;

    /// Minimum number of memory blocks.
    #[allow(clippy::cast_possible_truncation)]
    pub const MIN_M_COST: u32 = 2 * SYNC_POINTS as u32; // 2 blocks per slice

    /// Maximum number of memory blocks.
    pub const MAX_M_COST: u32 = 0x0FFFFFFF;

    /// Default number of iterations (i.e. "time").
    pub const DEFAULT_T_COST: u32 = 3;

    /// Minimum number of passes.
    pub const MIN_T_COST: u32 = 1;

    /// Maximum number of passes.
    pub const MAX_T_COST: u32 = u32::MAX;

    /// Default degree of parallelism.
    pub const DEFAULT_P_COST: u32 = 1;

    /// Minimum and maximum number of threads (i.e. parallelism).
    pub const MIN_P_COST: u32 = 1;

    /// Minimum and maximum number of threads (i.e. parallelism).
    pub const MAX_P_COST: u32 = 0xFFFFFF;

    /// Maximum length of a key ID in bytes.
    pub const MAX_KEYID_LEN: usize = 8;

    /// Maximum length of associated data in bytes.
    pub const MAX_DATA_LEN: usize = 32;

    /// Default output length.
    pub const DEFAULT_OUTPUT_LEN: usize = 32;

    /// Minimum digest size in bytes.
    pub const MIN_OUTPUT_LEN: usize = 4;

    /// Maximum digest size in bytes.
    pub const MAX_OUTPUT_LEN: usize = 0xFFFFFFFF;

    /// Create new parameters.
    pub fn new(m_cost: u32, t_cost: u32, p_cost: u32, output_len: Option<usize>) -> Result<Self> {
        let mut builder = ParamsBuilder::new();

        builder.m_cost(m_cost).t_cost(t_cost).p_cost(p_cost);

        if let Some(len) = output_len {
            builder.output_len(len);
        }

        builder.build()
    }

    /// Memory size, expressed in kibibytes, between 1 and (2^32)-1.
    ///
    /// Value is an integer in decimal (1 to 10 digits).
    pub fn m_cost(&self) -> u32 {
        self.m_cost
    }

    /// Number of iterations, between 1 and (2^32)-1.
    ///
    /// Value is an integer in decimal (1 to 10 digits).
    pub fn t_cost(&self) -> u32 {
        self.t_cost
    }

    /// Degree of parallelism, between 1 and 255.
    ///
    /// Value is an integer in decimal (1 to 3 digits).
    pub fn p_cost(&self) -> u32 {
        self.p_cost
    }

    /// Key identifier: byte slice between 0 and 8 bytes in length.
    ///
    /// Defaults to an empty byte slice.
    ///
    /// Note this field is only present as a helper for reading/storing in
    /// the PHC hash string format (i.e. it is totally ignored from a
    /// cryptographical standpoint).
    ///
    /// On top of that, this field is not longer part of the argon2 standard
    /// (see: <https://github.com/P-H-C/phc-winner-argon2/pull/173>), and should
    /// not be used for any non-legacy work.
    pub fn keyid(&self) -> &[u8] {
        self.keyid.as_bytes()
    }

    /// Associated data: byte slice between 0 and 32 bytes in length.
    ///
    /// Defaults to an empty byte slice.
    ///
    /// This field is not longer part of the argon2 standard
    /// (see: <https://github.com/P-H-C/phc-winner-argon2/pull/173>), and should
    /// not be used for any non-legacy work.
    pub fn data(&self) -> &[u8] {
        self.data.as_bytes()
    }

    /// Length of the output (in bytes).
    pub fn output_len(&self) -> Option<usize> {
        self.output_len
    }

    /// Get the number of lanes.
    #[allow(clippy::cast_possible_truncation)]
    pub(crate) fn lanes(&self) -> usize {
        self.p_cost as usize
    }

    /// Get the number of blocks in a lane.
    pub(crate) fn lane_length(&self) -> usize {
        self.segment_length() * SYNC_POINTS
    }

    /// Get the segment length given the configured `m_cost` and `p_cost`.
    ///
    /// Minimum memory_blocks = 8*`L` blocks, where `L` is the number of lanes.
    pub(crate) fn segment_length(&self) -> usize {
        let m_cost = self.m_cost as usize;

        let memory_blocks = if m_cost < 2 * SYNC_POINTS * self.lanes() {
            2 * SYNC_POINTS * self.lanes()
        } else {
            m_cost
        };

        memory_blocks / (self.lanes() * SYNC_POINTS)
    }

    /// Get the number of blocks required given the configured `m_cost` and `p_cost`.
    pub fn block_count(&self) -> usize {
        self.segment_length() * self.lanes() * SYNC_POINTS
    }
}

impl Default for Params {
    fn default() -> Params {
        Params {
            m_cost: Self::DEFAULT_M_COST,
            t_cost: Self::DEFAULT_T_COST,
            p_cost: Self::DEFAULT_P_COST,
            keyid: KeyId::default(),
            data: AssociatedData::default(),
            output_len: None,
        }
    }
}

macro_rules! param_buf {
    ($ty:ident, $name:expr, $max_len:expr, $error:expr, $doc:expr) => {
        #[doc = $doc]
        #[derive(Copy, Clone, Debug, Default, Eq, Hash, PartialEq, PartialOrd, Ord)]
        pub struct $ty {
            /// Byte array
            bytes: [u8; Self::MAX_LEN],

            /// Length of byte array
            len: usize,
        }

        impl $ty {
            /// Maximum length in bytes
            pub const MAX_LEN: usize = $max_len;

            #[doc = "Create a new"]
            #[doc = $name]
            #[doc = "from a slice."]
            pub fn new(slice: &[u8]) -> Result<Self> {
                let mut bytes = [0u8; Self::MAX_LEN];
                let len = slice.len();
                bytes.get_mut(..len).ok_or($error)?.copy_from_slice(slice);

                Ok(Self { bytes, len })
            }

            #[doc = "Decode"]
            #[doc = $name]
            #[doc = " from a B64 string"]
            pub fn from_b64(s: &str) -> Result<Self> {
                let mut bytes = [0u8; Self::MAX_LEN];
                let len = B64::decode(s, &mut bytes)?.len();

                Ok(Self { bytes, len })
            }

            /// Borrow the inner value as a byte slice.
            pub fn as_bytes(&self) -> &[u8] {
                &self.bytes[..self.len]
            }

            /// Get the length in bytes.
            pub fn len(&self) -> usize {
                self.len
            }

            /// Is this value empty?
            pub fn is_empty(&self) -> bool {
                self.len() == 0
            }
        }

        impl AsRef<[u8]> for $ty {
            fn as_ref(&self) -> &[u8] {
                self.as_bytes()
            }
        }

        impl FromStr for $ty {
            type Err = Error;

            fn from_str(s: &str) -> Result<Self> {
                Self::from_b64(s)
            }
        }

        impl TryFrom<&[u8]> for $ty {
            type Error = Error;

            fn try_from(bytes: &[u8]) -> Result<Self> {
                Self::new(bytes)
            }
        }
    };
}

// KeyId
param_buf!(
    KeyId,
    "KeyId",
    Params::MAX_KEYID_LEN,
    Error::KeyIdTooLong,
    "Key identifier"
);

// AssociatedData
param_buf!(
    AssociatedData,
    "AssociatedData",
    Params::MAX_DATA_LEN,
    Error::AdTooLong,
    "Associated data"
);

#[cfg(feature = "password-hash")]
#[cfg_attr(docsrs, doc(cfg(feature = "password-hash")))]
impl<'a> TryFrom<&'a PasswordHash<'a>> for Params {
    type Error = password_hash::Error;

    fn try_from(hash: &'a PasswordHash<'a>) -> password_hash::Result<Self> {
        let mut builder = ParamsBuilder::new();

        for (ident, value) in hash.params.iter() {
            match ident.as_str() {
                "m" => {
                    builder.m_cost(value.decimal()?);
                }
                "t" => {
                    builder.t_cost(value.decimal()?);
                }
                "p" => {
                    builder.p_cost(value.decimal()?);
                }
                "keyid" => {
                    builder.keyid(value.as_str().parse()?);
                }
                "data" => {
                    builder.data(value.as_str().parse()?);
                }
                _ => return Err(password_hash::Error::ParamNameInvalid),
            }
        }

        if let Some(output) = &hash.hash {
            builder.output_len(output.len());
        }

        Ok(builder.build()?)
    }
}

#[cfg(feature = "password-hash")]
#[cfg_attr(docsrs, doc(cfg(feature = "password-hash")))]
impl TryFrom<Params> for ParamsString {
    type Error = password_hash::Error;

    fn try_from(params: Params) -> password_hash::Result<ParamsString> {
        ParamsString::try_from(&params)
    }
}

#[cfg(feature = "password-hash")]
#[cfg_attr(docsrs, doc(cfg(feature = "password-hash")))]
impl TryFrom<&Params> for ParamsString {
    type Error = password_hash::Error;

    fn try_from(params: &Params) -> password_hash::Result<ParamsString> {
        let mut output = ParamsString::new();
        output.add_decimal("m", params.m_cost)?;
        output.add_decimal("t", params.t_cost)?;
        output.add_decimal("p", params.p_cost)?;

        if !params.keyid.is_empty() {
            output.add_b64_bytes("keyid", params.keyid.as_bytes())?;
        }

        if !params.data.is_empty() {
            output.add_b64_bytes("data", params.data.as_bytes())?;
        }

        Ok(output)
    }
}

/// Builder for Argon2 [`Params`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParamsBuilder {
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    keyid: Option<KeyId>,
    data: Option<AssociatedData>,
    output_len: Option<usize>,
}

impl ParamsBuilder {
    /// Create a new builder with the default parameters.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set memory size, expressed in kibibytes, between 1 and (2^32)-1.
    pub fn m_cost(&mut self, m_cost: u32) -> &mut Self {
        self.m_cost = m_cost;
        self
    }

    /// Set number of iterations, between 1 and (2^32)-1.
    pub fn t_cost(&mut self, t_cost: u32) -> &mut Self {
        self.t_cost = t_cost;
        self
    }

    /// Set degree of parallelism, between 1 and 255.
    pub fn p_cost(&mut self, p_cost: u32) -> &mut Self {
        self.p_cost = p_cost;
        self
    }

    /// Set key identifier.
    pub fn keyid(&mut self, keyid: KeyId) -> &mut Self {
        self.keyid = Some(keyid);
        self
    }

    /// Set associated data.
    pub fn data(&mut self, data: AssociatedData) -> &mut Self {
        self.data = Some(data);
        self
    }

    /// Set length of the output (in bytes).
    pub fn output_len(&mut self, len: usize) -> &mut Self {
        self.output_len = Some(len);
        self
    }

    /// Get the finished [`Params`].
    ///
    /// This performs validations to ensure that the given parameters are valid
    /// and compatible with each other, and will return an error if they are not.
    pub fn build(&self) -> Result<Params> {
        if self.m_cost < Params::MIN_M_COST {
            return Err(Error::MemoryTooLittle);
        }

        if self.m_cost > Params::MAX_M_COST {
            return Err(Error::MemoryTooMuch);
        }

        if self.m_cost < self.p_cost * 8 {
            return Err(Error::MemoryTooLittle);
        }

        if self.t_cost < Params::MIN_T_COST {
            return Err(Error::TimeTooSmall);
        }

        // Note: we don't need to check `MAX_T_COST`, since it's `u32::MAX`

        if self.p_cost < Params::MIN_P_COST {
            return Err(Error::ThreadsTooFew);
        }

        if self.p_cost > Params::MAX_P_COST {
            return Err(Error::ThreadsTooMany);
        }

        if let Some(len) = self.output_len {
            if len < Params::MIN_OUTPUT_LEN {
                return Err(Error::OutputTooShort);
            }

            if len > Params::MAX_OUTPUT_LEN {
                return Err(Error::OutputTooLong);
            }
        }

        let keyid = self.keyid.unwrap_or_default();

        let data = self.data.unwrap_or_default();

        let params = Params {
            m_cost: self.m_cost,
            t_cost: self.t_cost,
            p_cost: self.p_cost,
            keyid,
            data,
            output_len: self.output_len,
        };

        Ok(params)
    }
}

impl Default for ParamsBuilder {
    fn default() -> Self {
        let params = Params::default();
        Self {
            m_cost: params.m_cost,
            t_cost: params.t_cost,
            p_cost: params.p_cost,
            keyid: None,
            data: None,
            output_len: params.output_len,
        }
    }
}

impl TryFrom<ParamsBuilder> for Params {
    type Error = Error;

    fn try_from(builder: ParamsBuilder) -> Result<Params> {
        builder.build()
    }
}

#[cfg(all(test, feature = "alloc", feature = "password-hash"))]
mod tests {

    use super::*;

    #[test]
    fn params_builder_bad_values() {
        assert_eq!(
            ParamsBuilder::new().m_cost(Params::MIN_M_COST - 1).build(),
            Err(Error::MemoryTooLittle)
        );
        assert_eq!(
            ParamsBuilder::new().m_cost(Params::MAX_M_COST + 1).build(),
            Err(Error::MemoryTooMuch)
        );
        assert_eq!(
            ParamsBuilder::new().t_cost(Params::MIN_T_COST - 1).build(),
            Err(Error::TimeTooSmall)
        );
        assert_eq!(
            ParamsBuilder::new().p_cost(Params::MIN_P_COST - 1).build(),
            Err(Error::ThreadsTooFew)
        );
        assert_eq!(
            ParamsBuilder::new()
                .m_cost(Params::DEFAULT_P_COST * 8 - 1)
                .build(),
            Err(Error::MemoryTooLittle)
        );
        assert_eq!(
            ParamsBuilder::new()
                .m_cost((Params::MAX_P_COST + 1) * 8)
                .p_cost(Params::MAX_P_COST + 1)
                .build(),
            Err(Error::ThreadsTooMany)
        );
    }

    #[test]
    fn associated_data_too_long() {
        let ret = AssociatedData::new(&[0u8; Params::MAX_DATA_LEN + 1]);
        assert_eq!(ret, Err(Error::AdTooLong));
    }

    #[test]
    fn keyid_too_long() {
        let ret = KeyId::new(&[0u8; Params::MAX_KEYID_LEN + 1]);
        assert_eq!(ret, Err(Error::KeyIdTooLong));
    }
}
