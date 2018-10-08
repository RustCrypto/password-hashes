#![cfg(feature="include_simple")]
use std::io;

use errors::CheckError;
use super::scrypt;
use ScryptParams;

use subtle::ConstantTimeEq;
// TODO: replace with rand core and seprate os-rng crate
use rand::{OsRng, RngCore};
use byteorder::{ByteOrder, LittleEndian};
use base64;

/// `scrypt_simple` is a helper function that should be sufficient for the
/// majority of cases where an application needs to use Scrypt to hash a
/// password for storage. The result is a String that contains the parameters
/// used as part of its encoding. The `scrypt_check` function may be used on
/// a password to check if it is equal to a hashed value.
///
/// # Format
/// The format of the output is a modified version of the Modular Crypt Format
/// that encodes algorithm used and the parameter values. If all parameter
/// values can each fit within a single byte, a compact format is used
/// (format 0). However, if any value cannot, an expanded format where the
/// rand `p` parameters are encoded using 4 bytes (format 1) is used. Both
/// formats use a 128-bit salt and a 256-bit hash. The format is indicated as
/// "rscrypt" which is short for "Rust Scrypt format."
///
/// `$rscrypt$<format>$<base64(log_n,r,p)>$<base64(salt)>$<based64(hash)>$`
///
/// # Arguments
/// - `password` - The password to process as a str
/// - `params` - The ScryptParams to use
///
/// # Return
/// `Ok(String)` if calculation is succesfull with the computation result.
/// It will return `io::Error` error in the case of an unlikely `OsRng` failure.
#[cfg(feature="include_simple")]
pub fn scrypt_simple(password: &str, params: &ScryptParams)
    -> io::Result<String>
{
    let mut rng = OsRng::new()?;

    let mut salt = [0u8; 16];
    rng.try_fill_bytes(&mut salt)?;

    // 256-bit derived key
    let mut dk = [0u8; 32];

    scrypt(password.as_bytes(), &salt, params, &mut dk)
        .expect("32 bytes always satisfy output length requirements");

    // usually 128 bytes is enough
    let mut result = String::with_capacity(128);
    result.push_str("$rscrypt$");
    if params.r < 256 && params.p < 256 {
        result.push_str("0$");
        let mut tmp = [0u8; 3];
        tmp[0] = params.log_n;
        tmp[1] = params.r as u8;
        tmp[2] = params.p as u8;
        result.push_str(&base64::encode(&tmp));
    } else {
        result.push_str("1$");
        let mut tmp = [0u8; 9];
        tmp[0] = params.log_n;
        LittleEndian::write_u32(&mut tmp[1..5], params.r);
        LittleEndian::write_u32(&mut tmp[5..9], params.p);
        result.push_str(&base64::encode(&tmp));
    }
    result.push('$');
    result.push_str(&base64::encode(&salt));
    result.push('$');
    result.push_str(&base64::encode(&dk));
    result.push('$');

    Ok(result)
}

/// `scrypt_check` compares a password against the result of a previous call
/// to scrypt_simple and returns `Ok(())` if the passed in password hashes to
/// the same value, `Err(CheckError::HashMismatch)` if hashes have
/// different values, and `Err(CheckError::InvalidFormat)` if `hashed_value`
/// has an invalid format.
///
/// # Arguments
/// - password - The password to process as a str
/// - hashed_value - A string representing a hashed password returned
/// by `scrypt_simple()`
#[cfg(feature="include_simple")]
pub fn scrypt_check(password: &str, hashed_value: &str)
    -> Result<(), CheckError>
{
    let mut iter = hashed_value.split('$');

    // Check that there are no characters before the first "$"
    if iter.next() != Some("") { Err(CheckError::InvalidFormat)?; }

    // Check the name
    if iter.next() != Some("rscrypt") { Err(CheckError::InvalidFormat)?; }

    // Parse format - currenlty only version 0 (compact) and 1 (expanded) are
    // supported
    let fstr = iter.next().ok_or(CheckError::InvalidFormat)?;
    let pvec = iter.next().ok_or(CheckError::InvalidFormat)
        .and_then(|s| base64::decode(s).map_err(|_| CheckError::InvalidFormat))?;
    let params = match fstr {
        "0" if pvec.len() == 3 => {
            let log_n = pvec[0];
            let r = pvec[1] as u32;
            let p = pvec[2] as u32;
            ScryptParams::new(log_n, r, p)
                .map_err(|_| CheckError::InvalidFormat)
        }
        "1" if pvec.len() == 9 => {
            let log_n = pvec[0];
            let mut pval = [0u32; 2];
            LittleEndian::read_u32_into(&pvec[1..9], &mut pval);
            ScryptParams::new(log_n, pval[0], pval[1])
                .map_err(|_| CheckError::InvalidFormat)
        }
        _ => Err(CheckError::InvalidFormat),
    }?;

    // Salt
    let salt = iter.next().ok_or(CheckError::InvalidFormat)
        .and_then(|s| base64::decode(s).map_err(|_| CheckError::InvalidFormat))?;

    // Hashed value
    let hash = iter.next().ok_or(CheckError::InvalidFormat)
        .and_then(|s| base64::decode(s).map_err(|_| CheckError::InvalidFormat))?;

    // Make sure that the input ends with a "$"
    if iter.next() != Some("") { Err(CheckError::InvalidFormat)?; }

    // Make sure there is no trailing data after the final "$"
    if iter.next() != None { Err(CheckError::InvalidFormat)?; }

    let mut output = vec![0u8; hash.len()];
    scrypt(password.as_bytes(), &salt, &params, &mut output)
        .map_err(|_| CheckError::InvalidFormat)?;

    // Be careful here - its important that the comparison be done using a fixed
    // time equality check. Otherwise an adversary that can measure how long
    // this step takes can learn about the hashed value which would allow them
    // to mount an offline brute force attack against the hashed password.
    if output.ct_eq(&hash).unwrap_u8() == 1 {
        Ok(())
    } else {
        Err(CheckError::HashMismatch)?
    }
}
