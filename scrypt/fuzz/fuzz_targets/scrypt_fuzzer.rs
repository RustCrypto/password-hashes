// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![no_main]

use libfuzzer_sys::fuzz_target;
use scrypt::{scrypt, Params};

#[cfg(feature = "simple")]
use {
    password_hash::Ident,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    scrypt::Scrypt,
};

#[cfg(feature = "simple")]
const SAMPLE_HASH: &str =
    "$scrypt$ln=16,r=8,p=1$aM15713r3Xsvxbi31lqr1Q$nFNh2CVHVjNldFVKDHDlm4CbdRSCdEBsjjJxD+iCs5E";

// Generate random params
fn fuzzed_params(data: &[u8]) -> Option<Params> {
    if data.len() >= 4 {
        let log_n = data[0] % 16; // Cap log_n to 16
        let r = u32::from_le_bytes([data[1], data[2], data[3], 0]) % 32; // Cap r to a reasonable value like 32
        let p = if data.len() > 4 {
            u32::from_le_bytes([data[4], data[5], data[6], 0]) % 16
        } else {
            1
        };
        let len = if data.len() > 7 {
            data[7] as usize % 65
        } else {
            32
        };

        Params::new(log_n, r, p, len).ok()
    } else {
        None
    }
}

// Generate random salt value
#[cfg(feature = "simple")]
fn fuzzed_salt(data: &[u8]) -> Option<SaltString> {
    let salt_data = if data.len() >= 16 { &data[..16] } else { data };
    SaltString::encode_b64(salt_data).ok()
}

// Validate the salt string
fn validate_salt(salt_str: &str) -> bool {
    // Check length
    let length = salt_str.len();
    if !(4..=64).contains(&length) {
        return false;
    }

    for char in salt_str.chars() {
        if !matches!(char, 'a'..='z' | 'A'..='Z' | '0'..='9' | '/' | '+' | '.' | '-') {
            return false;
        }
    }

    true
}

// Prepare random data by splitting random data
fn split_fuzz_data<'a>(data: &'a [u8], splits: &[usize]) -> Vec<&'a [u8]> {
    let mut result = Vec::new();
    let mut start = 0;

    for &split in splits {
        if start + split <= data.len() {
            result.push(&data[start..start + split]);
            start += split;
        } else {
            result.push(&data[start..]);
            break;
        }
    }

    result
}

fuzz_target!(|data: &[u8]| {
    let params = fuzzed_params(data).unwrap_or_else(|| Params::new(16, 8, 1, 64).unwrap());
    let splits = split_fuzz_data(data, &[32, 32, 32]);
    let password = splits.first().unwrap_or(&data);
    let salt = splits.get(1).unwrap_or(&data);
    let mut result = vec![0u8; 256];

    #[cfg(feature = "simple")]
    if let Some(salt_string) = fuzzed_salt(salt) {
        if !validate_salt(salt_string.as_str()) {
            return;
        }

        let salt_value = salt_string.as_salt(); // Safe to use now

        let formatted_hash = format!("$scrypt$ln=16,r=8,p=1${}$invalid$", hex::encode(password));

        if let Ok(hash) =
            PasswordHash::new(SAMPLE_HASH).or_else(|_| PasswordHash::new(formatted_hash.as_str()))
        {
            // Randomly choose the fuzz target function
            let target_selector = if !data.is_empty() { data[0] % 5 } else { 0 };
            match target_selector {
                0 => {
                    let _ = scrypt(password, salt, &params, &mut result);
                }
                1 => {
                    let _ = Scrypt.verify_password(password, &hash).is_err();
                }
                2 => {
                    let _ = Scrypt.hash_password_customized(
                        password,
                        Some(Ident::new_unwrap("scrypt")),
                        None,
                        params,
                        salt_value,
                    );
                }
                3 => {
                    if let Some(random_params) = fuzzed_params(password) {
                        let _ = scrypt(password, salt, &random_params, &mut result);
                    }
                }
                4 => {
                    let _ = PasswordHash::new(SAMPLE_HASH).is_ok();
                }
                _ => {
                    let _ = scrypt(password, salt, &params, &mut result);
                }
            }
        }
    } else {
        // Skip this iteration if the salt is invalid
        return;
    }
});
