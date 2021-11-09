/*
  Copyright (c) 2018-present evan GmbH.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

use async_trait::async_trait;
use secp256k1::{sign, Message, SecretKey, Signature};
use sha2::Digest;
use sha3::Keccak256;
use std::{convert::TryInto, error::Error};

#[async_trait(?Send)]
pub trait Signer {
    async fn sign_message(
        &self,
        message_to_sign: &str,
        signing_key: &str,
    ) -> Result<([u8; 65], [u8; 32]), Box<dyn Error>>;
}

/// Signer for signing messages locally with a private key.
pub struct LocalSigner {}

impl LocalSigner {
    /// Creates new `LocalSigner` instance.
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for LocalSigner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait(?Send)]
impl Signer for LocalSigner {
    /// Signs a message using secp256k1.
    /// `message_to_sign` can be a string, that will be hashed with `Keccak256` before signing it
    /// or a pre-hashed message, that starts with `0x`.
    ///
    /// # Arguments
    /// * `message_to_sign` - text to sign or a hash (starting with `0x`)
    /// * `signing_key` - Key to be used for signing
    ///
    /// # Returns
    /// `[u8; 65]` - Signature
    /// `[u8; 32]` - Hashed Message
    async fn sign_message(
        &self,
        message_to_sign: &str,
        signing_key: &str,
    ) -> Result<([u8; 65], [u8; 32]), Box<dyn Error>> {
        let mut hash_arr = [0u8; 32];

        if message_to_sign.starts_with("0x") {
            // already hashed
            let hash_vec = hex::decode(message_to_sign.trim_start_matches("0x"))?;
            hash_arr[..32].clone_from_slice(&hash_vec[..32]);
        } else {
            // create hash of data (including header)
            let mut hasher = Keccak256::new();
            hasher.input(&message_to_sign);
            let hash = hasher.result();

            // sign this hash
            hash_arr = hash.try_into().map_err(|_| "slice with incorrect length")?;
        }

        let message = Message::parse(&hash_arr);
        let mut private_key_arr = [0u8; 32];
        hex::decode_to_slice(signing_key, &mut private_key_arr)
            .map_err(|err| format!("private key for local signer invalid; {}", &err))?;
        let secret_key = SecretKey::parse(&private_key_arr)?;
        let (sig, rec): (Signature, _) = sign(&message, &secret_key);

        // sig to bytes (len 64), append recovery id
        let signature_arr = &sig.serialize();
        let mut sig_and_rec: [u8; 65] = [0; 65];
        sig_and_rec[..64].clone_from_slice(&signature_arr[..64]);
        sig_and_rec[64] = rec.serialize();

        Ok((sig_and_rec, hash_arr))
    }
}
