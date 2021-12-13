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

use crate::{
    crypto::crypto_utils::create_assertion_proof,
    datatypes::{
        RevocationListCredential, RevocationListCredentialSubject,
        UnproofedRevocationListCredential, DEFAULT_REVOCATION_CONTEXTS,
    },
    utils::{decode_base64_config, get_now_as_iso_string},
};

use flate2::{read::GzDecoder, write::GzEncoder, Compression};
use std::{error::Error, io::prelude::*};
use vade_evan_substrate::signing::Signer;

pub struct Issuer {}

const MAX_REVOCATION_ENTRIES: usize = 131072;

impl Issuer {
    /// Creates a new revocation list. This list is used to store the revocation stat of a given credential id.
    /// It needs to be publicly published and updated after every revocation. The definition is signed by the issuer.
    ///
    /// # Arguments
    /// * `assigned_did` - DID that will point to the revocation list
    /// * `issuer_did` - DID of the issuer
    /// * `issuer_public_key_did` - DID of the public key that will be associated with the created signature
    /// * `issuer_proving_key` - Private key of the issuer used for signing the definition
    /// * `signer` - `Signer` to sign with
    ///
    /// # Returns
    /// * `RevocationListCredential` - The initial revocation list credential.
    pub async fn create_revocation_list(
        assigned_did: &str,
        issuer_did: &str,
        issuer_public_key_did: &str,
        issuer_proving_key: &str,
        signer: &Box<dyn Signer>,
    ) -> Result<RevocationListCredential, Box<dyn Error>> {
        let available_bytes = [0u8; MAX_REVOCATION_ENTRIES / 8];
        let mut gzip_encoder = GzEncoder::new(Vec::new(), Compression::default());
        gzip_encoder.write_all(&available_bytes)?;
        let compressed_bytes = gzip_encoder.finish();
        let unfinished_revocation_list = UnproofedRevocationListCredential {
            context: DEFAULT_REVOCATION_CONTEXTS
                .iter()
                .map(|c| String::from(c.to_owned()))
                .collect::<Vec<_>>(),
            id: assigned_did.to_owned(),
            r#type: vec![
                "VerifiableCredential".to_string(),
                "RevocationList2020Credential".to_string(),
            ],
            issuer: issuer_public_key_did.to_owned(),
            issued: get_now_as_iso_string(),
            credential_subject: RevocationListCredentialSubject {
                id: format!("{}#{}", assigned_did, "list"),
                r#type: "RevocationList2020".to_string(),
                encoded_list: base64::encode_config(&compressed_bytes?, base64::URL_SAFE),
            },
        };

        let document_to_sign = serde_json::to_value(&unfinished_revocation_list)?;
        let proof = create_assertion_proof(
            &document_to_sign,
            &issuer_public_key_did,
            issuer_did,
            issuer_proving_key,
            signer,
        )
        .await?;

        let revocation_list = RevocationListCredential::new(unfinished_revocation_list, proof);

        Ok(revocation_list)
    }

    /// Revokes a credential by flipping the specific index in the given revocation list.
    /// See <https://w3c-ccg.github.io/vc-status-rl-2020/#revocationlist2020credential> for reference
    /// # Arguments
    /// * `issuer` - DID of the issuer
    /// * `revocation_list` - Revocation list the credential belongs to
    /// * `revocation_id` - Revocation ID of the credential
    /// * `issuer_public_key_did` - DID of the public key that will be associated with the created signature
    /// * `issuer_proving_key` - Private key of the issuer used for signing the definition
    /// * `signer` - `Signer` to sign with
    ///
    /// # Returns
    /// * `RevocationListCredential` - The updated revocation list that needs to be stored in the original revocation list's place.
    pub async fn revoke_credential(
        issuer: &str,
        mut revocation_list: RevocationListCredential,
        revocation_id: &str,
        issuer_public_key_did: &str,
        issuer_proving_key: &str,
        signer: &Box<dyn Signer>,
    ) -> Result<RevocationListCredential, Box<dyn Error>> {
        let revocation_id = revocation_id
            .parse::<usize>()
            .map_err(|e| format!("Error parsing revocation_id: {}", e))?;

        if revocation_id > MAX_REVOCATION_ENTRIES {
            let error = format!(
                "Cannot revoke credential: revocation_id {} is larger than list limit of {}",
                revocation_id, MAX_REVOCATION_ENTRIES
            );
            return Err(Box::from(error));
        }

        let encoded_list = decode_base64_config(
            &revocation_list.credential_subject.encoded_list,
            base64::URL_SAFE,
            "Encoded revocation list",
        )?;
        let mut decoder = GzDecoder::new(&encoded_list[..]);
        let mut decoded_list = Vec::new();
        decoder.read_to_end(&mut decoded_list)?;

        let byte_index_float: f32 = (revocation_id / 8) as f32;
        let bit: u8 = 1 << (revocation_id % 8);
        let byte_index: usize = byte_index_float.floor() as usize;
        decoded_list[byte_index] |= bit;

        let mut gzip_encoder = GzEncoder::new(Vec::new(), Compression::default());
        gzip_encoder.write_all(&decoded_list)?;
        let compressed_bytes = gzip_encoder.finish()?;

        revocation_list.credential_subject.encoded_list =
            base64::encode_config(&compressed_bytes, base64::URL_SAFE);
        revocation_list.issued = get_now_as_iso_string();

        let document_to_sign = serde_json::to_value(&revocation_list)?;
        let proof = create_assertion_proof(
            &document_to_sign,
            &issuer_public_key_did,
            issuer,
            issuer_proving_key,
            signer,
        )
        .await?;

        revocation_list.proof = proof;

        Ok(revocation_list)
    }
}

#[cfg(test)]

mod tests {
    extern crate utilities;
    use super::*;
    use utilities::test_data::{
        accounts::local::{ISSUER_DID, ISSUER_PRIVATE_KEY, ISSUER_PUBLIC_KEY_DID},
        jwt_coherent_context_test_data::{EXAMPLE_REVOCATION_LIST_DID, REVOCATION_LIST_CREDENTIAL},
    };
    use vade_evan_substrate::signing::{LocalSigner, Signer};

    #[tokio::test]
    async fn revocation_can_create_revocation_registry() -> Result<(), Box<dyn Error>> {
        let signer: Box<dyn Signer> = Box::new(LocalSigner::new());

        Issuer::create_revocation_list(
            EXAMPLE_REVOCATION_LIST_DID,
            ISSUER_DID,
            ISSUER_PUBLIC_KEY_DID,
            ISSUER_PRIVATE_KEY,
            &signer,
        )
        .await?;

        Ok(())
    }

    #[tokio::test]
    async fn revocation_throws_error_when_max_count_reached() -> Result<(), Box<dyn Error>> {
        let signer: Box<dyn Signer> = Box::new(LocalSigner::new());

        let revocation_list: RevocationListCredential =
            serde_json::from_str(&REVOCATION_LIST_CREDENTIAL)?;

        let result = Issuer::revoke_credential(
            ISSUER_DID,
            revocation_list.clone(),
            &(MAX_REVOCATION_ENTRIES + 1).to_string(),
            ISSUER_PUBLIC_KEY_DID,
            ISSUER_PRIVATE_KEY,
            &signer,
        )
        .await
        .map_err(|e| format!("{}", e))
        .err();

        assert_eq!(
            result,
            Some(format!(
                "Cannot revoke credential: revocation_id {} is larger than list limit of {}",
                MAX_REVOCATION_ENTRIES + 1,
                MAX_REVOCATION_ENTRIES
            ))
        );
        Ok(())
    }

    #[tokio::test]
    async fn revocation_can_set_revoked_status() -> Result<(), Box<dyn Error>> {
        let signer: Box<dyn Signer> = Box::new(LocalSigner::new());

        let revocation_list: RevocationListCredential =
            serde_json::from_str(&REVOCATION_LIST_CREDENTIAL)?;

        let updated_revocation_list = Issuer::revoke_credential(
            ISSUER_DID,
            revocation_list.clone(),
            "1",
            ISSUER_PUBLIC_KEY_DID,
            ISSUER_PRIVATE_KEY,
            &signer,
        )
        .await?;

        assert_ne!(
            &revocation_list.credential_subject.encoded_list,
            &updated_revocation_list.credential_subject.encoded_list
        );

        Ok(())
    }
}
