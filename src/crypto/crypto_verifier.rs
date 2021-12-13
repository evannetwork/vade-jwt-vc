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
    datatypes::{CredentialStatus, RevocationListCredential},
    utils::decode_base64_config,
};

use flate2::read::GzDecoder;
use std::{error::Error, io::prelude::*};

pub struct CryptoVerifier {}

impl CryptoVerifier {
    /// Checks if a given credential is revoked in the given revocation list
    ///
    /// # Arguments
    /// * `credential` - BbsCredential which has to be checked
    /// * `revocation_list` - Revocation list the credential belongs to
    ///
    /// # Returns
    /// * `bool` - bool value if the credential is revoked or not

    pub fn is_revoked(
        credential_status: &CredentialStatus,
        revocation_list: &RevocationListCredential,
    ) -> Result<bool, Box<dyn Error>> {
        let encoded_list = decode_base64_config(
            revocation_list.credential_subject.encoded_list.to_string(),
            base64::URL_SAFE,
            "Encoded Revocation List",
        )?;
        let mut decoder = GzDecoder::new(&encoded_list[..]);
        let mut decoded_list = Vec::new();
        decoder.read_to_end(&mut decoded_list)?;

        let revocation_list_index_number = credential_status
            .revocation_list_index
            .parse::<usize>()
            .map_err(|e| format!("Error parsing revocation_list_id: {}", e))?;

        let byte_index_float: f32 = (revocation_list_index_number / 8) as f32;
        let byte_index: usize = byte_index_float.floor() as usize;
        let revoked = decoded_list[byte_index] & (1 << (revocation_list_index_number % 8)) != 0;
        Ok(revoked)
    }
}

#[cfg(test)]

mod tests {
    extern crate utilities;

    use super::*;
    use crate::datatypes::Credential;
    use utilities::test_data::jwt_coherent_context_test_data::{
        FINISHED_CREDENTIAL, REVOCATION_LIST_CREDENTIAL, REVOCATION_LIST_CREDENTIAL_REVOKED_ID_1,
    };

    #[test]
    fn can_check_not_revoked_credential() -> Result<(), Box<dyn Error>> {
        let credential: Credential = serde_json::from_str(&FINISHED_CREDENTIAL)?;
        let revocation_list: RevocationListCredential =
            serde_json::from_str(&REVOCATION_LIST_CREDENTIAL)?;

        match CryptoVerifier::is_revoked(&credential.credential_status, &revocation_list) {
            Ok(revoked) => assert_eq!(false, revoked),
            Err(e) => assert!(false, "Unexpected error: {}", e),
        };
        Ok(())
    }

    #[test]
    fn can_check_revoked_credential() -> Result<(), Box<dyn Error>> {
        let credential: Credential = serde_json::from_str(&FINISHED_CREDENTIAL)?;
        let revocation_list: RevocationListCredential =
            serde_json::from_str(&REVOCATION_LIST_CREDENTIAL_REVOKED_ID_1)?;

        match CryptoVerifier::is_revoked(&credential.credential_status, &revocation_list) {
            Ok(revoked) => assert_eq!(true, revoked),
            Err(e) => assert!(false, "Unexpected error: {}", e),
        };
        Ok(())
    }
}
