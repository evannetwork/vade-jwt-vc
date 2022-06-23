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
    crypto::{
        crypto_utils::{check_assertion_proof, create_assertion_proof},
        crypto_verifier::CryptoVerifier,
    },
    datatypes::{
        CreateRevocationListPayload, Credential, IssueCredentialPayload, ProofVerification,
        RevokeCredentialPayload, SignerOptions, TypeOptions, VerifyProofPayload,
    },
    issuer::Issuer,
};
use async_trait::async_trait;
use std::error::Error;
use vade::{VadePlugin, VadePluginResultValue};
use vade_evan_substrate::signing::Signer;

const EVAN_METHOD: &str = "did:evan";
const PROOF_METHOD_JWT: &str = "jwt";

pub struct VadeJwtVC {
    signer: Box<dyn Signer>,
}

macro_rules! parse {
    ($data:expr, $type_name:expr) => {{
        serde_json::from_str($data)
            .map_err(|e| format!("{} when parsing {} {}", &e, $type_name, $data))?
    }};
}

macro_rules! ignore_unrelated {
    ($method:expr, $options:expr) => {{
        if $method != EVAN_METHOD {
            return Ok(VadePluginResultValue::Ignored);
        }
        let type_options: TypeOptions = parse!($options, "options");
        match type_options.r#type.as_deref() {
            Some(PROOF_METHOD_JWT) => (),
            _ => return Ok(VadePluginResultValue::Ignored),
        };
    }};
}

impl VadeJwtVC {
    /// Creates new instance of `VadeJwtVC`.
    pub fn new(signer: Box<dyn Signer>) -> VadeJwtVC {
        match env_logger::try_init() {
            Ok(_) | Err(_) => (),
        };
        VadeJwtVC { signer }
    }
}

#[async_trait(?Send)]
impl VadePlugin for VadeJwtVC {
    /// Issues a new credential. This requires an UnsignedCredential.
    /// This method returns a signed Credential which has proof attached
    ///
    /// # Arguments
    ///
    /// * `method` - method to issue a credential for (e.g. "did:example")
    /// * `options` - serialized [`SignerOptions`](https://docs.rs/vade_jwt_vc/*/vade_jwt_vc/struct.SignerOptions.html)
    /// * `payload` - serialized [`IssueCredentialPayload`](https://docs.rs/vade_jwt_vc/*/vade_jwt_vc/struct.IssueCredentialPayload.html)
    ///
    /// # Returns
    /// * serialized [`Credential`](https://docs.rs/vade_jwt_vc/*/vade_jwt_vc/struct.Credential.html)
    async fn vc_zkp_issue_credential(
        &mut self,
        method: &str,
        options: &str,
        payload: &str,
    ) -> Result<VadePluginResultValue<Option<String>>, Box<dyn Error>> {
        ignore_unrelated!(method, options);

        let options: SignerOptions = serde_json::from_str(options)?;
        let issue_credential_payload: IssueCredentialPayload = serde_json::from_str(payload)?;

        let proof = create_assertion_proof(
            &serde_json::to_value(issue_credential_payload.unsigned_vc.clone())?,
            &issue_credential_payload.issuer_public_key_id,
            &issue_credential_payload.unsigned_vc.issuer,
            &options.private_key,
            &self.signer,
        )
        .await?;

        let signed_credential = Credential {
            context: issue_credential_payload.unsigned_vc.context,
            id: issue_credential_payload.unsigned_vc.id,
            r#type: issue_credential_payload.unsigned_vc.r#type,
            issuer: issue_credential_payload.unsigned_vc.issuer,
            issuance_date: issue_credential_payload.unsigned_vc.issuance_date,
            valid_until: issue_credential_payload.unsigned_vc.valid_until,
            credential_subject: issue_credential_payload.unsigned_vc.credential_subject,
            credential_schema: issue_credential_payload.unsigned_vc.credential_schema,
            credential_status: issue_credential_payload.unsigned_vc.credential_status,
            proof,
        };

        Ok(VadePluginResultValue::Success(Some(serde_json::to_string(
            &signed_credential,
        )?)))
    }

    /// Verifies the proof sent in a verified credential.
    ///
    /// # Arguments
    ///
    /// * `method` - method to verify a proof for (e.g. "did:example")
    /// * `options` - serialized [`TypeOptions`](https://docs.rs/vade_jwt_vc/*/vade_jwt_vc/struct.TypeOptions.html)
    /// * `payload` - serialized [`VerifyProofPayload`](https://docs.rs/vade_jwt_vc/*/vade_jwt_vc/struct.VerifyProofPayload.html)
    ///
    /// # Returns
    /// * `Option<String>` - A JSON object representing a `ProofVerification` type, specifying whether verification was successful
    async fn vc_zkp_verify_proof(
        &mut self,
        method: &str,
        options: &str,
        payload: &str,
    ) -> Result<VadePluginResultValue<Option<String>>, Box<dyn Error>> {
        ignore_unrelated!(method, options);

        let verify_proof_payload: VerifyProofPayload = serde_json::from_str(payload)?;
        match verify_proof_payload.revocation_list {
            Some(value) => {
                let revoked = CryptoVerifier::is_revoked(
                    &verify_proof_payload
                        .credential
                        .credential_status
                        .clone()
                        .ok_or("CredentialStatus required to check revocation status")?,
                    &value,
                )?;
                if revoked {
                    let verification_result = ProofVerification { verified: false };
                    return Ok(VadePluginResultValue::Success(Some(serde_json::to_string(
                        &verification_result,
                    )?)));
                }
            }
            _ => {}
        };

        let result = check_assertion_proof(
            &serde_json::to_string(&verify_proof_payload.credential)?,
            &verify_proof_payload.signer_address,
        );

        let res = match result {
            Ok(_) => ProofVerification { verified: true },
            Err(_) => ProofVerification { verified: false },
        };

        Ok(VadePluginResultValue::Success(Some(serde_json::to_string(
            &res,
        )?)))
    }

    /// Creates a new revocation list. The list consists of a encoded bit list which can
    /// hold up to 131,072 revokable ids. The list is GZIP encoded and will be updated on every revocation.
    /// The output is a W3C credential with a JWS signature by the given key.
    ///
    /// # Arguments
    ///
    /// * `method` - method to create a revocation list for (e.g. "did:example")
    /// * `options` - serialized [`TypeOptions`](https://docs.rs/vade_jwt_vc/*/vade_jwt_vc/struct.AuthenticationOptions.html)
    /// * `payload` - serialized [`CreateRevocationListPayload`](https://docs.rs/vade_jwt_vc/*/vade_jwt_vc/struct.CreateRevocationListPayload.html)
    ///
    /// # Returns
    /// * created revocation list as a JSON object as serialized [`RevocationList`](https://docs.rs/vade_jwt_vc/*/vade_jwt_vc/struct.RevocationList.html)
    async fn vc_zkp_create_revocation_registry_definition(
        &mut self,
        method: &str,
        options: &str,
        payload: &str,
    ) -> Result<VadePluginResultValue<Option<String>>, Box<dyn Error>> {
        ignore_unrelated!(method, options);
        let payload: CreateRevocationListPayload = parse!(payload, "payload");

        let revocation_list = Issuer::create_revocation_list(
            &payload.credential_did,
            &payload.issuer_did,
            &payload.issuer_public_key_did,
            &payload.issuer_proving_key,
            &self.signer,
        )
        .await?;

        let serialized_list = serde_json::to_string(&revocation_list)?;

        Ok(VadePluginResultValue::Success(Some(serialized_list)))
    }

    /// Revokes a credential. The information returned by this function needs to be persisted in order to update the revocation list. To revoke a credential, the revoker must be in possession of the private key associated
    /// with the credential's revocation list.
    ///
    /// # Arguments
    ///
    /// * `method` - method to revoke a credential for (e.g. "did:example")
    /// * `options` - serialized [`TypeOptions`](https://docs.rs/vade_jwt_vc/*/vade_jwt_vc/struct.AuthenticationOptions.html)
    /// * `payload` - serialized [`RevokeCredentialPayload`](https://docs.rs/vade_jwt_vc/*/vade_jwt_vc/struct.RevokeCredentialPayload.html)
    ///
    /// # Returns
    /// * `Option<String>` - The updated revocation list as a JSON object. Contains information
    /// needed to update the respective revocation list.
    async fn vc_zkp_revoke_credential(
        &mut self,
        method: &str,
        options: &str,
        payload: &str,
    ) -> Result<VadePluginResultValue<Option<String>>, Box<dyn Error>> {
        ignore_unrelated!(method, options);
        let payload: RevokeCredentialPayload = parse!(payload, "payload");
        let updated_list = Issuer::revoke_credential(
            &payload.issuer,
            payload.revocation_list,
            &payload.revocation_id,
            &payload.issuer_public_key_did,
            &payload.issuer_proving_key,
            &self.signer,
        )
        .await?;

        let serialized = serde_json::to_string(&updated_list)?;

        Ok(VadePluginResultValue::Success(Some(serialized)))
    }
}
