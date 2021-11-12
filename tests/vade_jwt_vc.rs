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

use std::error::Error;
use utilities::test_data::{
    accounts::local::{
        ISSUER_DID,
        SIGNER_1_ADDRESS,
        SIGNER_1_DID,
        SIGNER_1_PRIVATE_KEY,
    },
    jwt_coherent_context_test_data::{
        PUB_KEY,
        UNSIGNED_CREDENTIAL,
    },
};
use vade::Vade;

use vade_jwt_vc::{
    VadeJwtVC,
    datatypes::{IssueCredentialPayload,VerifyProofPayload,ProofVerification,UnsignedCredential,Credential}
};

const EVAN_METHOD: &str = "did:evan";

fn get_vade() -> Vade {
    let mut vade = Vade::new();
    vade.register_plugin(Box::from(get_vade_jwt()));
    vade
}

fn get_vade_jwt() -> VadeJwtVC {
    VadeJwtVC::new()
}

fn get_options() -> String {
    format!(
        r###"{{
            "privateKey": "{}",
            "identity": "{}"
        }}"###,
        SIGNER_1_PRIVATE_KEY, SIGNER_1_DID,
    )
}

async fn create_unfinished_credential(vade: &mut Vade) -> Result<Credential, Box<dyn Error>> {
    let key_id = format!("{}#key-1", ISSUER_DID);
    let unsigned_vc = get_unsigned_vc()?;
    let issue_cred = IssueCredentialPayload {
        unsigned_vc,
        issuer_public_key_id: key_id.clone(),
        issuer_public_key: PUB_KEY.to_string(),
    };
    let issue_cred_json = serde_json::to_string(&issue_cred)?;

    let result = vade
        .vc_zkp_issue_credential(EVAN_METHOD, &get_options(), &issue_cred_json)
        .await?;

    let credential_value = &result[0].as_ref().ok_or("Invalid Credential Value Returned")?;
    let credential: Credential =
        serde_json::from_str(credential_value)?;

    Ok(credential)
}

fn get_unsigned_vc() -> Result<UnsignedCredential, Box<dyn Error>> {
    let unsigned_vc: UnsignedCredential = serde_json::from_str(UNSIGNED_CREDENTIAL)?;
    return Ok(unsigned_vc);
}

#[tokio::test]
async fn vade_jwt_vc_can_propose_request_issue_verify_a_credential() -> Result<(), Box<dyn Error>> {
    let mut vade = get_vade();

    let credential = create_unfinished_credential(&mut vade).await?;
    // verify proof
    let verify_proof_payload = VerifyProofPayload {
        credential,
        signer_address: SIGNER_1_ADDRESS.to_string(),
    };
    let verify_proof_json = serde_json::to_string(&verify_proof_payload)?;
    let result = vade.vc_zkp_verify_proof(EVAN_METHOD, "{}", &verify_proof_json)
        .await?;

    
    let proof_verification: ProofVerification = serde_json::from_str(&result[0].as_ref().ok_or("Invalid ProofVerification Returned")?)?;
    assert_eq!(proof_verification.verified, true);
    Ok(())
}

