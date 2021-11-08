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

use serde_json::Value;
use std::{collections::HashMap, env, error::Error};
use utilities::test_data::{
    accounts::local::{
        HOLDER_DID,
        ISSUER_DID,
        ISSUER_PRIVATE_KEY,
        ISSUER_PUBLIC_KEY_DID,
        SIGNER_1_ADDRESS,
        SIGNER_1_DID,
        SIGNER_1_PRIVATE_KEY,
        SIGNER_2_DID,
        SIGNER_2_PRIVATE_KEY,
        VERIFIER_DID,
    },
    jwt_coherent_context_test_data::{
        MASTER_SECRET,
        PUB_KEY,
        SECRET_KEY,
        SUBJECT_DID,
        UNSIGNED_CREDENTIAL,
    },
    did::EXAMPLE_DID_DOCUMENT_2,
    environment::DEFAULT_VADE_EVAN_SUBSTRATE_IP,
    vc_zkp::{SCHEMA_DESCRIPTION, SCHEMA_NAME, SCHEMA_PROPERTIES, SCHEMA_REQUIRED_PROPERTIES},
};
use vade::Vade;

use vade_jwt_vc::{
    VadeJwtVC,
    crypto::signing::{LocalSigner, Signer},
    datatypes::{IssueCredentialPayload,VerifyProofPayload,ProofVerification,UnsignedCredential,Credential}
};

const EVAN_METHOD: &str = "did:evan";
const TYPE_OPTIONS: &str = r#"{ "type": "bbs" }"#;
const SCHEMA_DID: &str =
    "did:evan:zkp:0xd641c26161e769cef4b41760211972b274a8f37f135a34083e4e48b3f1035eda";

fn get_vade() -> Vade {
    let mut vade = Vade::new();
    vade.register_plugin(Box::from(get_vade_jwt()));
    vade
}

fn get_vade_jwt() -> VadeJwtVC {
    // vade to work with
    let signer: Box<dyn Signer> = Box::new(LocalSigner::new());
    VadeJwtVC::new(signer)
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
        issuer_secret_key: SECRET_KEY.to_string(),
    };
    let issue_cred_json = serde_json::to_string(&issue_cred)?;

    let result = vade
        .vc_zkp_issue_credential(EVAN_METHOD, &get_options(), &issue_cred_json)
        .await?;

    let credential: Credential =
        serde_json::from_str(&result[0].as_ref().unwrap())?;

    Ok(credential)
}

fn get_unsigned_vc() -> Result<UnsignedCredential, Box<dyn Error>> {
    let mut unsigned_vc: UnsignedCredential = serde_json::from_str(UNSIGNED_CREDENTIAL)?;
    return Ok(unsigned_vc);
}

#[tokio::test]
async fn vade_jwt_vc_can_propose_request_issue_verify_a_credential() -> Result<(), Box<dyn Error>> {
    let mut vade = get_vade();

    let unfinished_credential = create_unfinished_credential(&mut vade).await?;
    // // verify proof
    // let verify_proof_payload = VerifyProofPayload {
    //     presentation: presentation.clone(),
    //     proof_request: proof_request.clone(),
    //     keys_to_schema_map: public_key_schema_map,
    //     signer_address: SIGNER_1_ADDRESS.to_string(),
    //     nquads_to_schema_map: nqsm,
    // };
    // let verify_proof_json = serde_json::to_string(&verify_proof_payload)?;
    // vade.vc_zkp_verify_proof(EVAN_METHOD, TYPE_OPTIONS, &verify_proof_json)
    //     .await?;

    Ok(())
}

