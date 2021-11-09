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

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub const CREDENTIAL_PROOF_PURPOSE: &str = "assertionMethod";

/// Metadata about a property of a credential schema
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SchemaProperty {
    pub r#type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub items: Option<Vec<String>>,
}

/// AssertionProof, typically used to ensure authenticity and integrity of a verifiable credential
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AssertionProof {
    pub r#type: String,
    pub created: String,
    pub proof_purpose: String,
    pub verification_method: String,
    pub jws: String,
}

/// A verifiable credential issued by an issuer upon receiving a `CredentialRequest`.
/// Specifies the signed values, the DID of the prover/subject, the `CredentialSchema`, and the `CredentialSignature`
/// including revocation info.
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Credential {
    #[serde(rename(serialize = "@context", deserialize = "@context"))]
    pub context: Vec<String>,
    pub id: String,
    pub r#type: Vec<String>,
    pub issuer: String,
    pub issuance_date: String,
    pub credential_subject: CredentialSubject,
    pub credential_schema: CredentialSchemaReference,
    pub credential_status: CredentialStatus,
    pub proof: AssertionProof,
}

/// A verifiable credential with a blind signature that still needs to be processed by the holder
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct UnsignedCredential {
    #[serde(rename(serialize = "@context", deserialize = "@context"))]
    pub context: Vec<String>,
    pub id: String,
    pub r#type: Vec<String>,
    pub issuer: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<String>,
    pub issuance_date: String,
    pub credential_subject: CredentialSubject,
    pub credential_schema: CredentialSchemaReference,
    pub credential_status: CredentialStatus,
}

/// Payload/data part of a verifiable credential.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSubject {
    pub id: String,
    pub data: HashMap<String, String>,
}

/// 'credentialStatus' property of a verifiable credential containing revocation information.
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CredentialStatus {
    pub id: String,
    pub r#type: String,
    pub revocation_list_index: String,
    pub revocation_list_credential: String,
}

/// Result of a verify_proof call
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProofVerification {
    pub verified: bool,
}

/// Reference to a credential schema.
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSchemaReference {
    pub id: String,
    pub r#type: String,
}

/// Payload for signing an Unsigned credential
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IssueCredentialPayload {
    /// The VC to sign, without any appended proof
    pub unsigned_vc: UnsignedCredential,
    /// DID url of the public key of the issuer used to later verify the signature
    pub issuer_public_key_id: String,
    /// The public key of the issuer used to later verify the signature
    pub issuer_public_key: String,
}

/// Payload for verifying a signed Credential.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyProofPayload {
    /// VC to verify
    pub credential: Credential,
    /// Signer address
    pub signer_address: String,
}

/// Contains necessary information to sign the data
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SingerOptions {
    /// Reference to the private key, will be forwarded to external signer if available
    pub private_key: String,
    /// DID of the identity
    pub identity: String,
}