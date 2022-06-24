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

export const CREDENTIAL_PROOF_PURPOSE = 'assertionMethod';

/**
 * Message passed to vade containing the desired credential type.
 * Does not perform action if type does not indicate credential type jwt.
 * This can be done by passing "jwt" as the value for "type".
 */
export interface TypeOptions {
  type?: string;
}

/**
 * Metadata about a property of a credential schema
 */
export interface SchemaProperty {
  type: string;
  format?: string;
  items?: string[];
}

/**
 * AssertionProof, typically used to ensure authenticity and integrity of a verifiable credential
 */
export interface AssertionProof {
  type: string;
  created: string;
  proofPurpose: string;
  verificationMethod: string;
  jws: string;
}

/**
 * A verifiable credential issued by an issuer upon receiving a `CredentialRequest`.
 * Specifies the signed values, the DID of the prover/subject, the `CredentialSchema`, and the `CredentialSignature`
 * including revocation info.
 */
export interface Credential {
  '@context': (string | { [key in string]?: { '@type': string } })[];
  id: string;
  type: string[];
  issuer: string;
  issuanceDate: string;
  validUntil?: string;
  credentialSubject: CredentialSubject;
  credentialSchema: CredentialSchemaReference;
  credentialStatus: CredentialStatus;
  proof: AssertionProof;
}

export interface IssueCredentialResult {
  credential: Credential;
}

/**
 * A verifiable credential with a blind signature that still needs to be processed by the holder
 */
export interface UnsignedCredential {
  '@context': (string | { [key in string]?: { '@type': string } })[];
  id: string;
  type: string[];
  issuer: string;
  credentialSubject: CredentialSubject;
  credentialSchema: CredentialSchemaReference;
  credentialStatus: CredentialStatus;
  validUntil?: string;
  issuanceDate: string;
}

/**
 * Payload/data part of a verifiable credential.
 */
export interface CredentialSubject {
  id?: string;
  data: Record<string, string>;
}

/**
 * 'credentialStatus' property of a verifiable credential containing revocation information.
 */
export interface CredentialStatus {
  id: string;
  type: string;
  revocationListIndex: string;
  revocationListCredential: string;
}

/**
 * Result of a verify_proof call
 */
export interface ProofVerification {
  verified: bool;
}

/**
 * Reference to a credential schema.
 */
export interface CredentialSchemaReference {
  id: string;
  type: string;
}

/**
 * Payload for signing an Unsigned credential
 */
export interface IssueCredentialPayload {
  /** The VC to sign, without any appended proof */
  unsignedVc: UnsignedCredential;
  // DID url of the public key of the issuer used to later verify the signature
  issuerPublicKeyId: string;
  // The public key of the issuer used to later verify the signature
  issuerPublicKey: string;
}

/**
 * Payload for verifying a signed Credential.
 */
export interface VerifyProofPayload {
  // VC to verify
  credential: Credential;
  // Signer address
  signerAddress: string;
}

/**
 * Contains necessary information to sign the data
 */
export interface SignerOptions {
  // Reference to the private key, will be forwarded to external signer if available
  privateKey: string;
  // DID of the identity
  identity: string;
}
