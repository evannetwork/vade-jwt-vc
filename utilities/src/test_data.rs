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

#[allow(dead_code)]
pub mod accounts {
    pub mod local {
        #[allow(dead_code)]
        pub const ISSUER_ADDRESS: &str = "0xd2787429c2a5d88662a8c4af690a4479e0199c5e";

        #[allow(dead_code)]
        pub const ISSUER_DID: &str = "did:evan:testcore:0x6240cedfc840579b7fdcd686bdc65a9a8c42dea6";

        #[allow(dead_code)]
        pub const ISSUER_PRIVATE_KEY: &str =
            "30d446cc76b19c6eacad89237d021eb2c85144b61d63cb852aee09179f460920";

        #[allow(dead_code)]
        pub const ISSUER_PUBLIC_KEY_DID: &str =
            "did:evan:testcore:0x6240cedfc840579b7fdcd686bdc65a9a8c42dea6#key-1";

        #[allow(dead_code)]
        pub const SIGNER_1_ADDRESS: &str = "0xcd5e1dbb5552c2baa1943e6b5f66d22107e9c05c";

        #[allow(dead_code)]
        pub const SIGNER_1_DID: &str =
            "did:evan:testcore:0x0d87204c3957d73b68ae28d0af961d3c72403906";

        #[allow(dead_code)]
        pub const SIGNER_1_PRIVATE_KEY: &str =
            "dfcdcb6d5d09411ae9cbe1b0fd9751ba8803dd4b276d5bf9488ae4ede2669106";
    }

    pub mod remote {
        #[allow(dead_code)]
        pub const SIGNER_1_PRIVATE_KEY: &str = "a1c48241-5978-4348-991e-255e92d81f1e";

        #[allow(dead_code)]
        pub const SIGNER_1_SIGNED_MESSAGE_HASH: &str =
            "0x52091d1299031b18c1099620a1786363855d9fcd91a7686c866ad64f83de13ff";
    }
}

#[allow(dead_code)]
pub mod jwt_coherent_context_test_data {

    pub const EXAMPLE_REVOCATION_LIST_DID: &str =
    "did:evan:zkp:0x1234512345123451234512345123456789";

    pub const FINISHED_CREDENTIAL: &str = r###"{
        "@context":[
           "https://www.w3.org/2018/credentials/v1",
           "https:://schema.org",
           "https://w3id.org/vc-status-list-2021/v1"
        ],
        "id":"94450c72-5dc4-4e46-8df0-106819064656",
        "type":[
           "VerifiableCredential"
        ],
        "issuer":"did:evan:testcore:0x6240cedfc840579b7fdcd686bdc65a9a8c42dea6",
        "issuanceDate":"2021-04-20T08:35:56+0000",
        "credentialSubject":{
           "id":"did:evan:testcore:0x67ce8b01b3b75a9ba4a1462139a1edaa0d2f539f",
           "data":{
              "test_property_string3":"value",
              "test_property_string":"value",
              "test_property_string2":"value",
              "test_property_string4":"value",
              "test_property_string1":"value"
           }
        },
        "credentialSchema":{
           "id":"did:evan:zkp:0xd641c26161e769cef4b41760211972b274a8f37f135a34083e4e48b3f1035eda",
           "type":"EvanZKPSchema"
        },
        "credentialStatus":{
           "id":"did:evan:zkp:0xcac3f4186e273083820c8c59f3c52efb713a755de255d0eb997b4990253ea388#0",
           "type":"RevocationList2021Status",
           "revocationListIndex":"1",
           "revocationListCredential":"did:evan:zkp:0xcac3f4186e273083820c8c59f3c52efb713a755de255d0eb997b4990253ea388"
        },
        "proof":{
           "type":"EcdsaPublicKeySecp256k1",
           "created":"2021-12-14T14:20:50.000Z",
           "proofPurpose":"assertionMethod",
           "verificationMethod":"did:evan:testcore:0x6240cedfc840579b7fdcd686bdc65a9a8c42dea6#key-1",
           "jws":"eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NkstUiJ9.eyJpYXQiOiIyMDIxLTEyLTE0VDE0OjIwOjUwLjAwMFoiLCJkb2MiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLCJodHRwczo6Ly9zY2hlbWEub3JnIiwiaHR0cHM6Ly93M2lkLm9yZy92Yy1zdGF0dXMtbGlzdC0yMDIxL3YxIl0sImlkIjoiOTQ0NTBjNzItNWRjNC00ZTQ2LThkZjAtMTA2ODE5MDY0NjU2IiwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCJdLCJpc3N1ZXIiOiJkaWQ6ZXZhbjp0ZXN0Y29yZToweDYyNDBjZWRmYzg0MDU3OWI3ZmRjZDY4NmJkYzY1YTlhOGM0MmRlYTYiLCJpc3N1YW5jZURhdGUiOiIyMDIxLTA0LTIwVDA4OjM1OjU2KzAwMDAiLCJjcmVkZW50aWFsU3ViamVjdCI6eyJpZCI6ImRpZDpldmFuOnRlc3Rjb3JlOjB4NjdjZThiMDFiM2I3NWE5YmE0YTE0NjIxMzlhMWVkYWEwZDJmNTM5ZiIsImRhdGEiOnsidGVzdF9wcm9wZXJ0eV9zdHJpbmczIjoidmFsdWUiLCJ0ZXN0X3Byb3BlcnR5X3N0cmluZzIiOiJ2YWx1ZSIsInRlc3RfcHJvcGVydHlfc3RyaW5nMSI6InZhbHVlIiwidGVzdF9wcm9wZXJ0eV9zdHJpbmciOiJ2YWx1ZSIsInRlc3RfcHJvcGVydHlfc3RyaW5nNCI6InZhbHVlIn19LCJjcmVkZW50aWFsU2NoZW1hIjp7ImlkIjoiZGlkOmV2YW46emtwOjB4ZDY0MWMyNjE2MWU3NjljZWY0YjQxNzYwMjExOTcyYjI3NGE4ZjM3ZjEzNWEzNDA4M2U0ZTQ4YjNmMTAzNWVkYSIsInR5cGUiOiJFdmFuWktQU2NoZW1hIn0sImNyZWRlbnRpYWxTdGF0dXMiOnsiaWQiOiJkaWQ6ZXZhbjp6a3A6MHhjYWMzZjQxODZlMjczMDgzODIwYzhjNTlmM2M1MmVmYjcxM2E3NTVkZTI1NWQwZWI5OTdiNDk5MDI1M2VhMzg4IzAiLCJ0eXBlIjoiUmV2b2NhdGlvbkxpc3QyMDIxU3RhdHVzIiwicmV2b2NhdGlvbkxpc3RJbmRleCI6IjEiLCJyZXZvY2F0aW9uTGlzdENyZWRlbnRpYWwiOiJkaWQ6ZXZhbjp6a3A6MHhjYWMzZjQxODZlMjczMDgzODIwYzhjNTlmM2M1MmVmYjcxM2E3NTVkZTI1NWQwZWI5OTdiNDk5MDI1M2VhMzg4In19LCJpc3MiOiJkaWQ6ZXZhbjp0ZXN0Y29yZToweDYyNDBjZWRmYzg0MDU3OWI3ZmRjZDY4NmJkYzY1YTlhOGM0MmRlYTYifQ.aVr434yDZJjoTWpgcTw27ThXOuJNGIsHMbXpX_3-j19FY1uQVLILWHZaMlqlWSexSs2Q4c-PvXfzMMsj1aUOCQA"
        }
     }"###;

    pub const REVOCATION_LIST_CREDENTIAL: &str = r###"{
        "@context":[
            "https://www.w3.org/2018/credentials/v1",
            "https://w3id.org/vc-status-list-2021/v1"
        ],
        "id":"did:evan:zkp:0x1234512345123451234512345123456789",
        "type":[
            "VerifiableCredential",
            "StatusList2021Credential"
        ],
        "issuer":"did:evan:testcore:0x6240cedfc840579b7fdcd686bdc65a9a8c42dea6#key-1",
        "issued":"2021-03-15T06:53:13.000Z",
        "credentialSubject":{
            "id":"did:evan:zkp:0x1234512345123451234512345123456789#list",
            "type":"RevocationList2021",
            "encodedList":"H4sIAAAAAAAA_-3AMQEAAADCoPVPbQwfKAAAAAAAAAAAAAAAAAAAAOBthtJUqwBAAAA="
        },
        "proof":{
            "type":"EcdsaPublicKeySecp256k1",
            "created":"2021-03-15T06:53:13.000Z",
            "proofPurpose":"assertionMethod",
            "verificationMethod":"did:evan:testcore:0x6240cedfc840579b7fdcd686bdc65a9a8c42dea6#key-1",
            "jws":"eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NkstUiJ9.eyJpYXQiOiIyMDIxLTAzLTE1VDA2OjUzOjEzLjAwMFoiLCJkb2MiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLCJodHRwczovL3czaWQub3JnL3ZjLXN0YXR1cy1saXN0LTIwMjEvdjEiXSwiaWQiOiJkaWQ6ZXZhbjp6a3A6MHgxMjM0NTEyMzQ1MTIzNDUxMjM0NTEyMzQ1MTIzNDU2Nzg5IiwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIlN0YXR1c0xpc3QyMDIxQ3JlZGVudGlhbCJdLCJpc3N1ZXIiOiJkaWQ6ZXZhbjp0ZXN0Y29yZToweDYyNDBjZWRmYzg0MDU3OWI3ZmRjZDY4NmJkYzY1YTlhOGM0MmRlYTYja2V5LTEiLCJpc3N1ZWQiOiIyMDIxLTAzLTE1VDA2OjUzOjEzLjAwMFoiLCJjcmVkZW50aWFsU3ViamVjdCI6eyJpZCI6ImRpZDpldmFuOnprcDoweDEyMzQ1MTIzNDUxMjM0NTEyMzQ1MTIzNDUxMjM0NTY3ODkjbGlzdCIsInR5cGUiOiJSZXZvY2F0aW9uTGlzdDIwMjEiLCJlbmNvZGVkTGlzdCI6Ikg0c0lBQUFBQUFBQV8tM0FNUUVBQUFEQ29QVlBiUXdmS0FBQUFBQUFBQUFBQUFBQUFBQUFBT0J0aHRKVXF3QkFBQUE9In19LCJpc3MiOiJkaWQ6ZXZhbjp0ZXN0Y29yZToweDYyNDBjZWRmYzg0MDU3OWI3ZmRjZDY4NmJkYzY1YTlhOGM0MmRlYTYifQ.F98jOR5Cs9HEe4gz6RRc0Unnc-YkX_PUWs20eLrrlqgkN4g7OKNcAlxqo4ARPKU2oqWMq5NWO3Fj2rK8dMZnDQA"
        }
    }"###;
    
    pub const REVOCATION_LIST_CREDENTIAL_REVOKED_ID_1: &str = r###"{
        "@context":[
            "https://www.w3.org/2018/credentials/v1",
            "https://w3id.org/vc-status-list-2021/v1"
        ],
        "id":"did:evan:zkp:0x1234512345123451234512345123456789",
        "type":[
            "VerifiableCredential",
            "StatusList2021Credential"
        ],
        "issuer":"did:evan:testcore:0x6240cedfc840579b7fdcd686bdc65a9a8c42dea6#key-1",
        "issued":"2021-03-15T07:20:08.000Z",
        "credentialSubject":{
            "id":"did:evan:zkp:0x1234512345123451234512345123456789#list",
            "type":"RevocationList2021",
            "encodedList":"H4sIAAAAAAAA_-3AMQ0AAAACIGf_0MbwgQYAAAAAAAAAAAAAAAAAAAB4G7mHB0sAQAAA"
        },
        "proof":{
            "type":"EcdsaPublicKeySecp256k1",
            "created":"2021-03-15T07:20:08.000Z",
            "proofPurpose":"assertionMethod",
            "verificationMethod":"did:evan:testcore:0x6240cedfc840579b7fdcd686bdc65a9a8c42dea6#key-1",
            "jws":"eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NkstUiJ9.eyJpYXQiOiIyMDIxLTAzLTE1VDA3OjIwOjA4LjAwMFoiLCJkb2MiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLCJodHRwczovL3czaWQub3JnL3ZjLXN0YXR1cy1saXN0LTIwMjEvdjEiXSwiaWQiOiJkaWQ6ZXZhbjp6a3A6MHgxMjM0NTEyMzQ1MTIzNDUxMjM0NTEyMzQ1MTIzNDU2Nzg5IiwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIlN0YXR1c0xpc3QyMDIxQ3JlZGVudGlhbCJdLCJpc3N1ZXIiOiJkaWQ6ZXZhbjp0ZXN0Y29yZToweDYyNDBjZWRmYzg0MDU3OWI3ZmRjZDY4NmJkYzY1YTlhOGM0MmRlYTYja2V5LTEiLCJpc3N1ZWQiOiIyMDIxLTAzLTE1VDA3OjIwOjA4LjAwMFoiLCJjcmVkZW50aWFsU3ViamVjdCI6eyJpZCI6ImRpZDpldmFuOnprcDoweDEyMzQ1MTIzNDUxMjM0NTEyMzQ1MTIzNDUxMjM0NTY3ODkjbGlzdCIsInR5cGUiOiJSZXZvY2F0aW9uTGlzdDIwMjEiLCJlbmNvZGVkTGlzdCI6Ikg0c0lBQUFBQUFBQV8tM0FNUTBBQUFBQ0lHZl8wTWJ3Z1FZQUFBQUFBQUFBQUFBQUFBQUFBQUI0RzdtSEIwc0FRQUFBIn0sInByb29mIjp7InR5cGUiOiJFY2RzYVB1YmxpY0tleVNlY3AyNTZrMSIsImNyZWF0ZWQiOiIyMDIxLTAzLTE1VDA2OjUzOjEzLjAwMFoiLCJwcm9vZlB1cnBvc2UiOiJhc3NlcnRpb25NZXRob2QiLCJ2ZXJpZmljYXRpb25NZXRob2QiOiJkaWQ6ZXZhbjp0ZXN0Y29yZToweDYyNDBjZWRmYzg0MDU3OWI3ZmRjZDY4NmJkYzY1YTlhOGM0MmRlYTYja2V5LTEiLCJqd3MiOiJleUowZVhBaU9pSktWMVFpTENKaGJHY2lPaUpGVXpJMU5rc3RVaUo5LmV5SnBZWFFpT2lJeU1ESXhMVEF6TFRFMVZEQTJPalV6T2pFekxqQXdNRm9pTENKa2IyTWlPbnNpUUdOdmJuUmxlSFFpT2xzaWFIUjBjSE02THk5M2QzY3Vkek11YjNKbkx6SXdNVGd2WTNKbFpHVnVkR2xoYkhNdmRqRWlMQ0pvZEhSd2N6b3ZMM2N6YVdRdWIzSm5MM1pqTFhOMFlYUjFjeTFzYVhOMExUSXdNakV2ZGpFaVhTd2lhV1FpT2lKa2FXUTZaWFpoYmpwNmEzQTZNSGd4TWpNME5URXlNelExTVRJek5EVXhNak0wTlRFeU16UTFNVEl6TkRVMk56ZzVJaXdpZEhsd1pTSTZXeUpXWlhKcFptbGhZbXhsUTNKbFpHVnVkR2xoYkNJc0lsTjBZWFIxYzB4cGMzUXlNREl4UTNKbFpHVnVkR2xoYkNKZExDSnBjM04xWlhJaU9pSmthV1E2WlhaaGJqcDBaWE4wWTI5eVpUb3dlRFl5TkRCalpXUm1ZemcwTURVM09XSTNabVJqWkRZNE5tSmtZelkxWVRsaE9HTTBNbVJsWVRZamEyVjVMVEVpTENKcGMzTjFaV1FpT2lJeU1ESXhMVEF6TFRFMVZEQTJPalV6T2pFekxqQXdNRm9pTENKamNtVmtaVzUwYVdGc1UzVmlhbVZqZENJNmV5SnBaQ0k2SW1ScFpEcGxkbUZ1T25wcmNEb3dlREV5TXpRMU1USXpORFV4TWpNME5URXlNelExTVRJek5EVXhNak0wTlRZM09Ea2piR2x6ZENJc0luUjVjR1VpT2lKU1pYWnZZMkYwYVc5dVRHbHpkREl3TWpFaUxDSmxibU52WkdWa1RHbHpkQ0k2SWtnMGMwbEJRVUZCUVVGQlFWOHRNMEZOVVVWQlFVRkVRMjlRVmxCaVVYZG1TMEZCUVVGQlFVRkJRVUZCUVVGQlFVRkJRVUZCVDBKMGFIUktWWEYzUWtGQlFVRTlJbjE5TENKcGMzTWlPaUprYVdRNlpYWmhianAwWlhOMFkyOXlaVG93ZURZeU5EQmpaV1JtWXpnME1EVTNPV0kzWm1SalpEWTRObUprWXpZMVlUbGhPR00wTW1SbFlUWWlmUS5GOThqT1I1Q3M5SEVlNGd6NlJSYzBVbm5jLVlrWF9QVVdzMjBlTHJybHFna040ZzdPS05jQWx4cW80QVJQS1Uyb3FXTXE1TldPM0ZqMnJLOGRNWm5EUUEifX0sImlzcyI6ImRpZDpldmFuOnRlc3Rjb3JlOjB4NjI0MGNlZGZjODQwNTc5YjdmZGNkNjg2YmRjNjVhOWE4YzQyZGVhNiJ9.HeV3GYQDGZR21GI9vgC6GBXL1a6UHNUp_jdJMUkNv3ppOK01n5jL_H7mVN08i6H0z1ZBJEQRk2E1MV5IwNAysAA"
        }
    }"###;
    
    pub const UNSIGNED_CREDENTIAL: &str = r###"{
        "@context":[
           "https://www.w3.org/2018/credentials/v1",
           "https:://schema.org",
           "https://w3id.org/vc-status-list-2021/v1"
        ],
        "id":"94450c72-5dc4-4e46-8df0-106819064656",
        "type":[
           "VerifiableCredential"
        ],
        "issuer":"did:evan:testcore:0x6240cedfc840579b7fdcd686bdc65a9a8c42dea6",
        "credentialSubject":{
           "id":"did:evan:testcore:0x67ce8b01b3b75a9ba4a1462139a1edaa0d2f539f",
           "data":{
              "test_property_string4":"value",
              "test_property_string":"value",
              "test_property_string2":"value",
              "test_property_string1":"value",
              "test_property_string3":"value"
           }
        },
        "issuanceDate": "2021-04-20T08:35:56+0000",
        "credentialSchema":{
           "id":"did:evan:zkp:0xd641c26161e769cef4b41760211972b274a8f37f135a34083e4e48b3f1035eda",
           "type":"EvanZKPSchema"
        },
        "credentialStatus":{
           "id":"did:evan:zkp:0xcac3f4186e273083820c8c59f3c52efb713a755de255d0eb997b4990253ea388#0",
           "type":"RevocationList2021Status",
           "revocationListIndex": "1",
           "revocationListCredential":"did:evan:zkp:0xcac3f4186e273083820c8c59f3c52efb713a755de255d0eb997b4990253ea388"
        }
     }"###;

    pub const PUB_KEY: &str = "jCv7l26izalfcsFe6j/IqtVlDolo2Y3lNld7xOG63GjSNHBVWrvZQe2O859q9JeVEV4yXtfYofGQSWrMVfgH5ySbuHpQj4fSgLu4xXyFgMidUO1sIe0NHRcXpOorP01o";
}
