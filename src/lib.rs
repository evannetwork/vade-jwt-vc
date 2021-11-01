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

//! This crate allows you to issue and verify VC with simple JWT signature based on SECP256K1 curve.
//! For this purpose a [`VadePlugin`] implementation is exported: [`VadeJwtVC`].
//!
//! ## VadeJwtVC
//!
//! Supports issue and verify VC with simple JWT signature based on SECP256K1 curve:
//!
//! - [`vc_zkp_issue_credential`]
//! - [`vc_zkp_verify_proof`]
//!
//! ## Compiling vade_jwt_vc
//!
//! ```sh
//! cargo build --release
//! ```

//! [`vc_zkp_issue_credential`]: https://docs.rs/vade_evan_bbs/*/vade_evan_bbs/struct.VadeEvanBbs.html#method.vc_zkp_issue_credential
//! [`vc_zkp_verify_proof`]: https://docs.rs/vade_evan_bbs/*/vade_evan_bbs/struct.VadeEvanBbs.html#method.vc_zkp_verify_proof
//! [`VadeJwtVC `]: https://git.slock.it/equs/interop/vade/vade-jwt-vc
//! [`VadePlugin`]: https://docs.rs/vade/*/vade/trait.VadePlugin.html

#[macro_use]

// did
mod vade_jwt_vc;
pub use self::vade_jwt_vc::*;
