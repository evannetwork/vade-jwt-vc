# VadeJwtVC Plugin

[![crates.io](https://img.shields.io/crates/v/vade-jwt-vc.svg)](https://crates.io/crates/vade-jwt-vc)
[![Documentation](https://docs.rs/vade-jwt-vc/badge.svg)](https://docs.rs/vade-jwt-vc:q)
[![Apache-2 licensed](https://img.shields.io/crates/l/vade-jwt-vc.svg)](./LICENSE.txt)

## About
This crate allows you to issue and verify VC with simple JWT signature based on SECP256K1 curve.
For this purpose a [`VadePlugin`] implementation is exported: [`VadeJwtVC`].

## VadeJwtVC

Supports issue and verify VC with simple JWT signature based on SECP256K1 curve:

- [`vc_zkp_issue_credential`]
- [`vc_zkp_verify_proof`]

## Compiling vade_jwt_vc

```sh
cargo build --release
```

[`vc_zkp_issue_credential`]: https://docs.rs/vade_evan_bbs/*/vade_evan_bbs/struct.VadeEvanBbs.html#method.vc_zkp_issue_credential
[`vc_zkp_verify_proof`]: https://docs.rs/vade_evan_bbs/*/vade_evan_bbs/struct.VadeEvanBbs.html#method.vc_zkp_verify_proof
[`VadeJwtVC `]: https://git.slock.it/equs/interop/vade/vade-jwt-vc
[`VadePlugin`]: https://docs.rs/vade/*/vade/trait.VadePlugin.html